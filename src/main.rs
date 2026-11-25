//! Multi-Entity, Multi-Bank, Multi-Currency Banking & Payment Acquiring Oracle Daemon (`banking-oracle`).

use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use banking_oracle::adapters::acquirers::{
    OcbcMerchantCardAdapter, OcbcMerchantCardConfig, StripeAcquirerAdapter, StripeAcquirerConfig,
};
use banking_oracle::adapters::banks::{
    Iso20022BankAdapter, Iso20022BankConfig, OcbcCorporateBankAdapter, OcbcCorporateConfig,
};
use banking_oracle::api::{build_oracle_router, OracleApiState};
use banking_oracle::domain::entities::{
    AccountOwner, BankAccount, Counterparty, MerchantProfile,
};
use banking_oracle::engine::{ChainOutboxRelayer, PollingSupervisor, ReconciliationEngine};
use banking_oracle::ports::acquirer_adapter::PaymentAcquirerAdapter;
use banking_oracle::ports::bank_adapter::BankTechnicalAdapter;
use banking_oracle::ports::http_transport::ReqwestHttpTransport;
use banking_oracle::ports::store::OracleStore;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleDaemonConfig {
    pub listen_addr: String,
    pub state_file_path: String,
    pub l1_rpc_url: String,
    pub domain_salt: String,
    pub admin_bearer_token: String,
    pub poll_interval_secs: u64,
    pub outbox_flush_interval_secs: u64,
    #[serde(default)]
    pub ocbc_corporate: OcbcCorporateConfig,
    #[serde(default)]
    pub iso20022_banks: Vec<Iso20022BankConfig>,
    #[serde(default)]
    pub ocbc_merchant_card: OcbcMerchantCardConfig,
    #[serde(default)]
    pub stripe: StripeAcquirerConfig,
    #[serde(default)]
    pub bootstrap_entities: Vec<AccountOwner>,
    #[serde(default)]
    pub bootstrap_bank_accounts: Vec<BankAccount>,
    #[serde(default)]
    pub bootstrap_merchant_profiles: Vec<MerchantProfile>,
    #[serde(default)]
    pub bootstrap_counterparties: Vec<Counterparty>,
}

impl Default for OracleDaemonConfig {
    fn default() -> Self {
        Self {
            listen_addr: std::env::var("ORACLE_LISTEN").unwrap_or_else(|_| "0.0.0.0:9088".into()),
            state_file_path: std::env::var("ORACLE_STATE_FILE")
                .unwrap_or_else(|_| "./banking-oracle.snap.json".into()),
            l1_rpc_url: std::env::var("SLX_RPC_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8545".into()),
            domain_salt: std::env::var("ORACLE_DOMAIN_SALT")
                .unwrap_or_else(|_| "superlexicon-banking-oracle-salt-v2".into()),
            admin_bearer_token: std::env::var("ORACLE_ADMIN_TOKEN")
                .unwrap_or_else(|_| "dev_admin_token_change_me".into()),
            poll_interval_secs: 30,
            outbox_flush_interval_secs: 5,
            ocbc_corporate: OcbcCorporateConfig::default(),
            iso20022_banks: vec![],
            ocbc_merchant_card: OcbcMerchantCardConfig::default(),
            stripe: StripeAcquirerConfig::default(),
            bootstrap_entities: vec![],
            bootstrap_bank_accounts: vec![],
            bootstrap_merchant_profiles: vec![],
            bootstrap_counterparties: vec![],
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "banking_oracle=info".into()),
        )
        .init();

    let mut cfg = OracleDaemonConfig::default();
    for arg in std::env::args().skip(1) {
        if let Some(cfg_path) = arg.strip_prefix("--config=") {
            let raw = fs::read_to_string(cfg_path)?;
            cfg = serde_json::from_str(&raw)?;
        } else if let Some(listen) = arg.strip_prefix("--listen=") {
            cfg.listen_addr = listen.to_string();
        } else if let Some(rpc) = arg.strip_prefix("--rpc=") {
            cfg.l1_rpc_url = rpc.to_string();
        } else if let Some(state_file) = arg.strip_prefix("--state=") {
            cfg.state_file_path = state_file.to_string();
        } else if arg == "--help" || arg == "-h" {
            println!("Usage: banking-oracle [--config=deploy/config.example.json] [--listen=0.0.0.0:9088] [--rpc=http://127.0.0.1:8545] [--state=./banking-oracle.snap.json]");
            return Ok(());
        }
    }

    let transport = Arc::new(ReqwestHttpTransport::new(20)?);
    let store = Arc::new(OracleStore::open_persistent(PathBuf::from(
        &cfg.state_file_path,
    ))?);

    for ent in cfg.bootstrap_entities {
        store.upsert_entity(ent)?;
    }
    for acct in cfg.bootstrap_bank_accounts {
        store.upsert_bank_account(acct)?;
    }
    for mch in cfg.bootstrap_merchant_profiles {
        store.upsert_merchant_profile(mch)?;
    }
    for cp in cfg.bootstrap_counterparties {
        store.upsert_counterparty(cp)?;
    }

    let mut bank_map: HashMap<String, Arc<dyn BankTechnicalAdapter>> = HashMap::new();
    let ocbc_corp = Arc::new(OcbcCorporateBankAdapter::new(
        cfg.ocbc_corporate.clone(),
        transport.clone(),
    ));
    bank_map.insert(ocbc_corp.adapter_id().to_string(), ocbc_corp);

    for iso_cfg in cfg.iso20022_banks {
        let iso_adapter = Arc::new(Iso20022BankAdapter::new(iso_cfg, transport.clone()));
        bank_map.insert(iso_adapter.adapter_id().to_string(), iso_adapter);
    }

    let mut acq_map: HashMap<String, Arc<dyn PaymentAcquirerAdapter>> = HashMap::new();
    let ocbc_card = Arc::new(OcbcMerchantCardAdapter::new(
        cfg.ocbc_merchant_card.clone(),
        transport.clone(),
    ));
    acq_map.insert(ocbc_card.acquirer_id().to_string(), ocbc_card);

    let stripe = Arc::new(StripeAcquirerAdapter::new(
        cfg.stripe.clone(),
        transport.clone(),
    ));
    acq_map.insert(stripe.acquirer_id().to_string(), stripe);

    let bank_adapters = Arc::new(bank_map);
    let acquirer_adapters = Arc::new(acq_map);

    let engine = Arc::new(ReconciliationEngine::new(
        store.clone(),
        cfg.domain_salt.into_bytes(),
    ));
    let poller = Arc::new(PollingSupervisor::new(
        engine.clone(),
        bank_adapters.clone(),
        acquirer_adapters.clone(),
    ));
    let relayer = Arc::new(ChainOutboxRelayer::new(
        store.clone(),
        transport,
        cfg.l1_rpc_url.clone(),
    ));

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let _poll_handle = poller
        .clone()
        .spawn_background_loop(cfg.poll_interval_secs, shutdown_rx.clone());
    let _relay_handle = relayer
        .clone()
        .spawn_background_loop(cfg.outbox_flush_interval_secs, shutdown_rx);

    let api_state = Arc::new(OracleApiState {
        engine,
        poller,
        relayer,
        bank_adapters,
        acquirer_adapters,
        admin_bearer_token: cfg.admin_bearer_token,
    });

    let router = build_oracle_router(api_state);
    let sock: SocketAddr = cfg.listen_addr.parse()?;
    tracing::info!(
        listen = %sock,
        rpc = %cfg.l1_rpc_url,
        state_file = %cfg.state_file_path,
        "SuperLexicon Multi-Bank & Acquirer Oracle listening"
    );

    axum::Server::bind(&sock)
        .serve(router.into_make_service())
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            let _ = shutdown_tx.send(true);
        })
        .await?;

    Ok(())
}
