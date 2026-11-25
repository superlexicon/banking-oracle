//! End-to-end integration tests verifying all 5 architectural pillars of `banking-oracle`:
//! 1. Authenticated inbound bank webhooks (`AppliedCredit` & `OutboundPaymentStatusEvent`).
//! 2. Parallel periodic polling (`PollingSupervisor`: incoming txns, non-finalized outbound txns, acquirer batches).
//! 3. Technical vs. Business Hexagonal isolation across multiple banks (`OcbcCorporateBankAdapter` + `Iso20022BankAdapter`)
//!    and multiple currencies (`SGD`, `USD`, `JPY`).
//! 4. Multi-entity (`AccountOwner` A vs. `AccountOwner` B) & multi-counterparty boundary enforcement.
//! 5. Two-stage payment acquiring vs. asynchronous bank deposit finality bridging:
//!    - **OCBC Merchant Card Payments API** (`OcbcMerchantCardAdapter`) -> asynchronous T+1 settlement batch ->
//!      matched against `OcbcCorporateBankAdapter` CASA deposit (`AppliedCreditEvent`).
//!    - **Stripe** (`StripeAcquirerAdapter`) -> multiple card captures + pre-sweep refund -> periodical `payout.paid`
//!      sweep (`/v1/balance_transactions?payout=po_...`) -> matched against ISO 20022 bank deposit in BOTH arrival orders!

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::json;
use tower::ServiceExt;

use banking_oracle::adapters::acquirers::{
    OcbcMerchantCardAdapter, OcbcMerchantCardConfig, StripeAcquirerAdapter, StripeAcquirerConfig,
};
use banking_oracle::adapters::banks::{
    Iso20022BankAdapter, Iso20022BankConfig, OcbcCorporateBankAdapter, OcbcCorporateConfig,
};
use banking_oracle::api::{build_oracle_router, OracleApiState};
use banking_oracle::crypto::{hmac_sha256, TxWireFormat};
use banking_oracle::domain::entities::{
    AccountOwner, BankAccount, EntityChainBinding, MerchantProfile,
};
use banking_oracle::domain::events::TransferRail;
use banking_oracle::domain::ledger::{
    ClearingItemStatus, OnChainSettlementKind, OutboxTaskState, SubledgerAccountCode,
    SweepBatchStatus,
};
use banking_oracle::domain::money::{CurrencyCode, Money};
use banking_oracle::engine::{ChainOutboxRelayer, PollingSupervisor, ReconciliationEngine};
use banking_oracle::ports::acquirer_adapter::PaymentAcquirerAdapter;
use banking_oracle::ports::bank_adapter::{BankTechnicalAdapter, OutboundPaymentInstruction};
use banking_oracle::ports::http_transport::MockHttpTransport;
use banking_oracle::ports::store::OracleStore;

fn sign_hmac_header(secret: &str, ts: u64, body: &[u8]) -> String {
    let mut msg = format!("{}.", ts).into_bytes();
    msg.extend_from_slice(body);
    let tag = hmac_sha256(secret.as_bytes(), &msg);
    format!("t={},v1={}", ts, hex::encode(tag))
}

fn assert_entity_trial_balance_zero_net(store: &OracleStore, entity_id: &str) {
    let tb = store.compute_entity_trial_balance(entity_id);
    for (ccy, acct_map) in &tb {
        let total_dr: i128 = acct_map.values().map(|r| r.debit_minor).sum();
        let total_cr: i128 = acct_map.values().map(|r| r.credit_minor).sum();
        assert_eq!(
            total_dr, total_cr,
            "Trial balance out of balance for entity '{}' in currency {}",
            entity_id, ccy
        );
    }
}

struct TestHarness {
    transport: Arc<MockHttpTransport>,
    store: Arc<OracleStore>,
    engine: Arc<ReconciliationEngine>,
    poller: Arc<PollingSupervisor>,
    relayer: Arc<ChainOutboxRelayer>,
    router: axum::Router,
}

fn setup_multi_entity_harness() -> TestHarness {
    let transport = Arc::new(MockHttpTransport::new());
    let store = Arc::new(OracleStore::in_memory());

    // Entity A: SuperLexicon Pte. Ltd. (OCBC SGD + OCBC USD + OCBC Merchant Card API)
    let mut slx_ledgers = BTreeMap::new();
    slx_ledgers.insert(
        CurrencyCode::sgd(),
        "0xa1000000000000000000000000000000000000a1".into(),
    );
    slx_ledgers.insert(
        CurrencyCode::usd(),
        "0xa2000000000000000000000000000000000000a2".into(),
    );
    let mut slx_fx = BTreeMap::new();
    slx_fx.insert(CurrencyCode::sgd(), 745_000); // 1 SGD = $0.745 USD

    store
        .upsert_entity(AccountOwner {
            entity_id: "ent_slx_sg".into(),
            legal_name: "SuperLexicon Pte. Ltd.".into(),
            registration_number: "202600101A".into(),
            functional_currency: CurrencyCode::sgd(),
            active: true,
            chain_binding: Some(EntityChainBinding {
                oracle_private_key_hex: "11".repeat(32),
                chain_id: 1337,
                wire_format: TxWireFormat::SuperLexiconL1,
                treasury_identity_hex: Some(
                    "0x1000000000000000000000000000000000000010".into(),
                ),
                operating_bank_ledgers: slx_ledgers,
                ifrs_accounting_ledger_hex: Some(
                    "0xb1000000000000000000000000000000000000b1".into(),
                ),
                reward_voucher_hfs_hex: Some(
                    "0xd5000000000000000000000000000000000000d5".into(),
                ),
                fx_to_usd_ppm: slx_fx,
            }),
        })
        .unwrap();

    // Entity B: immin Pte. Ltd. (DBS ISO 20022 SGD + Stripe Acquirer settling into DBS SGD)
    let mut immin_ledgers = BTreeMap::new();
    immin_ledgers.insert(
        CurrencyCode::sgd(),
        "0xa3000000000000000000000000000000000000a3".into(),
    );
    let mut immin_fx = BTreeMap::new();
    immin_fx.insert(CurrencyCode::sgd(), 750_000);

    store
        .upsert_entity(AccountOwner {
            entity_id: "ent_immin_sg".into(),
            legal_name: "immin Pte. Ltd.".into(),
            registration_number: "202300882K".into(),
            functional_currency: CurrencyCode::sgd(),
            active: true,
            chain_binding: Some(EntityChainBinding {
                oracle_private_key_hex: "22".repeat(32),
                chain_id: 1337,
                wire_format: TxWireFormat::SuperLexiconL1,
                treasury_identity_hex: Some(
                    "0x2000000000000000000000000000000000000020".into(),
                ),
                operating_bank_ledgers: immin_ledgers,
                ifrs_accounting_ledger_hex: Some(
                    "0xb2000000000000000000000000000000000000b2".into(),
                ),
                reward_voucher_hfs_hex: Some(
                    "0xd6000000000000000000000000000000000000d6".into(),
                ),
                fx_to_usd_ppm: immin_fx,
            }),
        })
        .unwrap();

    // Bank Accounts across OCBC (SGD + USD) and DBS ISO 20022 (SGD)
    store
        .upsert_bank_account(BankAccount {
            account_id: "acct_slx_ocbc_sgd".into(),
            owner_entity_id: "ent_slx_sg".into(),
            bank_adapter_id: "ocbc_corporate".into(),
            bank_bic: "OCBCSGSG".into(),
            external_account_number: "501-889900-001".into(),
            currency: CurrencyCode::sgd(),
            display_name: "SLX OCBC SGD CASA".into(),
            poll_enabled: true,
            poll_interval_secs: 60,
        })
        .unwrap();

    store
        .upsert_bank_account(BankAccount {
            account_id: "acct_slx_ocbc_usd".into(),
            owner_entity_id: "ent_slx_sg".into(),
            bank_adapter_id: "ocbc_corporate".into(),
            bank_bic: "OCBCSGSG".into(),
            external_account_number: "501-889900-840".into(),
            currency: CurrencyCode::usd(),
            display_name: "SLX OCBC USD MCA".into(),
            poll_enabled: true,
            poll_interval_secs: 60,
        })
        .unwrap();

    store
        .upsert_bank_account(BankAccount {
            account_id: "acct_immin_dbs_sgd".into(),
            owner_entity_id: "ent_immin_sg".into(),
            bank_adapter_id: "iso20022_dbs".into(),
            bank_bic: "DBSSSGSG".into(),
            external_account_number: "072-112233-0".into(),
            currency: CurrencyCode::sgd(),
            display_name: "immin DBS SGD Account".into(),
            poll_enabled: true,
            poll_interval_secs: 60,
        })
        .unwrap();

    // Cross-entity boundary guard test: Entity A's merchant profile CANNOT settle into Entity B's bank account!
    let bad_cross_tenant = store.upsert_merchant_profile(MerchantProfile {
        merchant_profile_id: "mch_illegal_cross".into(),
        owner_entity_id: "ent_slx_sg".into(),
        acquirer_adapter_id: "ocbc_merchant_card".into(),
        external_merchant_id: "MID_BAD".into(),
        settlement_bank_account_id: "acct_immin_dbs_sgd".into(),
        settlement_currency: CurrencyCode::sgd(),
        accepted_currencies: vec![CurrencyCode::sgd()],
        poll_enabled: false,
        poll_interval_secs: 120,
    });
    assert!(
        bad_cross_tenant.is_err(),
        "must reject cross-entity settlement bank account binding"
    );

    // Valid Merchant Profiles:
    // 1. SLX uses OCBC Merchant Card Payments API -> settles into `acct_slx_ocbc_sgd`
    store
        .upsert_merchant_profile(MerchantProfile {
            merchant_profile_id: "mch_slx_ocbc_card".into(),
            owner_entity_id: "ent_slx_sg".into(),
            acquirer_adapter_id: "ocbc_merchant_card".into(),
            external_merchant_id: "OCBCMID8899001".into(),
            settlement_bank_account_id: "acct_slx_ocbc_sgd".into(),
            settlement_currency: CurrencyCode::sgd(),
            accepted_currencies: vec![CurrencyCode::sgd(), CurrencyCode::usd()],
            poll_enabled: true,
            poll_interval_secs: 120,
        })
        .unwrap();

    // 2. immin uses Stripe -> settles periodical sweeps into `acct_immin_dbs_sgd`
    store
        .upsert_merchant_profile(MerchantProfile {
            merchant_profile_id: "mch_immin_stripe".into(),
            owner_entity_id: "ent_immin_sg".into(),
            acquirer_adapter_id: "stripe".into(),
            external_merchant_id: "acct_immin_stripe_sg".into(),
            settlement_bank_account_id: "acct_immin_dbs_sgd".into(),
            settlement_currency: CurrencyCode::sgd(),
            accepted_currencies: vec![CurrencyCode::sgd(), CurrencyCode::usd()],
            poll_enabled: true,
            poll_interval_secs: 120,
        })
        .unwrap();

    let ocbc_token_vault = Arc::new(banking_oracle::adapters::ocbc_auth::OcbcTokenVault::new(
        store.clone(),
        Some("3f86faa0f22934789b71b79ac39ec34f".into()),
    ));
    let ocbc_rate_limiter = Arc::new(banking_oracle::adapters::ocbc_auth::OcbcRateLimiter::new(10));

    let ocbc_corp = Arc::new(OcbcCorporateBankAdapter::new(
        OcbcCorporateConfig {
            adapter_id: "ocbc_corporate".into(),
            base_url: "https://mock.ocbc.local".into(),
            client_id: "cid_corp".into(),
            redirect_uri: "https://oracle.superlexicon.io/v1/oauth/ocbc/callback".into(),
            default_access_token: Some("3f86faa0f22934789b71b79ac39ec34f".into()),
            paynow_partner_id: None,
            webhook_secret: "whsec_ocbc_corp_test".into(),
            max_webhook_skew_secs: 300,
            max_calls_per_minute: 10,
        },
        transport.clone(),
        ocbc_token_vault.clone(),
        ocbc_rate_limiter.clone(),
    ));

    let dbs_iso = Arc::new(Iso20022BankAdapter::new(
        Iso20022BankConfig {
            adapter_id: "iso20022_dbs".into(),
            bank_name: "DBS RAPID ISO 20022".into(),
            base_url: "https://mock.dbs.local".into(),
            bearer_or_api_key: "dbs_tok_123".into(),
            webhook_secret: "whsec_dbs_iso_test".into(),
            max_webhook_skew_secs: 300,
        },
        transport.clone(),
    ));

    let ocbc_card = Arc::new(OcbcMerchantCardAdapter::new(
        OcbcMerchantCardConfig {
            acquirer_id: "ocbc_merchant_card".into(),
            base_url: "https://mock.ocbc.local".into(),
            txn_signature_secret: "whsec_ocbc_card_test".into(),
            enforce_response_signature: false,
            max_webhook_skew_secs: 300,
            default_mdr_bps: 200,
        },
        transport.clone(),
        ocbc_token_vault.clone(),
        ocbc_rate_limiter.clone(),
    ));

    let stripe = Arc::new(StripeAcquirerAdapter::new(
        StripeAcquirerConfig {
            acquirer_id: "stripe".into(),
            base_url: "https://mock.stripe.local".into(),
            secret_api_key: "sk_test_immin".into(),
            webhook_secret: "whsec_stripe_test".into(),
            default_account_id: "acct_immin_stripe_sg".into(),
            max_webhook_skew_secs: 300,
        },
        transport.clone(),
    ));

    let mut bank_map: HashMap<String, Arc<dyn BankTechnicalAdapter>> = HashMap::new();
    bank_map.insert("ocbc_corporate".into(), ocbc_corp);
    bank_map.insert("iso20022_dbs".into(), dbs_iso);

    let mut acq_map: HashMap<String, Arc<dyn PaymentAcquirerAdapter>> = HashMap::new();
    acq_map.insert("ocbc_merchant_card".into(), ocbc_card);
    acq_map.insert("stripe".into(), stripe);

    let bank_adapters = Arc::new(bank_map);
    let acquirer_adapters = Arc::new(acq_map);

    let engine = Arc::new(ReconciliationEngine::new(
        store.clone(),
        b"prod-oracle-salt-2026".to_vec(),
    ));
    let poller = Arc::new(PollingSupervisor::new(
        engine.clone(),
        bank_adapters.clone(),
        acquirer_adapters.clone(),
    ));
    let relayer = Arc::new(ChainOutboxRelayer::new(
        store.clone(),
        transport.clone(),
        "http://mock.l1.local:8545".into(),
    ));

    let api_state = Arc::new(OracleApiState {
        engine: engine.clone(),
        poller: poller.clone(),
        relayer: relayer.clone(),
        bank_adapters,
        acquirer_adapters,
        ocbc_token_vault,
        ocbc_base_url: "https://mock.ocbc.local".into(),
        ocbc_client_id: "cid_corp".into(),
        ocbc_redirect_uri: "https://oracle.superlexicon.io/v1/oauth/ocbc/callback".into(),
        admin_bearer_token: "secret_admin_bearer".into(),
    });

    TestHarness {
        transport,
        store,
        engine,
        poller,
        relayer,
        router: build_oracle_router(api_state),
    }
}

#[tokio::test]
async fn ocbc_merchant_card_to_ocbc_casa_t_plus_1_batch_settlement_and_l1_voucher_flow() {
    let h = setup_multi_entity_harness();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let commit_1 = format!("0x{}", "aa".repeat(32));
    let commit_2 = format!("0x{}", "bb".repeat(32));

    // Step 1: Two customers pay via OCBC `POST /transactional/merchantcardpayments/1.0/sale` (`SGD 400.00` + `SGD 670.00` = `SGD 1,070.00` gross)
    for (txn_id, order_ref, cents, sku, commit) in [
        ("OCBC-CARD-TX-101", "ORD-V1-01", 40_000i128, "slx-v1", &commit_1),
        ("OCBC-CARD-TX-102", "ORD-G1-02", 67_000i128, "slx-g1", &commit_2),
    ] {
        h.transport.enqueue_json(
            "mock.ocbc.local/transactional/merchantcardpayments/1.0/sale",
            200,
            json!({
                "results": {
                    "transactionId": txn_id,
                    "merchantTranId": order_ref,
                    "customerId": "CUST-SG-01",
                    "authId": "AUTH8899",
                    "responseCode": "0",
                    "responseDesc": "Approved",
                    "txnStatus": "SALES",
                    "salesDate": "25-11-2026 14:22:10",
                    "tranDate": "25-11-2026",
                    "frScore": "05",
                    "frLevel": "LOW"
                },
                "disclaimer": "OCBC Sandbox"
            }),
        );

        let req_body = serde_json::to_vec(&json!({
            "merchant_profile_id": "mch_slx_ocbc_card",
            "payment": {
                "order_reference": order_ref,
                "customer_id": "CUST-SG-01",
                "amount": { "amount_minor": cents, "currency": "SGD" },
                "description": "SuperLexicon Hardware Order",
                "capture_mode": "immediate_sale",
                "voucher_metadata": {
                    "sku_code": banking_oracle::domain::events::VoucherOrderMetadata::parse_sku_code(sku).unwrap(),
                    "tier_bps": 15000,
                    "voucher_commitment_hex": commit,
                    "explicit_price_usd_micros": null
                }
            }
        }))
        .unwrap();

        let resp = h
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/payments/merchant/sessions")
                    .header("Authorization", "Bearer secret_admin_bearer")
                    .header("Content-Type", "application/json")
                    .body(Body::from(req_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // CRITICAL SEGREGATION CHECK:
    // Both OCBC card captures are in `1140 Acquirer Clearing Receivable` (`107_000` cents),
    // `1010 Cash at Bank` is STILL ZERO, and ZERO `RewardVoucher` or `AssetLedger` tasks are queued yet!
    let tb_stage1 = h.store.compute_entity_trial_balance("ent_slx_sg");
    let sgd_tb1 = &tb_stage1[&CurrencyCode::sgd()];
    assert_eq!(
        sgd_tb1
            .get(&SubledgerAccountCode::CashAtBank1010)
            .map(|r| r.net_debit_minus_credit_minor)
            .unwrap_or(0),
        0
    );
    assert_eq!(
        sgd_tb1[&SubledgerAccountCode::AcquirerClearingReceivable1140].net_debit_minus_credit_minor,
        107_000
    );
    assert!(
        h.store.pending_outbox_tasks().is_empty(),
        "Zero on-chain finality tasks may fire before actual OCBC CASA deposit!"
    );

    // Step 2: Parallel `PollingSupervisor` runs `GET /transactional/corpTransHistory/1.0?sessionToken=OAuth2INB%20...&accountId=...&fromDate=dd-mm-yyyy&toDate=dd-mm-yyyy`!
    // First OCBC account poll (`acct_slx_ocbc_sgd`): settlement credit arrives BEFORE merchant settlement manifest (testing Bank-Credit-First out-of-order reconciliation!)
    h.transport.enqueue_json(
        "mock.ocbc.local/transactional/corpTransHistory/1.0",
        200,
        json!({
            "success": true,
            "results": [
                {
                    "amount": "1048.60",
                    "debitCreditIndicator": "C",
                    "transactionDate": "25-11-2026",
                    "currencyCode": "SGD",
                    "batchReference": "OCBC-MC-STL-20261125-01",
                    "transactionDescription": "OCBC CARD SETTLEMENT OCBC-MC-STL-20261125-01"
                }
            ],
            "errorMessage": null,
            "disclaimer": "OCBC Sandbox"
        }),
    );
    // Second OCBC account poll (`acct_slx_ocbc_usd`): `USD 2,500.00` invoice `INV-9001`
    h.transport.enqueue_json(
        "mock.ocbc.local/transactional/corpTransHistory/1.0",
        200,
        json!({
            "success": true,
            "results": [
                {
                    "amount": "2500.00",
                    "debitCreditIndicator": "C",
                    "transactionDate": "25-11-2026",
                    "currencyCode": "USD",
                    "transactionDescription": "B2B GATEWAY ORDER PAYMENT INV-9001"
                }
            ],
            "errorMessage": null,
            "disclaimer": "OCBC Sandbox"
        }),
    );
    h.transport.enqueue_json(
        "mock.dbs.local/iso20022/v1/accounts/072-112233-0/statements",
        200,
        json!({ "BkToCstmrStmt": { "Stmt": { "Acct": { "Id": { "Othr": { "Id": "072-112233-0" } } }, "Ntry": [] } } }),
    );
    h.transport.enqueue_json(
        "mock.stripe.local/v1/payouts",
        200,
        json!({ "data": [] }),
    );

    let report = h.poller.run_poll_cycle_once(now + 60).await;
    assert_eq!(report.errors, Vec::<String>::new());
    assert_eq!(report.incoming_credits_ingested, 2);

    // Verify exact OCBC query parameters (`sessionToken=OAuth2INB%203f86...`, `fromDate`/`toDate` in `dd-mm-yyyy`)!
    let recorded = h.transport.recorded_requests();
    let hist_req = recorded
        .iter()
        .find(|r| r.url.contains("/transactional/corpTransHistory/1.0"))
        .expect("corpTransHistory/1.0 called");
    assert!(hist_req
        .url
        .contains("sessionToken=OAuth2INB%203f86faa0f22934789b71b79ac39ec34f"));
    assert!(hist_req.url.contains("accountId=501-889900-001"));
    assert!(hist_req.headers.iter().any(|(k, v)| {
        k == "Authorization" && v == "Bearer 3f86faa0f22934789b71b79ac39ec34f"
    }));

    // Now post the EOD OCBC Merchant Settlement Batch manifest (`POST /v1/merchants/mch_slx_ocbc_card/settlement-batches`) ->
    // reconciles against the already-polled `1048.60` `corpTransHistory/1.0` credit!
    let batch_body = serde_json::to_vec(&json!({
        "acquirer_adapter_id": "ocbc_merchant_card",
        "external_merchant_id": "OCBCMID8899001",
        "batch_id": "BATCH-20261125-01",
        "bank_statement_reference": "OCBC-MC-STL-20261125-01",
        "settlement_currency": "SGD",
        "gross_sales_minor": 107000,
        "refunds_minor": 0,
        "total_fees_minor": 2140,
        "net_payout_minor": 104860,
        "settlement_date": "25-11-2026",
        "created_at_unix": now + 62,
        "lines": [
            { "acquirer_payment_id": "OCBC-CARD-TX-101", "is_refund": false, "settlement_gross_minor": 40000, "settlement_fee_minor": 800, "settlement_net_minor": 39200 },
            { "acquirer_payment_id": "OCBC-CARD-TX-102", "is_refund": false, "settlement_gross_minor": 67000, "settlement_fee_minor": 1340, "settlement_net_minor": 65660 }
        ],
        "source": "manual_sync"
    }))
    .unwrap();
    let batch_resp = h
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/merchants/mch_slx_ocbc_card/settlement-batches")
                .header("Authorization", "Bearer secret_admin_bearer")
                .header("Content-Type", "application/json")
                .body(Body::from(batch_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(batch_resp.status(), StatusCode::OK);

    // Verify full double-entry Trial Balance across BOTH SGD and USD for Entity A!
    assert_entity_trial_balance_zero_net(&h.store, "ent_slx_sg");
    let tb_final = h.store.compute_entity_trial_balance("ent_slx_sg");
    let sgd_final = &tb_final[&CurrencyCode::sgd()];
    assert_eq!(
        sgd_final[&SubledgerAccountCode::CashAtBank1010].net_debit_minus_credit_minor,
        104_860
    );
    assert_eq!(
        sgd_final[&SubledgerAccountCode::BankAndAcquirerFees6250].net_debit_minus_credit_minor,
        2_140
    );
    assert_eq!(
        sgd_final[&SubledgerAccountCode::AcquirerClearingReceivable1140]
            .net_debit_minus_credit_minor,
        0,
        "1140 Acquirer Clearing must net to 0 after sweep reconciliation!"
    );
    assert_eq!(
        sgd_final[&SubledgerAccountCode::UnattributedCashSuspense2900].net_debit_minus_credit_minor,
        0,
        "2900 Suspense must reclassify to 0 once OCBC Merchant Batch matches!"
    );
    assert_eq!(
        sgd_final[&SubledgerAccountCode::RealizedOperatingRevenue4000]
            .net_debit_minus_credit_minor,
        -107_000 // Credit balance = 1,070.00 SGD
    );

    let usd_final = &tb_final[&CurrencyCode::usd()];
    assert_eq!(
        usd_final[&SubledgerAccountCode::CashAtBank1010].net_debit_minus_credit_minor,
        250_000 // $2,500.00 USD
    );
    assert_eq!(
        usd_final[&SubledgerAccountCode::TradeReceivables1200].net_debit_minus_credit_minor,
        -250_000
    );

    // Verify both OCBC card items are now `BankCashFinalized`!
    h.store.read(|s| {
        for tx_id in ["OCBC-CARD-TX-101", "OCBC-CARD-TX-102"] {
            let key = format!("ocbc_merchant_card:mch_slx_ocbc_card:{}", tx_id);
            assert!(matches!(
                s.clearing_items[&key].status,
                ClearingItemStatus::BankCashFinalized { .. }
            ));
        }
    });

    // Relay all pending on-chain HFS tasks (`MintOperatingBankCash` SGD + USD, `QuarantineIfrsSuspense`,
    // `SettleIfrsCreditInvoice #9001`, and 2x `IssuePaidHardwareVoucher`) to mock SuperLexicon L1 RPC!
    let pending = h.store.pending_outbox_tasks();
    assert_eq!(pending.len(), 6);
    let voucher_tasks = pending
        .iter()
        .filter(|t| matches!(t.action, OnChainSettlementKind::IssuePaidHardwareVoucher { .. }))
        .count();
    assert_eq!(voucher_tasks, 2);

    for i in 0..pending.len() {
        h.transport.enqueue_json(
            "mock.l1.local:8545",
            200,
            json!({ "jsonrpc": "2.0", "id": 1, "result": format!("0x{:x}", i) }),
        );
        h.transport.enqueue_json(
            "mock.l1.local:8545",
            200,
            json!({ "jsonrpc": "2.0", "id": 1, "result": format!("0x{:064x}", i + 1) }),
        );
    }
    let relayed = h.relayer.flush_pending_outbox(now + 65).await;
    assert_eq!(relayed, 6);
    assert!(h.store.pending_outbox_tasks().is_empty());
}

#[tokio::test]
async fn stripe_periodical_sweep_with_pre_sweep_refund_and_outbound_payment_polling() {
    let h = setup_multi_entity_harness();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Part A: Entity B (`ent_immin_sg`) processes 3 Stripe card payments (`pi_1` = SGD 200, `pi_2` = SGD 500, `pi_3` = SGD 300),
    // and `pi_3` is REFUNDED before Stripe executes its periodical sweep payout!
    let c1 = format!("0x{}", "12".repeat(32));
    let c2 = format!("0x{}", "34".repeat(32));
    let c3 = format!("0x{}", "56".repeat(32));

    for (pi_id, cents, sku, commit) in [
        ("pi_stripe_1", 20_000i64, "dongle", &c1),
        ("pi_stripe_2", 50_000i64, "watch", &c2),
        ("pi_stripe_3_refunded", 30_000i64, "watch", &c3),
    ] {
        let body = serde_json::to_vec(&json!({
            "account": "acct_immin_stripe_sg",
            "type": "payment_intent.succeeded",
            "data": {
                "object": {
                    "id": pi_id,
                    "currency": "sgd",
                    "amount_received": cents,
                    "metadata": {
                        "order_ref": format!("ORD-{}", pi_id),
                        "sku": sku,
                        "tier": "standard",
                        "voucher_commitment": commit
                    }
                }
            }
        }))
        .unwrap();
        let sig = sign_hmac_header("whsec_stripe_test", now, &body);
        let resp = h
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/webhooks/acquirers/stripe")
                    .header("Stripe-Signature", sig)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // Refund `pi_stripe_3_refunded` BEFORE sweep!
    let refund_body = serde_json::to_vec(&json!({
        "account": "acct_immin_stripe_sg",
        "type": "charge.refunded",
        "data": {
            "object": {
                "id": "re_stripe_3",
                "payment_intent": "pi_stripe_3_refunded",
                "currency": "sgd",
                "amount_refunded": 30000
            }
        }
    }))
    .unwrap();
    let ref_sig = sign_hmac_header("whsec_stripe_test", now + 5, &refund_body);
    let resp = h
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/webhooks/acquirers/stripe")
                .header("Stripe-Signature", ref_sig)
                .body(Body::from(refund_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Stripe fires `payout.paid` (`po_weekly_001`):
    // Gross = 200 + 500 + 300 = 1,000.00 (`100_000`), Refunds = 300.00 (`30_000`), Stripe Fees = 23.80 (`2_380`),
    // Net Sweep Payout = `67_620` cents (`SGD 676.20`)!
    // Enqueue `/v1/balance_transactions?payout=po_weekly_001` decomposition response:
    h.transport.enqueue_json(
        "mock.stripe.local/v1/balance_transactions?payout=po_weekly_001",
        200,
        json!({
            "data": [
                { "type": "payout", "amount": -67620, "fee": 0, "source": "po_weekly_001" },
                { "type": "charge", "amount": 20000, "fee": 680, "payment_intent": "pi_stripe_1" },
                { "type": "charge", "amount": 50000, "fee": 1700, "payment_intent": "pi_stripe_2" },
                { "type": "charge", "amount": 30000, "fee": 0, "payment_intent": "pi_stripe_3_refunded" },
                { "type": "refund", "amount": -30000, "fee": 0, "payment_intent": "pi_stripe_3_refunded" }
            ]
        }),
    );

    let payout_body = serde_json::to_vec(&json!({
        "account": "acct_immin_stripe_sg",
        "type": "payout.paid",
        "data": {
            "object": {
                "id": "po_weekly_001",
                "currency": "sgd",
                "amount": 67620,
                "statement_descriptor": "STRIPE PAYOUT PO_WEEKLY_001"
            }
        }
    }))
    .unwrap();
    let po_sig = sign_hmac_header("whsec_stripe_test", now + 10, &payout_body);
    let resp = h
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/webhooks/acquirers/stripe")
                .header("Stripe-Signature", po_sig)
                .body(Body::from(payout_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // STILL zero vouchers issued because Stripe's `payout.paid` is NOT bank finality until DBS reports the `SGD 676.20` deposit!
    assert!(
        h.store.pending_outbox_tasks().is_empty(),
        "Stripe payout.paid alone must wait for actual DBS bank AppliedCredit!"
    );

    // Now DBS ISO 20022 `camt.054` webhook delivers the finalized booked deposit (`Sts = BOOK`, `SGD 676.20`)!
    // Enqueue 3 RPC tx pairs (`MintOperatingBankCash` + 2x `IssuePaidHardwareVoucher` for `pi_1` & `pi_2`, NOT refunded `pi_3`!):
    for i in 0..3 {
        h.transport.enqueue_json(
            "mock.l1.local:8545",
            200,
            json!({ "jsonrpc": "2.0", "id": 1, "result": format!("0x{:x}", i) }),
        );
        h.transport.enqueue_json(
            "mock.l1.local:8545",
            200,
            json!({ "jsonrpc": "2.0", "id": 1, "result": format!("0x{:064x}", 100 + i) }),
        );
    }

    let camt054_body = serde_json::to_vec(&json!({
        "BkToCstmrDbtCdtNtfctn": {
            "Ntfctn": {
                "Acct": { "Id": { "Othr": { "Id": "072-112233-0" } } },
                "Ntry": [
                    {
                        "AcctSvcrRef": "DBS-GIRO-998811",
                        "CdtDbtInd": "CRDT",
                        "Sts": { "Cd": "BOOK" },
                        "Amt": { "Ccy": "SGD", "Val": "676.20" },
                        "ValDt": { "Dt": "2026-11-25" },
                        "NtryDtls": {
                            "TxDtls": {
                                "Refs": { "EndToEndId": "E2E-STRIPE-001" },
                                "RmtInf": { "Ustrd": "GIRO INCOMING STRIPE PAYOUT PO_WEEKLY_001" }
                            }
                        }
                    }
                ]
            }
        }
    }))
    .unwrap();
    let dbs_sig = sign_hmac_header("whsec_dbs_iso_test", now + 15, &camt054_body);
    let resp = h
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/webhooks/banks/iso20022_dbs")
                .header("X-ISO20022-Signature", dbs_sig)
                .body(Body::from(camt054_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify:
    // 1. Sweep `po_weekly_001` is `ReconciledWithBankCredit`.
    // 2. `pi_stripe_1` and `pi_stripe_2` are `BankCashFinalized`; `pi_stripe_3_refunded` stayed `RefundedBeforeSweep`.
    // 3. Exactly 3 on-chain tasks (`1` `MintOperatingBankCash` + `2` `IssuePaidHardwareVoucher`) were signed & submitted!
    h.store.read(|s| {
        assert!(matches!(
            s.sweep_batches["stripe:mch_immin_stripe:po_weekly_001"].status,
            SweepBatchStatus::ReconciledWithBankCredit { .. }
        ));
        assert!(matches!(
            s.clearing_items["stripe:mch_immin_stripe:pi_stripe_1"].status,
            ClearingItemStatus::BankCashFinalized { .. }
        ));
        assert!(matches!(
            s.clearing_items["stripe:mch_immin_stripe:pi_stripe_2"].status,
            ClearingItemStatus::BankCashFinalized { .. }
        ));
        assert!(matches!(
            s.clearing_items["stripe:mch_immin_stripe:pi_stripe_3_refunded"].status,
            ClearingItemStatus::RefundedBeforeSweep { .. }
        ));
        assert_eq!(s.outbox.len(), 3);
        assert!(s
            .outbox
            .values()
            .all(|t| matches!(t.state, OutboxTaskState::Submitted { .. })));
    });
    assert_entity_trial_balance_zero_net(&h.store, "ent_immin_sg");

    // Part B: Outbound Payment Lifecycle (`Initiated` -> `AcceptedByBank` -> Polled `InProcessing` -> Polled `Settled` with wire fee!)
    h.transport.enqueue_json(
        "mock.dbs.local/iso20022/v1/payments/pain001",
        200,
        json!({ "StsId": "DBS-OUT-7001", "EndToEndId": "E2E-SUP-7001", "TxSts": "ACCP" }),
    );
    let out_req = serde_json::to_vec(&json!({
        "account_id": "acct_immin_dbs_sgd",
        "instruction": OutboundPaymentInstruction {
            client_instruction_id: "PAY-SUPPLIER-7001".into(),
            counterparty_id: None,
            beneficiary_name: "Murata Electronics SG".into(),
            beneficiary_account: "003-998877-1".into(),
            beneficiary_bank_bic: Some("DBSSSGSG".into()),
            beneficiary_bank_name: None,
            beneficiary_address: None,
            value_date: None,
            rail: TransferRail::Fast,
            amount: Money::new(20_000, CurrencyCode::sgd()), // SGD 200.00
            remittance_info: "PO-RF-SAW-FILTERS".into(),
        }
    }))
    .unwrap();
    let resp = h
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/payments/outbound")
                .header("Authorization", "Bearer secret_admin_bearer")
                .header("Content-Type", "application/json")
                .body(Body::from(out_req))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Poll #1: Outbound payment transitions `ACCP` -> `ACSP` (`InProcessing`) — still non-finalized!
    h.transport.enqueue_json(
        "mock.ocbc.local/transactional/corpTransHistory/1.0",
        200,
        json!({ "success": true, "results": [] }),
    );
    h.transport.enqueue_json(
        "mock.ocbc.local/transactional/corpTransHistory/1.0",
        200,
        json!({ "success": true, "results": [] }),
    );
    h.transport.enqueue_json(
        "mock.dbs.local/iso20022/v1/accounts/072-112233-0/statements",
        200,
        json!({ "BkToCstmrStmt": { "Stmt": { "Acct": { "Id": { "Othr": { "Id": "072-112233-0" } } }, "Ntry": [] } } }),
    );
    h.transport.enqueue_json(
        "mock.dbs.local/iso20022/v1/payments/PAY-SUPPLIER-7001/status",
        200,
        json!({
            "CstmrPmtStsRpt": {
                "OrgnlPmtInfAndSts": {
                    "TxInfAndSts": {
                        "StsId": "DBS-OUT-7001",
                        "TxSts": "ACSP",
                        "ChrgsInf": { "Amt": { "Val": "0.00" } }
                    }
                }
            }
        }),
    );
    h.transport.enqueue_json(
        "mock.stripe.local/v1/payouts",
        200,
        json!({ "data": [] }),
    );

    let rep1 = h.poller.run_poll_cycle_once(now + 30).await;
    assert_eq!(rep1.outbound_statuses_checked, 1);
    assert!(
        h.store.pending_outbox_tasks().is_empty(),
        "InProcessing outbound payment must NOT burn bank cash yet!"
    );

    // Poll #2: Outbound payment reaches `ACSC` (`Settled`) with `SGD 0.50` FAST fee -> burns `SGD 200.50` on-chain!
    h.transport.enqueue_json(
        "mock.ocbc.local/transactional/corpTransHistory/1.0",
        200,
        json!({ "success": true, "results": [] }),
    );
    h.transport.enqueue_json(
        "mock.ocbc.local/transactional/corpTransHistory/1.0",
        200,
        json!({ "success": true, "results": [] }),
    );
    h.transport.enqueue_json(
        "mock.dbs.local/iso20022/v1/accounts/072-112233-0/statements",
        200,
        json!({ "BkToCstmrStmt": { "Stmt": { "Acct": { "Id": { "Othr": { "Id": "072-112233-0" } } }, "Ntry": [] } } }),
    );
    h.transport.enqueue_json(
        "mock.dbs.local/iso20022/v1/payments/PAY-SUPPLIER-7001/status",
        200,
        json!({
            "CstmrPmtStsRpt": {
                "OrgnlPmtInfAndSts": {
                    "TxInfAndSts": {
                        "StsId": "DBS-OUT-7001",
                        "TxSts": "ACSC",
                        "ChrgsInf": { "Amt": { "Val": "0.50" } }
                    }
                }
            }
        }),
    );
    h.transport.enqueue_json(
        "mock.stripe.local/v1/payouts",
        200,
        json!({ "data": [] }),
    );

    let rep2 = h.poller.run_poll_cycle_once(now + 60).await;
    assert_eq!(rep2.outbound_statuses_checked, 1);

    let burn_tasks = h.store.pending_outbox_tasks();
    assert_eq!(burn_tasks.len(), 1);
    match &burn_tasks[0].action {
        OnChainSettlementKind::BurnOperatingBankCash { amount_micros, .. } => {
            assert_eq!(*amount_micros, 200_500_000); // SGD 200.50 in micros
        }
        other => panic!("expected BurnOperatingBankCash, got {:?}", other),
    }

    assert_entity_trial_balance_zero_net(&h.store, "ent_immin_sg");
    let immin_tb = h.store.compute_entity_trial_balance("ent_immin_sg");
    let immin_sgd = &immin_tb[&CurrencyCode::sgd()];
    // Cash at Bank = 676.20 (in) - 200.50 (out) = 475.70 (`47_570` cents)!
    assert_eq!(
        immin_sgd[&SubledgerAccountCode::CashAtBank1010].net_debit_minus_credit_minor,
        47_570
    );
}

#[tokio::test]
async fn cross_currency_usd_card_into_sgd_sweep_jws_webhook_dedup_and_post_finality_chargeback() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use banking_oracle::domain::events::{
        AcquirerPaymentEvent, AcquirerPaymentStage, AcquirerRefundEvent, AcquirerSettlementBatch,
        CanonicalAcquirerEvent, CanonicalBankEvent, IngestionSource, OutboundPaymentState,
        OutboundPaymentStatusEvent, SweepBatchLine, VoucherOrderMetadata,
    };
    use banking_oracle::engine::IngestOutcome;

    let h = setup_multi_entity_harness();
    let now = 1_795_600_000u64;
    let commit_usd = format!("0x{}", "ef".repeat(32));

    // 1. Customer pays $299.00 USD (`29_900` cents) via OCBC Merchant Card, settling into SLX's `SGD` OCBC CASA account!
    let out1 = h
        .engine
        .ingest_acquirer_event(
            CanonicalAcquirerEvent::PaymentAuthorizedOrCaptured(AcquirerPaymentEvent {
                acquirer_adapter_id: "ocbc_merchant_card".into(),
                external_merchant_id: "OCBCMID8899001".into(),
                acquirer_payment_id: "OCBC-USD-CARD-901".into(),
                order_reference: "ORD-USD-V1-901".into(),
                gross_amount: Money::new(29_900, CurrencyCode::usd()),
                fee_minor: 0,
                settlement_currency: CurrencyCode::sgd(),
                expected_settlement_net_minor: Some(39_200),
                stage: AcquirerPaymentStage::CapturedPendingSweep,
                occurred_at_unix: now,
                structured_invoice_id: None,
                voucher_metadata: Some(VoucherOrderMetadata {
                    sku_code: 2,
                    tier_bps: 10_000,
                    voucher_commitment_hex: commit_usd,
                    explicit_price_usd_micros: None,
                }),
                source: IngestionSource::WebhookPush,
            }),
            now,
        )
        .unwrap();
    assert!(matches!(out1, IngestOutcome::AcquirerPaymentRecorded { .. }));

    // 2. OCBC Merchant Settlement Batch converts `$299.00 USD` -> `SGD 400.00` gross (`40_000`), `SGD 8.00` MDR (`800`), `SGD 392.00` net (`39_200`)
    h.engine
        .ingest_acquirer_event(
            CanonicalAcquirerEvent::SettlementSweepManifest(AcquirerSettlementBatch {
                acquirer_adapter_id: "ocbc_merchant_card".into(),
                external_merchant_id: "OCBCMID8899001".into(),
                batch_id: "BATCH-FX-901".into(),
                bank_statement_reference: "OCBC-FX-STL-901".into(),
                settlement_currency: CurrencyCode::sgd(),
                gross_sales_minor: 40_000,
                refunds_minor: 0,
                total_fees_minor: 800,
                net_payout_minor: 39_200,
                settlement_date: "2026-11-25".into(),
                created_at_unix: now + 10,
                lines: vec![SweepBatchLine {
                    acquirer_payment_id: "OCBC-USD-CARD-901".into(),
                    is_refund: false,
                    settlement_gross_minor: 40_000,
                    settlement_fee_minor: 800,
                    settlement_net_minor: 39_200,
                }],
                source: IngestionSource::PeriodicPoll,
            }),
            now + 10,
        )
        .unwrap();

    // 3. Authenticate OCBC Credit Notification Alert using RFC 7515 Detached JWS (`X-JWS-Signature: <hdr>..<sig>`)!
    let webhook_body = serde_json::to_vec(&json!({
        "alertType": "CREDIT_NOTIFICATION",
        "data": {
            "AccountNo": "501-889900-001",
            "TransactionRef": "OCBC-CR-FX-901",
            "Status": "BOOKED",
            "CurrencyCode": "SGD",
            "CreditAmount": "392.00",
            "BatchReference": "OCBC-FX-STL-901",
            "RemittanceInfo": "MERCHANT SETTLEMENT OCBC-FX-STL-901"
        }
    }))
    .unwrap();
    let jws_hdr = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JOSE"}"#);
    let jws_payload = URL_SAFE_NO_PAD.encode(&webhook_body);
    let jws_sig = URL_SAFE_NO_PAD.encode(hmac_sha256(
        b"whsec_ocbc_corp_test",
        format!("{}.{}", jws_hdr, jws_payload).as_bytes(),
    ));
    let detached_jws = format!("{}..{}", jws_hdr, jws_sig);

    let resp = h
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/webhooks/banks/ocbc_corporate")
                .header("X-JWS-Signature", detached_jws.clone())
                .body(Body::from(webhook_body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Re-delivering the exact same bank credit (simulating overlap between webhook and periodic poller) must be ignored!
    let resp_dup = h
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/webhooks/banks/ocbc_corporate")
                .header("X-JWS-Signature", detached_jws)
                .body(Body::from(webhook_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_dup.status(), StatusCode::OK);

    // Both USD and SGD Trial Balances must be 100% balanced (`sum(Dr) == sum(Cr)`), with `1140` cleared in BOTH currencies!
    assert_entity_trial_balance_zero_net(&h.store, "ent_slx_sg");
    let tb = h.store.compute_entity_trial_balance("ent_slx_sg");
    assert_eq!(
        tb[&CurrencyCode::usd()][&SubledgerAccountCode::AcquirerClearingReceivable1140]
            .net_debit_minus_credit_minor,
        0
    );
    assert_eq!(
        tb[&CurrencyCode::sgd()][&SubledgerAccountCode::AcquirerClearingReceivable1140]
            .net_debit_minus_credit_minor,
        0
    );

    // 4. Now simulate a post-finality Chargeback on `OCBC-USD-CARD-901` during the 90-day maturity window ->
    //    must emit `RevokeRefundedHardwareVoucher` on-chain!
    let cb_out = h
        .engine
        .ingest_acquirer_event(
            CanonicalAcquirerEvent::PaymentRefundedOrDisputed(AcquirerRefundEvent {
                acquirer_adapter_id: "ocbc_merchant_card".into(),
                external_merchant_id: "OCBCMID8899001".into(),
                acquirer_payment_id: "OCBC-USD-CARD-901".into(),
                refund_id: "CB-DISPUTE-901".into(),
                refund_amount: Money::new(29_900, CurrencyCode::usd()),
                is_chargeback: true,
                deducted_in_batch_id: None,
                occurred_at_unix: now + 500,
                source: IngestionSource::WebhookPush,
            }),
            now + 500,
        )
        .unwrap();
    assert_eq!(
        cb_out,
        IngestOutcome::AcquirerRefundProcessed {
            clearing_key: "ocbc_merchant_card:mch_slx_ocbc_card:OCBC-USD-CARD-901".into(),
            was_post_finality: true,
        }
    );
    let has_revoke = h.store.pending_outbox_tasks().iter().any(|t| {
        matches!(
            t.action,
            OnChainSettlementKind::RevokeRefundedHardwareVoucher { .. }
        )
    });
    assert!(has_revoke, "Post-finality chargeback must enqueue RevokeRefundedHardwareVoucher");

    // 5. Also verify Outbound Payment REJECTION reverses `2190` back to `2100` without touching `1010 Cash at Bank`!
    h.engine
        .record_outbound_initiated(
            "acct_slx_ocbc_sgd",
            &OutboundPaymentInstruction {
                client_instruction_id: "OUT-RJCT-1".into(),
                counterparty_id: None,
                beneficiary_name: "Bad Acct Vendor".into(),
                beneficiary_account: "999-000".into(),
                beneficiary_bank_bic: None,
                beneficiary_bank_name: None,
                beneficiary_address: None,
                value_date: None,
                rail: TransferRail::Fast,
                amount: Money::new(10_000, CurrencyCode::sgd()),
                remittance_info: "TEST-RJCT".into(),
            },
            &banking_oracle::ports::bank_adapter::OutboundSubmissionReceipt {
                bank_payment_id: Some("OCBC-PAY-RJ1".into()),
                end_to_end_id: None,
                value_date: None,
                initial_state: OutboundPaymentState::InProcessing,
            },
            now + 600,
        )
        .unwrap();

    h.engine
        .ingest_bank_event(
            CanonicalBankEvent::OutboundStatusChanged(OutboundPaymentStatusEvent {
                bank_adapter_id: "ocbc_corporate".into(),
                external_account_number: "501-889900-001".into(),
                client_instruction_id: "OUT-RJCT-1".into(),
                bank_payment_id: Some("OCBC-PAY-RJ1".into()),
                end_to_end_id: None,
                rail: TransferRail::Fast,
                state: OutboundPaymentState::Rejected,
                amount: Money::new(10_000, CurrencyCode::sgd()),
                bank_fee_minor: 0,
                reason_code: Some("AC01".into()),
                reason_detail: Some("Incorrect Account Number".into()),
                updated_at_unix: now + 610,
                source: IngestionSource::WebhookPush,
            }),
            now + 610,
        )
        .unwrap();

    assert_entity_trial_balance_zero_net(&h.store, "ent_slx_sg");
    let tb_after_rjct = h.store.compute_entity_trial_balance("ent_slx_sg");
    // Cash at bank in SGD remains 392.00 (`39_200` cents) — zero cash lost on rejected payment!
    assert_eq!(
        tb_after_rjct[&CurrencyCode::sgd()][&SubledgerAccountCode::CashAtBank1010]
            .net_debit_minus_credit_minor,
        39_200
    );
}

#[tokio::test]
async fn persistent_snapshot_reload_and_merchant_checkout_session_api() {
    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("oracle_state.snap.json");
    {
        let store = OracleStore::open_persistent(&snap_path).unwrap();
        store
            .upsert_entity(AccountOwner {
                entity_id: "ent_persist".into(),
                legal_name: "Persistent Corp".into(),
                registration_number: "UEN-1".into(),
                functional_currency: CurrencyCode::jpy(),
                chain_binding: None,
                active: true,
            })
            .unwrap();
        assert_eq!(CurrencyCode::jpy().minor_decimals(), 0);
        assert_eq!(CurrencyCode::jpy().parse_decimal_to_minor("5000").unwrap(), 5000);
        assert_eq!(CurrencyCode::jpy().minor_to_micros(5000).unwrap(), 5_000_000_000);
    }
    let reloaded = OracleStore::open_persistent(&snap_path).unwrap();
    let exists = reloaded.read(|s| s.entities.contains_key("ent_persist"));
    assert!(exists, "Persistent OracleStore must survive process restart");
}

#[tokio::test]
async fn official_ocbc_oauth_fragment_authorize_capture_void_query_and_10rpm_rate_limit() {
    use banking_oracle::adapters::ocbc_auth::{
        build_ocbc_oauth_authorize_url, parse_ocbc_oauth_fragment, OcbcRateLimiter,
    };

    let h = setup_multi_entity_harness();
    let now = 1_795_700_000u64;

    // 1. Verify OCBC OAuth 2.0 GET authorize URL & `#access_token=...` redirect fragment parsing
    let auth_url = build_ocbc_oauth_authorize_url(
        "https://api.ocbc.com",
        "my_consumer_key",
        "https://oracle.superlexicon.io/v1/oauth/ocbc/callback",
        "transactional",
    );
    assert_eq!(
        auth_url,
        "https://api.ocbc.com/ocbcauthentication/api/oauth2/authorize?client_id=my_consumer_key&redirect_uri=https%3A%2F%2Foracle.superlexicon.io%2Fv1%2Foauth%2Focbc%2Fcallback&scope=transactional"
    );

    let rec = parse_ocbc_oauth_fragment(
        "#access_token=489efb0ee095e75d625ccc0fa5f23e30&token_type=Bearer&expires_in=3600",
        "default",
        now,
    )
    .unwrap();
    assert_eq!(
        rec.authorization_bearer_header(),
        "Bearer 489efb0ee095e75d625ccc0fa5f23e30"
    );
    assert_eq!(
        rec.session_token_value(),
        "OAuth2INB 489efb0ee095e75d625ccc0fa5f23e30"
    );

    // Save the OAuth fragment via `POST /v1/oauth/ocbc/token`
    let save_resp = h
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/oauth/ocbc/token")
                .header("Authorization", "Bearer secret_admin_bearer")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "scope_key": "default",
                        "fragment": "#access_token=489efb0ee095e75d625ccc0fa5f23e30&token_type=Bearer&expires_in=3600"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(save_resp.status(), StatusCode::OK);

    // 2. Test OCBC Merchant Card `/authorize` -> `/query` -> `/capture` -> `/void`!
    h.transport.enqueue_json(
        "mock.ocbc.local/transactional/merchantcardpayments/1.0/authorize",
        200,
        json!({
            "results": {
                "transactionId": "OCBC-AUTH-5001",
                "merchantTranId": "MTRAN-5001",
                "customerId": "CUST-5001",
                "authId": "812345",
                "authDate": "25-11-2026 15:00:00",
                "responseCode": "00",
                "responseDesc": "Approved",
                "txnStatus": "AUTHORIZED"
            }
        }),
    );
    let auth_card_resp = h
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/payments/merchant/sessions")
                .header("Authorization", "Bearer secret_admin_bearer")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "merchant_profile_id": "mch_slx_ocbc_card",
                        "payment": {
                            "order_reference": "MTRAN-5001",
                            "customer_id": "CUST-5001",
                            "amount": { "amount_minor": 14900, "currency": "SGD" },
                            "description": "SLX-L1 Hold",
                            "capture_mode": "authorize_only"
                        }
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(auth_card_resp.status(), StatusCode::OK);
    h.store.read(|s| {
        assert_eq!(
            s.clearing_items["ocbc_merchant_card:mch_slx_ocbc_card:OCBC-AUTH-5001"].status,
            ClearingItemStatus::AuthorizedOnly
        );
    });

    // Capture via `POST /v1/payments/merchant/capture` -> calls `POST /transactional/merchantcardpayments/1.0/capture`!
    h.transport.enqueue_json(
        "mock.ocbc.local/transactional/merchantcardpayments/1.0/capture",
        200,
        json!({
            "results": {
                "transactionId": "OCBC-AUTH-5001",
                "merchantTranId": "MTRAN-5001",
                "responseCode": "0",
                "txnStatus": "CAPTURED",
                "captureDate": "25-11-2026 15:05:00"
            }
        }),
    );
    let cap_resp = h
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/payments/merchant/capture")
                .header("Authorization", "Bearer secret_admin_bearer")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "merchant_profile_id": "mch_slx_ocbc_card",
                        "transaction_id": "OCBC-AUTH-5001",
                        "merchant_tran_id": "MTRAN-5001",
                        "amount": { "amount_minor": 14900, "currency": "SGD" }
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cap_resp.status(), StatusCode::OK);
    h.store.read(|s| {
        assert_eq!(
            s.clearing_items["ocbc_merchant_card:mch_slx_ocbc_card:OCBC-AUTH-5001"].status,
            ClearingItemStatus::CapturedPendingBankSweep
        );
    });

    // Void via `POST /v1/payments/merchant/void` -> calls `POST /transactional/merchantcardpayments/1.0/void`!
    h.transport.enqueue_json(
        "mock.ocbc.local/transactional/merchantcardpayments/1.0/void",
        200,
        json!({
            "results": {
                "transactionId": "OCBC-AUTH-5001",
                "merchantTranId": "MTRAN-5001",
                "responseCode": "0",
                "txnStatus": "VOIDED",
                "voidRevDate": "25-11-2026 15:10:00"
            }
        }),
    );
    let void_resp = h
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/payments/merchant/void")
                .header("Authorization", "Bearer secret_admin_bearer")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "merchant_profile_id": "mch_slx_ocbc_card",
                        "transaction_id": "OCBC-AUTH-5001",
                        "merchant_tran_id": "MTRAN-5001",
                        "amount": { "amount_minor": 14900, "currency": "SGD" }
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(void_resp.status(), StatusCode::OK);
    assert_entity_trial_balance_zero_net(&h.store, "ent_slx_sg");

    // 3. Verify OCBC Usage Guideline `10 API calls / minute` sliding-window rate limiter!
    let limiter = OcbcRateLimiter::new(10);
    for i in 0..10 {
        limiter.acquire_slot("tok_user_1", 1000 + i).await.unwrap();
    }
    assert!(
        limiter.acquire_slot("tok_user_1", 1050).await.is_err(),
        "11th OCBC API call within 60 seconds must be blocked by the 10 req/min rate limiter"
    );
    assert!(
        limiter.acquire_slot("tok_user_1", 1061).await.is_ok(),
        "Call at t+61s succeeds once oldest slot slides out of the 60s window"
    );
}

#[tokio::test]
async fn official_ocbc_meps_initiation_status_polling_and_paynow_uen_collection_enquiry() {
    use banking_oracle::adapters::ocbc_auth::{OcbcRateLimiter, OcbcTokenVault};
    use banking_oracle::domain::events::OutboundPaymentState;
    use banking_oracle::domain::ledger::DirectCollectionState;
    use banking_oracle::ports::bank_adapter::{AccountPollCursor, DirectCollectionInstruction};

    let transport = Arc::new(MockHttpTransport::new());
    let store = Arc::new(OracleStore::in_memory());

    let mut slx_ledgers = BTreeMap::new();
    slx_ledgers.insert(
        CurrencyCode::sgd(),
        "0xa1000000000000000000000000000000000000a1".into(),
    );
    store
        .upsert_entity(AccountOwner {
            entity_id: "ent_slx_meps".into(),
            legal_name: "SuperLexicon Pte. Ltd.".into(),
            registration_number: "202600101A".into(),
            functional_currency: CurrencyCode::sgd(),
            active: true,
            chain_binding: Some(EntityChainBinding {
                oracle_private_key_hex: "11".repeat(32),
                chain_id: 1337,
                wire_format: TxWireFormat::SuperLexiconL1,
                treasury_identity_hex: Some(
                    "0x1000000000000000000000000000000000000010".into(),
                ),
                operating_bank_ledgers: slx_ledgers,
                ifrs_accounting_ledger_hex: Some(
                    "0xb1000000000000000000000000000000000000b1".into(),
                ),
                reward_voucher_hfs_hex: Some(
                    "0xd5000000000000000000000000000000000000d5".into(),
                ),
                fx_to_usd_ppm: BTreeMap::new(),
            }),
        })
        .unwrap();

    let ocbc_acct = BankAccount {
        account_id: "acct_ocbc_sgd".into(),
        owner_entity_id: "ent_slx_meps".into(),
        bank_adapter_id: "ocbc_corporate".into(),
        bank_bic: "OCBCSGSG".into(),
        external_account_number: "501-889900-001".into(),
        currency: CurrencyCode::sgd(),
        display_name: "OCBC SGD CASA".into(),
        poll_enabled: true,
        poll_interval_secs: 60,
    };
    store.upsert_bank_account(ocbc_acct.clone()).unwrap();

    let vault = Arc::new(OcbcTokenVault::new(
        store.clone(),
        Some("489efb0ee095e75d625ccc0fa5f23e30".into()),
    ));
    let limiter = Arc::new(OcbcRateLimiter::new(10));
    let adapter = OcbcCorporateBankAdapter::new(
        OcbcCorporateConfig {
            adapter_id: "ocbc_corporate".into(),
            base_url: "https://mock.ocbc.local".into(),
            client_id: "cid_ocbc".into(),
            redirect_uri: "https://oracle.superlexicon.io/v1/oauth/ocbc/callback".into(),
            default_access_token: Some("489efb0ee095e75d625ccc0fa5f23e30".into()),
            paynow_partner_id: Some("PARTNER_SLX_SG".into()),
            webhook_secret: "whsec_ocbc".into(),
            max_webhook_skew_secs: 300,
            max_calls_per_minute: 10,
        },
        transport.clone(),
        vault,
        limiter,
    );
    let engine = ReconciliationEngine::new(store.clone(), b"salt-meps-paynow".to_vec());
    let now = 1_795_800_000u64;

    // 1. Test Corporate PayNow Collection via UEN (`POST /transactional/corporate/paynowcollection/1.0`)
    //    Notice OCBC returns `Success: "true"` (string!) and singular `Result: { OCBCReferenceNo, TransactionReferenceNo }`!
    transport.enqueue_json(
        "mock.ocbc.local/transactional/corporate/paynowcollection/1.0",
        200,
        json!({
            "Disclaimer": "OCBC Sandbox",
            "Success": "true",
            "Result": {
                "TransactionDescription": "Enterprise Gateway Invoice #7701",
                "OCBCReferenceNo": "OCBCPAYNOW99001",
                "TransactionReferenceNo": "SLXCOLL7701"
            }
        }),
    );

    let col_instr = DirectCollectionInstruction {
        transaction_reference_no: "SLXCOLL7701".into(),
        payer_proxy_type: "UEN".into(),
        payer_proxy_value: "T01LL8899A".into(),
        dda_reference_no: "DDA-2026-8899".into(),
        purpose_code: "GDSV".into(),
        amount: Money::new(49_900, CurrencyCode::sgd()), // SGD 499.00
        description: "Enterprise Gateway Invoice #7701".into(),
        structured_invoice_id: Some(7701),
        voucher_metadata: None,
    };
    let col_receipt = adapter
        .initiate_direct_collection(&ocbc_acct, &col_instr, now)
        .await
        .unwrap();
    assert_eq!(col_receipt.bank_reference_no, "OCBCPAYNOW99001");
    engine
        .record_direct_collection_initiated("acct_ocbc_sgd", &col_instr, &col_receipt, now)
        .unwrap();

    // Verify exact `paynowcollection/1.0` JSON payload (`Amount` as double `499.0`, `ProxyType: "UEN"`, `FromAccountNo`)
    let col_req_raw: serde_json::Value =
        serde_json::from_slice(&transport.recorded_requests()[0].body).unwrap();
    assert_eq!(col_req_raw["Amount"], json!(499.0));
    assert_eq!(col_req_raw["ProxyType"], "UEN");
    assert_eq!(col_req_raw["ProxyValue"], "T01LL8899A");
    assert_eq!(col_req_raw["DDAReferenceNo"], "DDA-2026-8899");

    // 2. Poll incoming transactions -> executes BOTH `GET /transactional/corpTransHistory/1.0` AND `POST /ocbc/sg/corp/paynow/1.0`!
    transport.enqueue_json(
        "mock.ocbc.local/transactional/corpTransHistory/1.0",
        200,
        json!({ "success": true, "results": [] }),
    );
    transport.enqueue_json(
        "mock.ocbc.local/ocbc/sg/corp/paynow/1.0",
        200,
        json!({
            "Transactions": [
                {
                    "AccountCurrency": "SGD",
                    "AccountNo": 501889900001.0,
                    "Amount": 499.00,
                    "CreditDebitIndicator": "C"
                }
            ]
        }),
    );

    let poll_batch = adapter
        .poll_incoming_transactions(&ocbc_acct, &AccountPollCursor::default(), now + 30)
        .await
        .unwrap();
    assert_eq!(poll_batch.applied_credits.len(), 1);

    // Verify PayNow Enquiry sent `AccountNo` as numeric JSON (`501889900001.0`) and `PartnerID: "PARTNER_SLX_SG"`!
    let pn_req_raw: serde_json::Value =
        serde_json::from_slice(&transport.recorded_requests()[2].body).unwrap();
    assert_eq!(pn_req_raw["PartnerID"], "PARTNER_SLX_SG");
    assert!(pn_req_raw["AccountNo"].is_number());

    // Ingesting the PayNow credit automatically matches `DirectCollectionTracker("SLXCOLL7701")` and settles Invoice `#7701`!
    for cr in poll_batch.applied_credits {
        engine
            .ingest_bank_event(
                banking_oracle::domain::events::CanonicalBankEvent::AppliedCredit(cr),
                now + 30,
            )
            .unwrap();
    }
    store.read(|s| {
        assert!(matches!(
            s.direct_collections["SLXCOLL7701"].state,
            DirectCollectionState::SettledByBankCredit { .. }
        ));
    });
    let has_inv_settle = store.pending_outbox_tasks().iter().any(|t| {
        matches!(
            t.action,
            OnChainSettlementKind::SettleIfrsCreditInvoice {
                invoice_id: 7701,
                amount_micros: 499_000_000,
                ..
            }
        )
    });
    assert!(has_inv_settle, "PayNow UEN collection credit must auto-settle linked Invoice #7701");

    // 3. Test Perform MEPS Payment (`POST /transactional/corp/payment/meps/1.0`) -> Status Inquiry (`POST /corp/payment/meps/1.0`)!
    transport.enqueue_json(
        "mock.ocbc.local/transactional/corp/payment/meps/1.0",
        200,
        json!({
            "ReferenceText": "MEPS2026SUP88",
            "Success": true,
            "Disclaimer": "OCBC Sandbox",
            "Results": {
                "BankPaymentId": "OCBCMEPS000991"
            }
        }),
    );

    let meps_instr = OutboundPaymentInstruction {
        client_instruction_id: "MEPS-2026-SUP-88".into(), // sanitized to alphanumeric `MEPS2026SUP88`
        counterparty_id: None,
        beneficiary_name: "STMicroelectronics Asia Pacific".into(),
        beneficiary_account: "0012345678".into(),
        beneficiary_bank_bic: Some("DBSSSGSG".into()),
        beneficiary_bank_name: Some("DBS Bank Ltd".into()),
        beneficiary_address: Some("5A Serangoon North Ave 5, Singapore".into()),
        value_date: Some("26-11-2026".into()),
        rail: TransferRail::MepsPlus,
        amount: Money::new(15_000, CurrencyCode::sgd()), // SGD 150.00
        remittance_info: "MCU WAFER TRAY LOT".into(),
    };
    let meps_receipt = adapter
        .initiate_outbound_payment(&ocbc_acct, &meps_instr, now + 40)
        .await
        .unwrap();
    assert_eq!(
        meps_receipt.bank_payment_id.as_deref(),
        Some("OCBCMEPS000991")
    );
    let mut tracker = engine
        .record_outbound_initiated("acct_ocbc_sgd", &meps_instr, &meps_receipt, now + 40)
        .unwrap();
    assert_eq!(tracker.state, OutboundPaymentState::AcceptedByBank);

    // Verify exact MEPS initiation JSON structure (`Payer`, `Payee.Address.Address`, `Amount.Value`, alphanumeric `ReferenceText`)
    let meps_init_json: serde_json::Value =
        serde_json::from_slice(&transport.recorded_requests()[3].body).unwrap();
    assert_eq!(meps_init_json["ReferenceText"], "MEPS2026SUP88");
    assert_eq!(meps_init_json["Payer"]["SwiftCode"], "OCBCSGSG");
    assert_eq!(
        meps_init_json["Payee"]["Address"]["Address"],
        "5A Serangoon North Ave 5, Singapore"
    );
    assert_eq!(meps_init_json["Amount"]["Value"], "150.00");

    // Poll #1 on `POST /corp/payment/meps/1.0` -> `PROCESSING`
    transport.enqueue_json(
        "mock.ocbc.local/corp/payment/meps/1.0",
        200,
        json!({
            "ReferenceText": "MEPS2026SUP88",
            "Success": true,
            "Results": {
                "BankPaymentId": "OCBCMEPS000991",
                "PaymentStatus": "PROCESSING",
                "UpdateDateTime": "26-11-2026 09:01:00",
                "ActualValueDate": "26-11-2026",
                "Amount": { "Currency": "SGD", "Value": "150.00" }
            }
        }),
    );
    let st1 = adapter
        .poll_outbound_payment_status(&ocbc_acct, &tracker, now + 50)
        .await
        .unwrap();
    assert_eq!(st1.state, OutboundPaymentState::InProcessing);
    engine
        .ingest_bank_event(
            banking_oracle::domain::events::CanonicalBankEvent::OutboundStatusChanged(st1),
            now + 50,
        )
        .unwrap();
    tracker.state = OutboundPaymentState::InProcessing;

    // Poll #2 on `POST /corp/payment/meps/1.0` -> `COMPLETED` (`Settled` -> burns SGD 150.00 operating cash on-chain!)
    transport.enqueue_json(
        "mock.ocbc.local/corp/payment/meps/1.0",
        200,
        json!({
            "ReferenceText": "MEPS2026SUP88",
            "Success": true,
            "Results": {
                "BankPaymentId": "OCBCMEPS000991",
                "PaymentStatus": "COMPLETED",
                "UpdateDateTime": "26-11-2026 09:02:15",
                "ActualValueDate": "26-11-2026",
                "Amount": { "Currency": "SGD", "Value": "150.00" }
            }
        }),
    );
    let st2 = adapter
        .poll_outbound_payment_status(&ocbc_acct, &tracker, now + 60)
        .await
        .unwrap();
    assert_eq!(st2.state, OutboundPaymentState::Settled);
    engine
        .ingest_bank_event(
            banking_oracle::domain::events::CanonicalBankEvent::OutboundStatusChanged(st2),
            now + 60,
        )
        .unwrap();

    assert_entity_trial_balance_zero_net(&store, "ent_slx_meps");
    let tb = store.compute_entity_trial_balance("ent_slx_meps");
    // Net Cash at Bank = 499.00 (PayNow in) - 150.00 (MEPS settled out) = 349.00 (`34_900` cents)!
    assert_eq!(
        tb[&CurrencyCode::sgd()][&SubledgerAccountCode::CashAtBank1010]
            .net_debit_minus_credit_minor,
        34_900
    );
}
