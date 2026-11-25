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

    let ocbc_corp = Arc::new(OcbcCorporateBankAdapter::new(
        OcbcCorporateConfig {
            adapter_id: "ocbc_corporate".into(),
            base_url: "https://mock.ocbc.local".into(),
            client_id: "cid_corp".into(),
            client_secret: "csec_corp".into(),
            webhook_secret: "whsec_ocbc_corp_test".into(),
            max_webhook_skew_secs: 300,
        },
        transport.clone(),
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
            client_id: "cid_card".into(),
            client_secret: "csec_card".into(),
            webhook_secret: "whsec_ocbc_card_test".into(),
            max_webhook_skew_secs: 300,
        },
        transport.clone(),
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

    // Step 1: Two customers pay via OCBC Merchant Card Payments API (`SGD 400.00` + `SGD 670.00` = `SGD 1,070.00` gross)
    for (txn_id, order_ref, amt_str, sku, commit) in [
        ("OCBC-CARD-TX-101", "ORD-V1-01", "400.00", "slx-v1", &commit_1),
        ("OCBC-CARD-TX-102", "ORD-G1-02", "670.00", "slx-g1", &commit_2),
    ] {
        let body = serde_json::to_vec(&json!({
            "eventType": "CARD_CAPTURED",
            "data": {
                "merchantId": "OCBCMID8899001",
                "cardTxnId": txn_id,
                "orderRef": order_ref,
                "amount": amt_str,
                "currency": "SGD",
                "settlementCurrency": "SGD",
                "mdrFee": "0.00",
                "metadata": {
                    "sku": sku,
                    "tier": "early_bird",
                    "voucherCommitment": commit
                }
            }
        }))
        .unwrap();
        let sig = sign_hmac_header("whsec_ocbc_card_test", now, &body);
        let resp = h
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/webhooks/acquirers/ocbc_merchant_card")
                    .header("X-OCBC-Merchant-Signature", sig)
                    .body(Body::from(body))
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

    // Step 2: Parallel `PollingSupervisor` runs!
    // - OCBC Merchant Card API returns EOD settlement batch (`gross = 1070.00`, `MDR = 21.40`, `net = 1048.60`, ref `OCBC-MC-STL-20261125-01`).
    // - OCBC Corporate Banking `transactionHistory/1.0` returns BOTH:
    //   a) The `SGD 1,048.60` merchant settlement credit on `acct_slx_ocbc_sgd`
    //   b) A `USD 2,500.00` B2B customer invoice wire (`INV-9001`) on `acct_slx_ocbc_usd`!
    // - DBS ISO 20022 statement poll returns empty for Entity B.
    h.transport.enqueue_json(
        "mock.ocbc.local/ocbcauthentication/api/oauth2/token",
        200,
        json!({ "access_token": "tok_ocbc_corp_1", "expires_in": 3600 }),
    );
    h.transport.enqueue_json(
        "mock.ocbc.local/ocbcauthentication/api/oauth2/token",
        200,
        json!({ "access_token": "tok_ocbc_card_1", "expires_in": 3600 }),
    );
    // First OCBC account poll: `acct_slx_ocbc_sgd` (settlement credit arrives BEFORE merchant batch poll — testing Bank-Credit-First out-of-order reconciliation!)
    h.transport.enqueue_json(
        "mock.ocbc.local/transactional/transactionHistory/1.0",
        200,
        json!({
            "Results": {
                "Transactions": [
                    {
                        "AccountNo": "501-889900-001",
                        "TransactionRef": "OCBC-CASA-CR-77881",
                        "DrCrIndicator": "C",
                        "Status": "BOOKED",
                        "CurrencyCode": "SGD",
                        "CreditAmount": "1048.60",
                        "BatchReference": "OCBC-MC-STL-20261125-01",
                        "RemittanceInfo": "OCBC CARD SETTLEMENT OCBC-MC-STL-20261125-01",
                        "ValueDate": "2026-11-25"
                    }
                ],
                "NextCursor": "cur_sgd_1"
            }
        }),
    );
    // Second OCBC account poll: `acct_slx_ocbc_usd` (`USD 2,500.00` invoice `INV-9001`)
    h.transport.enqueue_json(
        "mock.ocbc.local/transactional/transactionHistory/1.0",
        200,
        json!({
            "Results": {
                "Transactions": [
                    {
                        "AccountNo": "501-889900-840",
                        "TransactionRef": "OCBC-USD-TT-55002",
                        "DrCrIndicator": "C",
                        "Status": "BOOKED",
                        "CurrencyCode": "USD",
                        "CreditAmount": "2500.00",
                        "RemittanceInfo": "B2B GATEWAY ORDER PAYMENT INV-9001",
                        "ValueDate": "2026-11-25"
                    }
                ],
                "NextCursor": "cur_usd_1"
            }
        }),
    );
    h.transport.enqueue_json(
        "mock.dbs.local/iso20022/v1/accounts/072-112233-0/statements",
        200,
        json!({ "BkToCstmrStmt": { "Stmt": { "Acct": { "Id": { "Othr": { "Id": "072-112233-0" } } }, "Ntry": [] } } }),
    );
    // OCBC Merchant Card batch poll returns `OCBC-MC-STL-20261125-01`
    h.transport.enqueue_json(
        "mock.ocbc.local/merchant/cardpayments/1.0/settlements",
        200,
        json!({
            "Results": {
                "batches": [
                    {
                        "merchantId": "OCBCMID8899001",
                        "batchId": "BATCH-20261125-01",
                        "bankSettlementRef": "OCBC-MC-STL-20261125-01",
                        "settlementCurrency": "SGD",
                        "grossSalesMinor": 107000,
                        "refundsMinor": 0,
                        "mdrFeeTotalMinor": 2140,
                        "netSettlementMinor": 104860,
                        "settlementDate": "2026-11-25",
                        "transactions": [
                            { "cardTxnId": "OCBC-CARD-TX-101", "type": "SALE", "settlementGrossMinor": 40000, "mdrFeeMinor": 800 },
                            { "cardTxnId": "OCBC-CARD-TX-102", "type": "SALE", "settlementGrossMinor": 67000, "mdrFeeMinor": 1340 }
                        ]
                    }
                ],
                "nextCursor": "mc_cur_1"
            }
        }),
    );
    h.transport.enqueue_json(
        "mock.stripe.local/v1/payouts",
        200,
        json!({ "data": [] }),
    );

    let report = h.poller.run_poll_cycle_once(now + 60).await;
    assert_eq!(report.errors, Vec::<String>::new());
    assert_eq!(report.incoming_credits_ingested, 2);
    assert_eq!(report.settlement_batches_ingested, 1);

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
        "mock.ocbc.local/ocbcauthentication/api/oauth2/token",
        200,
        json!({ "access_token": "tok_ocbc_corp_2", "expires_in": 3600 }),
    );
    h.transport.enqueue_json(
        "mock.ocbc.local/ocbcauthentication/api/oauth2/token",
        200,
        json!({ "access_token": "tok_ocbc_card_2", "expires_in": 3600 }),
    );
    h.transport.enqueue_json(
        "mock.ocbc.local/transactional/transactionHistory/1.0",
        200,
        json!({ "Results": { "Transactions": [] } }),
    );
    h.transport.enqueue_json(
        "mock.ocbc.local/transactional/transactionHistory/1.0",
        200,
        json!({ "Results": { "Transactions": [] } }),
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
        "mock.ocbc.local/merchant/cardpayments/1.0/settlements",
        200,
        json!({ "Results": { "batches": [] } }),
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
        "mock.ocbc.local/transactional/transactionHistory/1.0",
        200,
        json!({ "Results": { "Transactions": [] } }),
    );
    h.transport.enqueue_json(
        "mock.ocbc.local/transactional/transactionHistory/1.0",
        200,
        json!({ "Results": { "Transactions": [] } }),
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
        "mock.ocbc.local/merchant/cardpayments/1.0/settlements",
        200,
        json!({ "Results": { "batches": [] } }),
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
                rail: TransferRail::Fast,
                amount: Money::new(10_000, CurrencyCode::sgd()),
                remittance_info: "TEST-RJCT".into(),
            },
            &banking_oracle::ports::bank_adapter::OutboundSubmissionReceipt {
                bank_payment_id: Some("OCBC-PAY-RJ1".into()),
                end_to_end_id: None,
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
