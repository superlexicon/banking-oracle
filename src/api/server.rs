//! Authenticated HTTP Webhook & Treasury API Server (`axum`).
//!
//! Exposes:
//! 1. Bank Callback Endpoints (`POST /v1/webhooks/banks/:adapter_id`) — authenticated by each bank's
//!    `BankTechnicalAdapter` (`X-OCBC-Signature`, `X-JWS-Signature`, `X-ISO20022-Signature`).
//! 2. Payment Acquirer Callback Endpoints (`POST /v1/webhooks/acquirers/:acquirer_id`) — authenticated
//!    by each `PaymentAcquirerAdapter` (`X-OCBC-Merchant-Signature`, `Stripe-Signature`).
//! 3. Multi-Entity Treasury & Reconciliation API (`Authorization: Bearer <admin_api_key>`) for onboarding
//!    `AccountOwner`s, `BankAccount`s, `MerchantProfile`s, `Counterparty` directory, initiating outbound
//!    bank payments or merchant card sessions, inspecting per-currency Trial Balances, and triggering polls.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::crypto::constant_time_eq;
use crate::domain::entities::{AccountOwner, BankAccount, Counterparty, MerchantProfile};
use crate::engine::chain_relayer::ChainOutboxRelayer;
use crate::engine::poller::PollingSupervisor;
use crate::engine::reconciliation::ReconciliationEngine;
use crate::ports::acquirer_adapter::{MerchantPaymentRequest, PaymentAcquirerAdapter};
use crate::ports::bank_adapter::{BankTechnicalAdapter, OutboundPaymentInstruction};

pub struct OracleApiState {
    pub engine: Arc<ReconciliationEngine>,
    pub poller: Arc<PollingSupervisor>,
    pub relayer: Arc<ChainOutboxRelayer>,
    pub bank_adapters: Arc<HashMap<String, Arc<dyn BankTechnicalAdapter>>>,
    pub acquirer_adapters: Arc<HashMap<String, Arc<dyn PaymentAcquirerAdapter>>>,
    pub admin_bearer_token: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct InitiateOutboundApiRequest {
    pub account_id: String,
    pub instruction: OutboundPaymentInstruction,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CreateMerchantSessionApiRequest {
    pub merchant_profile_id: String,
    pub payment: MerchantPaymentRequest,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn check_admin_auth(headers: &HeaderMap, expected_token: &str) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let provided = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");
    if expected_token.is_empty() || !constant_time_eq(provided.as_bytes(), expected_token.as_bytes()) {
        Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid or missing admin Bearer token" })),
        ))
    } else {
        Ok(())
    }
}

pub fn build_oracle_router(state: Arc<OracleApiState>) -> Router {
    Router::new()
        .route("/health", get(handle_health))
        .route("/v1/webhooks/banks/:adapter_id", post(handle_bank_webhook))
        .route(
            "/v1/webhooks/acquirers/:acquirer_id",
            post(handle_acquirer_webhook),
        )
        .route("/v1/entities", post(handle_upsert_entity))
        .route("/v1/accounts", post(handle_upsert_bank_account))
        .route("/v1/merchants", post(handle_upsert_merchant_profile))
        .route("/v1/counterparties", post(handle_upsert_counterparty))
        .route("/v1/payments/outbound", post(handle_initiate_outbound))
        .route(
            "/v1/payments/merchant/sessions",
            post(handle_create_merchant_session),
        )
        .route("/v1/admin/poll-now", post(handle_poll_now))
        .route(
            "/v1/entities/:entity_id/trial-balance",
            get(handle_entity_trial_balance),
        )
        .route("/v1/reconciliation/state", get(handle_reconciliation_state))
        .with_state(state)
}

async fn handle_health(State(st): State<Arc<OracleApiState>>) -> Json<serde_json::Value> {
    let mut banks: Vec<&str> = st.bank_adapters.keys().map(|s| s.as_str()).collect();
    banks.sort_unstable();
    let mut acquirers: Vec<&str> = st.acquirer_adapters.keys().map(|s| s.as_str()).collect();
    acquirers.sort_unstable();
    let counts = st.engine.store().read(|s| {
        json!({
            "entities": s.entities.len(),
            "bankAccounts": s.bank_accounts.len(),
            "merchantProfiles": s.merchant_profiles.len(),
            "pendingOutboxTasks": s.outbox.values().filter(|t| !matches!(t.state, crate::domain::ledger::OutboxTaskState::Submitted { .. })).count()
        })
    });
    Json(json!({
        "service": "banking-oracle",
        "status": "ok",
        "registeredBankAdapters": banks,
        "registeredAcquirerAdapters": acquirers,
        "counts": counts,
    }))
}

async fn handle_bank_webhook(
    State(st): State<Arc<OracleApiState>>,
    Path(adapter_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, Json<serde_json::Value>) {
    let Some(adapter) = st.bank_adapters.get(&adapter_id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("unknown bank adapter '{}'", adapter_id) })),
        );
    };
    let now = unix_now();
    let events = match adapter.verify_and_parse_webhook(&headers, &body, now).await {
        Ok(ev) => ev,
        Err(e) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": e.to_string() })),
            )
        }
    };

    let mut outcomes = Vec::with_capacity(events.len());
    for ev in events {
        match st.engine.ingest_bank_event(ev, now) {
            Ok(o) => outcomes.push(o),
            Err(e) => {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({ "error": e.to_string() })),
                )
            }
        }
    }
    let relayed = st.relayer.flush_pending_outbox(now).await;
    (
        StatusCode::OK,
        Json(json!({
            "status": "processed",
            "outcomes": outcomes,
            "relayedOnChainTasks": relayed,
        })),
    )
}

async fn handle_acquirer_webhook(
    State(st): State<Arc<OracleApiState>>,
    Path(acquirer_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, Json<serde_json::Value>) {
    let Some(adapter) = st.acquirer_adapters.get(&acquirer_id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("unknown acquirer adapter '{}'", acquirer_id) })),
        );
    };
    let now = unix_now();
    let events = match adapter.verify_and_parse_webhook(&headers, &body, now).await {
        Ok(ev) => ev,
        Err(e) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": e.to_string() })),
            )
        }
    };

    let mut outcomes = Vec::with_capacity(events.len());
    for ev in events {
        match st.engine.ingest_acquirer_event(ev, now) {
            Ok(o) => outcomes.push(o),
            Err(e) => {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({ "error": e.to_string() })),
                )
            }
        }
    }
    let relayed = st.relayer.flush_pending_outbox(now).await;
    (
        StatusCode::OK,
        Json(json!({
            "status": "processed",
            "outcomes": outcomes,
            "relayedOnChainTasks": relayed,
        })),
    )
}

async fn handle_upsert_entity(
    State(st): State<Arc<OracleApiState>>,
    headers: HeaderMap,
    Json(entity): Json<AccountOwner>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(resp) = check_admin_auth(&headers, &st.admin_bearer_token) {
        return resp;
    }
    match st.engine.store().upsert_entity(entity) {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        ),
    }
}

async fn handle_upsert_bank_account(
    State(st): State<Arc<OracleApiState>>,
    headers: HeaderMap,
    Json(acct): Json<BankAccount>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(resp) = check_admin_auth(&headers, &st.admin_bearer_token) {
        return resp;
    }
    if !st.bank_adapters.contains_key(&acct.bank_adapter_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("unregistered bank_adapter_id '{}'", acct.bank_adapter_id) })),
        );
    }
    match st.engine.store().upsert_bank_account(acct) {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        ),
    }
}

async fn handle_upsert_merchant_profile(
    State(st): State<Arc<OracleApiState>>,
    headers: HeaderMap,
    Json(profile): Json<MerchantProfile>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(resp) = check_admin_auth(&headers, &st.admin_bearer_token) {
        return resp;
    }
    if !st
        .acquirer_adapters
        .contains_key(&profile.acquirer_adapter_id)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("unregistered acquirer_adapter_id '{}'", profile.acquirer_adapter_id) })),
        );
    }
    match st.engine.store().upsert_merchant_profile(profile) {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        ),
    }
}

async fn handle_upsert_counterparty(
    State(st): State<Arc<OracleApiState>>,
    headers: HeaderMap,
    Json(cp): Json<Counterparty>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(resp) = check_admin_auth(&headers, &st.admin_bearer_token) {
        return resp;
    }
    match st.engine.store().upsert_counterparty(cp) {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        ),
    }
}

async fn handle_initiate_outbound(
    State(st): State<Arc<OracleApiState>>,
    headers: HeaderMap,
    Json(req): Json<InitiateOutboundApiRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(resp) = check_admin_auth(&headers, &st.admin_bearer_token) {
        return resp;
    }
    let acct = st
        .engine
        .store()
        .read(|s| s.bank_accounts.get(&req.account_id).cloned());
    let Some(acct) = acct else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("unknown bank account '{}'", req.account_id) })),
        );
    };
    let Some(adapter) = st.bank_adapters.get(&acct.bank_adapter_id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("missing adapter '{}'", acct.bank_adapter_id) })),
        );
    };

    let now = unix_now();
    let receipt = match adapter
        .initiate_outbound_payment(&acct, &req.instruction, now)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": e.to_string() })),
            )
        }
    };

    match st
        .engine
        .record_outbound_initiated(&acct.account_id, &req.instruction, &receipt, now)
    {
        Ok(tracker) => {
            let relayed = st.relayer.flush_pending_outbox(now).await;
            (
                StatusCode::OK,
                Json(json!({
                    "status": "initiated",
                    "tracker": tracker,
                    "relayedOnChainTasks": relayed,
                })),
            )
        }
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": e.to_string() })),
        ),
    }
}

async fn handle_create_merchant_session(
    State(st): State<Arc<OracleApiState>>,
    headers: HeaderMap,
    Json(req): Json<CreateMerchantSessionApiRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(resp) = check_admin_auth(&headers, &st.admin_bearer_token) {
        return resp;
    }
    let merchant = st.engine.store().read(|s| {
        s.merchant_profiles
            .get(&req.merchant_profile_id)
            .cloned()
    });
    let Some(merchant) = merchant else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("unknown merchant profile '{}'", req.merchant_profile_id) })),
        );
    };
    let Some(adapter) = st.acquirer_adapters.get(&merchant.acquirer_adapter_id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("missing acquirer adapter '{}'", merchant.acquirer_adapter_id) })),
        );
    };

    let now = unix_now();
    match adapter
        .create_payment_session(&merchant, &req.payment, now)
        .await
    {
        Ok(session) => (StatusCode::OK, Json(json!(session))),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": e.to_string() })),
        ),
    }
}

async fn handle_poll_now(
    State(st): State<Arc<OracleApiState>>,
    headers: HeaderMap,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(resp) = check_admin_auth(&headers, &st.admin_bearer_token) {
        return resp;
    }
    let now = unix_now();
    let report = st.poller.run_poll_cycle_once(now).await;
    let relayed = st.relayer.flush_pending_outbox(now).await;
    (
        StatusCode::OK,
        Json(json!({
            "pollReport": report,
            "relayedOnChainTasks": relayed,
        })),
    )
}

async fn handle_entity_trial_balance(
    State(st): State<Arc<OracleApiState>>,
    Path(entity_id): Path<String>,
    headers: HeaderMap,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(resp) = check_admin_auth(&headers, &st.admin_bearer_token) {
        return resp;
    }
    let tb = st.engine.store().compute_entity_trial_balance(&entity_id);
    (
        StatusCode::OK,
        Json(json!({
            "entityId": entity_id,
            "trialBalance": tb,
        })),
    )
}

async fn handle_reconciliation_state(
    State(st): State<Arc<OracleApiState>>,
    headers: HeaderMap,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(resp) = check_admin_auth(&headers, &st.admin_bearer_token) {
        return resp;
    }
    let snap = st.engine.store().read(|s| {
        json!({
            "bankCredits": s.bank_credits,
            "outboundPayments": s.outbound_payments,
            "clearingItems": s.clearing_items,
            "sweepBatches": s.sweep_batches,
            "journals": s.journals,
            "outbox": s.outbox,
        })
    });
    (StatusCode::OK, Json(snap))
}
