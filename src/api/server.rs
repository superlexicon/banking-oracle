//! Authenticated HTTP Webhook, OCBC OAuth 2.0 Callback & Multi-Entity Treasury API Server (`axum`).
//!
//! Exposes:
//! 1. **OCBC OAuth 2.0 Webview Redirect & Token Storage**:
//!    - `GET  /v1/oauth/ocbc/authorize-url` — Builds `https://api.ocbc.com/ocbcauthentication/api/oauth2/authorize?client_id=...&redirect_uri=...&scope=transactional`
//!    - `GET  /v1/oauth/ocbc/callback`      — Captures `#access_token=...&token_type=Bearer&expires_in=3600` URL fragment from OCBC webview login
//!    - `POST /v1/oauth/ocbc/token`         — Persists the `OAuth2INB` `sessionToken` / `Bearer` token into `OcbcTokenVault`
//! 2. **Bank & Acquirer Webhook Endpoints**:
//!    - `POST /v1/webhooks/banks/:adapter_id`
//!    - `POST /v1/webhooks/acquirers/:acquirer_id`
//! 3. **Merchant Card Lifecycle (`/authorize`, `/sale`, `/capture`, `/void`, settlement batch upload) & Outbound Payments**:
//!    - `POST /v1/payments/merchant/sessions` (`/authorize` or `/sale` or Stripe session)
//!    - `POST /v1/payments/merchant/capture`  (`/capture`)
//!    - `POST /v1/payments/merchant/void`     (`/void`)
//!    - `POST /v1/merchants/:merchant_profile_id/settlement-batches`
//!    - `POST /v1/payments/outbound`

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Html,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::adapters::ocbc_auth::{
    build_ocbc_oauth_authorize_url, parse_ocbc_oauth_fragment, OcbcSessionTokenRecord,
    OcbcTokenVault,
};
use crate::crypto::constant_time_eq;
use crate::domain::entities::{AccountOwner, BankAccount, Counterparty, MerchantProfile};
use crate::domain::events::{AcquirerSettlementBatch, CanonicalAcquirerEvent};
use crate::domain::money::Money;
use crate::engine::chain_relayer::ChainOutboxRelayer;
use crate::engine::poller::PollingSupervisor;
use crate::engine::reconciliation::ReconciliationEngine;
use crate::ports::acquirer_adapter::{MerchantPaymentRequest, PaymentAcquirerAdapter};
use crate::ports::bank_adapter::{
    BankTechnicalAdapter, DirectCollectionInstruction, OutboundPaymentInstruction,
};

pub struct OracleApiState {
    pub engine: Arc<ReconciliationEngine>,
    pub poller: Arc<PollingSupervisor>,
    pub relayer: Arc<ChainOutboxRelayer>,
    pub bank_adapters: Arc<HashMap<String, Arc<dyn BankTechnicalAdapter>>>,
    pub acquirer_adapters: Arc<HashMap<String, Arc<dyn PaymentAcquirerAdapter>>>,
    pub ocbc_token_vault: Arc<OcbcTokenVault>,
    pub ocbc_base_url: String,
    pub ocbc_client_id: String,
    pub ocbc_redirect_uri: String,
    pub admin_bearer_token: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct InitiateOutboundApiRequest {
    pub account_id: String,
    pub instruction: OutboundPaymentInstruction,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct InitiateDirectCollectionApiRequest {
    pub account_id: String,
    pub instruction: DirectCollectionInstruction,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CreateMerchantSessionApiRequest {
    pub merchant_profile_id: String,
    pub payment: MerchantPaymentRequest,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CaptureOrVoidMerchantCardRequest {
    pub merchant_profile_id: String,
    pub transaction_id: String,
    pub merchant_tran_id: String,
    pub amount: Money,
}

#[derive(Debug, Deserialize, Default)]
pub struct OcbcAuthorizeQuery {
    pub scope: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SaveOcbcTokenRequest {
    /// Scope key (`"default"` or a specific `account_id` / `merchant_profile_id`).
    #[serde(default = "default_scope_key")]
    pub scope_key: String,
    /// Either a raw redirect fragment (`"#access_token=3f86...&token_type=Bearer&expires_in=3600"`)
    /// OR a direct `access_token` when `expires_in` is provided.
    pub fragment: Option<String>,
    pub access_token: Option<String>,
    #[serde(default = "default_expires_in")]
    pub expires_in: u64,
}

fn default_scope_key() -> String {
    "default".into()
}

fn default_expires_in() -> u64 {
    3600
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn check_admin_auth(
    headers: &HeaderMap,
    expected_token: &str,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let provided = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");
    if expected_token.is_empty()
        || !constant_time_eq(provided.as_bytes(), expected_token.as_bytes())
    {
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
        .route("/v1/oauth/ocbc/authorize-url", get(handle_ocbc_authorize_url))
        .route("/v1/oauth/ocbc/callback", get(handle_ocbc_oauth_callback_html))
        .route("/v1/oauth/ocbc/token", post(handle_save_ocbc_token))
        .route("/v1/webhooks/banks/:adapter_id", post(handle_bank_webhook))
        .route(
            "/v1/webhooks/acquirers/:acquirer_id",
            post(handle_acquirer_webhook),
        )
        .route("/v1/entities", post(handle_upsert_entity))
        .route("/v1/accounts", post(handle_upsert_bank_account))
        .route("/v1/merchants", post(handle_upsert_merchant_profile))
        .route(
            "/v1/merchants/:merchant_profile_id/settlement-batches",
            post(handle_ingest_settlement_batch),
        )
        .route("/v1/counterparties", post(handle_upsert_counterparty))
        .route("/v1/payments/outbound", post(handle_initiate_outbound))
        .route(
            "/v1/collections/direct",
            post(handle_initiate_direct_collection),
        )
        .route(
            "/v1/payments/merchant/sessions",
            post(handle_create_merchant_session),
        )
        .route(
            "/v1/payments/merchant/capture",
            post(handle_capture_merchant_payment),
        )
        .route(
            "/v1/payments/merchant/void",
            post(handle_void_merchant_payment),
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
            "ocbcTokensCached": s.ocbc_tokens.len(),
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

async fn handle_ocbc_authorize_url(
    State(st): State<Arc<OracleApiState>>,
    headers: HeaderMap,
    Query(q): Query<OcbcAuthorizeQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(resp) = check_admin_auth(&headers, &st.admin_bearer_token) {
        return resp;
    }
    let scope = q.scope.as_deref().unwrap_or("transactional");
    let url = build_ocbc_oauth_authorize_url(
        &st.ocbc_base_url,
        &st.ocbc_client_id,
        &st.ocbc_redirect_uri,
        scope,
    );
    (
        StatusCode::OK,
        Json(json!({
            "authorizeUrl": url,
            "clientId": st.ocbc_client_id,
            "redirectUri": st.ocbc_redirect_uri,
            "scope": scope,
        })),
    )
}

/// Browser landing page for OCBC's OAuth 2.0 Implicit Grant redirect:
/// `https://<redirect_uri>#access_token=3f86faa0f22934789b71b79ac39ec34f&token_type=Bearer&expires_in=3600`
/// Reads `window.location.hash` client-side and allows posting it with the admin token to `/v1/oauth/ocbc/token`.
async fn handle_ocbc_oauth_callback_html() -> Html<&'static str> {
    Html(
        r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>OCBC OAuth 2.0 Token Receiver</title></head>
<body style="font-family:system-ui,sans-serif;max-width:640px;margin:40px auto;padding:0 16px">
  <h2>OCBC OAuth 2.0 Redirect Captured</h2>
  <p>After OCBC iBanking Access Code + PIN + OTP verification, confirm your Oracle Admin Token to store the <code>sessionToken</code>:</p>
  <input id="adm" type="password" placeholder="Oracle Admin Bearer Token" style="width:100%;padding:8px;margin-bottom:8px"/>
  <input id="scope" type="text" value="default" placeholder="Scope key (default or account_id)" style="width:100%;padding:8px;margin-bottom:12px"/>
  <button id="btn" style="padding:10px 18px;cursor:pointer">Store OCBC Session Token</button>
  <pre id="out" style="background:#f4f4f5;padding:12px;margin-top:16px;white-space:pre-wrap"></pre>
  <script>
    const frag = window.location.hash || window.location.search;
    document.getElementById('btn').onclick = async () => {
      const adm = document.getElementById('adm').value.trim();
      const scope_key = document.getElementById('scope').value.trim() || 'default';
      const r = await fetch('/v1/oauth/ocbc/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + adm },
        body: JSON.stringify({ scope_key, fragment: frag })
      });
      document.getElementById('out').textContent = await r.text();
    };
  </script>
</body>
</html>"#,
    )
}

async fn handle_save_ocbc_token(
    State(st): State<Arc<OracleApiState>>,
    headers: HeaderMap,
    Json(req): Json<SaveOcbcTokenRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(resp) = check_admin_auth(&headers, &st.admin_bearer_token) {
        return resp;
    }
    let now = unix_now();
    let record_res = if let Some(frag) = &req.fragment {
        parse_ocbc_oauth_fragment(frag, &req.scope_key, now)
    } else if let Some(raw_tok) = &req.access_token {
        Ok(OcbcSessionTokenRecord::new(
            &req.scope_key,
            raw_tok,
            now.saturating_add(req.expires_in),
        ))
    } else {
        Err(anyhow::anyhow!(
            "provide either 'fragment' ('#access_token=...&token_type=Bearer&expires_in=3600') or 'access_token'"
        ))
    };

    match record_res.and_then(|rec| {
        let preview_session = rec.session_token_value();
        let exp = rec.expires_at_unix;
        st.ocbc_token_vault.save_token(rec)?;
        Ok((preview_session, exp))
    }) {
        Ok((session_fmt, exp)) => (
            StatusCode::OK,
            Json(json!({
                "status": "stored",
                "scopeKey": req.scope_key,
                "expiresAtUnix": exp,
                "sessionTokenFormat": format!("{}...", &session_fmt[..session_fmt.len().min(18)]),
            })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        ),
    }
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

async fn handle_ingest_settlement_batch(
    State(st): State<Arc<OracleApiState>>,
    Path(merchant_profile_id): Path<String>,
    headers: HeaderMap,
    Json(mut batch): Json<AcquirerSettlementBatch>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(resp) = check_admin_auth(&headers, &st.admin_bearer_token) {
        return resp;
    }
    let Some(mch) = st
        .engine
        .store()
        .read(|s| s.merchant_profiles.get(&merchant_profile_id).cloned())
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("unknown merchant_profile_id '{}'", merchant_profile_id) })),
        );
    };
    batch.acquirer_adapter_id = mch.acquirer_adapter_id;
    batch.external_merchant_id = mch.external_merchant_id;

    let now = unix_now();
    match st
        .engine
        .ingest_acquirer_event(CanonicalAcquirerEvent::SettlementSweepManifest(batch), now)
    {
        Ok(outcome) => {
            let relayed = st.relayer.flush_pending_outbox(now).await;
            (
                StatusCode::OK,
                Json(json!({ "outcome": outcome, "relayedOnChainTasks": relayed })),
            )
        }
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
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

async fn handle_initiate_direct_collection(
    State(st): State<Arc<OracleApiState>>,
    headers: HeaderMap,
    Json(req): Json<InitiateDirectCollectionApiRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(resp) = check_admin_auth(&headers, &st.admin_bearer_token) {
        return resp;
    }
    let Some(acct) = st
        .engine
        .store()
        .read(|s| s.bank_accounts.get(&req.account_id).cloned())
    else {
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
        .initiate_direct_collection(&acct, &req.instruction, now)
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
        .record_direct_collection_initiated(&acct.account_id, &req.instruction, &receipt, now)
    {
        Ok(tracker) => (
            StatusCode::OK,
            Json(json!({
                "status": "collection_initiated",
                "receipt": receipt,
                "tracker": tracker,
            })),
        ),
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
        Ok(mut session) => {
            let mut outcome = None;
            if let Some(ev) = session.immediate_event.take() {
                match st.engine.ingest_acquirer_event(ev, now) {
                    Ok(o) => outcome = Some(o),
                    Err(e) => {
                        return (
                            StatusCode::UNPROCESSABLE_ENTITY,
                            Json(json!({ "error": e.to_string() })),
                        )
                    }
                }
            }
            (
                StatusCode::OK,
                Json(json!({
                    "session": session,
                    "clearingOutcome": outcome,
                })),
            )
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": e.to_string() })),
        ),
    }
}

async fn handle_capture_merchant_payment(
    State(st): State<Arc<OracleApiState>>,
    headers: HeaderMap,
    Json(req): Json<CaptureOrVoidMerchantCardRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(resp) = check_admin_auth(&headers, &st.admin_bearer_token) {
        return resp;
    }
    let Some(merchant) = st
        .engine
        .store()
        .read(|s| s.merchant_profiles.get(&req.merchant_profile_id).cloned())
    else {
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
        .capture_authorized_payment(
            &merchant,
            &req.transaction_id,
            &req.merchant_tran_id,
            &req.amount,
            now,
        )
        .await
    {
        Ok(ev) => match st.engine.ingest_acquirer_event(ev, now) {
            Ok(outcome) => (StatusCode::OK, Json(json!({ "outcome": outcome }))),
            Err(e) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({ "error": e.to_string() })),
            ),
        },
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": e.to_string() })),
        ),
    }
}

async fn handle_void_merchant_payment(
    State(st): State<Arc<OracleApiState>>,
    headers: HeaderMap,
    Json(req): Json<CaptureOrVoidMerchantCardRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(resp) = check_admin_auth(&headers, &st.admin_bearer_token) {
        return resp;
    }
    let Some(merchant) = st
        .engine
        .store()
        .read(|s| s.merchant_profiles.get(&req.merchant_profile_id).cloned())
    else {
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
        .void_payment(
            &merchant,
            &req.transaction_id,
            &req.merchant_tran_id,
            &req.amount,
            now,
        )
        .await
    {
        Ok(ev) => match st.engine.ingest_acquirer_event(ev, now) {
            Ok(outcome) => {
                let relayed = st.relayer.flush_pending_outbox(now).await;
                (
                    StatusCode::OK,
                    Json(json!({ "outcome": outcome, "relayedOnChainTasks": relayed })),
                )
            }
            Err(e) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({ "error": e.to_string() })),
            ),
        },
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
            "directCollections": s.direct_collections,
            "clearingItems": s.clearing_items,
            "sweepBatches": s.sweep_batches,
            "journals": s.journals,
            "outbox": s.outbox,
        })
    });
    (StatusCode::OK, Json(snap))
}
