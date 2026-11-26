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
    http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::adapters::ocbc_auth::{
    build_ocbc_oauth_authorize_url, parse_ocbc_oauth_fragment, OcbcSessionTokenRecord,
    OcbcTokenVault,
};
use crate::crypto::{constant_time_eq, hmac_sha256, keccak256};
use crate::domain::entities::{AccountOwner, BankAccount, Counterparty, MerchantProfile};
use crate::domain::events::{AcquirerSettlementBatch, CanonicalAcquirerEvent, VoucherOrderMetadata};
use crate::domain::ledger::{ClearingItemStatus, PreorderAuthorizationRecord, PreorderLifecycleStatus};
use crate::domain::money::Money;
use crate::engine::chain_relayer::ChainOutboxRelayer;
use crate::engine::poller::PollingSupervisor;
use crate::engine::reconciliation::ReconciliationEngine;
use crate::ports::acquirer_adapter::{
    CardCaptureMode, MerchantPaymentRequest, PaymentAcquirerAdapter,
};
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

#[derive(Debug, Deserialize, Serialize)]
pub struct PublicPreorderAuthorizeRequest {
    pub merchant_profile_id: Option<String>,
    pub order_reference: Option<String>,
    pub identity_addr: String,
    #[serde(default)]
    pub nickname: String,
    pub full_name: String,
    pub billing_address: String,
    pub shipping_address: String,
    #[serde(default = "default_sku_code")]
    pub sku_code: u64,
    #[serde(default = "default_qty_one")]
    pub quantity: u64,
    #[serde(default = "default_ks_tier_bps")]
    pub tier_bps: u64,
    pub amount: Money,
    #[serde(default)]
    pub description: String,
    pub voucher_commitment: String,
    pub agreement_version: String,
    pub agreement_hash: String,
    pub agreement_accepted: bool,
    #[serde(default)]
    pub is_dollar_test: bool,
    pub return_url: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PublicPreorderCancelRequest {
    pub order_reference: String,
    pub cancel_token: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BatchCapturePreordersRequest {
    pub merchant_profile_id: Option<String>,
}

fn default_sku_code() -> u64 {
    1
}

fn default_qty_one() -> u64 {
    1
}

fn default_ks_tier_bps() -> u64 {
    2_000
}

fn derive_preorder_cancel_token(secret: &str, payment_id: &str, order_ref: &str) -> String {
    let msg = format!("preorder_cancel:v1:{}:{}", payment_id, order_ref);
    hex::encode(hmac_sha256(secret.as_bytes(), msg.as_bytes()))
}

async fn cors_middleware<B>(req: Request<B>, next: Next<B>) -> Response {
    if req.method() == Method::OPTIONS {
        let mut resp = StatusCode::NO_CONTENT.into_response();
        let h = resp.headers_mut();
        h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
        h.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST, OPTIONS"),
        );
        h.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("Content-Type, Authorization"),
        );
        return resp;
    }
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    h.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    h.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("Content-Type, Authorization"),
    );
    resp
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
        .route(
            "/v1/public/preorders/authorize",
            post(handle_public_preorder_authorize),
        )
        .route(
            "/v1/public/preorders/cancel",
            post(handle_public_preorder_cancel),
        )
        .route(
            "/v1/payments/preorders/capture-batch",
            post(handle_batch_capture_preorders),
        )
        .route("/v1/admin/poll-now", post(handle_poll_now))
        .route(
            "/v1/entities/:entity_id/trial-balance",
            get(handle_entity_trial_balance),
        )
        .route("/v1/reconciliation/state", get(handle_reconciliation_state))
        .layer(middleware::from_fn(cors_middleware))
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
            "preorders": s.preorders,
        })
    });
    (StatusCode::OK, Json(snap))
}

async fn handle_public_preorder_authorize(
    State(st): State<Arc<OracleApiState>>,
    Json(req): Json<PublicPreorderAuthorizeRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !req.agreement_accepted
        || req.agreement_version.trim().is_empty()
        || req.agreement_hash.trim().is_empty()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "Pre-Order Agreement must be explicitly reviewed and accepted before requesting Airwallex authorization."
            })),
        );
    }
    let id_addr = req.identity_addr.trim().to_ascii_lowercase();
    if !id_addr.starts_with("0x") || id_addr.len() != 42 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "A valid 20-byte Identity HFS address (0x...) is required." })),
        );
    }
    if req.full_name.trim().is_empty()
        || req.billing_address.trim().is_empty()
        || req.shipping_address.trim().is_empty()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "Full Name (as per credit card), Billing Address, and Shipping Address are required."
            })),
        );
    }
    if req.amount.amount_minor <= 0 || req.quantity == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Order amount and quantity must be positive." })),
        );
    }

    let merchant = st.engine.store().read(|s| {
        if let Some(ref pid) = req.merchant_profile_id {
            if let Some(m) = s.merchant_profiles.get(pid) {
                return Some(m.clone());
            }
        }
        s.merchant_profiles
            .values()
            .find(|m| m.acquirer_adapter_id == "airwallex")
            .or_else(|| s.merchant_profiles.values().next())
            .cloned()
    });
    let Some(merchant) = merchant else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": "No active Airwallex merchant profile configured in banking-oracle yet."
            })),
        );
    };
    let Some(adapter) = st.acquirer_adapters.get(&merchant.acquirer_adapter_id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("Acquirer adapter '{}' not registered", merchant.acquirer_adapter_id)
            })),
        );
    };

    let now = unix_now();
    let order_ref = req
        .order_reference
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| {
            let dig = keccak256(
                format!("{}:{}:{}:{}", id_addr, req.sku_code, req.quantity, now).as_bytes(),
            );
            format!("SLX-PRE-{}", &hex::encode(dig)[..12].to_ascii_uppercase())
        });

    let is_smoke = req.is_dollar_test && req.amount.amount_minor <= 200;
    let capture_mode = if is_smoke {
        CardCaptureMode::ImmediateSale
    } else {
        CardCaptureMode::AuthorizeOnly
    };

    let desc = if !req.description.trim().is_empty() {
        req.description.clone()
    } else if is_smoke {
        "Superlexicon $1 Oracle Test".to_string()
    } else {
        format!("Superlexicon PreOrder SKU{}x{}", req.sku_code, req.quantity)
    };

    let voucher_meta = if req.voucher_commitment.trim().starts_with("0x")
        && req.voucher_commitment.trim().len() == 66
    {
        Some(VoucherOrderMetadata {
            sku_code: req.sku_code,
            tier_bps: req.tier_bps,
            voucher_commitment_hex: req.voucher_commitment.trim().to_ascii_lowercase(),
            explicit_price_usd_micros: Some((req.amount.amount_minor as u64).saturating_mul(10_000)),
        })
    } else {
        None
    };

    let acq_extra = json!({
        "metadata": {
            "order_ref": order_ref,
            "capture_mode": if is_smoke { "immediate_sale" } else { "authorize_only" },
            "identity_hfs": id_addr,
            "nickname": req.nickname.trim(),
            "cardholder_full_name": req.full_name.trim(),
            "billing_address": req.billing_address.trim(),
            "shipping_address": req.shipping_address.trim(),
            "agreement_version": req.agreement_version.trim(),
            "agreement_hash": req.agreement_hash.trim(),
            "sku": req.sku_code.to_string(),
            "qty": req.quantity.to_string(),
            "voucher_commitment": req.voucher_commitment.trim(),
        }
    });

    let pay_req = MerchantPaymentRequest {
        order_reference: order_ref.clone(),
        customer_id: None,
        amount: req.amount.clone(),
        description: desc,
        capture_mode,
        acquirer_specific_payload: acq_extra,
        success_url: req.return_url.clone(),
        cancel_url: req.return_url,
        structured_invoice_id: None,
        voucher_metadata: voucher_meta,
    };

    match adapter.create_payment_session(&merchant, &pay_req, now).await {
        Ok(mut session) => {
            let mut outcome = None;
            if let Some(ev) = session.immediate_event.take() {
                if let Ok(o) = st.engine.ingest_acquirer_event(ev, now) {
                    outcome = Some(o);
                }
            }
            let init_status = if is_smoke {
                PreorderLifecycleStatus::CapturedNonCancelable
            } else {
                PreorderLifecycleStatus::AuthorizedHold
            };
            let cancel_token = derive_preorder_cancel_token(
                &st.admin_bearer_token,
                &session.acquirer_payment_id,
                &order_ref,
            );
            let rec = PreorderAuthorizationRecord {
                order_reference: order_ref.clone(),
                merchant_profile_id: merchant.merchant_profile_id.clone(),
                acquirer_payment_id: session.acquirer_payment_id.clone(),
                identity_addr: id_addr,
                nickname: req.nickname.trim().to_string(),
                full_name: req.full_name.trim().to_string(),
                billing_address: req.billing_address.trim().to_string(),
                shipping_address: req.shipping_address.trim().to_string(),
                sku_code: req.sku_code,
                quantity: req.quantity,
                amount: req.amount,
                voucher_commitment: req.voucher_commitment.trim().to_string(),
                agreement_version: req.agreement_version,
                agreement_hash: req.agreement_hash,
                is_dollar_test: is_smoke,
                status: init_status,
                created_at_unix: now,
                updated_at_unix: now,
            };
            let _ = st.engine.store().write(|s| {
                s.preorders.insert(order_ref.clone(), rec);
                Ok(())
            });
            let payment_ref_hash = format!(
                "0x{}",
                hex::encode(keccak256(
                    format!("{}:{}", merchant.acquirer_adapter_id, session.acquirer_payment_id)
                        .as_bytes()
                ))
            );
            (
                StatusCode::OK,
                Json(json!({
                    "orderReference": order_ref,
                    "acquirerId": session.acquirer_id,
                    "paymentIntentId": session.acquirer_payment_id,
                    "clientSecretOrUrl": session.checkout_url_or_token,
                    "captureMode": if is_smoke { "immediate_sale" } else { "authorize_only" },
                    "cancelToken": cancel_token,
                    "paymentRefHash": payment_ref_hash,
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

async fn handle_public_preorder_cancel(
    State(st): State<Arc<OracleApiState>>,
    Json(req): Json<PublicPreorderCancelRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let ord_key = req.order_reference.trim();
    let rec_opt = st
        .engine
        .store()
        .read(|s| s.preorders.get(ord_key).cloned());
    let Some(rec) = rec_opt else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("unknown pre-order reference '{}'", ord_key) })),
        );
    };

    let expected_tok = derive_preorder_cancel_token(
        &st.admin_bearer_token,
        &rec.acquirer_payment_id,
        &rec.order_reference,
    );
    if !constant_time_eq(req.cancel_token.trim().as_bytes(), expected_tok.as_bytes()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid pre-order cancellation token" })),
        );
    }

    if rec.status == PreorderLifecycleStatus::CapturedNonCancelable {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "Card has already been charged after reaching the minimum campaign target. Self-cancellation is disabled after capture; refunds are at the sole discretion of Superlexicon Pte. Ltd."
            })),
        );
    }
    if rec.status == PreorderLifecycleStatus::CanceledPriorToCapture {
        return (
            StatusCode::OK,
            Json(json!({ "status": "already_canceled", "orderReference": rec.order_reference })),
        );
    }

    let already_captured_in_clearing = st.engine.store().read(|s| {
        s.clearing_items.values().any(|item| {
            item.acquirer_payment_id == rec.acquirer_payment_id
                && matches!(
                    item.status,
                    ClearingItemStatus::CapturedPendingBankSweep
                        | ClearingItemStatus::BankCashFinalized { .. }
                )
        })
    });
    if already_captured_in_clearing {
        let _ = st.engine.store().write(|s| {
            if let Some(p) = s.preorders.get_mut(&rec.order_reference) {
                p.status = PreorderLifecycleStatus::CapturedNonCancelable;
            }
            Ok(())
        });
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "Card has already been charged. Refunds after capture are at the sole discretion of Superlexicon Pte. Ltd."
            })),
        );
    }

    let Some(merchant) = st
        .engine
        .store()
        .read(|s| s.merchant_profiles.get(&rec.merchant_profile_id).cloned())
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "merchant profile missing" })),
        );
    };
    let Some(adapter) = st.acquirer_adapters.get(&merchant.acquirer_adapter_id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "acquirer adapter missing" })),
        );
    };

    let now = unix_now();
    match adapter
        .void_payment(
            &merchant,
            &rec.acquirer_payment_id,
            &rec.order_reference,
            &rec.amount,
            now,
        )
        .await
    {
        Ok(ev) => {
            let _ = st.engine.ingest_acquirer_event(ev, now);
            let _ = st.engine.store().write(|s| {
                if let Some(p) = s.preorders.get_mut(&rec.order_reference) {
                    p.status = PreorderLifecycleStatus::CanceledPriorToCapture;
                    p.updated_at_unix = now;
                }
                Ok(())
            });
            let relayed = st.relayer.flush_pending_outbox(now).await;
            (
                StatusCode::OK,
                Json(json!({
                    "status": "canceled_prior_to_capture",
                    "chargedAmount": 0,
                    "orderReference": rec.order_reference,
                    "paymentIntentId": rec.acquirer_payment_id,
                    "relayedOnChainTasks": relayed,
                })),
            )
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": e.to_string() })),
        ),
    }
}

async fn handle_batch_capture_preorders(
    State(st): State<Arc<OracleApiState>>,
    headers: HeaderMap,
    Json(req): Json<BatchCapturePreordersRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(resp) = check_admin_auth(&headers, &st.admin_bearer_token) {
        return resp;
    }
    let pending: Vec<PreorderAuthorizationRecord> = st.engine.store().read(|s| {
        s.preorders
            .values()
            .filter(|p| {
                p.status == PreorderLifecycleStatus::AuthorizedHold
                    && req
                        .merchant_profile_id
                        .as_ref()
                        .map(|id| &p.merchant_profile_id == id)
                        .unwrap_or(true)
            })
            .cloned()
            .collect()
    });

    let now = unix_now();
    let mut captured = Vec::new();
    let mut errors = Vec::new();

    for p in pending {
        let Some(merchant) = st
            .engine
            .store()
            .read(|s| s.merchant_profiles.get(&p.merchant_profile_id).cloned())
        else {
            continue;
        };
        let Some(adapter) = st.acquirer_adapters.get(&merchant.acquirer_adapter_id) else {
            continue;
        };
        match adapter
            .capture_authorized_payment(
                &merchant,
                &p.acquirer_payment_id,
                &p.order_reference,
                &p.amount,
                now,
            )
            .await
        {
            Ok(ev) => {
                let _ = st.engine.ingest_acquirer_event(ev, now);
                let _ = st.engine.store().write(|s| {
                    if let Some(rec) = s.preorders.get_mut(&p.order_reference) {
                        rec.status = PreorderLifecycleStatus::CapturedNonCancelable;
                        rec.updated_at_unix = now;
                    }
                    Ok(())
                });
                captured.push(json!({
                    "orderReference": p.order_reference,
                    "paymentIntentId": p.acquirer_payment_id,
                    "amount": p.amount,
                }));
            }
            Err(e) => {
                errors.push(json!({
                    "orderReference": p.order_reference,
                    "paymentIntentId": p.acquirer_payment_id,
                    "error": e.to_string(),
                }));
            }
        }
    }

    let relayed = st.relayer.flush_pending_outbox(now).await;
    (
        StatusCode::OK,
        Json(json!({
            "capturedCount": captured.len(),
            "captured": captured,
            "errors": errors,
            "relayedOnChainTasks": relayed,
        })),
    )
}
