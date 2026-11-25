//! Official CONNECT2OCBC OAuth 2.0 Authorization (`OAuth2INB` `sessionToken` + `Bearer` header)
//! and Per-User `10 API Calls / Minute` Rate Limiter.
//!
//! Implements OCBC's documented OAuth 2.0 flow:
//! 1. Authorize GET URL:
//!    `https://api.ocbc.com/ocbcauthentication/api/oauth2/authorize?client_id=<consumer key>&redirect_uri=<redirect URL>&scope=transactional`
//! 2. Webview Redirect Fragment Response:
//!    `https://<redirect_uri host>/<redirect_uri path>#access_token=3f86faa0f22934789b71b79ac39ec34f&token_type=Bearer&expires_in=3600`
//! 3. Dual Token Formatting:
//!    - HTTP Header: `Authorization: Bearer <access_token>`
//!    - Transactional Query Param `sessionToken`: `OAuth2INB <access_token>`
//! 4. Usage Guideline Rate Limit:
//!    - Default `10 API calls every 60 seconds` per user token unless OCBC approves a higher tier.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::ports::store::OracleStore;

/// Persisted OCBC OAuth 2.0 user/application token record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OcbcSessionTokenRecord {
    /// Key scoping this token (e.g. `"default"`, an `account_id`, or `entity_id`).
    pub scope_key: String,
    /// Raw OAuth2 `access_token` (without `"Bearer "` or `"OAuth2INB "` prefix).
    pub access_token: String,
    /// Usually `"Bearer"`.
    pub token_type: String,
    /// Expiration Unix timestamp (`obtained_at_unix + expires_in`).
    pub expires_at_unix: u64,
}

impl OcbcSessionTokenRecord {
    pub fn normalize_raw_token(raw: &str) -> String {
        let t = raw.trim();
        let t = t.strip_prefix("Bearer ").unwrap_or(t);
        let t = t.strip_prefix("OAuth2INB ").unwrap_or(t);
        t.trim().to_string()
    }

    pub fn new(scope_key: impl Into<String>, raw_token: &str, expires_at_unix: u64) -> Self {
        Self {
            scope_key: scope_key.into(),
            access_token: Self::normalize_raw_token(raw_token),
            token_type: "Bearer".into(),
            expires_at_unix,
        }
    }

    pub fn is_expired(&self, now_unix: u64) -> bool {
        self.expires_at_unix > 0 && now_unix >= self.expires_at_unix
    }

    /// Formats header value: `Bearer 3f86faa0f22934789b71b79ac39ec34f`.
    pub fn authorization_bearer_header(&self) -> String {
        format!("Bearer {}", self.access_token)
    }

    /// Formats transactional query parameter `sessionToken`: `OAuth2INB 3f86faa0f22934789b71b79ac39ec34f`.
    pub fn session_token_value(&self) -> String {
        format!("OAuth2INB {}", self.access_token)
    }

    /// URL-encoded `sessionToken` query value (`OAuth2INB%203f86...`).
    pub fn session_token_url_encoded(&self) -> String {
        format!("OAuth2INB%20{}", url_encode_component(&self.access_token))
    }
}

pub fn url_encode_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 16);
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// Build the exact OCBC OAuth 2.0 customer login redirect URL:
/// `https://api.ocbc.com/ocbcauthentication/api/oauth2/authorize?client_id=<consumer key>&redirect_uri=<redirect URL>&scope=transactional`
pub fn build_ocbc_oauth_authorize_url(
    base_url: &str,
    client_id: &str,
    redirect_uri: &str,
    scope: &str,
) -> String {
    format!(
        "{}/ocbcauthentication/api/oauth2/authorize?client_id={}&redirect_uri={}&scope={}",
        base_url.trim_end_matches('/'),
        url_encode_component(client_id),
        url_encode_component(redirect_uri),
        url_encode_component(if scope.is_empty() { "transactional" } else { scope })
    )
}

/// Parse the URL fragment (`#access_token=...&token_type=Bearer&expires_in=3600`) returned by
/// OCBC's OAuth 2.0 webview redirect after Access Code + PIN + SMS OTP login.
pub fn parse_ocbc_oauth_fragment(
    fragment_or_query: &str,
    scope_key: &str,
    now_unix: u64,
) -> Result<OcbcSessionTokenRecord> {
    let clean = fragment_or_query
        .trim()
        .trim_start_matches('#')
        .trim_start_matches('?');

    let mut access_token: Option<String> = None;
    let mut token_type = "Bearer".to_string();
    let mut expires_in: u64 = 3600;

    for pair in clean.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            match k.trim() {
                "access_token" => access_token = Some(v.trim().to_string()),
                "token_type" => token_type = v.trim().to_string(),
                "expires_in" => {
                    expires_in = v
                        .trim()
                        .parse::<u64>()
                        .map_err(|_| anyhow!("invalid expires_in '{}' in OCBC OAuth fragment", v))?;
                }
                _ => {}
            }
        }
    }

    let tok = access_token
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("missing access_token in OCBC OAuth redirect fragment"))?;

    Ok(OcbcSessionTokenRecord {
        scope_key: scope_key.to_string(),
        access_token: OcbcSessionTokenRecord::normalize_raw_token(&tok),
        token_type,
        expires_at_unix: now_unix.saturating_add(expires_in),
    })
}

/// Shared OCBC Token Vault backed by `OracleStore` so customer/corporate `sessionToken`s captured via
/// the OAuth 2.0 redirect webview are immediately available to both `OcbcCorporateBankAdapter` and
/// `OcbcMerchantCardAdapter` and survive process restarts.
pub struct OcbcTokenVault {
    store: Arc<OracleStore>,
    fallback_static_token: Option<String>,
}

impl OcbcTokenVault {
    pub fn new(store: Arc<OracleStore>, fallback_static_token: Option<String>) -> Self {
        Self {
            store,
            fallback_static_token: fallback_static_token.filter(|s| !s.trim().is_empty()),
        }
    }

    pub fn save_token(&self, record: OcbcSessionTokenRecord) -> Result<()> {
        self.store.upsert_ocbc_token(record)
    }

    /// Resolve the active OCBC token for `account_or_merchant_id` (falling back to `"default"` scope
    /// or configured Sandbox/Console static access token).
    pub fn resolve_token(
        &self,
        specific_scope_key: Option<&str>,
        now_unix: u64,
    ) -> Result<OcbcSessionTokenRecord> {
        let found = self.store.read(|s| {
            if let Some(k) = specific_scope_key {
                if let Some(rec) = s.ocbc_tokens.get(k) {
                    return Some(rec.clone());
                }
            }
            s.ocbc_tokens.get("default").cloned()
        });

        if let Some(rec) = found {
            if rec.is_expired(now_unix) {
                return Err(anyhow!(
                    "OCBC OAuth2 sessionToken for scope '{}' expired at unix={} (now={}); re-authorize via /v1/oauth/ocbc/authorize-url",
                    rec.scope_key,
                    rec.expires_at_unix,
                    now_unix
                ));
            }
            return Ok(rec);
        }

        if let Some(fallback) = &self.fallback_static_token {
            return Ok(OcbcSessionTokenRecord::new("static_fallback", fallback, 0));
        }

        Err(anyhow!(
            "no active OCBC OAuth2 access_token / sessionToken found; complete login via GET /v1/oauth/ocbc/authorize-url or POST /v1/oauth/ocbc/token"
        ))
    }
}

/// Sliding-window rate limiter enforcing OCBC's documented Usage Guideline:
/// *"By default, each user will be permitted to make 10 API calls every minute."*
pub struct OcbcRateLimiter {
    max_calls_per_minute: usize,
    call_timestamps: Mutex<HashMap<String, VecDeque<u64>>>,
}

impl OcbcRateLimiter {
    pub fn new(max_calls_per_minute: usize) -> Self {
        Self {
            max_calls_per_minute: max_calls_per_minute.max(1),
            call_timestamps: Mutex::new(HashMap::new()),
        }
    }

    pub async fn acquire_slot(&self, token_key: &str, now_unix: u64) -> Result<()> {
        let mut map = self.call_timestamps.lock().await;
        let q = map.entry(token_key.to_string()).or_default();
        while let Some(&oldest) = q.front() {
            if now_unix.saturating_sub(oldest) >= 60 {
                q.pop_front();
            } else {
                break;
            }
        }
        if q.len() >= self.max_calls_per_minute {
            return Err(anyhow!(
                "OCBC API rate limit guard: {}/{} calls already made in the last 60s (OCBC default limit is 10 calls/min)",
                q.len(),
                self.max_calls_per_minute
            ));
        }
        q.push_back(now_unix);
        Ok(())
    }
}
