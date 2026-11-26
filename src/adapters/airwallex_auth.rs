//! Airwallex Authentication (`POST /api/v1/authentication/login`), Token Caching,
//! Webhook `x-timestamp` + `x-signature` Verification, and Major/Minor Monetary Helpers.
//!
//! Shared by both `AirwallexBankAdapter` (Global Accounts, Deposits & Transfers) and
//! `AirwallexAcquirerAdapter` (`PaymentIntents` Card/APM Acceptance & Settlements) so a single
//! 30-minute Bearer token is cached and reused safely across concurrent requests.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use axum::http::HeaderMap;
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::Mutex;

use crate::crypto::{constant_time_eq, hmac_sha256, keccak256};
use crate::domain::events::VoucherOrderMetadata;
use crate::domain::money::{CurrencyCode, Money};
use crate::ports::http_transport::{HttpMethod, HttpTransport, OutboundHttpRequest};

/// Shared Airwallex API credentials (`x-client-id` + `x-api-key`) and webhook configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AirwallexAuthConfig {
    /// Production: `"https://api.airwallex.com"`, Sandbox: `"https://api-demo.airwallex.com"`.
    pub base_url: String,
    pub client_id: String,
    pub api_key: String,
    /// Optional connected / sub-account ID (`acct_...`) sent via `x-on-behalf-of`.
    #[serde(default)]
    pub default_on_behalf_of: Option<String>,
    pub webhook_secret: String,
    #[serde(default = "default_skew_secs")]
    pub max_webhook_skew_secs: u64,
}

fn default_skew_secs() -> u64 {
    300
}

impl Default for AirwallexAuthConfig {
    fn default() -> Self {
        Self {
            base_url: "https://api.airwallex.com".into(),
            client_id: "awx_client_id_dev".into(),
            api_key: "awx_api_key_dev".into(),
            default_on_behalf_of: None,
            webhook_secret: "whsec_airwallex_dev".into(),
            max_webhook_skew_secs: 300,
        }
    }
}

#[derive(Debug, Clone)]
struct CachedBearerToken {
    token: String,
    expires_at_unix: u64,
}

/// Thread-safe Airwallex Bearer token manager (`POST /api/v1/authentication/login`).
/// Airwallex tokens are valid for 30 minutes; we refresh 60 seconds before `expires_at`.
pub struct AirwallexTokenManager {
    cfg: AirwallexAuthConfig,
    transport: Arc<dyn HttpTransport>,
    cached: Mutex<Option<CachedBearerToken>>,
}

impl AirwallexTokenManager {
    pub fn new(cfg: AirwallexAuthConfig, transport: Arc<dyn HttpTransport>) -> Self {
        Self {
            cfg,
            transport,
            cached: Mutex::new(None),
        }
    }

    pub fn base_url(&self) -> &str {
        self.cfg.base_url.trim_end_matches('/')
    }

    pub fn config(&self) -> &AirwallexAuthConfig {
        &self.cfg
    }

    /// Obtain a valid Airwallex `Bearer` token, reusing the cached token until `expires_at - 60s`.
    pub async fn bearer_token(&self, now_unix_secs: u64) -> Result<String> {
        let mut guard = self.cached.lock().await;
        if let Some(ref cur) = *guard {
            if now_unix_secs.saturating_add(60) < cur.expires_at_unix {
                return Ok(cur.token.clone());
            }
        }

        let login_url = format!("{}/api/v1/authentication/login", self.base_url());
        let resp = self
            .transport
            .execute(OutboundHttpRequest {
                method: HttpMethod::Post,
                url: login_url,
                headers: vec![
                    ("Content-Type".into(), "application/json".into()),
                    ("Accept".into(), "application/json".into()),
                    ("x-client-id".into(), self.cfg.client_id.clone()),
                    ("x-api-key".into(), self.cfg.api_key.clone()),
                ],
                body: b"{}".to_vec(),
            })
            .await?;

        if !resp.is_success() {
            return Err(anyhow!(
                "Airwallex authentication/login failed with HTTP {}: {}",
                resp.status,
                String::from_utf8_lossy(&resp.body)
            ));
        }

        let doc: Value = resp.json()?;
        let token = doc["token"]
            .as_str()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| anyhow!("missing 'token' in Airwallex authentication/login response"))?
            .to_string();

        let expires_at_unix = doc["expires_at"]
            .as_str()
            .and_then(parse_airwallex_timestamp_secs)
            .unwrap_or_else(|| now_unix_secs.saturating_add(1800));

        *guard = Some(CachedBearerToken {
            token: token.clone(),
            expires_at_unix,
        });
        Ok(token)
    }

    /// Build authenticated Airwallex REST headers (`Authorization: Bearer <token>`, plus optional
    /// `x-on-behalf-of: acct_...` for multi-entity / connected sub-accounts).
    pub async fn auth_headers(
        &self,
        on_behalf_of_override: Option<&str>,
        include_json_content_type: bool,
        now_unix_secs: u64,
    ) -> Result<Vec<(String, String)>> {
        let token = self.bearer_token(now_unix_secs).await?;
        let mut headers = vec![
            ("Authorization".into(), format!("Bearer {}", token)),
            ("Accept".into(), "application/json".into()),
        ];
        if include_json_content_type {
            headers.push(("Content-Type".into(), "application/json".into()));
        }
        let obo = on_behalf_of_override
            .filter(|s| s.starts_with("acct_"))
            .or_else(|| {
                self.cfg
                    .default_on_behalf_of
                    .as_deref()
                    .filter(|s| !s.is_empty())
            });
        if let Some(acct_id) = obo {
            headers.push(("x-on-behalf-of".into(), acct_id.to_string()));
        }
        Ok(headers)
    }
}

/// Verify Airwallex's official webhook signature headers (`x-timestamp` + `x-signature`):
/// `x-signature = hex(HMAC_SHA256(webhook_secret, x_timestamp || raw_body))` (no separator dot).
/// Supports millisecond (`13` digits, Airwallex default) or second (`10` digits) `x-timestamp`.
pub fn verify_airwallex_webhook(
    headers: &HeaderMap,
    raw_body: &[u8],
    webhook_secret: &str,
    now_unix_secs: u64,
    max_skew_secs: u64,
) -> Result<u64> {
    if webhook_secret.is_empty() {
        return Err(anyhow!("Airwallex webhook_secret is empty"));
    }
    let ts_str = headers
        .get("x-timestamp")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("missing Airwallex 'x-timestamp' webhook header"))?;

    let sig_hex = headers
        .get("x-signature")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("missing Airwallex 'x-signature' webhook header"))?;

    let raw_ts: u64 = ts_str
        .parse()
        .map_err(|_| anyhow!("invalid Airwallex x-timestamp '{}'", ts_str))?;
    let ts_secs = if raw_ts >= 100_000_000_000 {
        raw_ts / 1000
    } else {
        raw_ts
    };

    let skew = now_unix_secs.abs_diff(ts_secs);
    if skew > max_skew_secs {
        return Err(anyhow!(
            "Airwallex webhook timestamp skew {}s exceeds maximum allowed {}s",
            skew,
            max_skew_secs
        ));
    }

    let provided_sig = hex::decode(sig_hex.strip_prefix("sha256=").unwrap_or(sig_hex))
        .map_err(|_| anyhow!("invalid hex in Airwallex x-signature header"))?;

    let mut preimage = Vec::with_capacity(ts_str.len() + raw_body.len());
    preimage.extend_from_slice(ts_str.as_bytes());
    preimage.extend_from_slice(raw_body);

    let expected = hmac_sha256(webhook_secret.as_bytes(), &preimage);
    if !constant_time_eq(&provided_sig, &expected) {
        return Err(anyhow!(
            "Airwallex HMAC-SHA256 webhook signature verification failed"
        ));
    }
    Ok(ts_secs)
}

/// Format an exact `Money` minor-unit integer into a JSON decimal number (e.g. `125050` SGD cents -> `1250.50`,
/// `5000` JPY -> `5000`) without IEEE-754 float rounding drift.
pub fn money_to_airwallex_major_number(money: &Money) -> Value {
    let decimals = money.currency.minor_decimals() as u32;
    let abs = money.amount_minor.unsigned_abs();
    let sign = if money.amount_minor < 0 { "-" } else { "" };
    let formatted = if decimals == 0 {
        format!("{}{}", sign, abs)
    } else {
        let factor = 10u128.pow(decimals);
        let whole = abs / factor;
        let frac = abs % factor;
        format!(
            "{}{}.{:0width$}",
            sign,
            whole,
            frac,
            width = decimals as usize
        )
    };
    serde_json::from_str::<Value>(&formatted).unwrap_or_else(|_| json!(formatted))
}

/// Parse an Airwallex JSON major-unit monetary value (number like `1250.5` or string like `"1250.50"`)
/// into exact integer minor units for `ccy`.
pub fn parse_airwallex_major_to_minor(val: &Value, ccy: &CurrencyCode) -> Result<i128> {
    match val {
        Value::String(s) => ccy.parse_decimal_to_minor(s),
        Value::Number(n) => ccy.parse_decimal_to_minor(&n.to_string()),
        _ => Err(anyhow!(
            "expected JSON number or string for Airwallex amount, got {}",
            val
        )),
    }
}

/// Derive a deterministic UUID-v4-shaped idempotency `request_id` from `(domain, scope, client_ref)`
/// so retrying a timed-out POST (`payment_intents/create`, `capture`, `cancel`, `transfers/create`)
/// hits Airwallex's idempotency cache instead of duplicating a charge or payout.
pub fn derive_airwallex_request_id(domain: &str, scope: &str, client_ref: &str) -> String {
    let mut b = keccak256(format!("AWX_REQ_V1|{}|{}|{}", domain, scope, client_ref).as_bytes());
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // RFC 4122 variant
    format!(
        "{}-{}-{}-{}-{}",
        hex::encode(&b[0..4]),
        hex::encode(&b[4..6]),
        hex::encode(&b[6..8]),
        hex::encode(&b[8..10]),
        hex::encode(&b[10..16])
    )
}

/// Parse Airwallex ISO-8601 timestamps (`"2026-11-26T09:10:00+0000"` or RFC 3339 `"2026-11-26T09:10:00Z"`).
pub fn parse_airwallex_timestamp_secs(s: &str) -> Option<u64> {
    let trimmed = s.trim();
    DateTime::parse_from_rfc3339(trimmed)
        .or_else(|_| DateTime::parse_from_str(trimmed, "%Y-%m-%dT%H:%M:%S%z"))
        .or_else(|_| DateTime::parse_from_str(trimmed, "%Y-%m-%dT%H:%M:%S%.f%z"))
        .ok()
        .and_then(|dt| u64::try_from(dt.timestamp()).ok())
}

/// Extract structured `INV-<digits>` invoice reference from remittance narrative or metadata.
pub fn extract_structured_invoice_id(text: &str) -> Option<u64> {
    let upper = text.to_ascii_uppercase();
    let idx = upper.find("INV-")?;
    let digits: String = upper[idx + 4..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse::<u64>().ok()
    }
}

/// Parse optional hardware `VoucherOrderMetadata` from an Airwallex `metadata` JSON object.
pub fn parse_airwallex_voucher_metadata(meta: &Value) -> Result<Option<VoucherOrderMetadata>> {
    if !meta.is_object() {
        return Ok(None);
    }
    let Some(commit) = meta
        .get("voucher_commitment")
        .or_else(|| meta.get("voucherCommitment"))
        .and_then(|v| v.as_str())
    else {
        return Ok(None);
    };
    let sku = meta
        .get("sku")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("missing Airwallex metadata.sku"))?;
    let tier = meta
        .get("tier")
        .and_then(|v| v.as_str())
        .unwrap_or("standard");
    let explicit_usd = meta.get("price_usd_micros").and_then(|v| {
        v.as_str()
            .and_then(|s| s.parse().ok())
            .or_else(|| v.as_u64())
    });
    Ok(Some(VoucherOrderMetadata {
        sku_code: VoucherOrderMetadata::parse_sku_code(sku)?,
        tier_bps: VoucherOrderMetadata::parse_tier_bps(tier)?,
        voucher_commitment_hex: commit.to_string(),
        explicit_price_usd_micros: explicit_usd,
    }))
}
