//! Official CONNECT2OCBC Corporate Banking Technical Adapter (`OcbcCorporateBankAdapter`).
//!
//! Implements all documented OCBC Corporate Banking & PayNow specifications:
//! 1. **Corporate Transaction History**:
//!    - `GET https://api.ocbc.com/transactional/corpTransHistory/1.0?sessionToken=OAuth2INB%20<token>&accountId=<id>&fromDate=<dd-mm-yyyy>&toDate=<dd-mm-yyyy>`
//!    - Response: `{ success, results: [{ amount, debitCreditIndicator, transactionDate, currencyCode }], errorMessage, disclaimer }`
//! 2. **Perform MEPS Payment (Outbound Initiation)**:
//!    - `POST https://api.ocbc.com/transactional/corp/payment/meps/1.0`
//!    - Request: `{ ReferenceText, ValueDate, Payer: { AccountNo, Currency, SwiftCode }, Payee: { AccountNo, AccountName, BeneficiaryBankName, SwiftCode, Address: { Address } }, Amount: { Currency, Value } }`
//!    - Response: `{ ReferenceText, Success, Disclaimer, Results: { BankPaymentId } }`
//! 3. **Retrieve Status of a MEPS Payment (Outbound Inquiry)**:
//!    - `POST https://api.ocbc.com/corp/payment/meps/1.0`
//!    - Request: `{ ReferenceText, AccountNo, AccountCurrency, ValueDate }`
//!    - Response: `{ ReferenceText, Success, Disclaimer, Results: { BankPaymentId, PaymentStatus: "SUBMITTED|PROCESSING|COMPLETED|FAILED|REJECTED|UNKNOWN", UpdateDateTime, ActualValueDate, Amount: { Value, Currency } } }`
//! 4. **Corporate PayNow Collection via UEN**:
//!    - `POST https://api.ocbc.com/transactional/corporate/paynowcollection/1.0`
//!    - Request: `{ TransactionDescription, Amount (double), ProxyType, ProxyValue, FromAccountNo, PurposeCode, TransactionReferenceNo, DDAReferenceNo }`
//!    - Response: `{ Disclaimer, Success (string/bool), Result: { TransactionDescription, OCBCReferenceNo, TransactionReferenceNo } }`
//! 5. **Enquire Details of PayNow Transactions**:
//!    - `POST https://api.ocbc.com/ocbc/sg/corp/paynow/1.0`
//!    - Request: `{ PartnerID, FromDate, ToDate, AccountCurrency, AccountNo (double) }`
//!    - Response: `{ Transactions: [{ AccountCurrency, AccountNo (double), Amount (double), CreditDebitIndicator }] }`

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use axum::http::HeaderMap;
use chrono::{TimeZone, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;

use crate::adapters::ocbc_auth::{url_encode_component, OcbcRateLimiter, OcbcTokenVault};
use crate::crypto::{keccak256, verify_jws_hs256, verify_timestamped_hmac_header};
use crate::domain::entities::BankAccount;
use crate::domain::events::{
    AppliedCreditEvent, CanonicalBankEvent, IngestionSource, OutboundPaymentState,
    OutboundPaymentStatusEvent, TransferRail, VoucherOrderMetadata,
};
use crate::domain::ledger::OutboundPaymentTracker;
use crate::domain::money::{CurrencyCode, Money};
use crate::ports::bank_adapter::{
    AccountPollCursor, BankTechnicalAdapter, DirectCollectionInstruction, DirectCollectionReceipt,
    IncomingPollBatch, OutboundPaymentInstruction, OutboundSubmissionReceipt,
};
use crate::ports::http_transport::{HttpMethod, HttpTransport, OutboundHttpRequest};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcbcCorporateConfig {
    pub adapter_id: String,
    pub base_url: String,
    /// Application Consumer Key (`client_id`) from OCBC API Store -> Subscriptions.
    pub client_id: String,
    /// Registered OAuth 2.0 Redirect URL approved by OCBC's API Team.
    pub redirect_uri: String,
    /// Optional Sandbox / API Console static `access_token`.
    #[serde(default)]
    pub default_access_token: Option<String>,
    /// Optional `PartnerID` for `POST /ocbc/sg/corp/paynow/1.0` PayNow Transaction Enquiry.
    #[serde(default)]
    pub paynow_partner_id: Option<String>,
    pub webhook_secret: String,
    pub max_webhook_skew_secs: u64,
    /// OCBC Usage Guideline default = `10` API calls per minute per user.
    #[serde(default = "default_ocbc_rpm")]
    pub max_calls_per_minute: usize,
}

fn default_ocbc_rpm() -> usize {
    10
}

impl Default for OcbcCorporateConfig {
    fn default() -> Self {
        Self {
            adapter_id: "ocbc_corporate".into(),
            base_url: "https://api.ocbc.com".into(),
            client_id: "ocbc_consumer_key".into(),
            redirect_uri: "https://oracle.superlexicon.io/v1/oauth/ocbc/callback".into(),
            default_access_token: None,
            paynow_partner_id: None,
            webhook_secret: "whsec_ocbc_corporate_dev".into(),
            max_webhook_skew_secs: 300,
            max_calls_per_minute: 10,
        }
    }
}

fn deserialize_bool_or_string<'de, D>(deserializer: D) -> std::result::Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    let val = serde_json::Value::deserialize(deserializer)?;
    match val {
        serde_json::Value::Bool(b) => Ok(b),
        serde_json::Value::String(s) => Ok(matches!(
            s.trim().to_ascii_lowercase().as_str(),
            "true" | "success" | "ok" | "y" | "yes" | "1" | "00"
        )),
        serde_json::Value::Number(n) => Ok(n.as_i64() == Some(1)),
        serde_json::Value::Null => Ok(false),
        _ => Ok(false),
    }
}

/// Documented response for `GET /transactional/corpTransHistory/1.0`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[allow(non_snake_case)]
pub struct OcbcCorpTransHistoryResponse {
    #[serde(default, deserialize_with = "deserialize_bool_or_string")]
    pub success: bool,
    #[serde(default)]
    pub results: Vec<OcbcCorpTransHistoryEntry>,
    pub errorMessage: Option<String>,
    pub disclaimer: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[allow(non_snake_case)]
pub struct OcbcCorpTransHistoryEntry {
    pub amount: String,
    pub debitCreditIndicator: String,
    pub transactionDate: String,
    pub currencyCode: String,
    #[serde(default, alias = "transactionRef", alias = "referenceNo")]
    pub transactionId: Option<String>,
    #[serde(default, alias = "description", alias = "narrative", alias = "remittanceInfo")]
    pub transactionDescription: Option<String>,
    #[serde(default, alias = "settlementRef")]
    pub batchReference: Option<String>,
}

/// Documented response for `POST /transactional/corp/payment/meps/1.0` & `POST /corp/payment/meps/1.0`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[allow(non_snake_case)]
pub struct OcbcMepsEnvelope {
    pub ReferenceText: Option<String>,
    #[serde(default, deserialize_with = "deserialize_bool_or_string")]
    pub Success: bool,
    pub Disclaimer: Option<String>,
    pub Results: Option<OcbcMepsResults>,
    pub errorMessage: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[allow(non_snake_case)]
pub struct OcbcMepsResults {
    pub BankPaymentId: Option<String>,
    pub PaymentStatus: Option<String>,
    pub UpdateDateTime: Option<String>,
    pub ActualValueDate: Option<String>,
    pub Amount: Option<OcbcMepsAmountObj>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[allow(non_snake_case)]
pub struct OcbcMepsAmountObj {
    pub Currency: Option<String>,
    pub Value: Option<String>,
}

/// Documented response for `POST /transactional/corporate/paynowcollection/1.0`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[allow(non_snake_case)]
pub struct OcbcPayNowCollectionResponse {
    pub Disclaimer: Option<String>,
    #[serde(default, deserialize_with = "deserialize_bool_or_string")]
    pub Success: bool,
    pub Result: Option<OcbcPayNowCollectionResult>,
    pub errorMessage: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[allow(non_snake_case)]
pub struct OcbcPayNowCollectionResult {
    pub TransactionDescription: Option<String>,
    pub OCBCReferenceNo: Option<String>,
    pub TransactionReferenceNo: Option<String>,
}

/// Documented response for `POST /ocbc/sg/corp/paynow/1.0`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[allow(non_snake_case)]
pub struct OcbcPayNowEnquiryResponse {
    #[serde(default)]
    pub Transactions: Vec<OcbcPayNowEnquiryEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[allow(non_snake_case)]
pub struct OcbcPayNowEnquiryEntry {
    pub AccountCurrency: String,
    pub AccountNo: serde_json::Value,
    pub Amount: serde_json::Value,
    pub CreditDebitIndicator: String,
    #[serde(default)]
    pub OCBCReferenceNo: Option<String>,
    #[serde(default)]
    pub TransactionReferenceNo: Option<String>,
    #[serde(default)]
    pub TransactionDescription: Option<String>,
    #[serde(default)]
    pub TransactionDate: Option<String>,
}

pub struct OcbcCorporateBankAdapter {
    cfg: OcbcCorporateConfig,
    transport: Arc<dyn HttpTransport>,
    token_vault: Arc<OcbcTokenVault>,
    rate_limiter: Arc<OcbcRateLimiter>,
}

impl OcbcCorporateBankAdapter {
    pub fn new(
        cfg: OcbcCorporateConfig,
        transport: Arc<dyn HttpTransport>,
        token_vault: Arc<OcbcTokenVault>,
        rate_limiter: Arc<OcbcRateLimiter>,
    ) -> Self {
        Self {
            cfg,
            transport,
            token_vault,
            rate_limiter,
        }
    }

    pub fn format_dd_mm_yyyy(unix_secs: u64) -> String {
        Utc.timestamp_opt(unix_secs as i64, 0)
            .single()
            .map(|dt| dt.format("%d-%m-%Y").to_string())
            .unwrap_or_else(|| "01-01-2026".to_string())
    }

    /// Ensure `ReferenceText` for OCBC MEPS satisfies OCBC's documented rule:
    /// *"Reference Text format is alphanumeric."*
    pub fn sanitize_meps_alphanumeric_ref(raw: &str) -> String {
        let cleaned: String = raw.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
        if cleaned.is_empty() {
            "SLXMEPSREF".into()
        } else {
            cleaned
        }
    }

    /// Convert account number string (e.g. `"501-889900-001"`) to numeric JSON value (`501889900001.0` / integer)
    /// as documented by OCBC `POST /ocbc/sg/corp/paynow/1.0` (`AccountNo: double`).
    pub fn account_no_as_numeric_json(acct_no: &str) -> serde_json::Value {
        let digits: String = acct_no.chars().filter(|c| c.is_ascii_digit()).collect();
        if let Ok(n) = digits.parse::<u64>() {
            json!(n as f64)
        } else {
            json!(acct_no)
        }
    }

    pub fn is_credit_indicator(ind: &str) -> bool {
        matches!(
            ind.trim().to_ascii_uppercase().as_str(),
            "C" | "CR" | "CRDT" | "CREDIT"
        )
    }

    /// Maps OCBC MEPS `PaymentStatus` (`SUBMITTED`, `PROCESSING`, `UNKNOWN`, `COMPLETED`, `FAILED`, `REJECTED`)
    /// and standard ISO status codes into canonical `OutboundPaymentState`.
    pub fn map_ocbc_outbound_state(status: &str) -> Result<OutboundPaymentState> {
        match status.trim().to_ascii_uppercase().as_str() {
            "INITIATED" => Ok(OutboundPaymentState::Initiated),
            "SUBMITTED" | "RCVD" | "ACCP" | "ACCEPTED" | "RECEIVED" => {
                Ok(OutboundPaymentState::AcceptedByBank)
            }
            "PROCESSING" | "UNKNOWN" | "PDNG" | "ACSP" | "PROC" | "IN_PROCESSING" | "PENDING" => {
                Ok(OutboundPaymentState::InProcessing)
            }
            "COMPLETED" | "ACSC" | "ACCC" | "SETTLED" | "SUCCESS" => {
                Ok(OutboundPaymentState::Settled)
            }
            "REJECTED" | "RJCT" => Ok(OutboundPaymentState::Rejected),
            "FAILED" | "FAIL" => Ok(OutboundPaymentState::Failed),
            "RETURNED" | "RTRN" => Ok(OutboundPaymentState::Returned),
            other => Err(anyhow!("unrecognized OCBC PaymentStatus '{}'", other)),
        }
    }

    fn extract_invoice_id(remittance: &str) -> Option<u64> {
        let upper = remittance.to_ascii_uppercase();
        if let Some(idx) = upper.find("INV-") {
            let digits: String = upper[idx + 4..]
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if let Ok(id) = digits.parse::<u64>() {
                return Some(id);
            }
        }
        None
    }

    fn format_money_decimal(money: &Money) -> String {
        let decimals = money.currency.minor_decimals() as usize;
        let factor = 10f64.powi(decimals as i32);
        format!("{:.*}", decimals, (money.amount_minor as f64) / factor)
    }

    fn format_money_double(money: &Money) -> f64 {
        let decimals = money.currency.minor_decimals() as i32;
        (money.amount_minor as f64) / 10f64.powi(decimals)
    }

    fn parse_json_amount_to_minor(val: &serde_json::Value, ccy: &CurrencyCode) -> Result<i128> {
        if let Some(s) = val.as_str() {
            ccy.parse_decimal_to_minor(s)
        } else if let Some(f) = val.as_f64() {
            let formatted = format!("{:.*}", ccy.minor_decimals() as usize, f);
            ccy.parse_decimal_to_minor(&formatted)
        } else if let Some(i) = val.as_i64() {
            let factor = 10i128.pow(ccy.minor_decimals() as u32);
            Ok((i as i128) * factor)
        } else {
            Err(anyhow!("unsupported JSON monetary value '{}'", val))
        }
    }

    /// `GET /transactional/corpTransHistory/1.0?sessionToken=OAuth2INB%20<token>&accountId=<id>&fromDate=<dd-mm-yyyy>&toDate=<dd-mm-yyyy>`
    async fn fetch_corp_trans_history(
        &self,
        account: &BankAccount,
        from_unix: u64,
        to_unix: u64,
        now_unix: u64,
    ) -> Result<OcbcCorpTransHistoryResponse> {
        let tok = self
            .token_vault
            .resolve_token(Some(&account.account_id), now_unix)?;
        self.rate_limiter
            .acquire_slot(&tok.access_token, now_unix)
            .await?;

        let from_date = Self::format_dd_mm_yyyy(from_unix);
        let to_date = Self::format_dd_mm_yyyy(to_unix);

        let url = format!(
            "{}/transactional/corpTransHistory/1.0?sessionToken={}&accountId={}&fromDate={}&toDate={}",
            self.cfg.base_url.trim_end_matches('/'),
            tok.session_token_url_encoded(),
            url_encode_component(&account.external_account_number),
            url_encode_component(&from_date),
            url_encode_component(&to_date),
        );

        let resp = self
            .transport
            .execute(OutboundHttpRequest {
                method: HttpMethod::Get,
                url,
                headers: vec![
                    ("Authorization".into(), tok.authorization_bearer_header()),
                    ("Accept".into(), "application/json".into()),
                ],
                body: vec![],
            })
            .await?;

        if !resp.is_success() {
            return Err(anyhow!(
                "OCBC corpTransHistory/1.0 failed with HTTP {}: {}",
                resp.status,
                String::from_utf8_lossy(&resp.body)
            ));
        }

        let parsed: OcbcCorpTransHistoryResponse = resp.json()?;
        if !parsed.success {
            return Err(anyhow!(
                "OCBC corpTransHistory/1.0 returned success=false: {}",
                parsed
                    .errorMessage
                    .unwrap_or_else(|| "unspecified OCBC error".into())
            ));
        }
        Ok(parsed)
    }

    /// `POST /ocbc/sg/corp/paynow/1.0` — Enquire details of PayNow transactions.
    async fn fetch_paynow_enquiry(
        &self,
        account: &BankAccount,
        partner_id: &str,
        from_unix: u64,
        to_unix: u64,
        now_unix: u64,
    ) -> Result<OcbcPayNowEnquiryResponse> {
        let tok = self
            .token_vault
            .resolve_token(Some(&account.account_id), now_unix)?;
        self.rate_limiter
            .acquire_slot(&tok.access_token, now_unix)
            .await?;

        let url = format!(
            "{}/ocbc/sg/corp/paynow/1.0?sessionToken={}",
            self.cfg.base_url.trim_end_matches('/'),
            tok.session_token_url_encoded(),
        );
        let body = serde_json::to_vec(&json!({
            "PartnerID": partner_id,
            "FromDate": Self::format_dd_mm_yyyy(from_unix),
            "ToDate": Self::format_dd_mm_yyyy(to_unix),
            "AccountCurrency": account.currency.as_str(),
            "AccountNo": Self::account_no_as_numeric_json(&account.external_account_number),
        }))?;

        let resp = self
            .transport
            .execute(OutboundHttpRequest {
                method: HttpMethod::Post,
                url,
                headers: vec![
                    ("Authorization".into(), tok.authorization_bearer_header()),
                    ("Content-Type".into(), "application/json".into()),
                    ("Accept".into(), "application/json".into()),
                ],
                body,
            })
            .await?;

        if !resp.is_success() {
            return Err(anyhow!(
                "OCBC /ocbc/sg/corp/paynow/1.0 failed with HTTP {}: {}",
                resp.status,
                String::from_utf8_lossy(&resp.body)
            ));
        }
        let val: serde_json::Value = resp.json()?;
        let root = val.get("Results").unwrap_or(&val);
        serde_json::from_value(root.clone())
            .map_err(|e| anyhow!("invalid OCBC PayNow enquiry JSON: {}", e))
    }

    fn deterministic_entry_tx_id(
        prefix: &str,
        account_no: &str,
        tx_date: &str,
        drcr: &str,
        ccy: &str,
        amount_minor: i128,
        desc: &str,
        explicit_id: Option<&str>,
        occurrence_within_poll: usize,
    ) -> String {
        if let Some(eid) = explicit_id {
            if !eid.trim().is_empty() {
                return eid.trim().to_string();
            }
        }
        let fp = keccak256(
            format!(
                "OCBC_{}_V1|{}|{}|{}|{}|{}|{}|{}",
                prefix,
                account_no,
                tx_date.trim(),
                drcr.trim().to_ascii_uppercase(),
                ccy.trim().to_ascii_uppercase(),
                amount_minor,
                desc.trim(),
                occurrence_within_poll
            )
            .as_bytes(),
        );
        format!("OCBC-{}-{}", prefix, hex::encode(&fp[0..12]))
    }
}

#[async_trait]
impl BankTechnicalAdapter for OcbcCorporateBankAdapter {
    fn adapter_id(&self) -> &str {
        &self.cfg.adapter_id
    }

    fn bank_name(&self) -> &str {
        "OCBC Bank (CONNECT2OCBC Corporate — History, MEPS & PayNow)"
    }

    async fn verify_and_parse_webhook(
        &self,
        headers: &HeaderMap,
        raw_body: &[u8],
        now_unix_secs: u64,
    ) -> Result<Vec<CanonicalBankEvent>> {
        if let Some(jws) = headers.get("x-jws-signature").and_then(|v| v.to_str().ok()) {
            verify_jws_hs256(jws, Some(raw_body), self.cfg.webhook_secret.as_bytes())?;
        } else {
            let sig = headers
                .get("x-ocbc-signature")
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| anyhow!("missing X-OCBC-Signature or X-JWS-Signature header"))?;
            verify_timestamped_hmac_header(
                sig,
                raw_body,
                self.cfg.webhook_secret.as_bytes(),
                now_unix_secs,
                self.cfg.max_webhook_skew_secs,
            )?;
        }

        let payload: serde_json::Value = serde_json::from_slice(raw_body)?;
        let alert_type = payload
            .get("alertType")
            .or_else(|| payload.get("eventType"))
            .and_then(|v| v.as_str())
            .unwrap_or("CREDIT_NOTIFICATION");

        match alert_type.to_ascii_uppercase().as_str() {
            "CREDIT_NOTIFICATION" | "INCOMING_FUNDS" => {
                let data = payload.get("data").unwrap_or(&payload);
                if let Some(st) = data
                    .get("Status")
                    .or_else(|| data.get("status"))
                    .and_then(|v| v.as_str())
                {
                    if !matches!(
                        st.to_ascii_uppercase().as_str(),
                        "BOOKED" | "POSTED" | "APPLIED" | "FINALIZED"
                    ) {
                        return Ok(vec![]);
                    }
                }
                let acct_no = data
                    .get("accountId")
                    .or_else(|| data.get("AccountNo"))
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("missing accountId / AccountNo in OCBC credit alert"))?
                    .to_string();
                let ccy = CurrencyCode::new(
                    data.get("currencyCode")
                        .or_else(|| data.get("CurrencyCode"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("SGD"),
                )?;
                let amt_str = data
                    .get("amount")
                    .or_else(|| data.get("CreditAmount"))
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("missing amount / CreditAmount in OCBC credit alert"))?;
                let amount = Money::new(ccy.parse_decimal_to_minor(amt_str)?, ccy);
                let tx_id = data
                    .get("transactionId")
                    .or_else(|| data.get("TransactionRef"))
                    .or_else(|| data.get("OCBCReferenceNo"))
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("missing transactionId / TransactionRef"))?
                    .to_string();
                let remittance = data
                    .get("remittanceInfo")
                    .or_else(|| data.get("RemittanceInfo"))
                    .or_else(|| data.get("transactionDescription"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let voucher_meta = if let Some(vm) = data.get("voucherMetadata") {
                    let sku = vm["sku"]
                        .as_str()
                        .map(VoucherOrderMetadata::parse_sku_code)
                        .transpose()?
                        .or_else(|| vm["skuCode"].as_u64())
                        .unwrap_or(1);
                    let tier = vm["tier"]
                        .as_str()
                        .map(VoucherOrderMetadata::parse_tier_bps)
                        .transpose()?
                        .or_else(|| vm["tierBps"].as_u64())
                        .unwrap_or(10_000);
                    vm["voucherCommitment"]
                        .as_str()
                        .map(|c| VoucherOrderMetadata {
                            sku_code: sku,
                            tier_bps: tier,
                            voucher_commitment_hex: c.to_string(),
                            explicit_price_usd_micros: vm["priceUsdMicros"].as_u64(),
                        })
                } else {
                    None
                };

                Ok(vec![CanonicalBankEvent::AppliedCredit(AppliedCreditEvent {
                    bank_adapter_id: self.cfg.adapter_id.clone(),
                    external_account_number: acct_no,
                    bank_tx_id: tx_id,
                    end_to_end_id: data
                        .get("endToEndId")
                        .or_else(|| data.get("EndToEndId"))
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    batch_or_sweep_ref: data
                        .get("batchReference")
                        .or_else(|| data.get("BatchReference"))
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    rail: TransferRail::Fast,
                    amount,
                    value_date: data
                        .get("transactionDate")
                        .or_else(|| data.get("ValueDate"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("26-11-2026")
                        .to_string(),
                    booked_at_unix: now_unix_secs,
                    structured_invoice_id: Self::extract_invoice_id(&remittance),
                    remittance_info: remittance,
                    payer_name: data
                        .get("senderName")
                        .or_else(|| data.get("SenderName"))
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    payer_account: data
                        .get("senderAccountNo")
                        .or_else(|| data.get("SenderAccountNo"))
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    voucher_metadata: voucher_meta,
                    running_balance_minor: None,
                    source: IngestionSource::WebhookPush,
                })])
            }
            "PAYMENT_STATUS" | "OUTBOUND_STATUS" | "MEPS_STATUS" => {
                let data = payload.get("Results").or_else(|| payload.get("data")).unwrap_or(&payload);
                let ccy = CurrencyCode::new(
                    data["Amount"]["Currency"]
                        .as_str()
                        .or_else(|| data["currencyCode"].as_str())
                        .or_else(|| data["CurrencyCode"].as_str())
                        .unwrap_or("SGD"),
                )?;
                let amt_str = data["Amount"]["Value"]
                    .as_str()
                    .or_else(|| data["amount"].as_str())
                    .or_else(|| data["Amount"].as_str())
                    .unwrap_or("0.00");
                let fee_str = data
                    .get("bankFee")
                    .or_else(|| data.get("BankFee"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("0.00");
                let st_str = data
                    .get("PaymentStatus")
                    .or_else(|| data.get("paymentStatus"))
                    .or_else(|| data.get("Status"))
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("missing PaymentStatus in OCBC outbound webhook"))?;
                let client_ref = payload
                    .get("ReferenceText")
                    .or_else(|| data.get("ReferenceText"))
                    .or_else(|| data.get("clientRef"))
                    .or_else(|| data.get("ClientRef"))
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("missing ReferenceText / ClientRef"))?
                    .to_string();

                Ok(vec![CanonicalBankEvent::OutboundStatusChanged(
                    OutboundPaymentStatusEvent {
                        bank_adapter_id: self.cfg.adapter_id.clone(),
                        external_account_number: data
                            .get("AccountNo")
                            .or_else(|| data.get("accountId"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        client_instruction_id: client_ref,
                        bank_payment_id: data
                            .get("BankPaymentId")
                            .or_else(|| data.get("transactionId"))
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        end_to_end_id: None,
                        rail: TransferRail::MepsPlus,
                        state: Self::map_ocbc_outbound_state(st_str)?,
                        amount: Money::new(ccy.parse_decimal_to_minor(amt_str)?, ccy.clone()),
                        bank_fee_minor: ccy.parse_decimal_to_minor(fee_str)?,
                        reason_code: if st_str.eq_ignore_ascii_case("UNKNOWN") {
                            Some("UNKNOWN".into())
                        } else {
                            data.get("ReasonCode").and_then(|v| v.as_str()).map(String::from)
                        },
                        reason_detail: data
                            .get("ReasonDescription")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        updated_at_unix: now_unix_secs,
                        source: IngestionSource::WebhookPush,
                    },
                )])
            }
            other => Err(anyhow!("unsupported OCBC webhook alertType '{}'", other)),
        }
    }

    async fn poll_incoming_transactions(
        &self,
        account: &BankAccount,
        cursor: &AccountPollCursor,
        now_unix_secs: u64,
    ) -> Result<IncomingPollBatch> {
        let from_unix = if cursor.last_polled_unix > 86_400 {
            cursor.last_polled_unix - 86_400
        } else {
            now_unix_secs.saturating_sub(7 * 86_400)
        };

        let mut credits = Vec::new();

        // 1. Poll `GET /transactional/corpTransHistory/1.0`
        let history = self
            .fetch_corp_trans_history(account, from_unix, now_unix_secs, now_unix_secs)
            .await?;

        let mut hist_occ: HashMap<(String, String, i128, String), usize> = HashMap::new();
        for row in &history.results {
            if !Self::is_credit_indicator(&row.debitCreditIndicator) {
                continue;
            }
            let ccy = CurrencyCode::new(&row.currencyCode)?;
            if ccy != account.currency {
                continue;
            }
            let minor = ccy.parse_decimal_to_minor(&row.amount)?;
            if minor <= 0 {
                continue;
            }
            let desc = row.transactionDescription.clone().unwrap_or_default();
            let occ_key = (
                row.transactionDate.trim().to_string(),
                ccy.as_str().to_string(),
                minor,
                desc.trim().to_string(),
            );
            let occ_idx = *hist_occ.entry(occ_key).and_modify(|n| *n += 1).or_insert(0);

            let tx_id = Self::deterministic_entry_tx_id(
                "HIST",
                &account.external_account_number,
                &row.transactionDate,
                &row.debitCreditIndicator,
                &row.currencyCode,
                minor,
                &desc,
                row.transactionId.as_deref(),
                occ_idx,
            );

            credits.push(AppliedCreditEvent {
                bank_adapter_id: self.cfg.adapter_id.clone(),
                external_account_number: account.external_account_number.clone(),
                bank_tx_id: tx_id,
                end_to_end_id: None,
                batch_or_sweep_ref: row.batchReference.clone(),
                rail: TransferRail::Fast,
                amount: Money::new(minor, ccy),
                value_date: row.transactionDate.clone(),
                booked_at_unix: now_unix_secs,
                structured_invoice_id: Self::extract_invoice_id(&desc),
                remittance_info: desc,
                payer_name: None,
                payer_account: None,
                voucher_metadata: None,
                running_balance_minor: None,
                source: IngestionSource::PeriodicPoll,
            });
        }

        // 2. If `paynow_partner_id` is configured (and currency is SGD), also poll `POST /ocbc/sg/corp/paynow/1.0`!
        if let Some(partner_id) = &self.cfg.paynow_partner_id {
            if account.currency == CurrencyCode::sgd() && !partner_id.trim().is_empty() {
                let pn = self
                    .fetch_paynow_enquiry(
                        account,
                        partner_id,
                        from_unix,
                        now_unix_secs,
                        now_unix_secs,
                    )
                    .await?;
                let mut pn_occ: HashMap<(String, i128, String), usize> = HashMap::new();
                let today_ddmmyyyy = Self::format_dd_mm_yyyy(now_unix_secs);

                for entry in &pn.Transactions {
                    if !Self::is_credit_indicator(&entry.CreditDebitIndicator) {
                        continue;
                    }
                    let ccy = CurrencyCode::new(&entry.AccountCurrency)?;
                    if ccy != account.currency {
                        continue;
                    }
                    let minor = Self::parse_json_amount_to_minor(&entry.Amount, &ccy)?;
                    if minor <= 0 {
                        continue;
                    }
                    let tx_date = entry
                        .TransactionDate
                        .clone()
                        .unwrap_or_else(|| today_ddmmyyyy.clone());
                    let desc = entry
                        .TransactionDescription
                        .clone()
                        .or_else(|| entry.TransactionReferenceNo.clone())
                        .unwrap_or_default();
                    let occ_idx = *pn_occ
                        .entry((tx_date.clone(), minor, desc.clone()))
                        .and_modify(|n| *n += 1)
                        .or_insert(0);

                    let explicit_ref = entry
                        .OCBCReferenceNo
                        .as_deref()
                        .or(entry.TransactionReferenceNo.as_deref());
                    let tx_id = Self::deterministic_entry_tx_id(
                        "PAYNOW",
                        &account.external_account_number,
                        &tx_date,
                        &entry.CreditDebitIndicator,
                        &entry.AccountCurrency,
                        minor,
                        &desc,
                        explicit_ref,
                        occ_idx,
                    );

                    credits.push(AppliedCreditEvent {
                        bank_adapter_id: self.cfg.adapter_id.clone(),
                        external_account_number: account.external_account_number.clone(),
                        bank_tx_id: tx_id,
                        end_to_end_id: entry.TransactionReferenceNo.clone(),
                        batch_or_sweep_ref: None,
                        rail: TransferRail::PayNow,
                        amount: Money::new(minor, ccy),
                        value_date: tx_date,
                        booked_at_unix: now_unix_secs,
                        structured_invoice_id: Self::extract_invoice_id(&desc),
                        remittance_info: desc,
                        payer_name: None,
                        payer_account: None,
                        voucher_metadata: None,
                        running_balance_minor: None,
                        source: IngestionSource::PeriodicPoll,
                    });
                }
            }
        }

        Ok(IncomingPollBatch {
            applied_credits: credits,
            next_cursor: AccountPollCursor {
                last_polled_unix: now_unix_secs,
                cursor_token: None,
            },
        })
    }

    /// Calls `POST https://api.ocbc.com/transactional/corp/payment/meps/1.0` with exact documented
    /// `Payer`, `Payee` (`Address: { Address }`), `Amount` (`{ Currency, Value }`), `ReferenceText`, and `ValueDate`.
    async fn initiate_outbound_payment(
        &self,
        account: &BankAccount,
        instruction: &OutboundPaymentInstruction,
        now_unix_secs: u64,
    ) -> Result<OutboundSubmissionReceipt> {
        let tok = self
            .token_vault
            .resolve_token(Some(&account.account_id), now_unix_secs)?;
        self.rate_limiter
            .acquire_slot(&tok.access_token, now_unix_secs)
            .await?;

        let url = format!(
            "{}/transactional/corp/payment/meps/1.0?sessionToken={}",
            self.cfg.base_url.trim_end_matches('/'),
            tok.session_token_url_encoded(),
        );

        let ref_text = Self::sanitize_meps_alphanumeric_ref(&instruction.client_instruction_id);
        let value_date = instruction
            .value_date
            .clone()
            .unwrap_or_else(|| Self::format_dd_mm_yyyy(now_unix_secs));
        let amt_val = Self::format_money_decimal(&instruction.amount);

        let body = serde_json::to_vec(&json!({
            "ReferenceText": ref_text,
            "ValueDate": value_date,
            "Payer": {
                "AccountNo": account.external_account_number,
                "Currency": account.currency.as_str(),
                "SwiftCode": account.bank_bic,
            },
            "Payee": {
                "AccountNo": instruction.beneficiary_account,
                "AccountName": instruction.beneficiary_name,
                "BeneficiaryBankName": instruction.beneficiary_bank_name.clone().unwrap_or_else(|| "Beneficiary Bank".into()),
                "SwiftCode": instruction.beneficiary_bank_bic.clone().unwrap_or_default(),
                "Address": {
                    "Address": instruction.beneficiary_address.clone().unwrap_or_else(|| "Singapore".into()),
                }
            },
            "Amount": {
                "Currency": instruction.amount.currency.as_str(),
                "Value": amt_val,
            }
        }))?;

        let resp = self
            .transport
            .execute(OutboundHttpRequest {
                method: HttpMethod::Post,
                url,
                headers: vec![
                    ("Authorization".into(), tok.authorization_bearer_header()),
                    ("Content-Type".into(), "application/json".into()),
                    ("Accept".into(), "application/json".into()),
                ],
                body,
            })
            .await?;

        if !resp.is_success() {
            return Err(anyhow!(
                "OCBC Perform MEPS Payment (/transactional/corp/payment/meps/1.0) failed with HTTP {}: {}",
                resp.status,
                String::from_utf8_lossy(&resp.body)
            ));
        }

        let parsed: OcbcMepsEnvelope = resp.json()?;
        if !parsed.Success {
            return Err(anyhow!(
                "OCBC MEPS initiation returned Success=false: {}",
                parsed
                    .errorMessage
                    .unwrap_or_else(|| "unspecified OCBC MEPS error".into())
            ));
        }
        let bank_pay_id = parsed.Results.and_then(|r| r.BankPaymentId);

        Ok(OutboundSubmissionReceipt {
            bank_payment_id: bank_pay_id,
            end_to_end_id: Some(ref_text),
            value_date: Some(value_date),
            initial_state: OutboundPaymentState::AcceptedByBank,
        })
    }

    /// Calls `POST https://api.ocbc.com/corp/payment/meps/1.0` (`Retrieve status of a MEPS payment`)
    /// with `{ ReferenceText, AccountNo, AccountCurrency, ValueDate }`.
    async fn poll_outbound_payment_status(
        &self,
        account: &BankAccount,
        tracker: &OutboundPaymentTracker,
        now_unix_secs: u64,
    ) -> Result<OutboundPaymentStatusEvent> {
        let tok = self
            .token_vault
            .resolve_token(Some(&account.account_id), now_unix_secs)?;
        self.rate_limiter
            .acquire_slot(&tok.access_token, now_unix_secs)
            .await?;

        let url = format!(
            "{}/corp/payment/meps/1.0?sessionToken={}",
            self.cfg.base_url.trim_end_matches('/'),
            tok.session_token_url_encoded(),
        );

        let ref_text = Self::sanitize_meps_alphanumeric_ref(&tracker.client_instruction_id);
        let value_date = if tracker.value_date.is_empty() {
            Self::format_dd_mm_yyyy(tracker.created_at_unix)
        } else {
            tracker.value_date.clone()
        };

        let body = serde_json::to_vec(&json!({
            "ReferenceText": ref_text,
            "AccountNo": account.external_account_number,
            "AccountCurrency": account.currency.as_str(),
            "ValueDate": value_date,
        }))?;

        let resp = self
            .transport
            .execute(OutboundHttpRequest {
                method: HttpMethod::Post,
                url,
                headers: vec![
                    ("Authorization".into(), tok.authorization_bearer_header()),
                    ("Content-Type".into(), "application/json".into()),
                    ("Accept".into(), "application/json".into()),
                ],
                body,
            })
            .await?;

        if !resp.is_success() {
            return Err(anyhow!(
                "OCBC MEPS status inquiry (/corp/payment/meps/1.0) failed with HTTP {}: {}",
                resp.status,
                String::from_utf8_lossy(&resp.body)
            ));
        }

        let parsed: OcbcMepsEnvelope = resp.json()?;
        if !parsed.Success {
            return Err(anyhow!(
                "OCBC MEPS status inquiry returned Success=false: {}",
                parsed
                    .errorMessage
                    .unwrap_or_else(|| "unspecified OCBC MEPS inquiry error".into())
            ));
        }
        let results = parsed
            .Results
            .ok_or_else(|| anyhow!("missing Results object in OCBC MEPS status inquiry"))?;
        let st_str = results
            .PaymentStatus
            .as_deref()
            .ok_or_else(|| anyhow!("missing Results.PaymentStatus in OCBC MEPS status inquiry"))?;
        let mapped_state = Self::map_ocbc_outbound_state(st_str)?;

        Ok(OutboundPaymentStatusEvent {
            bank_adapter_id: self.cfg.adapter_id.clone(),
            external_account_number: account.external_account_number.clone(),
            client_instruction_id: tracker.client_instruction_id.clone(),
            bank_payment_id: results
                .BankPaymentId
                .or_else(|| tracker.bank_payment_id.clone()),
            end_to_end_id: Some(ref_text),
            rail: tracker.rail.clone(),
            state: mapped_state,
            amount: tracker.amount.clone(),
            bank_fee_minor: 0,
            reason_code: if st_str.eq_ignore_ascii_case("UNKNOWN") {
                Some("UNKNOWN".into())
            } else {
                None
            },
            reason_detail: results.UpdateDateTime,
            updated_at_unix: now_unix_secs,
            source: IngestionSource::PeriodicPoll,
        })
    }

    /// Calls `POST https://api.ocbc.com/transactional/corporate/paynowcollection/1.0`
    /// (`Initiate collection from any corporate registered in Singapore using Unique Entity Number (UEN)`).
    async fn initiate_direct_collection(
        &self,
        account: &BankAccount,
        instruction: &DirectCollectionInstruction,
        now_unix_secs: u64,
    ) -> Result<DirectCollectionReceipt> {
        let tok = self
            .token_vault
            .resolve_token(Some(&account.account_id), now_unix_secs)?;
        self.rate_limiter
            .acquire_slot(&tok.access_token, now_unix_secs)
            .await?;

        let url = format!(
            "{}/transactional/corporate/paynowcollection/1.0?sessionToken={}",
            self.cfg.base_url.trim_end_matches('/'),
            tok.session_token_url_encoded(),
        );

        let body = serde_json::to_vec(&json!({
            "TransactionDescription": instruction.description,
            "Amount": Self::format_money_double(&instruction.amount),
            "ProxyType": instruction.payer_proxy_type,
            "ProxyValue": instruction.payer_proxy_value,
            "FromAccountNo": account.external_account_number,
            "PurposeCode": instruction.purpose_code,
            "TransactionReferenceNo": instruction.transaction_reference_no,
            "DDAReferenceNo": instruction.dda_reference_no,
        }))?;

        let resp = self
            .transport
            .execute(OutboundHttpRequest {
                method: HttpMethod::Post,
                url,
                headers: vec![
                    ("Authorization".into(), tok.authorization_bearer_header()),
                    ("Content-Type".into(), "application/json".into()),
                    ("Accept".into(), "application/json".into()),
                ],
                body,
            })
            .await?;

        if !resp.is_success() {
            return Err(anyhow!(
                "OCBC Corporate PayNow Collection (/transactional/corporate/paynowcollection/1.0) failed with HTTP {}: {}",
                resp.status,
                String::from_utf8_lossy(&resp.body)
            ));
        }

        let parsed: OcbcPayNowCollectionResponse = resp.json()?;
        if !parsed.Success {
            return Err(anyhow!(
                "OCBC PayNow Collection returned Success=false: {}",
                parsed
                    .errorMessage
                    .unwrap_or_else(|| "unspecified PayNow collection error".into())
            ));
        }
        let res = parsed
            .Result
            .ok_or_else(|| anyhow!("missing Result object in OCBC PayNow Collection response"))?;

        Ok(DirectCollectionReceipt {
            transaction_reference_no: res
                .TransactionReferenceNo
                .unwrap_or_else(|| instruction.transaction_reference_no.clone()),
            bank_reference_no: res.OCBCReferenceNo.unwrap_or_default(),
            description: res
                .TransactionDescription
                .unwrap_or_else(|| instruction.description.clone()),
        })
    }
}
