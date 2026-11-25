//! Official CONNECT2OCBC Corporate Transaction History & Banking Adapter (`OcbcCorporateBankAdapter`).
//!
//! Implements the exact documented OCBC Corporate Transaction History specification:
//! - **Endpoint**: `GET https://api.ocbc.com/transactional/corpTransHistory/1.0`
//! - **Headers**:
//!   - `Authorization: Bearer <access_token>`
//!   - `Accept: application/json`
//! - **Query Parameters**:
//!   - `sessionToken` (`string`): `OAuth2INB <access_token>` (retrieved via OCBC OAuth 2.0 `authorize` redirect)
//!   - `accountId` (`string`): Corporate Account ID
//!   - `fromDate` (`string`): Start date in **`dd-mm-yyyy`** format
//!   - `toDate` (`string`): End date in **`dd-mm-yyyy`** format
//! - **Response JSON (`Resource Representations`)**:
//!   - `success` (`boolean`)
//!   - `results` (`array` of `{ amount, debitCreditIndicator, transactionDate, currencyCode, ... }`)
//!   - `errorMessage` (`string`)
//!   - `disclaimer` (`string`)
//! - **Rate Limit**: Enforces OCBC's documented default limit of `10 API calls / minute` per user token.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use axum::http::HeaderMap;
use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::adapters::ocbc_auth::{
    url_encode_component, OcbcRateLimiter, OcbcTokenVault,
};
use crate::crypto::{keccak256, verify_jws_hs256, verify_timestamped_hmac_header};
use crate::domain::entities::BankAccount;
use crate::domain::events::{
    AppliedCreditEvent, CanonicalBankEvent, IngestionSource, OutboundPaymentState,
    OutboundPaymentStatusEvent, TransferRail, VoucherOrderMetadata,
};
use crate::domain::ledger::OutboundPaymentTracker;
use crate::domain::money::{CurrencyCode, Money};
use crate::ports::bank_adapter::{
    AccountPollCursor, BankTechnicalAdapter, IncomingPollBatch, OutboundPaymentInstruction,
    OutboundSubmissionReceipt,
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
    /// Optional Sandbox / API Console static `access_token` (used when interactive OAuth2 sessionToken has not yet been posted).
    #[serde(default)]
    pub default_access_token: Option<String>,
    pub webhook_secret: String,
    pub max_webhook_skew_secs: u64,
    /// OCBC Usage Guideline default = `10` API calls per minute per user.
    #[serde(default = "default_ocbc_rpm")]
    pub max_calls_per_minute: usize,
    /// Optional host-to-host outbound initiation endpoint path if enabled on your OCBC corporate tier.
    #[serde(default)]
    pub outbound_initiation_path: Option<String>,
    /// Optional dedicated outbound status inquiry endpoint path; when `None`, `poll_outbound_payment_status`
    /// reconciles finalized debits (`debitCreditIndicator == "D"`) directly from `corpTransHistory/1.0`!
    #[serde(default)]
    pub outbound_inquiry_path: Option<String>,
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
            webhook_secret: "whsec_ocbc_corporate_dev".into(),
            max_webhook_skew_secs: 300,
            max_calls_per_minute: 10,
            outbound_initiation_path: None,
            outbound_inquiry_path: None,
        }
    }
}

/// Exact response schema documented by OCBC for `GET /transactional/corpTransHistory/1.0`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[allow(non_snake_case)]
pub struct OcbcCorpTransHistoryResponse {
    #[serde(default)]
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
    /// Optional extended fields if provided by OCBC corporate host feed or API console profile:
    #[serde(default, alias = "transactionRef", alias = "referenceNo")]
    pub transactionId: Option<String>,
    #[serde(default, alias = "description", alias = "narrative", alias = "remittanceInfo")]
    pub transactionDescription: Option<String>,
    #[serde(default, alias = "settlementRef")]
    pub batchReference: Option<String>,
    #[serde(default)]
    pub clientRef: Option<String>,
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

    pub fn config(&self) -> &OcbcCorporateConfig {
        &self.cfg
    }

    pub fn format_dd_mm_yyyy(unix_secs: u64) -> String {
        Utc.timestamp_opt(unix_secs as i64, 0)
            .single()
            .map(|dt| dt.format("%d-%m-%Y").to_string())
            .unwrap_or_else(|| "01-01-2026".to_string())
    }

    pub fn is_credit_indicator(ind: &str) -> bool {
        matches!(
            ind.trim().to_ascii_uppercase().as_str(),
            "C" | "CR" | "CRDT" | "CREDIT"
        )
    }

    pub fn is_debit_indicator(ind: &str) -> bool {
        matches!(
            ind.trim().to_ascii_uppercase().as_str(),
            "D" | "DR" | "DBIT" | "DEBIT"
        )
    }

    pub fn map_ocbc_outbound_state(status: &str) -> Result<OutboundPaymentState> {
        match status.trim().to_ascii_uppercase().as_str() {
            "INITIATED" | "SUBMITTED" => Ok(OutboundPaymentState::Initiated),
            "RCVD" | "ACCP" | "ACCEPTED" | "RECEIVED" => Ok(OutboundPaymentState::AcceptedByBank),
            "PDNG" | "ACSP" | "PROC" | "IN_PROCESSING" | "PENDING" => {
                Ok(OutboundPaymentState::InProcessing)
            }
            "ACSC" | "ACCC" | "SETTLED" | "COMPLETED" | "SUCCESS" => {
                Ok(OutboundPaymentState::Settled)
            }
            "RJCT" | "REJECTED" => Ok(OutboundPaymentState::Rejected),
            "FAIL" | "FAILED" => Ok(OutboundPaymentState::Failed),
            "RTRN" | "RETURNED" => Ok(OutboundPaymentState::Returned),
            other => Err(anyhow!("unrecognized OCBC payment status '{}'", other)),
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

    /// Execute the exact documented `GET /transactional/corpTransHistory/1.0` call with
    /// `sessionToken=OAuth2INB <token>`, `accountId`, `fromDate` (`dd-mm-yyyy`), `toDate` (`dd-mm-yyyy`),
    /// and `Authorization: Bearer <access_token>`.
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

    /// Synthesize a deterministic, poll-idempotent `bank_tx_id` when OCBC's `corpTransHistory/1.0`
    /// row only provides `{ amount, debitCreditIndicator, transactionDate, currencyCode }` without
    /// a dedicated reference number:
    /// - Two identical `SGD 299.00` credits on `25-11-2026` receive `#occ0` and `#occ1` (neither is dropped!).
    /// - Re-polling `25-11-2026` produces the exact same `#occ0` and `#occ1` IDs (zero duplicates!).
    fn deterministic_entry_tx_id(
        account_no: &str,
        entry: &OcbcCorpTransHistoryEntry,
        amount_minor: i128,
        occurrence_within_poll: usize,
    ) -> String {
        if let Some(explicit_id) = &entry.transactionId {
            if !explicit_id.trim().is_empty() {
                return explicit_id.trim().to_string();
            }
        }
        let desc = entry.transactionDescription.as_deref().unwrap_or("");
        let fp = keccak256(
            format!(
                "OCBC_CORP_HIST_V1|{}|{}|{}|{}|{}|{}|{}",
                account_no,
                entry.transactionDate.trim(),
                entry.debitCreditIndicator.trim().to_ascii_uppercase(),
                entry.currencyCode.trim().to_ascii_uppercase(),
                amount_minor,
                desc.trim(),
                occurrence_within_poll
            )
            .as_bytes(),
        );
        format!("OCBC-HIST-{}", hex::encode(&fp[0..12]))
    }
}

#[async_trait]
impl BankTechnicalAdapter for OcbcCorporateBankAdapter {
    fn adapter_id(&self) -> &str {
        &self.cfg.adapter_id
    }

    fn bank_name(&self) -> &str {
        "OCBC Bank (CONNECT2OCBC Corporate)"
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
                if let Some(st) = data.get("Status").or_else(|| data.get("status")).and_then(|v| v.as_str()) {
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
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("missing transactionId / TransactionRef in OCBC credit alert"))?
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
                    vm["voucherCommitment"].as_str().map(|c| VoucherOrderMetadata {
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
                        .unwrap_or("25-11-2026")
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
            "PAYMENT_STATUS" | "OUTBOUND_STATUS" => {
                let data = payload.get("data").unwrap_or(&payload);
                let ccy = CurrencyCode::new(
                    data.get("currencyCode")
                        .or_else(|| data.get("CurrencyCode"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("SGD"),
                )?;
                let amt_str = data
                    .get("amount")
                    .or_else(|| data.get("Amount"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("0.00");
                let fee_str = data
                    .get("bankFee")
                    .or_else(|| data.get("BankFee"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("0.00");
                let st_str = data
                    .get("paymentStatus")
                    .or_else(|| data.get("PaymentStatus"))
                    .or_else(|| data.get("Status"))
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("missing PaymentStatus in OCBC outbound webhook"))?;

                Ok(vec![CanonicalBankEvent::OutboundStatusChanged(
                    OutboundPaymentStatusEvent {
                        bank_adapter_id: self.cfg.adapter_id.clone(),
                        external_account_number: data
                            .get("accountId")
                            .or_else(|| data.get("AccountNo"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        client_instruction_id: data
                            .get("clientRef")
                            .or_else(|| data.get("ClientRef"))
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| anyhow!("missing clientRef / ClientRef"))?
                            .to_string(),
                        bank_payment_id: data
                            .get("transactionId")
                            .or_else(|| data.get("BankPaymentId"))
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        end_to_end_id: data
                            .get("endToEndId")
                            .or_else(|| data.get("EndToEndId"))
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        rail: TransferRail::Fast,
                        state: Self::map_ocbc_outbound_state(st_str)?,
                        amount: Money::new(ccy.parse_decimal_to_minor(amt_str)?, ccy.clone()),
                        bank_fee_minor: ccy.parse_decimal_to_minor(fee_str)?,
                        reason_code: data
                            .get("ReasonCode")
                            .or_else(|| data.get("reasonCode"))
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        reason_detail: data
                            .get("ReasonDescription")
                            .or_else(|| data.get("errorMessage"))
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
        // Use a safe 24h overlap from `last_polled_unix` (or 7 days on initial sync) because `fromDate`/`toDate` are day-granular (`dd-mm-yyyy`)!
        let from_unix = if cursor.last_polled_unix > 86_400 {
            cursor.last_polled_unix - 86_400
        } else {
            now_unix_secs.saturating_sub(7 * 86_400)
        };

        let history = self
            .fetch_corp_trans_history(account, from_unix, now_unix_secs, now_unix_secs)
            .await?;

        let mut occurrence_counter: HashMap<(String, String, i128, String), usize> = HashMap::new();
        let mut credits = Vec::new();

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
            let desc = row
                .transactionDescription
                .clone()
                .unwrap_or_default();
            let occ_key = (
                row.transactionDate.trim().to_string(),
                ccy.as_str().to_string(),
                minor,
                desc.trim().to_string(),
            );
            let occ_idx = *occurrence_counter
                .entry(occ_key)
                .and_modify(|n| *n += 1)
                .or_insert(0);

            let tx_id = Self::deterministic_entry_tx_id(
                &account.external_account_number,
                row,
                minor,
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

        Ok(IncomingPollBatch {
            applied_credits: credits,
            next_cursor: AccountPollCursor {
                last_polled_unix: now_unix_secs,
                cursor_token: None,
            },
        })
    }

    async fn initiate_outbound_payment(
        &self,
        account: &BankAccount,
        instruction: &OutboundPaymentInstruction,
        now_unix_secs: u64,
    ) -> Result<OutboundSubmissionReceipt> {
        let Some(init_path) = &self.cfg.outbound_initiation_path else {
            return Err(anyhow!(
                "OCBC corporate outbound initiation path is not configured (set ocbc_corporate.outbound_initiation_path once corporate FAST/GIRO/MEPS initiation API subscription is enabled)"
            ));
        };
        let tok = self
            .token_vault
            .resolve_token(Some(&account.account_id), now_unix_secs)?;
        self.rate_limiter
            .acquire_slot(&tok.access_token, now_unix_secs)
            .await?;

        let url = format!(
            "{}/{}?sessionToken={}",
            self.cfg.base_url.trim_end_matches('/'),
            init_path.trim_start_matches('/'),
            tok.session_token_url_encoded(),
        );
        let decimals = instruction.amount.currency.minor_decimals() as usize;
        let factor = 10f64.powi(decimals as i32);
        let amt_str = format!(
            "{:.*}",
            decimals,
            (instruction.amount.amount_minor as f64) / factor
        );

        let body = serde_json::to_vec(&json!({
            "clientRef": instruction.client_instruction_id,
            "accountId": account.external_account_number,
            "currencyCode": instruction.amount.currency.as_str(),
            "amount": amt_str,
            "beneficiaryName": instruction.beneficiary_name,
            "beneficiaryAccountNo": instruction.beneficiary_account,
            "beneficiaryBankBic": instruction.beneficiary_bank_bic,
            "remittanceInfo": instruction.remittance_info,
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
                "OCBC outbound initiation failed with HTTP {}",
                resp.status
            ));
        }

        let val: serde_json::Value = resp.json()?;
        let res = val.get("results").or_else(|| val.get("Results")).unwrap_or(&val);
        let st_str = res
            .get("paymentStatus")
            .or_else(|| res.get("PaymentStatus"))
            .and_then(|v| v.as_str())
            .unwrap_or("ACCP");

        Ok(OutboundSubmissionReceipt {
            bank_payment_id: res
                .get("transactionId")
                .or_else(|| res.get("BankPaymentId"))
                .and_then(|v| v.as_str())
                .map(String::from),
            end_to_end_id: res.get("endToEndId").and_then(|v| v.as_str()).map(String::from),
            initial_state: Self::map_ocbc_outbound_state(st_str)?,
        })
    }

    async fn poll_outbound_payment_status(
        &self,
        account: &BankAccount,
        tracker: &OutboundPaymentTracker,
        now_unix_secs: u64,
    ) -> Result<OutboundPaymentStatusEvent> {
        if let Some(inq_path) = &self.cfg.outbound_inquiry_path {
            let tok = self
                .token_vault
                .resolve_token(Some(&account.account_id), now_unix_secs)?;
            self.rate_limiter
                .acquire_slot(&tok.access_token, now_unix_secs)
                .await?;
            let url = format!(
                "{}/{}?sessionToken={}",
                self.cfg.base_url.trim_end_matches('/'),
                inq_path.trim_start_matches('/'),
                tok.session_token_url_encoded()
            );
            let body = serde_json::to_vec(&json!({
                "accountId": account.external_account_number,
                "clientRef": tracker.client_instruction_id,
                "transactionId": tracker.bank_payment_id,
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
                return Err(anyhow!("OCBC outbound inquiry HTTP {}", resp.status));
            }
            let val: serde_json::Value = resp.json()?;
            let res = val.get("results").or_else(|| val.get("Results")).unwrap_or(&val);
            let st_str = res
                .get("paymentStatus")
                .or_else(|| res.get("PaymentStatus"))
                .and_then(|v| v.as_str())
                .unwrap_or("PDNG");
            return Ok(OutboundPaymentStatusEvent {
                bank_adapter_id: self.cfg.adapter_id.clone(),
                external_account_number: account.external_account_number.clone(),
                client_instruction_id: tracker.client_instruction_id.clone(),
                bank_payment_id: tracker.bank_payment_id.clone(),
                end_to_end_id: tracker.end_to_end_id.clone(),
                rail: tracker.rail.clone(),
                state: Self::map_ocbc_outbound_state(st_str)?,
                amount: tracker.amount.clone(),
                bank_fee_minor: 0,
                reason_code: None,
                reason_detail: None,
                updated_at_unix: now_unix_secs,
                source: IngestionSource::PeriodicPoll,
            });
        }

        // Fallback using the documented `GET /transactional/corpTransHistory/1.0` debit rows (`debitCreditIndicator == "D"`):
        let history = self
            .fetch_corp_trans_history(
                account,
                tracker.created_at_unix.saturating_sub(86_400),
                now_unix_secs,
                now_unix_secs,
            )
            .await?;

        let matched_debit = history.results.iter().find(|row| {
            if !Self::is_debit_indicator(&row.debitCreditIndicator) {
                return false;
            }
            let Ok(ccy) = CurrencyCode::new(&row.currencyCode) else {
                return false;
            };
            let Ok(minor) = ccy.parse_decimal_to_minor(&row.amount) else {
                return false;
            };
            if ccy != tracker.amount.currency || minor != tracker.amount.amount_minor {
                return false;
            }
            if let Some(cref) = &row.clientRef {
                return cref == &tracker.client_instruction_id;
            }
            if let Some(desc) = &row.transactionDescription {
                return desc.contains(&tracker.client_instruction_id)
                    || (!tracker.remittance_info.is_empty()
                        && desc.contains(&tracker.remittance_info));
            }
            true
        });

        let resolved_state = if matched_debit.is_some() {
            OutboundPaymentState::Settled
        } else {
            tracker.state
        };

        Ok(OutboundPaymentStatusEvent {
            bank_adapter_id: self.cfg.adapter_id.clone(),
            external_account_number: account.external_account_number.clone(),
            client_instruction_id: tracker.client_instruction_id.clone(),
            bank_payment_id: tracker.bank_payment_id.clone(),
            end_to_end_id: tracker.end_to_end_id.clone(),
            rail: tracker.rail.clone(),
            state: resolved_state,
            amount: tracker.amount.clone(),
            bank_fee_minor: 0,
            reason_code: None,
            reason_detail: None,
            updated_at_unix: now_unix_secs,
            source: IngestionSource::PeriodicPoll,
        })
    }
}
