//! CONNECT2OCBC Corporate & Transactional Banking Technical Adapter (`OcbcCorporateBankAdapter`).
//!
//! Encapsulates OCBC's OAuth 2.0 token flow (`Authorization: Bearer <token>`), webhook authentication
//! (`X-OCBC-Signature` HMAC-SHA256 & `X-JWS-Signature` detached HS256 JWS), corporate transaction
//! history polling (`/transactional/transactionHistory/1.0`), and FAST / PayNow / GIRO / MEPS+ / TT
//! outbound payment initiation & status inquiries (`/transactional/paymentInquiry/1.0`).

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::Mutex;

use crate::crypto::{verify_jws_hs256, verify_timestamped_hmac_header};
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
    pub client_id: String,
    pub client_secret: String,
    pub webhook_secret: String,
    pub max_webhook_skew_secs: u64,
}

impl Default for OcbcCorporateConfig {
    fn default() -> Self {
        Self {
            adapter_id: "ocbc_corporate".into(),
            base_url: "https://api.ocbc.com".into(),
            client_id: "ocbc_sandbox_client_id".into(),
            client_secret: "ocbc_sandbox_client_secret".into(),
            webhook_secret: "whsec_ocbc_corporate_dev".into(),
            max_webhook_skew_secs: 300,
        }
    }
}

#[derive(Default)]
struct CachedOAuthToken {
    access_token: String,
    expires_at_unix: u64,
}

pub struct OcbcCorporateBankAdapter {
    cfg: OcbcCorporateConfig,
    transport: Arc<dyn HttpTransport>,
    token_cache: Mutex<CachedOAuthToken>,
}

impl OcbcCorporateBankAdapter {
    pub fn new(cfg: OcbcCorporateConfig, transport: Arc<dyn HttpTransport>) -> Self {
        Self {
            cfg,
            transport,
            token_cache: Mutex::new(CachedOAuthToken::default()),
        }
    }

    async fn bearer_token(&self, now_unix: u64) -> Result<String> {
        let mut guard = self.token_cache.lock().await;
        if !guard.access_token.is_empty() && guard.expires_at_unix > now_unix + 30 {
            return Ok(guard.access_token.clone());
        }

        let url = format!(
            "{}/ocbcauthentication/api/oauth2/token",
            self.cfg.base_url.trim_end_matches('/')
        );
        let body = format!(
            "grant_type=client_credentials&client_id={}&client_secret={}&scope=transactional",
            self.cfg.client_id, self.cfg.client_secret
        );
        let resp = self
            .transport
            .execute(OutboundHttpRequest {
                method: HttpMethod::Post,
                url,
                headers: vec![
                    (
                        "Content-Type".into(),
                        "application/x-www-form-urlencoded".into(),
                    ),
                    ("Accept".into(), "application/json".into()),
                ],
                body: body.into_bytes(),
            })
            .await?;

        if !resp.is_success() {
            return Err(anyhow!(
                "OCBC OAuth2 token request failed with HTTP {}",
                resp.status
            ));
        }
        let val: serde_json::Value = resp.json()?;
        let tok = val
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("missing access_token in OCBC OAuth2 response"))?
            .to_string();
        let ttl = val
            .get("expires_in")
            .and_then(|v| v.as_u64())
            .unwrap_or(3600);
        guard.access_token = tok.clone();
        guard.expires_at_unix = now_unix + ttl;
        Ok(tok)
    }

    fn parse_rail(raw: Option<&str>) -> TransferRail {
        match raw.unwrap_or("").trim().to_ascii_uppercase().as_str() {
            "FAST" => TransferRail::Fast,
            "PAYNOW" | "SGQR" => TransferRail::PayNow,
            "GIRO" | "IBG" => TransferRail::Giro,
            "MEPS" | "MEPS+" => TransferRail::MepsPlus,
            "TT" | "SWIFT" | "GPI" => TransferRail::SwiftGpi,
            "IFT" | "INTERNAL" => TransferRail::InternalBook,
            "SETTLEMENT" | "MERCHANT_SETTLEMENT" => TransferRail::AcquirerSettlementSweep,
            "" => TransferRail::Fast,
            other => TransferRail::Other(other.to_string()),
        }
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

    fn extract_invoice_id(remittance: &str, explicit: Option<u64>) -> Option<u64> {
        if explicit.is_some() {
            return explicit;
        }
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

    fn parse_voucher_meta(obj: &serde_json::Value) -> Result<Option<VoucherOrderMetadata>> {
        let Some(vm) = obj.get("voucherMetadata").or_else(|| obj.get("voucher_metadata")) else {
            return Ok(None);
        };
        if vm.is_null() {
            return Ok(None);
        }
        let sku_code = if let Some(n) = vm.get("skuCode").or_else(|| vm.get("sku_code")).and_then(|x| x.as_u64()) {
            n
        } else if let Some(s) = vm.get("sku").and_then(|x| x.as_str()) {
            VoucherOrderMetadata::parse_sku_code(s)?
        } else {
            return Err(anyhow!("missing sku in voucherMetadata"));
        };
        let tier_bps = if let Some(n) = vm.get("tierBps").or_else(|| vm.get("tier_bps")).and_then(|x| x.as_u64()) {
            n
        } else if let Some(s) = vm.get("tier").and_then(|x| x.as_str()) {
            VoucherOrderMetadata::parse_tier_bps(s)?
        } else {
            10_000
        };
        let commit = vm
            .get("voucherCommitment")
            .or_else(|| vm.get("voucher_commitment"))
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow!("missing voucherCommitment"))?
            .to_string();
        let explicit_usd = vm
            .get("priceUsdMicros")
            .or_else(|| vm.get("price_usd_micros"))
            .and_then(|x| x.as_u64());
        Ok(Some(VoucherOrderMetadata {
            sku_code,
            tier_bps,
            voucher_commitment_hex: commit,
            explicit_price_usd_micros: explicit_usd,
        }))
    }

    fn parse_credit_json(
        &self,
        item: &serde_json::Value,
        default_acct_no: Option<&str>,
        default_ccy: Option<&CurrencyCode>,
        source: IngestionSource,
        fallback_now: u64,
    ) -> Result<AppliedCreditEvent> {
        let acct_no = item
            .get("AccountNo")
            .or_else(|| item.get("accountNo"))
            .and_then(|v| v.as_str())
            .or(default_acct_no)
            .ok_or_else(|| anyhow!("missing AccountNo in OCBC credit entry"))?
            .to_string();

        let ccy = if let Some(c_str) = item
            .get("CurrencyCode")
            .or_else(|| item.get("currency"))
            .and_then(|v| v.as_str())
        {
            CurrencyCode::new(c_str)?
        } else if let Some(dc) = default_ccy {
            dc.clone()
        } else {
            CurrencyCode::sgd()
        };

        let amount = if let Some(minor) = item.get("amountMinor").and_then(|v| v.as_i64()) {
            Money::new(minor as i128, ccy)
        } else if let Some(dec_str) = item
            .get("CreditAmount")
            .or_else(|| item.get("Amount"))
            .and_then(|v| v.as_str())
        {
            Money::new(ccy.parse_decimal_to_minor(dec_str)?, ccy)
        } else if let Some(num) = item
            .get("CreditAmount")
            .or_else(|| item.get("Amount"))
            .and_then(|v| v.as_f64())
        {
            let formatted = format!("{:.*}", ccy.minor_decimals() as usize, num);
            Money::new(ccy.parse_decimal_to_minor(&formatted)?, ccy)
        } else {
            return Err(anyhow!("missing CreditAmount / Amount in OCBC credit entry"));
        };

        let tx_id = item
            .get("TransactionRef")
            .or_else(|| item.get("BankRef"))
            .or_else(|| item.get("transactionId"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("missing TransactionRef in OCBC credit entry"))?
            .to_string();

        let remittance = item
            .get("RemittanceInfo")
            .or_else(|| item.get("Narrative"))
            .or_else(|| item.get("PaymentDetails"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let explicit_inv = item.get("invoiceId").and_then(|v| v.as_u64());
        let voucher_metadata = Self::parse_voucher_meta(item)?;

        Ok(AppliedCreditEvent {
            bank_adapter_id: self.cfg.adapter_id.clone(),
            external_account_number: acct_no,
            bank_tx_id: tx_id,
            end_to_end_id: item
                .get("EndToEndId")
                .or_else(|| item.get("endToEndId"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            batch_or_sweep_ref: item
                .get("BatchReference")
                .or_else(|| item.get("SettlementRef"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            rail: Self::parse_rail(
                item.get("PaymentType")
                    .or_else(|| item.get("Channel"))
                    .and_then(|v| v.as_str()),
            ),
            amount,
            value_date: item
                .get("ValueDate")
                .and_then(|v| v.as_str())
                .unwrap_or("2026-11-25")
                .to_string(),
            booked_at_unix: item
                .get("BookedAtUnix")
                .and_then(|v| v.as_u64())
                .unwrap_or(fallback_now),
            structured_invoice_id: Self::extract_invoice_id(&remittance, explicit_inv),
            remittance_info: remittance,
            payer_name: item
                .get("SenderName")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            payer_account: item
                .get("SenderAccountNo")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            voucher_metadata,
            running_balance_minor: item
                .get("RunningBalanceMinor")
                .and_then(|v| v.as_i64())
                .map(|n| n as i128),
            source,
        })
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
            .unwrap_or("");

        match alert_type.to_ascii_uppercase().as_str() {
            "CREDIT_NOTIFICATION" | "INCOMING_FUNDS" => {
                let data = payload.get("data").unwrap_or(&payload);
                // Ignore unfinalized float notifications if status is explicitly pending
                if let Some(st) = data.get("Status").and_then(|v| v.as_str()) {
                    if !matches!(
                        st.to_ascii_uppercase().as_str(),
                        "BOOKED" | "POSTED" | "APPLIED" | "FINALIZED"
                    ) {
                        return Ok(vec![]);
                    }
                }
                let ev = self.parse_credit_json(
                    data,
                    None,
                    None,
                    IngestionSource::WebhookPush,
                    now_unix_secs,
                )?;
                Ok(vec![CanonicalBankEvent::AppliedCredit(ev)])
            }
            "PAYMENT_STATUS" | "OUTBOUND_STATUS" => {
                let data = payload.get("data").unwrap_or(&payload);
                let ccy = CurrencyCode::new(
                    data.get("CurrencyCode")
                        .and_then(|v| v.as_str())
                        .unwrap_or("SGD"),
                )?;
                let amt_minor = if let Some(m) = data.get("amountMinor").and_then(|v| v.as_i64()) {
                    m as i128
                } else {
                    let s = data
                        .get("Amount")
                        .and_then(|v| v.as_str())
                        .unwrap_or("0.00");
                    ccy.parse_decimal_to_minor(s)?
                };
                let fee_minor = if let Some(m) = data.get("feeMinor").and_then(|v| v.as_i64()) {
                    m as i128
                } else if let Some(s) = data.get("BankFee").and_then(|v| v.as_str()) {
                    ccy.parse_decimal_to_minor(s)?
                } else {
                    0
                };
                let state_str = data
                    .get("PaymentStatus")
                    .or_else(|| data.get("Status"))
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("missing PaymentStatus in OCBC outbound webhook"))?;
                let out = OutboundPaymentStatusEvent {
                    bank_adapter_id: self.cfg.adapter_id.clone(),
                    external_account_number: data
                        .get("AccountNo")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    client_instruction_id: data
                        .get("ClientRef")
                        .or_else(|| data.get("CustomerReference"))
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| anyhow!("missing ClientRef in OCBC outbound webhook"))?
                        .to_string(),
                    bank_payment_id: data
                        .get("BankPaymentId")
                        .or_else(|| data.get("TransactionRef"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    end_to_end_id: data
                        .get("EndToEndId")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    rail: Self::parse_rail(data.get("PaymentType").and_then(|v| v.as_str())),
                    state: Self::map_ocbc_outbound_state(state_str)?,
                    amount: Money::new(amt_minor, ccy),
                    bank_fee_minor: fee_minor,
                    reason_code: data
                        .get("ReasonCode")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    reason_detail: data
                        .get("ReasonDescription")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    updated_at_unix: now_unix_secs,
                    source: IngestionSource::WebhookPush,
                };
                Ok(vec![CanonicalBankEvent::OutboundStatusChanged(out)])
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
        let token = self.bearer_token(now_unix_secs).await?;
        let url = format!(
            "{}/transactional/transactionHistory/1.0",
            self.cfg.base_url.trim_end_matches('/')
        );
        let req_body = serde_json::to_vec(&json!({
            "AccountNo": account.external_account_number,
            "CurrencyCode": account.currency.as_str(),
            "SinceTimestamp": cursor.last_polled_unix,
            "CursorToken": cursor.cursor_token,
        }))?;
        let resp = self
            .transport
            .execute(OutboundHttpRequest {
                method: HttpMethod::Post,
                url,
                headers: vec![
                    ("Authorization".into(), format!("Bearer {}", token)),
                    ("client_id".into(), self.cfg.client_id.clone()),
                    ("Content-Type".into(), "application/json".into()),
                    ("Accept".into(), "application/json".into()),
                ],
                body: req_body,
            })
            .await?;

        if !resp.is_success() {
            return Err(anyhow!(
                "OCBC transactionHistory poll failed with HTTP {}",
                resp.status
            ));
        }

        let val: serde_json::Value = resp.json()?;
        let results = val.get("Results").unwrap_or(&val);
        let txs = results
            .get("Transactions")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let mut credits = Vec::new();
        for item in &txs {
            let drcr = item
                .get("DrCrIndicator")
                .and_then(|v| v.as_str())
                .unwrap_or("C")
                .to_ascii_uppercase();
            if drcr != "C" && drcr != "CRDT" && drcr != "CREDIT" {
                continue;
            }
            let status = item
                .get("Status")
                .and_then(|v| v.as_str())
                .unwrap_or("BOOKED")
                .to_ascii_uppercase();
            if !matches!(status.as_str(), "BOOKED" | "POSTED" | "APPLIED") {
                continue;
            }
            credits.push(self.parse_credit_json(
                item,
                Some(&account.external_account_number),
                Some(&account.currency),
                IngestionSource::PeriodicPoll,
                now_unix_secs,
            )?);
        }

        let next_tok = results
            .get("NextCursor")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| cursor.cursor_token.clone());

        Ok(IncomingPollBatch {
            applied_credits: credits,
            next_cursor: AccountPollCursor {
                last_polled_unix: now_unix_secs,
                cursor_token: next_tok,
            },
        })
    }

    async fn initiate_outbound_payment(
        &self,
        account: &BankAccount,
        instruction: &OutboundPaymentInstruction,
        now_unix_secs: u64,
    ) -> Result<OutboundSubmissionReceipt> {
        let token = self.bearer_token(now_unix_secs).await?;
        let endpoint_slug = match &instruction.rail {
            TransferRail::Fast => "fastpayment/1.0",
            TransferRail::PayNow => "paynow/1.0",
            TransferRail::MepsPlus => "meps/1.0",
            TransferRail::Giro => "giro/1.0",
            TransferRail::SwiftGpi => "tt/1.0",
            _ => "internaltransfer/1.0",
        };
        let url = format!(
            "{}/transactional/{}",
            self.cfg.base_url.trim_end_matches('/'),
            endpoint_slug
        );
        let decimals = instruction.amount.currency.minor_decimals() as usize;
        let factor = 10f64.powi(decimals as i32);
        let amt_str = format!(
            "{:.*}",
            decimals,
            (instruction.amount.amount_minor as f64) / factor
        );

        let body = serde_json::to_vec(&json!({
            "ClientRef": instruction.client_instruction_id,
            "DebitAccountNo": account.external_account_number,
            "CurrencyCode": instruction.amount.currency.as_str(),
            "Amount": amt_str,
            "BeneficiaryName": instruction.beneficiary_name,
            "BeneficiaryAccountNo": instruction.beneficiary_account,
            "BeneficiaryBankBic": instruction.beneficiary_bank_bic,
            "RemittanceInfo": instruction.remittance_info,
        }))?;

        let resp = self
            .transport
            .execute(OutboundHttpRequest {
                method: HttpMethod::Post,
                url,
                headers: vec![
                    ("Authorization".into(), format!("Bearer {}", token)),
                    ("client_id".into(), self.cfg.client_id.clone()),
                    ("Content-Type".into(), "application/json".into()),
                ],
                body,
            })
            .await?;

        if !resp.is_success() {
            return Err(anyhow!(
                "OCBC outbound payment submission failed with HTTP {}",
                resp.status
            ));
        }

        let val: serde_json::Value = resp.json()?;
        let res = val.get("Results").unwrap_or(&val);
        let state_str = res
            .get("PaymentStatus")
            .and_then(|v| v.as_str())
            .unwrap_or("ACCP");

        Ok(OutboundSubmissionReceipt {
            bank_payment_id: res
                .get("BankPaymentId")
                .or_else(|| res.get("TransactionRef"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            end_to_end_id: res
                .get("EndToEndId")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            initial_state: Self::map_ocbc_outbound_state(state_str)?,
        })
    }

    async fn poll_outbound_payment_status(
        &self,
        account: &BankAccount,
        tracker: &OutboundPaymentTracker,
        now_unix_secs: u64,
    ) -> Result<OutboundPaymentStatusEvent> {
        let now = if now_unix_secs == 0 {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        } else {
            now_unix_secs
        };
        let token = self.bearer_token(now).await?;
        let url = format!(
            "{}/transactional/paymentInquiry/1.0",
            self.cfg.base_url.trim_end_matches('/')
        );
        let body = serde_json::to_vec(&json!({
            "AccountNo": account.external_account_number,
            "ClientRef": tracker.client_instruction_id,
            "BankPaymentId": tracker.bank_payment_id,
        }))?;
        let resp = self
            .transport
            .execute(OutboundHttpRequest {
                method: HttpMethod::Post,
                url,
                headers: vec![
                    ("Authorization".into(), format!("Bearer {}", token)),
                    ("client_id".into(), self.cfg.client_id.clone()),
                    ("Content-Type".into(), "application/json".into()),
                ],
                body,
            })
            .await?;

        if !resp.is_success() {
            return Err(anyhow!(
                "OCBC paymentInquiry failed with HTTP {}",
                resp.status
            ));
        }

        let val: serde_json::Value = resp.json()?;
        let res = val.get("Results").unwrap_or(&val);
        let state_str = res
            .get("PaymentStatus")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("missing PaymentStatus in OCBC paymentInquiry response"))?;
        let fee_minor = if let Some(m) = res.get("feeMinor").and_then(|v| v.as_i64()) {
            m as i128
        } else if let Some(s) = res.get("BankFee").and_then(|v| v.as_str()) {
            tracker.amount.currency.parse_decimal_to_minor(s)?
        } else {
            0
        };

        Ok(OutboundPaymentStatusEvent {
            bank_adapter_id: self.cfg.adapter_id.clone(),
            external_account_number: account.external_account_number.clone(),
            client_instruction_id: tracker.client_instruction_id.clone(),
            bank_payment_id: res
                .get("BankPaymentId")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .or_else(|| tracker.bank_payment_id.clone()),
            end_to_end_id: res
                .get("EndToEndId")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .or_else(|| tracker.end_to_end_id.clone()),
            rail: tracker.rail.clone(),
            state: Self::map_ocbc_outbound_state(state_str)?,
            amount: tracker.amount.clone(),
            bank_fee_minor: fee_minor,
            reason_code: res
                .get("ReasonCode")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            reason_detail: res
                .get("ReasonDescription")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            updated_at_unix: now,
            source: IngestionSource::PeriodicPoll,
        })
    }
}
