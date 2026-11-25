//! Official CONNECT2OCBC Merchant Card Payments API Adapter (`OcbcMerchantCardAdapter`).
//!
//! Implements the exact documented OCBC Merchant Card Payments specification:
//! - **Base Endpoint**: `https://api.ocbc.com/transactional/merchantcardpayments/1.0`
//! - **Sub-Operations (`POST` JSON + `Authorization: Bearer <access_token>`)**:
//!   1. `/authorize` — Authorize card hold (`AcquirerPaymentStage::AuthorizedOnly`)
//!   2. `/sale`      — Authorize + Capture sale (`AcquirerPaymentStage::CapturedPendingSweep`)
//!   3. `/capture`   — Capture prior authorization by `transactionId`
//!   4. `/void`      — Void / reverse transaction by `transactionId` (`voidRevDate`)
//!   5. `/query`     — Poll transaction status by `transactionId` / `merchantTranId`
//! - **Exact Documented Response Representation**:
//!   `results` (`authDate`, `frScore`, `salesDate`, `transactionId`, `authId`, `responseCode`,
//!   `txnStatus`, `responseDesc`, `txnSignature2`, `customerId`, `tranDate`, `frLevel`,
//!   `captureDate`, `voidRevDate`, `merchantTranId`, `txnSignature`) + `disclaimer`.
//! - **Segregation from Corporate CASA**: Even when settling into an OCBC CASA account, `/sale` and
//!   `/capture` book into `1140 Acquirer Clearing Receivable` (`CapturedPendingBankSweep`) and only
//!   reach `BankCashFinalized` once reconciled against the net deposit on `corpTransHistory/1.0`.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::Mutex;

use crate::adapters::ocbc_auth::{OcbcRateLimiter, OcbcTokenVault};
use crate::crypto::{constant_time_eq, hmac_sha256, verify_timestamped_hmac_header};
use crate::domain::entities::MerchantProfile;
use crate::domain::events::{
    AcquirerPaymentEvent, AcquirerPaymentStage, AcquirerRefundEvent, AcquirerSettlementBatch,
    CanonicalAcquirerEvent, IngestionSource, SweepBatchLine, VoucherOrderMetadata,
};
use crate::domain::money::{CurrencyCode, Money};
use crate::ports::acquirer_adapter::{
    AcquirerBatchPollResult, AcquirerPollCursor, CardCaptureMode, MerchantPaymentRequest,
    MerchantPaymentSession, PaymentAcquirerAdapter,
};
use crate::ports::http_transport::{HttpMethod, HttpTransport, OutboundHttpRequest};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcbcMerchantCardConfig {
    pub acquirer_id: String,
    pub base_url: String,
    /// Optional secret key for computing/verifying `txnSignature` & `txnSignature2` and inbound callbacks.
    #[serde(default)]
    pub txn_signature_secret: String,
    /// Enforce constant-time `txnSignature2` verification on responses when `txn_signature_secret` is non-empty.
    #[serde(default)]
    pub enforce_response_signature: bool,
    pub max_webhook_skew_secs: u64,
    /// Merchant Discount Rate (MDR) in basis points (e.g. `200` = `2.00%`) used when grouping queried
    /// `SETTLED` card transactions into a merchant settlement batch.
    #[serde(default = "default_mdr_bps")]
    pub default_mdr_bps: u64,
}

fn default_mdr_bps() -> u64 {
    200
}

impl Default for OcbcMerchantCardConfig {
    fn default() -> Self {
        Self {
            acquirer_id: "ocbc_merchant_card".into(),
            base_url: "https://api.ocbc.com".into(),
            txn_signature_secret: "whsec_ocbc_merchant_card_dev".into(),
            enforce_response_signature: false,
            max_webhook_skew_secs: 300,
            default_mdr_bps: 200,
        }
    }
}

/// Exact JSON envelope returned by `POST /transactional/merchantcardpayments/1.0/{authorize,sale,capture,void,query}`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[allow(non_snake_case)]
pub struct OcbcMerchantCardEnvelope {
    pub results: Option<OcbcMerchantCardResults>,
    #[serde(flatten)]
    pub flat_results: OcbcMerchantCardResults,
    pub disclaimer: Option<String>,
}

impl OcbcMerchantCardEnvelope {
    pub fn body(&self) -> &OcbcMerchantCardResults {
        self.results.as_ref().unwrap_or(&self.flat_results)
    }
}

/// Exact documented `Resource Representations` for `https://api.ocbc.com/transactional/merchantcardpayments/1.0`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[allow(non_snake_case)]
pub struct OcbcMerchantCardResults {
    pub authDate: Option<String>,
    pub frScore: Option<String>,
    pub salesDate: Option<String>,
    pub transactionId: Option<String>,
    pub authId: Option<String>,
    pub responseCode: Option<String>,
    pub txnStatus: Option<String>,
    pub responseDesc: Option<String>,
    pub txnSignature2: Option<String>,
    pub customerId: Option<String>,
    pub tranDate: Option<String>,
    pub frLevel: Option<String>,
    pub captureDate: Option<String>,
    pub voidRevDate: Option<String>,
    pub merchantTranId: Option<String>,
    pub txnSignature: Option<String>,
    /// Present when echoed in query/callback or merchant context:
    #[serde(default)]
    pub amount: Option<String>,
    #[serde(default)]
    pub currencyCode: Option<String>,
    #[serde(default)]
    pub merchantId: Option<String>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

/// Cached local order context (`amount`, `currency`, `voucher_metadata`, `invoice_id`) keyed by
/// `transactionId` and `merchantTranId` because OCBC's `/query` response representation returns
/// `{ transactionId, merchantTranId, txnStatus, responseCode, authDate, salesDate, captureDate, voidRevDate, ... }`
/// without repeating custom order metadata!
#[derive(Debug, Clone)]
struct TrackedCardOrderContext {
    merchant_tran_id: String,
    amount: Money,
    structured_invoice_id: Option<u64>,
    voucher_metadata: Option<VoucherOrderMetadata>,
}

pub struct OcbcMerchantCardAdapter {
    cfg: OcbcMerchantCardConfig,
    transport: Arc<dyn HttpTransport>,
    token_vault: Arc<OcbcTokenVault>,
    rate_limiter: Arc<OcbcRateLimiter>,
    tracked_orders: Mutex<HashMap<String, TrackedCardOrderContext>>,
    queued_settlement_batches: Mutex<Vec<AcquirerSettlementBatch>>,
}

impl OcbcMerchantCardAdapter {
    pub fn new(
        cfg: OcbcMerchantCardConfig,
        transport: Arc<dyn HttpTransport>,
        token_vault: Arc<OcbcTokenVault>,
        rate_limiter: Arc<OcbcRateLimiter>,
    ) -> Self {
        Self {
            cfg,
            transport,
            token_vault,
            rate_limiter,
            tracked_orders: Mutex::new(HashMap::new()),
            queued_settlement_batches: Mutex::new(Vec::new()),
        }
    }

    /// Enqueue an EOD merchant settlement batch report (from OCBC merchant portal / SFTP CSV-JSON)
    /// to be picked up by the next `poll_settlement_batches` cycle.
    pub async fn enqueue_settlement_batch_manifest(&self, batch: AcquirerSettlementBatch) {
        self.queued_settlement_batches.lock().await.push(batch);
    }

    /// Compute outbound `txnSignature` = `hex(HMAC-SHA256(secret, "{merchantId}|{merchantTranId}|{amount_str}|{currency}"))`.
    pub fn compute_request_txn_signature(
        &self,
        merchant_id: &str,
        merchant_tran_id: &str,
        amount_str: &str,
        currency: &str,
    ) -> String {
        if self.cfg.txn_signature_secret.is_empty() {
            return String::new();
        }
        let msg = format!(
            "{}|{}|{}|{}",
            merchant_id, merchant_tran_id, amount_str, currency
        );
        hex::encode(hmac_sha256(
            self.cfg.txn_signature_secret.as_bytes(),
            msg.as_bytes(),
        ))
    }

    /// Compute expected `txnSignature2` = `hex(HMAC-SHA256(secret, "{transactionId}|{merchantTranId}|{responseCode}"))`.
    pub fn compute_response_txn_signature2(
        &self,
        transaction_id: &str,
        merchant_tran_id: &str,
        response_code: &str,
    ) -> String {
        let msg = format!("{}|{}|{}", transaction_id, merchant_tran_id, response_code);
        hex::encode(hmac_sha256(
            self.cfg.txn_signature_secret.as_bytes(),
            msg.as_bytes(),
        ))
    }

    fn verify_response_integrity(&self, res: &OcbcMerchantCardResults) -> Result<()> {
        let rc = res.responseCode.as_deref().unwrap_or("0");
        if rc != "0" && rc != "00" && !rc.eq_ignore_ascii_case("APPROVED") {
            return Err(anyhow!(
                "OCBC merchantcardpayments bank decline responseCode='{}': {}",
                rc,
                res.responseDesc
                    .as_deref()
                    .unwrap_or("unspecified bank responseDesc")
            ));
        }
        if self.cfg.enforce_response_signature && !self.cfg.txn_signature_secret.is_empty() {
            let sig2 = res
                .txnSignature2
                .as_deref()
                .ok_or_else(|| anyhow!("missing txnSignature2 in OCBC merchantcardpayments response"))?;
            let tx_id = res.transactionId.as_deref().unwrap_or("");
            let m_id = res.merchantTranId.as_deref().unwrap_or("");
            let expected = self.compute_response_txn_signature2(tx_id, m_id, rc);
            if !constant_time_eq(sig2.as_bytes(), expected.as_bytes()) {
                return Err(anyhow!("OCBC merchantcardpayments txnSignature2 verification failed"));
            }
        }
        Ok(())
    }

    async fn post_card_operation(
        &self,
        merchant: &MerchantProfile,
        sub_path: &str,
        payload: serde_json::Value,
        now_unix: u64,
    ) -> Result<OcbcMerchantCardEnvelope> {
        let tok = self
            .token_vault
            .resolve_token(Some(&merchant.merchant_profile_id), now_unix)?;
        self.rate_limiter
            .acquire_slot(&tok.access_token, now_unix)
            .await?;

        let url = format!(
            "{}/transactional/merchantcardpayments/1.0/{}?sessionToken={}",
            self.cfg.base_url.trim_end_matches('/'),
            sub_path.trim_start_matches('/'),
            tok.session_token_url_encoded()
        );
        let body = serde_json::to_vec(&payload)?;
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
                "OCBC merchantcardpayments/1.0/{} failed with HTTP {}: {}",
                sub_path,
                resp.status,
                String::from_utf8_lossy(&resp.body)
            ));
        }

        let env: OcbcMerchantCardEnvelope = resp.json()?;
        self.verify_response_integrity(env.body())?;
        Ok(env)
    }

    fn format_decimal(money: &Money) -> String {
        let decimals = money.currency.minor_decimals() as usize;
        let factor = 10f64.powi(decimals as i32);
        format!("{:.*}", decimals, (money.amount_minor as f64) / factor)
    }

    fn map_txn_status_to_stage(txn_status: Option<&str>, res: &OcbcMerchantCardResults) -> Option<AcquirerPaymentStage> {
        if res.voidRevDate.as_deref().is_some_and(|s| !s.is_empty()) {
            return None; // Voided/reversed!
        }
        match txn_status.unwrap_or("").trim().to_ascii_uppercase().as_str() {
            "A" | "AUTH" | "AUTHORIZED" => Some(AcquirerPaymentStage::AuthorizedOnly),
            "C" | "S" | "SALE" | "SALES" | "CAPTURED" | "SETTLED" => {
                Some(AcquirerPaymentStage::CapturedPendingSweep)
            }
            "" => {
                if res.salesDate.is_some() || res.captureDate.is_some() {
                    Some(AcquirerPaymentStage::CapturedPendingSweep)
                } else {
                    Some(AcquirerPaymentStage::AuthorizedOnly)
                }
            }
            "V" | "VOID" | "VOIDED" | "REVERSED" => None,
            _ => Some(AcquirerPaymentStage::CapturedPendingSweep),
        }
    }

    fn parse_voucher_from_json(meta: Option<&serde_json::Value>) -> Result<Option<VoucherOrderMetadata>> {
        let Some(m) = meta else {
            return Ok(None);
        };
        let Some(commit) = m
            .get("voucherCommitment")
            .or_else(|| m.get("voucher_commitment"))
            .and_then(|v| v.as_str())
        else {
            return Ok(None);
        };
        let sku = m
            .get("sku")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("missing metadata.sku"))?;
        let tier = m.get("tier").and_then(|v| v.as_str()).unwrap_or("standard");
        Ok(Some(VoucherOrderMetadata {
            sku_code: VoucherOrderMetadata::parse_sku_code(sku)?,
            tier_bps: VoucherOrderMetadata::parse_tier_bps(tier)?,
            voucher_commitment_hex: commit.to_string(),
            explicit_price_usd_micros: m
                .get("priceUsdMicros")
                .or_else(|| m.get("price_usd_micros"))
                .and_then(|v| v.as_u64()),
        }))
    }
}

#[async_trait]
impl PaymentAcquirerAdapter for OcbcMerchantCardAdapter {
    fn acquirer_id(&self) -> &str {
        &self.cfg.acquirer_id
    }

    fn acquirer_name(&self) -> &str {
        "OCBC Merchant Card Payments API (merchantcardpayments/1.0)"
    }

    /// Calls `POST /transactional/merchantcardpayments/1.0/authorize` or `/sale` depending on `req.capture_mode`.
    async fn create_payment_session(
        &self,
        merchant: &MerchantProfile,
        req: &MerchantPaymentRequest,
        now_unix_secs: u64,
    ) -> Result<MerchantPaymentSession> {
        let op = match req.capture_mode {
            CardCaptureMode::AuthorizeOnly => "authorize",
            CardCaptureMode::ImmediateSale => "sale",
        };
        let amt_str = Self::format_decimal(&req.amount);
        let txn_sig = self.compute_request_txn_signature(
            &merchant.external_merchant_id,
            &req.order_reference,
            &amt_str,
            req.amount.currency.as_str(),
        );

        let mut payload = json!({
            "merchantId": merchant.external_merchant_id,
            "merchantTranId": req.order_reference,
            "customerId": req.customer_id.clone().unwrap_or_else(|| "CUST-ANON".into()),
            "amount": amt_str,
            "currencyCode": req.amount.currency.as_str(),
            "description": req.description,
            "txnSignature": txn_sig,
        });
        if let Some(extra_obj) = req.acquirer_specific_payload.as_object() {
            for (k, v) in extra_obj {
                payload[k] = v.clone();
            }
        }

        let env = self
            .post_card_operation(merchant, op, payload, now_unix_secs)
            .await?;
        let r = env.body();
        let tx_id = r
            .transactionId
            .clone()
            .ok_or_else(|| anyhow!("missing transactionId in OCBC /{} response", op))?;

        let ctx = TrackedCardOrderContext {
            merchant_tran_id: req.order_reference.clone(),
            amount: req.amount.clone(),
            structured_invoice_id: req.structured_invoice_id,
            voucher_metadata: req.voucher_metadata.clone(),
        };
        {
            let mut map = self.tracked_orders.lock().await;
            map.insert(tx_id.clone(), ctx.clone());
            map.insert(req.order_reference.clone(), ctx);
        }

        let stage = match req.capture_mode {
            CardCaptureMode::AuthorizeOnly => AcquirerPaymentStage::AuthorizedOnly,
            CardCaptureMode::ImmediateSale => AcquirerPaymentStage::CapturedPendingSweep,
        };

        let immediate = CanonicalAcquirerEvent::PaymentAuthorizedOrCaptured(AcquirerPaymentEvent {
            acquirer_adapter_id: self.cfg.acquirer_id.clone(),
            external_merchant_id: merchant.external_merchant_id.clone(),
            acquirer_payment_id: tx_id.clone(),
            order_reference: r
                .merchantTranId
                .clone()
                .unwrap_or_else(|| req.order_reference.clone()),
            gross_amount: req.amount.clone(),
            fee_minor: 0,
            settlement_currency: merchant.settlement_currency.clone(),
            expected_settlement_net_minor: None,
            stage,
            occurred_at_unix: now_unix_secs,
            structured_invoice_id: req.structured_invoice_id,
            voucher_metadata: req.voucher_metadata.clone(),
            source: IngestionSource::ManualSync,
        });

        Ok(MerchantPaymentSession {
            acquirer_id: self.cfg.acquirer_id.clone(),
            acquirer_payment_id: tx_id,
            auth_id: r.authId.clone(),
            response_code: r.responseCode.clone(),
            txn_status: r.txnStatus.clone(),
            checkout_url_or_token: r.txnSignature2.clone().unwrap_or_default(),
            immediate_event: Some(immediate),
            created_at_unix: now_unix_secs,
        })
    }

    /// Calls `POST /transactional/merchantcardpayments/1.0/capture`.
    async fn capture_authorized_payment(
        &self,
        merchant: &MerchantProfile,
        acquirer_payment_id: &str,
        merchant_order_ref: &str,
        amount: &Money,
        now_unix_secs: u64,
    ) -> Result<CanonicalAcquirerEvent> {
        let amt_str = Self::format_decimal(amount);
        let txn_sig = self.compute_request_txn_signature(
            &merchant.external_merchant_id,
            merchant_order_ref,
            &amt_str,
            amount.currency.as_str(),
        );
        let env = self
            .post_card_operation(
                merchant,
                "capture",
                json!({
                    "merchantId": merchant.external_merchant_id,
                    "transactionId": acquirer_payment_id,
                    "merchantTranId": merchant_order_ref,
                    "amount": amt_str,
                    "currencyCode": amount.currency.as_str(),
                    "txnSignature": txn_sig,
                }),
                now_unix_secs,
            )
            .await?;
        let r = env.body();
        let tracked = self
            .tracked_orders
            .lock()
            .await
            .get(acquirer_payment_id)
            .cloned();

        Ok(CanonicalAcquirerEvent::PaymentAuthorizedOrCaptured(
            AcquirerPaymentEvent {
                acquirer_adapter_id: self.cfg.acquirer_id.clone(),
                external_merchant_id: merchant.external_merchant_id.clone(),
                acquirer_payment_id: r
                    .transactionId
                    .clone()
                    .unwrap_or_else(|| acquirer_payment_id.to_string()),
                order_reference: r
                    .merchantTranId
                    .clone()
                    .unwrap_or_else(|| merchant_order_ref.to_string()),
                gross_amount: amount.clone(),
                fee_minor: 0,
                settlement_currency: merchant.settlement_currency.clone(),
                expected_settlement_net_minor: None,
                stage: AcquirerPaymentStage::CapturedPendingSweep,
                occurred_at_unix: now_unix_secs,
                structured_invoice_id: tracked.as_ref().and_then(|t| t.structured_invoice_id),
                voucher_metadata: tracked.and_then(|t| t.voucher_metadata),
                source: IngestionSource::ManualSync,
            },
        ))
    }

    /// Calls `POST /transactional/merchantcardpayments/1.0/void`.
    async fn void_payment(
        &self,
        merchant: &MerchantProfile,
        acquirer_payment_id: &str,
        merchant_order_ref: &str,
        amount: &Money,
        now_unix_secs: u64,
    ) -> Result<CanonicalAcquirerEvent> {
        let amt_str = Self::format_decimal(amount);
        let txn_sig = self.compute_request_txn_signature(
            &merchant.external_merchant_id,
            merchant_order_ref,
            &amt_str,
            amount.currency.as_str(),
        );
        let env = self
            .post_card_operation(
                merchant,
                "void",
                json!({
                    "merchantId": merchant.external_merchant_id,
                    "transactionId": acquirer_payment_id,
                    "merchantTranId": merchant_order_ref,
                    "txnSignature": txn_sig,
                }),
                now_unix_secs,
            )
            .await?;
        let r = env.body();
        Ok(CanonicalAcquirerEvent::PaymentRefundedOrDisputed(
            AcquirerRefundEvent {
                acquirer_adapter_id: self.cfg.acquirer_id.clone(),
                external_merchant_id: merchant.external_merchant_id.clone(),
                acquirer_payment_id: r
                    .transactionId
                    .clone()
                    .unwrap_or_else(|| acquirer_payment_id.to_string()),
                refund_id: format!(
                    "VOID-{}-{}",
                    acquirer_payment_id,
                    r.voidRevDate.as_deref().unwrap_or("NOW")
                ),
                refund_amount: amount.clone(),
                is_chargeback: false,
                deducted_in_batch_id: None,
                occurred_at_unix: now_unix_secs,
                source: IngestionSource::ManualSync,
            },
        ))
    }

    async fn verify_and_parse_webhook(
        &self,
        headers: &HeaderMap,
        raw_body: &[u8],
        now_unix_secs: u64,
    ) -> Result<Vec<CanonicalAcquirerEvent>> {
        if let Some(sig) = headers
            .get("x-ocbc-merchant-signature")
            .and_then(|v| v.to_str().ok())
        {
            verify_timestamped_hmac_header(
                sig,
                raw_body,
                self.cfg.txn_signature_secret.as_bytes(),
                now_unix_secs,
                self.cfg.max_webhook_skew_secs,
            )?;
        } else {
            return Err(anyhow!("missing X-OCBC-Merchant-Signature header"));
        }

        let payload: serde_json::Value = serde_json::from_slice(raw_body)?;
        if payload["eventType"]
            .as_str()
            .is_some_and(|t| t.eq_ignore_ascii_case("MERCHANT_SETTLEMENT_BATCH"))
        {
            let b = payload.get("results").or_else(|| payload.get("data")).unwrap_or(&payload);
            let stl_ccy = CurrencyCode::new(b["settlementCurrency"].as_str().unwrap_or("SGD"))?;
            let mut lines = Vec::new();
            if let Some(arr) = b["transactions"].as_array() {
                for t in arr {
                    let g = t["settlementGrossMinor"].as_i64().unwrap_or(0) as i128;
                    let f = t["mdrFeeMinor"].as_i64().unwrap_or(0) as i128;
                    lines.push(SweepBatchLine {
                        acquirer_payment_id: t["transactionId"]
                            .as_str()
                            .or_else(|| t["cardTxnId"].as_str())
                            .ok_or_else(|| anyhow!("missing transactionId in settlement line"))?
                            .to_string(),
                        is_refund: t["type"].as_str() == Some("VOID") || g < 0,
                        settlement_gross_minor: g,
                        settlement_fee_minor: f,
                        settlement_net_minor: g - f,
                    });
                }
            }
            return Ok(vec![CanonicalAcquirerEvent::SettlementSweepManifest(
                AcquirerSettlementBatch {
                    acquirer_adapter_id: self.cfg.acquirer_id.clone(),
                    external_merchant_id: b["merchantId"]
                        .as_str()
                        .ok_or_else(|| anyhow!("missing merchantId"))?
                        .to_string(),
                    batch_id: b["batchId"].as_str().unwrap_or("OCBC-BATCH").to_string(),
                    bank_statement_reference: b["bankSettlementRef"]
                        .as_str()
                        .unwrap_or("OCBC-MERCH-STL")
                        .to_string(),
                    settlement_currency: stl_ccy,
                    gross_sales_minor: b["grossSalesMinor"].as_i64().unwrap_or(0) as i128,
                    refunds_minor: b["refundsMinor"].as_i64().unwrap_or(0) as i128,
                    total_fees_minor: b["mdrFeeTotalMinor"].as_i64().unwrap_or(0) as i128,
                    net_payout_minor: b["netSettlementMinor"].as_i64().unwrap_or(0) as i128,
                    settlement_date: b["settlementDate"]
                        .as_str()
                        .unwrap_or("25-11-2026")
                        .to_string(),
                    created_at_unix: now_unix_secs,
                    lines,
                    source: IngestionSource::WebhookPush,
                },
            )]);
        }

        // Parse standard OCBC `merchantcardpayments/1.0` `results` representation
        let env: OcbcMerchantCardEnvelope = serde_json::from_value(payload)?;
        let r = env.body();
        self.verify_response_integrity(r)?;

        let tx_id = r
            .transactionId
            .clone()
            .ok_or_else(|| anyhow!("missing results.transactionId in OCBC callback"))?;
        let mid = r
            .merchantId
            .clone()
            .ok_or_else(|| anyhow!("missing merchantId in OCBC callback"))?;
        let ccy = CurrencyCode::new(r.currencyCode.as_deref().unwrap_or("SGD"))?;
        let amt_minor = ccy.parse_decimal_to_minor(r.amount.as_deref().unwrap_or("0.00"))?;

        if let Some(stage) = Self::map_txn_status_to_stage(r.txnStatus.as_deref(), r) {
            Ok(vec![CanonicalAcquirerEvent::PaymentAuthorizedOrCaptured(
                AcquirerPaymentEvent {
                    acquirer_adapter_id: self.cfg.acquirer_id.clone(),
                    external_merchant_id: mid,
                    acquirer_payment_id: tx_id.clone(),
                    order_reference: r.merchantTranId.clone().unwrap_or(tx_id),
                    gross_amount: Money::new(amt_minor, ccy.clone()),
                    fee_minor: 0,
                    settlement_currency: ccy,
                    expected_settlement_net_minor: None,
                    stage,
                    occurred_at_unix: now_unix_secs,
                    structured_invoice_id: r
                        .metadata
                        .as_ref()
                        .and_then(|m| m["invoiceId"].as_u64()),
                    voucher_metadata: Self::parse_voucher_from_json(r.metadata.as_ref())?,
                    source: IngestionSource::WebhookPush,
                },
            )])
        } else {
            Ok(vec![CanonicalAcquirerEvent::PaymentRefundedOrDisputed(
                AcquirerRefundEvent {
                    acquirer_adapter_id: self.cfg.acquirer_id.clone(),
                    external_merchant_id: mid,
                    acquirer_payment_id: tx_id.clone(),
                    refund_id: format!(
                        "VOID-{}-{}",
                        tx_id,
                        r.voidRevDate.as_deref().unwrap_or("CALLBACK")
                    ),
                    refund_amount: Money::new(amt_minor, ccy),
                    is_chargeback: false,
                    deducted_in_batch_id: None,
                    occurred_at_unix: now_unix_secs,
                    source: IngestionSource::WebhookPush,
                },
            )])
        }
    }

    /// Calls `POST /transactional/merchantcardpayments/1.0/query` using `transactionId`.
    async fn poll_payment_status(
        &self,
        merchant: &MerchantProfile,
        acquirer_payment_id: &str,
        now_unix_secs: u64,
    ) -> Result<CanonicalAcquirerEvent> {
        let tracked = self
            .tracked_orders
            .lock()
            .await
            .get(acquirer_payment_id)
            .cloned();
        let merchant_tran_id = tracked
            .as_ref()
            .map(|t| t.merchant_tran_id.clone())
            .unwrap_or_else(|| acquirer_payment_id.to_string());

        let env = self
            .post_card_operation(
                merchant,
                "query",
                json!({
                    "merchantId": merchant.external_merchant_id,
                    "transactionId": acquirer_payment_id,
                    "merchantTranId": merchant_tran_id,
                }),
                now_unix_secs,
            )
            .await?;
        let r = env.body();

        let fallback_money = if let Some(t) = &tracked {
            t.amount.clone()
        } else {
            let ccy = CurrencyCode::new(
                r.currencyCode
                    .as_deref()
                    .unwrap_or(merchant.settlement_currency.as_str()),
            )?;
            let minor = ccy.parse_decimal_to_minor(r.amount.as_deref().unwrap_or("0.00"))?;
            Money::new(minor, ccy)
        };

        if let Some(stage) = Self::map_txn_status_to_stage(r.txnStatus.as_deref(), r) {
            Ok(CanonicalAcquirerEvent::PaymentAuthorizedOrCaptured(
                AcquirerPaymentEvent {
                    acquirer_adapter_id: self.cfg.acquirer_id.clone(),
                    external_merchant_id: merchant.external_merchant_id.clone(),
                    acquirer_payment_id: r
                        .transactionId
                        .clone()
                        .unwrap_or_else(|| acquirer_payment_id.to_string()),
                    order_reference: r.merchantTranId.clone().unwrap_or(merchant_tran_id),
                    gross_amount: fallback_money,
                    fee_minor: 0,
                    settlement_currency: merchant.settlement_currency.clone(),
                    expected_settlement_net_minor: None,
                    stage,
                    occurred_at_unix: now_unix_secs,
                    structured_invoice_id: tracked.as_ref().and_then(|t| t.structured_invoice_id),
                    voucher_metadata: tracked.and_then(|t| t.voucher_metadata),
                    source: IngestionSource::PeriodicPoll,
                },
            ))
        } else {
            Ok(CanonicalAcquirerEvent::PaymentRefundedOrDisputed(
                AcquirerRefundEvent {
                    acquirer_adapter_id: self.cfg.acquirer_id.clone(),
                    external_merchant_id: merchant.external_merchant_id.clone(),
                    acquirer_payment_id: acquirer_payment_id.to_string(),
                    refund_id: format!(
                        "VOID-{}-{}",
                        acquirer_payment_id,
                        r.voidRevDate.as_deref().unwrap_or("QUERY")
                    ),
                    refund_amount: fallback_money,
                    is_chargeback: false,
                    deducted_in_batch_id: None,
                    occurred_at_unix: now_unix_secs,
                    source: IngestionSource::PeriodicPoll,
                },
            ))
        }
    }

    async fn poll_settlement_batches(
        &self,
        merchant: &MerchantProfile,
        _cursor: &AcquirerPollCursor,
        now_unix_secs: u64,
    ) -> Result<AcquirerBatchPollResult> {
        let mut q = self.queued_settlement_batches.lock().await;
        let mut matched = Vec::new();
        let mut remaining = Vec::new();
        for b in q.drain(..) {
            if b.external_merchant_id == merchant.external_merchant_id {
                matched.push(b);
            } else {
                remaining.push(b);
            }
        }
        *q = remaining;
        Ok(AcquirerBatchPollResult {
            settlement_batches: matched,
            next_cursor: AcquirerPollCursor {
                last_polled_unix: now_unix_secs,
                cursor_token: None,
            },
        })
    }
}
