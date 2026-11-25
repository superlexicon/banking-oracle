//! OCBC Merchant Card Payments API Adapter (`OcbcMerchantCardAdapter`).
//!
//! Explicitly segregated from `OcbcCorporateBankAdapter` (`ocbc_corporate`) because card-acquiring
//! authorization & capture (`MID` / `TID` switch) occurs non-synchronously from the actual net
//! cash deposit into the merchant's OCBC corporate CASA bank account (`T+1` / `T+2` merchant
//! settlement batch net of MDR / interchange fees and refunds).

use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::Mutex;

use crate::crypto::verify_timestamped_hmac_header;
use crate::domain::entities::MerchantProfile;
use crate::domain::events::{
    AcquirerPaymentEvent, AcquirerPaymentStage, AcquirerRefundEvent, AcquirerSettlementBatch,
    CanonicalAcquirerEvent, IngestionSource, SweepBatchLine, VoucherOrderMetadata,
};
use crate::domain::money::{CurrencyCode, Money};
use crate::ports::acquirer_adapter::{
    AcquirerBatchPollResult, AcquirerPollCursor, MerchantPaymentRequest, MerchantPaymentSession,
    PaymentAcquirerAdapter,
};
use crate::ports::http_transport::{HttpMethod, HttpTransport, OutboundHttpRequest};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcbcMerchantCardConfig {
    pub acquirer_id: String,
    pub base_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub webhook_secret: String,
    pub max_webhook_skew_secs: u64,
}

impl Default for OcbcMerchantCardConfig {
    fn default() -> Self {
        Self {
            acquirer_id: "ocbc_merchant_card".into(),
            base_url: "https://api.ocbc.com".into(),
            client_id: "ocbc_merchant_client_id".into(),
            client_secret: "ocbc_merchant_client_secret".into(),
            webhook_secret: "whsec_ocbc_merchant_card_dev".into(),
            max_webhook_skew_secs: 300,
        }
    }
}

#[derive(Default)]
struct CardOAuthCache {
    token: String,
    expires_at_unix: u64,
}

pub struct OcbcMerchantCardAdapter {
    cfg: OcbcMerchantCardConfig,
    transport: Arc<dyn HttpTransport>,
    oauth: Mutex<CardOAuthCache>,
}

impl OcbcMerchantCardAdapter {
    pub fn new(cfg: OcbcMerchantCardConfig, transport: Arc<dyn HttpTransport>) -> Self {
        Self {
            cfg,
            transport,
            oauth: Mutex::new(CardOAuthCache::default()),
        }
    }

    async fn bearer_token(&self, now_unix: u64) -> Result<String> {
        let mut guard = self.oauth.lock().await;
        if !guard.token.is_empty() && guard.expires_at_unix > now_unix + 30 {
            return Ok(guard.token.clone());
        }
        let url = format!(
            "{}/ocbcauthentication/api/oauth2/token",
            self.cfg.base_url.trim_end_matches('/')
        );
        let body = format!(
            "grant_type=client_credentials&client_id={}&client_secret={}&scope=merchant_card",
            self.cfg.client_id, self.cfg.client_secret
        );
        let resp = self
            .transport
            .execute(OutboundHttpRequest {
                method: HttpMethod::Post,
                url,
                headers: vec![(
                    "Content-Type".into(),
                    "application/x-www-form-urlencoded".into(),
                )],
                body: body.into_bytes(),
            })
            .await?;
        if !resp.is_success() {
            return Err(anyhow!(
                "OCBC Merchant Card OAuth2 failed with HTTP {}",
                resp.status
            ));
        }
        let val: serde_json::Value = resp.json()?;
        let tok = val["access_token"]
            .as_str()
            .ok_or_else(|| anyhow!("missing access_token in OCBC Merchant Card OAuth2"))?
            .to_string();
        let ttl = val["expires_in"].as_u64().unwrap_or(3600);
        guard.token = tok.clone();
        guard.expires_at_unix = now_unix + ttl;
        Ok(tok)
    }

    fn extract_voucher_meta(meta: &serde_json::Value) -> Result<Option<VoucherOrderMetadata>> {
        if !meta.is_object() {
            return Ok(None);
        }
        let Some(commit) = meta
            .get("voucherCommitment")
            .or_else(|| meta.get("voucher_commitment"))
            .and_then(|v| v.as_str())
        else {
            return Ok(None);
        };
        let sku_str = meta
            .get("sku")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("missing metadata.sku"))?;
        let tier_str = meta
            .get("tier")
            .and_then(|v| v.as_str())
            .unwrap_or("standard");
        let explicit_usd = meta
            .get("priceUsdMicros")
            .or_else(|| meta.get("price_usd_micros"))
            .and_then(|v| v.as_u64());
        Ok(Some(VoucherOrderMetadata {
            sku_code: VoucherOrderMetadata::parse_sku_code(sku_str)?,
            tier_bps: VoucherOrderMetadata::parse_tier_bps(tier_str)?,
            voucher_commitment_hex: commit.to_string(),
            explicit_price_usd_micros: explicit_usd,
        }))
    }

    fn parse_card_payment_obj(
        &self,
        data: &serde_json::Value,
        default_mid: Option<&str>,
        default_stl_ccy: Option<&CurrencyCode>,
        stage: AcquirerPaymentStage,
        source: IngestionSource,
        now_unix: u64,
    ) -> Result<AcquirerPaymentEvent> {
        let mid = data["merchantId"]
            .as_str()
            .or(default_mid)
            .ok_or_else(|| anyhow!("missing merchantId in OCBC card payload"))?
            .to_string();
        let ccy = CurrencyCode::new(data["currency"].as_str().unwrap_or("SGD"))?;
        let stl_ccy = if let Some(sc) = data["settlementCurrency"].as_str() {
            CurrencyCode::new(sc)?
        } else if let Some(dc) = default_stl_ccy {
            dc.clone()
        } else {
            ccy.clone()
        };

        let gross_minor = if let Some(m) = data["amountMinor"].as_i64() {
            m as i128
        } else {
            let s = data["amount"]
                .as_str()
                .ok_or_else(|| anyhow!("missing amount in OCBC card payload"))?;
            ccy.parse_decimal_to_minor(s)?
        };
        let fee_minor = if let Some(m) = data["mdrFeeMinor"].as_i64() {
            m as i128
        } else if let Some(s) = data["mdrFee"].as_str() {
            ccy.parse_decimal_to_minor(s)?
        } else {
            0
        };

        let meta = &data["metadata"];
        let invoice_id = meta["invoiceId"]
            .as_u64()
            .or_else(|| meta["invoice_id"].as_str().and_then(|s| s.parse().ok()));

        Ok(AcquirerPaymentEvent {
            acquirer_adapter_id: self.cfg.acquirer_id.clone(),
            external_merchant_id: mid,
            acquirer_payment_id: data["cardTxnId"]
                .as_str()
                .or_else(|| data["transactionId"].as_str())
                .ok_or_else(|| anyhow!("missing cardTxnId in OCBC card payload"))?
                .to_string(),
            order_reference: data["orderRef"]
                .as_str()
                .unwrap_or("ORDER-UNKNOWN")
                .to_string(),
            gross_amount: Money::new(gross_minor, ccy),
            fee_minor,
            settlement_currency: stl_ccy,
            expected_settlement_net_minor: data["expectedSettlementNetMinor"]
                .as_i64()
                .map(|n| n as i128),
            stage,
            occurred_at_unix: data["timestampUnix"].as_u64().unwrap_or(now_unix),
            structured_invoice_id: invoice_id,
            voucher_metadata: Self::extract_voucher_meta(meta)?,
            source,
        })
    }

    fn parse_settlement_batch_obj(
        &self,
        b: &serde_json::Value,
        default_mid: Option<&str>,
        source: IngestionSource,
        now_unix: u64,
    ) -> Result<AcquirerSettlementBatch> {
        let mid = b["merchantId"]
            .as_str()
            .or(default_mid)
            .ok_or_else(|| anyhow!("missing merchantId in OCBC settlement batch"))?
            .to_string();
        let stl_ccy = CurrencyCode::new(b["settlementCurrency"].as_str().unwrap_or("SGD"))?;

        let parse_amt = |key_minor: &str, key_dec: &str| -> Result<i128> {
            if let Some(m) = b[key_minor].as_i64() {
                Ok(m as i128)
            } else if let Some(s) = b[key_dec].as_str() {
                stl_ccy.parse_decimal_to_minor(s)
            } else {
                Ok(0)
            }
        };

        let gross_sales_minor = parse_amt("grossSalesMinor", "grossSalesAmount")?;
        let refunds_minor = parse_amt("refundsMinor", "refundsAmount")?;
        let total_fees_minor = parse_amt("mdrFeeTotalMinor", "mdrFeeTotalAmount")?;
        let net_payout_minor = parse_amt("netSettlementMinor", "netSettlementAmount")?;

        let mut lines = Vec::new();
        if let Some(arr) = b["transactions"].as_array() {
            for t in arr {
                let is_ref = t["type"]
                    .as_str()
                    .map(|s| s.eq_ignore_ascii_case("REFUND"))
                    .unwrap_or(false);
                let g = if let Some(m) = t["settlementGrossMinor"].as_i64() {
                    m as i128
                } else {
                    stl_ccy.parse_decimal_to_minor(t["settlementGross"].as_str().unwrap_or("0.00"))?
                };
                let f = if let Some(m) = t["mdrFeeMinor"].as_i64() {
                    m as i128
                } else {
                    stl_ccy.parse_decimal_to_minor(t["mdrFee"].as_str().unwrap_or("0.00"))?
                };
                lines.push(SweepBatchLine {
                    acquirer_payment_id: t["cardTxnId"]
                        .as_str()
                        .ok_or_else(|| anyhow!("missing cardTxnId in OCBC batch line"))?
                        .to_string(),
                    is_refund: is_ref,
                    settlement_gross_minor: g,
                    settlement_fee_minor: f,
                    settlement_net_minor: g - f,
                });
            }
        }

        let batch_id = b["batchId"]
            .as_str()
            .ok_or_else(|| anyhow!("missing batchId in OCBC settlement batch"))?
            .to_string();
        let bank_ref = b["bankSettlementRef"]
            .as_str()
            .unwrap_or(&batch_id)
            .to_string();

        Ok(AcquirerSettlementBatch {
            acquirer_adapter_id: self.cfg.acquirer_id.clone(),
            external_merchant_id: mid,
            batch_id,
            bank_statement_reference: bank_ref,
            settlement_currency: stl_ccy,
            gross_sales_minor,
            refunds_minor,
            total_fees_minor,
            net_payout_minor,
            settlement_date: b["settlementDate"]
                .as_str()
                .unwrap_or("2026-11-25")
                .to_string(),
            created_at_unix: now_unix,
            lines,
            source,
        })
    }
}

#[async_trait]
impl PaymentAcquirerAdapter for OcbcMerchantCardAdapter {
    fn acquirer_id(&self) -> &str {
        &self.cfg.acquirer_id
    }

    fn acquirer_name(&self) -> &str {
        "OCBC Merchant Card Payments API"
    }

    async fn create_payment_session(
        &self,
        merchant: &MerchantProfile,
        req: &MerchantPaymentRequest,
        now_unix_secs: u64,
    ) -> Result<MerchantPaymentSession> {
        let token = self.bearer_token(now_unix_secs).await?;
        let url = format!(
            "{}/merchant/cardpayments/1.0/sessions",
            self.cfg.base_url.trim_end_matches('/')
        );

        let mut meta = json!({});
        if let Some(inv) = req.structured_invoice_id {
            meta["invoiceId"] = json!(inv);
        }
        if let Some(vm) = &req.voucher_metadata {
            meta["sku"] = json!(vm.sku_code.to_string());
            meta["tier"] = json!(vm.tier_bps.to_string());
            meta["voucherCommitment"] = json!(vm.voucher_commitment_hex);
            if let Some(usd) = vm.explicit_price_usd_micros {
                meta["priceUsdMicros"] = json!(usd);
            }
        }

        let body = serde_json::to_vec(&json!({
            "merchantId": merchant.external_merchant_id,
            "orderRef": req.order_reference,
            "amountMinor": req.amount.amount_minor,
            "currency": req.amount.currency.as_str(),
            "captureMode": "AUTO_CAPTURE",
            "description": req.description,
            "returnUrl": req.success_url,
            "cancelUrl": req.cancel_url,
            "metadata": meta,
        }))?;

        let resp = self
            .transport
            .execute(OutboundHttpRequest {
                method: HttpMethod::Post,
                url,
                headers: vec![
                    ("Authorization".into(), format!("Bearer {}", token)),
                    ("X-OCBC-Client-Id".into(), self.cfg.client_id.clone()),
                    (
                        "X-OCBC-Merchant-Id".into(),
                        merchant.external_merchant_id.clone(),
                    ),
                    ("Content-Type".into(), "application/json".into()),
                ],
                body,
            })
            .await?;

        if !resp.is_success() {
            return Err(anyhow!(
                "OCBC Merchant Card session creation failed with HTTP {}",
                resp.status
            ));
        }

        let val: serde_json::Value = resp.json()?;
        Ok(MerchantPaymentSession {
            acquirer_id: self.cfg.acquirer_id.clone(),
            acquirer_payment_id: val["cardTxnId"]
                .as_str()
                .ok_or_else(|| anyhow!("missing cardTxnId in OCBC session response"))?
                .to_string(),
            checkout_url_or_token: val["paymentPageUrl"]
                .as_str()
                .unwrap_or("")
                .to_string(),
            created_at_unix: now_unix_secs,
        })
    }

    async fn verify_and_parse_webhook(
        &self,
        headers: &HeaderMap,
        raw_body: &[u8],
        now_unix_secs: u64,
    ) -> Result<Vec<CanonicalAcquirerEvent>> {
        let sig = headers
            .get("x-ocbc-merchant-signature")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| anyhow!("missing X-OCBC-Merchant-Signature header"))?;
        verify_timestamped_hmac_header(
            sig,
            raw_body,
            self.cfg.webhook_secret.as_bytes(),
            now_unix_secs,
            self.cfg.max_webhook_skew_secs,
        )?;

        let payload: serde_json::Value = serde_json::from_slice(raw_body)?;
        let ev_type = payload["eventType"]
            .as_str()
            .unwrap_or("")
            .to_ascii_uppercase();
        let data = payload.get("data").unwrap_or(&payload);

        match ev_type.as_str() {
            "CARD_AUTHORIZED" => Ok(vec![CanonicalAcquirerEvent::PaymentAuthorizedOrCaptured(
                self.parse_card_payment_obj(
                    data,
                    None,
                    None,
                    AcquirerPaymentStage::AuthorizedOnly,
                    IngestionSource::WebhookPush,
                    now_unix_secs,
                )?,
            )]),
            "CARD_CAPTURED" | "PAYMENT_CAPTURED" => {
                Ok(vec![CanonicalAcquirerEvent::PaymentAuthorizedOrCaptured(
                    self.parse_card_payment_obj(
                        data,
                        None,
                        None,
                        AcquirerPaymentStage::CapturedPendingSweep,
                        IngestionSource::WebhookPush,
                        now_unix_secs,
                    )?,
                )])
            }
            "CARD_REFUNDED" | "CARD_CHARGEBACK" => {
                let ccy = CurrencyCode::new(data["currency"].as_str().unwrap_or("SGD"))?;
                let minor = if let Some(m) = data["refundAmountMinor"].as_i64() {
                    m as i128
                } else {
                    ccy.parse_decimal_to_minor(data["refundAmount"].as_str().unwrap_or("0.00"))?
                };
                Ok(vec![CanonicalAcquirerEvent::PaymentRefundedOrDisputed(
                    AcquirerRefundEvent {
                        acquirer_adapter_id: self.cfg.acquirer_id.clone(),
                        external_merchant_id: data["merchantId"]
                            .as_str()
                            .ok_or_else(|| anyhow!("missing merchantId"))?
                            .to_string(),
                        acquirer_payment_id: data["cardTxnId"]
                            .as_str()
                            .ok_or_else(|| anyhow!("missing cardTxnId"))?
                            .to_string(),
                        refund_id: data["refundId"]
                            .as_str()
                            .unwrap_or("OCBC-REFUND")
                            .to_string(),
                        refund_amount: Money::new(minor, ccy),
                        is_chargeback: ev_type == "CARD_CHARGEBACK",
                        deducted_in_batch_id: data["batchId"].as_str().map(String::from),
                        occurred_at_unix: now_unix_secs,
                        source: IngestionSource::WebhookPush,
                    },
                )])
            }
            "MERCHANT_SETTLEMENT_BATCH" => {
                Ok(vec![CanonicalAcquirerEvent::SettlementSweepManifest(
                    self.parse_settlement_batch_obj(
                        data,
                        None,
                        IngestionSource::WebhookPush,
                        now_unix_secs,
                    )?,
                )])
            }
            other => Err(anyhow!(
                "unsupported OCBC Merchant Card webhook eventType '{}'",
                other
            )),
        }
    }

    async fn poll_payment_status(
        &self,
        merchant: &MerchantProfile,
        acquirer_payment_id: &str,
        now_unix_secs: u64,
    ) -> Result<CanonicalAcquirerEvent> {
        let token = self.bearer_token(now_unix_secs).await?;
        let url = format!(
            "{}/merchant/cardpayments/1.0/inquiry",
            self.cfg.base_url.trim_end_matches('/')
        );
        let body = serde_json::to_vec(&json!({
            "merchantId": merchant.external_merchant_id,
            "cardTxnId": acquirer_payment_id,
        }))?;
        let resp = self
            .transport
            .execute(OutboundHttpRequest {
                method: HttpMethod::Post,
                url,
                headers: vec![
                    ("Authorization".into(), format!("Bearer {}", token)),
                    ("X-OCBC-Client-Id".into(), self.cfg.client_id.clone()),
                    ("Content-Type".into(), "application/json".into()),
                ],
                body,
            })
            .await?;

        if !resp.is_success() {
            return Err(anyhow!(
                "OCBC Merchant Card inquiry failed with HTTP {}",
                resp.status
            ));
        }

        let val: serde_json::Value = resp.json()?;
        let data = val.get("Results").unwrap_or(&val);
        let status = data["status"]
            .as_str()
            .unwrap_or("AUTHORIZED")
            .to_ascii_uppercase();
        let stage = if status == "CAPTURED" || status == "SETTLED" {
            AcquirerPaymentStage::CapturedPendingSweep
        } else {
            AcquirerPaymentStage::AuthorizedOnly
        };

        Ok(CanonicalAcquirerEvent::PaymentAuthorizedOrCaptured(
            self.parse_card_payment_obj(
                data,
                Some(&merchant.external_merchant_id),
                Some(&merchant.settlement_currency),
                stage,
                IngestionSource::PeriodicPoll,
                now_unix_secs,
            )?,
        ))
    }

    async fn poll_settlement_batches(
        &self,
        merchant: &MerchantProfile,
        cursor: &AcquirerPollCursor,
        now_unix_secs: u64,
    ) -> Result<AcquirerBatchPollResult> {
        let token = self.bearer_token(now_unix_secs).await?;
        let url = format!(
            "{}/merchant/cardpayments/1.0/settlements",
            self.cfg.base_url.trim_end_matches('/')
        );
        let body = serde_json::to_vec(&json!({
            "merchantId": merchant.external_merchant_id,
            "sinceTimestamp": cursor.last_polled_unix,
            "cursorToken": cursor.cursor_token,
        }))?;
        let resp = self
            .transport
            .execute(OutboundHttpRequest {
                method: HttpMethod::Post,
                url,
                headers: vec![
                    ("Authorization".into(), format!("Bearer {}", token)),
                    ("X-OCBC-Client-Id".into(), self.cfg.client_id.clone()),
                    ("Content-Type".into(), "application/json".into()),
                ],
                body,
            })
            .await?;

        if !resp.is_success() {
            return Err(anyhow!(
                "OCBC Merchant Card settlements poll failed with HTTP {}",
                resp.status
            ));
        }

        let val: serde_json::Value = resp.json()?;
        let results = val.get("Results").unwrap_or(&val);
        let arr = results["batches"].as_array().cloned().unwrap_or_default();
        let mut batches = Vec::with_capacity(arr.len());
        for b in &arr {
            batches.push(self.parse_settlement_batch_obj(
                b,
                Some(&merchant.external_merchant_id),
                IngestionSource::PeriodicPoll,
                now_unix_secs,
            )?);
        }

        Ok(AcquirerBatchPollResult {
            settlement_batches: batches,
            next_cursor: AcquirerPollCursor {
                last_polled_unix: now_unix_secs,
                cursor_token: results["nextCursor"].as_str().map(String::from),
            },
        })
    }
}
