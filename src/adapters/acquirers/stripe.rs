//! Stripe 3rd-Party Payment Acquirer Adapter (`StripeAcquirerAdapter`) with Periodical Sweep Bridging.
//!
//! Bridges the segregation between Stripe's payment processing (`payment_intent.succeeded` /
//! `checkout.session.completed`) and Stripe's periodical bank deposit sweeps (`payout.paid` +
//! `/v1/balance_transactions?payout=po_...`), so individual customer payments are ONLY treated as
//! cash-finalized once Stripe's batch sweep is matched against the actual `AppliedCreditEvent` on
//! the account owner's corporate bank account.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};

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
pub struct StripeAcquirerConfig {
    pub acquirer_id: String,
    pub base_url: String,
    pub secret_api_key: String,
    pub webhook_secret: String,
    pub default_account_id: String,
    pub max_webhook_skew_secs: u64,
}

impl Default for StripeAcquirerConfig {
    fn default() -> Self {
        Self {
            acquirer_id: "stripe".into(),
            base_url: "https://api.stripe.com".into(),
            secret_api_key: "sk_test_superlexicon".into(),
            webhook_secret: "whsec_stripe_dev".into(),
            default_account_id: "acct_default_stripe".into(),
            max_webhook_skew_secs: 300,
        }
    }
}

pub struct StripeAcquirerAdapter {
    cfg: StripeAcquirerConfig,
    transport: Arc<dyn HttpTransport>,
}

impl StripeAcquirerAdapter {
    pub fn new(cfg: StripeAcquirerConfig, transport: Arc<dyn HttpTransport>) -> Self {
        Self { cfg, transport }
    }

    fn stripe_headers(&self, stripe_account: Option<&str>) -> Vec<(String, String)> {
        let mut h = vec![
            (
                "Authorization".into(),
                format!("Bearer {}", self.cfg.secret_api_key),
            ),
            ("Accept".into(), "application/json".into()),
        ];
        if let Some(acct) = stripe_account {
            if !acct.is_empty() && acct != self.cfg.default_account_id {
                h.push(("Stripe-Account".into(), acct.to_string()));
            }
        }
        h
    }

    fn parse_stripe_voucher_meta(meta: &serde_json::Value) -> Result<Option<VoucherOrderMetadata>> {
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
            .ok_or_else(|| anyhow!("missing Stripe metadata.sku"))?;
        let tier = meta
            .get("tier")
            .and_then(|v| v.as_str())
            .unwrap_or("standard");
        let explicit_usd = meta
            .get("price_usd_micros")
            .and_then(|v| v.as_str().and_then(|s| s.parse().ok()).or_else(|| v.as_u64()));
        Ok(Some(VoucherOrderMetadata {
            sku_code: VoucherOrderMetadata::parse_sku_code(sku)?,
            tier_bps: VoucherOrderMetadata::parse_tier_bps(tier)?,
            voucher_commitment_hex: commit.to_string(),
            explicit_price_usd_micros: explicit_usd,
        }))
    }

    async fn fetch_payout_balance_transactions(
        &self,
        stripe_account: &str,
        payout_id: &str,
    ) -> Result<Vec<serde_json::Value>> {
        let url = format!(
            "{}/v1/balance_transactions?payout={}&limit=100",
            self.cfg.base_url.trim_end_matches('/'),
            payout_id
        );
        let resp = self
            .transport
            .execute(OutboundHttpRequest {
                method: HttpMethod::Get,
                url,
                headers: self.stripe_headers(Some(stripe_account)),
                body: vec![],
            })
            .await?;

        if !resp.is_success() {
            return Err(anyhow!(
                "Stripe balance_transactions fetch for payout '{}' failed with HTTP {}",
                payout_id,
                resp.status
            ));
        }
        let val: serde_json::Value = resp.json()?;
        Ok(val["data"].as_array().cloned().unwrap_or_default())
    }

    async fn build_sweep_manifest_from_payout(
        &self,
        stripe_account: &str,
        payout_obj: &serde_json::Value,
        source: IngestionSource,
        now_unix: u64,
    ) -> Result<AcquirerSettlementBatch> {
        let payout_id = payout_obj["id"]
            .as_str()
            .ok_or_else(|| anyhow!("missing id in Stripe payout object"))?
            .to_string();
        let stl_ccy = CurrencyCode::new(payout_obj["currency"].as_str().unwrap_or("SGD"))?;
        let net_payout_minor = payout_obj["amount"]
            .as_i64()
            .ok_or_else(|| anyhow!("missing amount in Stripe payout '{}'", payout_id))?
            as i128;

        // Use inline `balance_transactions` array if provided in webhook test/expansion, else query `/v1/balance_transactions?payout=po_...`
        let bal_txs = if let Some(arr) = payout_obj["balance_transactions"].as_array() {
            arr.clone()
        } else {
            self.fetch_payout_balance_transactions(stripe_account, &payout_id)
                .await?
        };

        let mut gross_sales_minor: i128 = 0;
        let mut refunds_minor: i128 = 0;
        let mut total_fees_minor: i128 = 0;
        let mut lines: Vec<SweepBatchLine> = Vec::new();

        for btx in &bal_txs {
            let btx_type = btx["type"].as_str().unwrap_or("");
            if btx_type == "payout" {
                // Skip the offsetting payout transfer row itself in Stripe's balance_transactions list
                continue;
            }
            let amount = btx["amount"].as_i64().unwrap_or(0) as i128;
            let fee = btx["fee"].as_i64().unwrap_or(0) as i128;
            let source_id = btx["payment_intent"]
                .as_str()
                .or_else(|| btx["source"].as_str())
                .unwrap_or("unknown")
                .to_string();

            if btx_type == "refund" || btx_type == "adjustment" || amount < 0 {
                refunds_minor += amount.abs();
                total_fees_minor += fee;
                lines.push(SweepBatchLine {
                    acquirer_payment_id: source_id,
                    is_refund: true,
                    settlement_gross_minor: amount, // negative
                    settlement_fee_minor: fee,
                    settlement_net_minor: amount - fee,
                });
            } else {
                gross_sales_minor += amount;
                total_fees_minor += fee;
                lines.push(SweepBatchLine {
                    acquirer_payment_id: source_id,
                    is_refund: false,
                    settlement_gross_minor: amount,
                    settlement_fee_minor: fee,
                    settlement_net_minor: amount - fee,
                });
            }
        }

        let bank_trace = payout_obj["statement_descriptor"]
            .as_str()
            .or_else(|| payout_obj["trace_id"]["value"].as_str())
            .unwrap_or(&payout_id)
            .to_string();

        Ok(AcquirerSettlementBatch {
            acquirer_adapter_id: self.cfg.acquirer_id.clone(),
            external_merchant_id: stripe_account.to_string(),
            batch_id: payout_id,
            bank_statement_reference: bank_trace,
            settlement_currency: stl_ccy,
            gross_sales_minor,
            refunds_minor,
            total_fees_minor,
            net_payout_minor,
            settlement_date: payout_obj["arrival_date"]
                .as_u64()
                .map(|ts| ts.to_string())
                .unwrap_or_else(|| "2026-11-25".into()),
            created_at_unix: now_unix,
            lines,
            source,
        })
    }
}

#[async_trait]
impl PaymentAcquirerAdapter for StripeAcquirerAdapter {
    fn acquirer_id(&self) -> &str {
        &self.cfg.acquirer_id
    }

    fn acquirer_name(&self) -> &str {
        "Stripe Payments & Periodical Payout Sweeps"
    }

    async fn create_payment_session(
        &self,
        merchant: &MerchantProfile,
        req: &MerchantPaymentRequest,
        now_unix_secs: u64,
    ) -> Result<MerchantPaymentSession> {
        let url = format!(
            "{}/v1/checkout/sessions",
            self.cfg.base_url.trim_end_matches('/')
        );
        let mut form_pairs = vec![
            ("mode".to_string(), "payment".to_string()),
            ("client_reference_id".into(), req.order_reference.clone()),
            (
                "line_items[0][price_data][currency]".into(),
                req.amount.currency.as_str().to_ascii_lowercase(),
            ),
            (
                "line_items[0][price_data][unit_amount]".into(),
                req.amount.amount_minor.to_string(),
            ),
            (
                "line_items[0][price_data][product_data][name]".into(),
                req.description.clone(),
            ),
            ("line_items[0][quantity]".into(), "1".into()),
            ("metadata[order_ref]".into(), req.order_reference.clone()),
            (
                "payment_intent_data[metadata][order_ref]".into(),
                req.order_reference.clone(),
            ),
        ];
        if let Some(s_url) = &req.success_url {
            form_pairs.push(("success_url".into(), s_url.clone()));
        }
        if let Some(c_url) = &req.cancel_url {
            form_pairs.push(("cancel_url".into(), c_url.clone()));
        }
        if let Some(inv) = req.structured_invoice_id {
            form_pairs.push(("metadata[invoice_id]".into(), inv.to_string()));
            form_pairs.push((
                "payment_intent_data[metadata][invoice_id]".into(),
                inv.to_string(),
            ));
        }
        if let Some(vm) = &req.voucher_metadata {
            for prefix in ["metadata", "payment_intent_data[metadata]"] {
                form_pairs.push((format!("{}[sku]", prefix), vm.sku_code.to_string()));
                form_pairs.push((format!("{}[tier]", prefix), vm.tier_bps.to_string()));
                form_pairs.push((
                    format!("{}[voucher_commitment]", prefix),
                    vm.voucher_commitment_hex.clone(),
                ));
                if let Some(usd) = vm.explicit_price_usd_micros {
                    form_pairs.push((format!("{}[price_usd_micros]", prefix), usd.to_string()));
                }
            }
        }

        let encoded_body = form_pairs
            .into_iter()
            .map(|(k, v)| format!("{}={}", k, v.replace(' ', "%20")))
            .collect::<Vec<_>>()
            .join("&");

        let mut headers = self.stripe_headers(Some(&merchant.external_merchant_id));
        headers.push((
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        ));

        let resp = self
            .transport
            .execute(OutboundHttpRequest {
                method: HttpMethod::Post,
                url,
                headers,
                body: encoded_body.into_bytes(),
            })
            .await?;

        if !resp.is_success() {
            return Err(anyhow!(
                "Stripe checkout session creation failed with HTTP {}",
                resp.status
            ));
        }
        let val: serde_json::Value = resp.json()?;
        Ok(MerchantPaymentSession {
            acquirer_id: self.cfg.acquirer_id.clone(),
            acquirer_payment_id: val["payment_intent"]
                .as_str()
                .or_else(|| val["id"].as_str())
                .ok_or_else(|| anyhow!("missing payment_intent/id in Stripe session"))?
                .to_string(),
            auth_id: None,
            response_code: None,
            txn_status: val["payment_status"].as_str().map(String::from),
            checkout_url_or_token: val["url"].as_str().unwrap_or("").to_string(),
            immediate_event: None,
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
            .get("stripe-signature")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| anyhow!("missing Stripe-Signature header"))?;
        verify_timestamped_hmac_header(
            sig,
            raw_body,
            self.cfg.webhook_secret.as_bytes(),
            now_unix_secs,
            self.cfg.max_webhook_skew_secs,
        )?;

        let doc: serde_json::Value = serde_json::from_slice(raw_body)?;
        let stripe_acct = doc["account"]
            .as_str()
            .unwrap_or(&self.cfg.default_account_id)
            .to_string();
        let ev_type = doc["type"].as_str().unwrap_or("");
        let obj = &doc["data"]["object"];

        match ev_type {
            "checkout.session.completed" | "payment_intent.succeeded" => {
                if let Some(ps) = obj["payment_status"].as_str() {
                    if ps != "paid" {
                        return Ok(vec![]);
                    }
                }
                let payment_id = obj["payment_intent"]
                    .as_str()
                    .or_else(|| obj["id"].as_str())
                    .ok_or_else(|| anyhow!("missing payment_intent/id in Stripe webhook"))?
                    .to_string();
                let ccy = CurrencyCode::new(obj["currency"].as_str().unwrap_or("SGD"))?;
                let gross_minor = obj["amount_total"]
                    .as_i64()
                    .or_else(|| obj["amount_received"].as_i64())
                    .or_else(|| obj["amount"].as_i64())
                    .ok_or_else(|| anyhow!("missing amount in Stripe payment event"))?
                    as i128;
                let fee_minor = obj["fee"].as_i64().unwrap_or(0) as i128;
                let stl_ccy = obj["settlement_currency"]
                    .as_str()
                    .map(CurrencyCode::new)
                    .transpose()?
                    .unwrap_or_else(|| ccy.clone());
                let meta = &obj["metadata"];
                let order_ref = meta["order_ref"]
                    .as_str()
                    .or_else(|| obj["client_reference_id"].as_str())
                    .unwrap_or(&payment_id)
                    .to_string();
                let invoice_id = meta["invoice_id"]
                    .as_str()
                    .and_then(|s| s.parse().ok())
                    .or_else(|| meta["invoice_id"].as_u64());

                Ok(vec![CanonicalAcquirerEvent::PaymentAuthorizedOrCaptured(
                    AcquirerPaymentEvent {
                        acquirer_adapter_id: self.cfg.acquirer_id.clone(),
                        external_merchant_id: stripe_acct,
                        acquirer_payment_id: payment_id,
                        order_reference: order_ref,
                        gross_amount: Money::new(gross_minor, ccy),
                        fee_minor,
                        settlement_currency: stl_ccy,
                        expected_settlement_net_minor: None,
                        stage: AcquirerPaymentStage::CapturedPendingSweep,
                        occurred_at_unix: now_unix_secs,
                        structured_invoice_id: invoice_id,
                        voucher_metadata: Self::parse_stripe_voucher_meta(meta)?,
                        source: IngestionSource::WebhookPush,
                    },
                )])
            }
            "charge.refunded" | "charge.dispute.funds_withdrawn" => {
                let payment_id = obj["payment_intent"]
                    .as_str()
                    .or_else(|| obj["charge"].as_str())
                    .or_else(|| obj["id"].as_str())
                    .ok_or_else(|| anyhow!("missing payment_intent/id in Stripe refund"))?
                    .to_string();
                let ccy = CurrencyCode::new(obj["currency"].as_str().unwrap_or("SGD"))?;
                let ref_minor = obj["amount_refunded"]
                    .as_i64()
                    .or_else(|| obj["amount"].as_i64())
                    .unwrap_or(0) as i128;
                Ok(vec![CanonicalAcquirerEvent::PaymentRefundedOrDisputed(
                    AcquirerRefundEvent {
                        acquirer_adapter_id: self.cfg.acquirer_id.clone(),
                        external_merchant_id: stripe_acct,
                        acquirer_payment_id: payment_id,
                        refund_id: obj["id"].as_str().unwrap_or("re_stripe").to_string(),
                        refund_amount: Money::new(ref_minor, ccy),
                        is_chargeback: ev_type == "charge.dispute.funds_withdrawn",
                        deducted_in_batch_id: None,
                        occurred_at_unix: now_unix_secs,
                        source: IngestionSource::WebhookPush,
                    },
                )])
            }
            "payout.paid" => {
                let batch = self
                    .build_sweep_manifest_from_payout(
                        &stripe_acct,
                        obj,
                        IngestionSource::WebhookPush,
                        now_unix_secs,
                    )
                    .await?;
                Ok(vec![CanonicalAcquirerEvent::SettlementSweepManifest(batch)])
            }
            _ => Ok(vec![]),
        }
    }

    async fn poll_payment_status(
        &self,
        merchant: &MerchantProfile,
        acquirer_payment_id: &str,
        now_unix_secs: u64,
    ) -> Result<CanonicalAcquirerEvent> {
        let url = format!(
            "{}/v1/payment_intents/{}",
            self.cfg.base_url.trim_end_matches('/'),
            acquirer_payment_id
        );
        let resp = self
            .transport
            .execute(OutboundHttpRequest {
                method: HttpMethod::Get,
                url,
                headers: self.stripe_headers(Some(&merchant.external_merchant_id)),
                body: vec![],
            })
            .await?;

        if !resp.is_success() {
            return Err(anyhow!(
                "Stripe payment_intent poll failed with HTTP {}",
                resp.status
            ));
        }

        let obj: serde_json::Value = resp.json()?;
        let status = obj["status"].as_str().unwrap_or("");
        let stage = if status == "succeeded" {
            AcquirerPaymentStage::CapturedPendingSweep
        } else {
            AcquirerPaymentStage::AuthorizedOnly
        };
        let ccy = CurrencyCode::new(obj["currency"].as_str().unwrap_or("SGD"))?;
        let gross = obj["amount"].as_i64().unwrap_or(0) as i128;
        let meta = &obj["metadata"];

        Ok(CanonicalAcquirerEvent::PaymentAuthorizedOrCaptured(
            AcquirerPaymentEvent {
                acquirer_adapter_id: self.cfg.acquirer_id.clone(),
                external_merchant_id: merchant.external_merchant_id.clone(),
                acquirer_payment_id: acquirer_payment_id.to_string(),
                order_reference: meta["order_ref"]
                    .as_str()
                    .unwrap_or(acquirer_payment_id)
                    .to_string(),
                gross_amount: Money::new(gross, ccy),
                fee_minor: 0,
                settlement_currency: merchant.settlement_currency.clone(),
                expected_settlement_net_minor: None,
                stage,
                occurred_at_unix: now_unix_secs,
                structured_invoice_id: meta["invoice_id"].as_str().and_then(|s| s.parse().ok()),
                voucher_metadata: Self::parse_stripe_voucher_meta(meta)?,
                source: IngestionSource::PeriodicPoll,
            },
        ))
    }

    async fn poll_settlement_batches(
        &self,
        merchant: &MerchantProfile,
        cursor: &AcquirerPollCursor,
        now_unix_secs: u64,
    ) -> Result<AcquirerBatchPollResult> {
        let url = format!(
            "{}/v1/payouts?status=paid&created[gte]={}",
            self.cfg.base_url.trim_end_matches('/'),
            cursor.last_polled_unix
        );
        let resp = self
            .transport
            .execute(OutboundHttpRequest {
                method: HttpMethod::Get,
                url,
                headers: self.stripe_headers(Some(&merchant.external_merchant_id)),
                body: vec![],
            })
            .await?;

        if !resp.is_success() {
            return Err(anyhow!("Stripe payouts poll failed with HTTP {}", resp.status));
        }

        let val: serde_json::Value = resp.json()?;
        let payouts = val["data"].as_array().cloned().unwrap_or_default();
        let mut batches = Vec::with_capacity(payouts.len());
        for po in &payouts {
            batches.push(
                self.build_sweep_manifest_from_payout(
                    &merchant.external_merchant_id,
                    po,
                    IngestionSource::PeriodicPoll,
                    now_unix_secs,
                )
                .await?,
            );
        }

        Ok(AcquirerBatchPollResult {
            settlement_batches: batches,
            next_cursor: AcquirerPollCursor {
                last_polled_unix: now_unix_secs,
                cursor_token: None,
            },
        })
    }
}
