//! Airwallex Global Payment Acceptance Adapter (`AirwallexAcquirerAdapter`).
//!
//! Implements Airwallex's `PaymentIntents` & `Settlements` v1 REST APIs:
//! - `POST /api/v1/pa/payment_intents/create` (`auto_capture: true` for immediate sales, or
//!   `auto_capture: false` / `PaymentConsent` for hardware pre-order crowdfunding holds)
//! - `POST /api/v1/pa/payment_intents/{id}/capture` (crowdfunding target/milestone capture)
//! - `POST /api/v1/pa/payment_intents/{id}/cancel` (no-charge release when a target is not met)
//! - `GET  /api/v1/pa/payment_intents/{id}` (periodic status inquiry)
//! - `GET  /api/v1/pa/financial/settlements` + `/report` (like-for-like USD/EUR/SGD batch sweeps)
//! - Authenticated `x-timestamp` + `x-signature` (`HMAC-SHA256`) webhooks.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use axum::http::HeaderMap;
use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::adapters::airwallex_auth::{
    derive_airwallex_request_id, extract_structured_invoice_id, money_to_airwallex_major_number,
    parse_airwallex_major_to_minor, parse_airwallex_timestamp_secs,
    parse_airwallex_voucher_metadata, verify_airwallex_webhook, AirwallexAuthConfig,
    AirwallexTokenManager,
};
use crate::domain::entities::MerchantProfile;
use crate::domain::events::{
    AcquirerPaymentEvent, AcquirerPaymentStage, AcquirerRefundEvent, AcquirerSettlementBatch,
    CanonicalAcquirerEvent, IngestionSource, SweepBatchLine,
};
use crate::domain::money::{CurrencyCode, Money};
use crate::ports::acquirer_adapter::{
    AcquirerBatchPollResult, AcquirerPollCursor, CardCaptureMode, MerchantPaymentRequest,
    MerchantPaymentSession, PaymentAcquirerAdapter,
};
use crate::ports::http_transport::{HttpMethod, HttpTransport, OutboundHttpRequest};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AirwallexAcquirerConfig {
    pub acquirer_id: String,
    pub default_account_id: String,
    #[serde(default)]
    pub auth: AirwallexAuthConfig,
}

impl Default for AirwallexAcquirerConfig {
    fn default() -> Self {
        Self {
            acquirer_id: "airwallex".into(),
            default_account_id: "acct_airwallex_sg".into(),
            auth: AirwallexAuthConfig::default(),
        }
    }
}

pub struct AirwallexAcquirerAdapter {
    cfg: AirwallexAcquirerConfig,
    token_mgr: Arc<AirwallexTokenManager>,
    transport: Arc<dyn HttpTransport>,
}

impl AirwallexAcquirerAdapter {
    pub fn new(
        cfg: AirwallexAcquirerConfig,
        token_mgr: Arc<AirwallexTokenManager>,
        transport: Arc<dyn HttpTransport>,
    ) -> Self {
        Self {
            cfg,
            token_mgr,
            transport,
        }
    }

    pub fn with_own_token_manager(
        cfg: AirwallexAcquirerConfig,
        transport: Arc<dyn HttpTransport>,
    ) -> Self {
        let mgr = Arc::new(AirwallexTokenManager::new(cfg.auth.clone(), transport.clone()));
        Self::new(cfg, mgr, transport)
    }

    fn parse_payment_intent_to_event(
        &self,
        external_merchant_id: &str,
        default_settlement_ccy: Option<&CurrencyCode>,
        obj: &Value,
        stage_override: Option<AcquirerPaymentStage>,
        source: IngestionSource,
        now_unix_secs: u64,
    ) -> Result<AcquirerPaymentEvent> {
        let payment_id = obj["id"]
            .as_str()
            .ok_or_else(|| anyhow!("missing 'id' in Airwallex PaymentIntent"))?
            .to_string();
        let ccy = CurrencyCode::new(obj["currency"].as_str().unwrap_or("USD"))?;
        let gross_val = if !obj["captured_amount"].is_null()
            && parse_airwallex_major_to_minor(&obj["captured_amount"], &ccy).unwrap_or(0) > 0
        {
            &obj["captured_amount"]
        } else {
            &obj["amount"]
        };
        let gross_minor = parse_airwallex_major_to_minor(gross_val, &ccy)?;

        // Like-for-like multi-currency settlement: Airwallex settles USD/EUR/SGD directly in the
        // presentment currency (`base_currency` or `settlement_currency`) unless configured otherwise.
        let stl_ccy = obj["settlement_currency"]
            .as_str()
            .or_else(|| obj["base_currency"].as_str())
            .map(CurrencyCode::new)
            .transpose()?
            .or_else(|| default_settlement_ccy.cloned())
            .unwrap_or_else(|| ccy.clone());

        let fee_minor = if !obj["fee_amount"].is_null() {
            parse_airwallex_major_to_minor(&obj["fee_amount"], &ccy).unwrap_or(0)
        } else {
            0
        };

        let status = obj["status"].as_str().unwrap_or("");
        let stage = stage_override.unwrap_or_else(|| match status {
            "SUCCEEDED" => AcquirerPaymentStage::CapturedPendingSweep,
            _ => AcquirerPaymentStage::AuthorizedOnly,
        });

        let meta = &obj["metadata"];
        let order_ref = obj["merchant_order_id"]
            .as_str()
            .or_else(|| meta["order_ref"].as_str())
            .unwrap_or(&payment_id)
            .to_string();
        let invoice_id = meta["invoice_id"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .or_else(|| meta["invoice_id"].as_u64())
            .or_else(|| extract_structured_invoice_id(&order_ref));

        let occurred_at = obj["updated_at"]
            .as_str()
            .or_else(|| obj["created_at"].as_str())
            .and_then(parse_airwallex_timestamp_secs)
            .unwrap_or(now_unix_secs);

        Ok(AcquirerPaymentEvent {
            acquirer_adapter_id: self.cfg.acquirer_id.clone(),
            external_merchant_id: external_merchant_id.to_string(),
            acquirer_payment_id: payment_id,
            order_reference: order_ref,
            gross_amount: Money::new(gross_minor, ccy),
            fee_minor,
            settlement_currency: stl_ccy,
            expected_settlement_net_minor: None,
            stage,
            occurred_at_unix: occurred_at,
            structured_invoice_id: invoice_id,
            voucher_metadata: parse_airwallex_voucher_metadata(meta)?,
            source,
        })
    }

    async fn fetch_settlement_report_items(
        &self,
        merchant_acct: &str,
        settlement_id: &str,
        now_unix_secs: u64,
    ) -> Result<Vec<Value>> {
        let url = format!(
            "{}/api/v1/pa/financial/settlements/{}/report",
            self.token_mgr.base_url(),
            settlement_id
        );
        let headers = self
            .token_mgr
            .auth_headers(Some(merchant_acct), false, now_unix_secs)
            .await?;
        let resp = self
            .transport
            .execute(OutboundHttpRequest {
                method: HttpMethod::Get,
                url,
                headers,
                body: vec![],
            })
            .await?;
        if !resp.is_success() {
            return Err(anyhow!(
                "Airwallex settlement report fetch '{}' failed with HTTP {}",
                settlement_id,
                resp.status
            ));
        }
        let doc: Value = resp.json()?;
        Ok(doc["items"]
            .as_array()
            .or_else(|| doc["data"].as_array())
            .cloned()
            .unwrap_or_default())
    }

    async fn build_settlement_batch(
        &self,
        merchant_acct: &str,
        stl_obj: &Value,
        source: IngestionSource,
        now_unix_secs: u64,
    ) -> Result<AcquirerSettlementBatch> {
        let batch_id = stl_obj["id"]
            .as_str()
            .or_else(|| stl_obj["batch_id"].as_str())
            .ok_or_else(|| anyhow!("missing 'id' in Airwallex settlement object"))?
            .to_string();
        let stl_ccy = CurrencyCode::new(
            stl_obj["currency"]
                .as_str()
                .or_else(|| stl_obj["settlement_currency"].as_str())
                .unwrap_or("USD"),
        )?;

        let report_items = if let Some(arr) = stl_obj["items"]
            .as_array()
            .or_else(|| stl_obj["transactions"].as_array())
        {
            arr.clone()
        } else {
            self.fetch_settlement_report_items(merchant_acct, &batch_id, now_unix_secs)
                .await?
        };

        let mut gross_sales_minor: i128 = 0;
        let mut refunds_minor: i128 = 0;
        let mut total_fees_minor: i128 = 0;
        let mut lines: Vec<SweepBatchLine> = Vec::new();

        for item in &report_items {
            let tx_type = item["type"]
                .as_str()
                .or_else(|| item["transaction_type"].as_str())
                .unwrap_or("PAYMENT")
                .to_ascii_uppercase();
            if tx_type == "SETTLEMENT" || tx_type == "PAYOUT" {
                continue;
            }
            let amount_minor = if !item["settlement_amount"].is_null() {
                parse_airwallex_major_to_minor(&item["settlement_amount"], &stl_ccy)?
            } else {
                parse_airwallex_major_to_minor(&item["amount"], &stl_ccy)?
            };
            let fee_minor = if !item["fee"].is_null() {
                parse_airwallex_major_to_minor(&item["fee"], &stl_ccy)?.abs()
            } else if !item["fee_amount"].is_null() {
                parse_airwallex_major_to_minor(&item["fee_amount"], &stl_ccy)?.abs()
            } else {
                0
            };
            let pay_id = item["payment_intent_id"]
                .as_str()
                .or_else(|| item["source_id"].as_str())
                .or_else(|| item["id"].as_str())
                .unwrap_or("unknown")
                .to_string();

            if tx_type.contains("REFUND") || tx_type.contains("DISPUTE") || amount_minor < 0 {
                let neg_gross = -amount_minor.abs();
                refunds_minor += amount_minor.abs();
                total_fees_minor += fee_minor;
                lines.push(SweepBatchLine {
                    acquirer_payment_id: pay_id,
                    is_refund: true,
                    settlement_gross_minor: neg_gross,
                    settlement_fee_minor: fee_minor,
                    settlement_net_minor: neg_gross - fee_minor,
                });
            } else {
                gross_sales_minor += amount_minor;
                total_fees_minor += fee_minor;
                lines.push(SweepBatchLine {
                    acquirer_payment_id: pay_id,
                    is_refund: false,
                    settlement_gross_minor: amount_minor,
                    settlement_fee_minor: fee_minor,
                    settlement_net_minor: amount_minor - fee_minor,
                });
            }
        }

        let net_payout_minor = if !stl_obj["amount"].is_null() {
            parse_airwallex_major_to_minor(&stl_obj["amount"], &stl_ccy)?
        } else if !stl_obj["settled_amount"].is_null() {
            parse_airwallex_major_to_minor(&stl_obj["settled_amount"], &stl_ccy)?
        } else {
            gross_sales_minor - refunds_minor - total_fees_minor
        };

        let bank_ref = stl_obj["reference"]
            .as_str()
            .or_else(|| stl_obj["financial_transaction_id"].as_str())
            .unwrap_or(&batch_id)
            .to_string();
        let settlement_date = stl_obj["settled_at"]
            .as_str()
            .or_else(|| stl_obj["settlement_date"].as_str())
            .unwrap_or("2026-11-26")
            .chars()
            .take(10)
            .collect::<String>();

        Ok(AcquirerSettlementBatch {
            acquirer_adapter_id: self.cfg.acquirer_id.clone(),
            external_merchant_id: merchant_acct.to_string(),
            batch_id,
            bank_statement_reference: bank_ref,
            settlement_currency: stl_ccy,
            gross_sales_minor,
            refunds_minor,
            total_fees_minor,
            net_payout_minor,
            settlement_date,
            created_at_unix: now_unix_secs,
            lines,
            source,
        })
    }
}

#[async_trait]
impl PaymentAcquirerAdapter for AirwallexAcquirerAdapter {
    fn acquirer_id(&self) -> &str {
        &self.cfg.acquirer_id
    }

    fn acquirer_name(&self) -> &str {
        "Airwallex Global Payment Acceptance (Like-for-Like Multi-Currency)"
    }

    async fn create_payment_session(
        &self,
        merchant: &MerchantProfile,
        req: &MerchantPaymentRequest,
        now_unix_secs: u64,
    ) -> Result<MerchantPaymentSession> {
        let url = format!(
            "{}/api/v1/pa/payment_intents/create",
            self.token_mgr.base_url()
        );
        let auto_capture = req.capture_mode == CardCaptureMode::ImmediateSale;
        let request_id = derive_airwallex_request_id(
            "pi_create",
            &merchant.external_merchant_id,
            &req.order_reference,
        );

        let mut meta = json!({
            "order_ref": req.order_reference,
            "capture_mode": if auto_capture { "immediate_sale" } else { "authorize_only" },
        });
        if let Some(inv) = req.structured_invoice_id {
            meta["invoice_id"] = json!(inv.to_string());
        }
        if let Some(vm) = &req.voucher_metadata {
            meta["sku"] = json!(vm.sku_code.to_string());
            meta["tier"] = json!(vm.tier_bps.to_string());
            meta["voucher_commitment"] = json!(vm.voucher_commitment_hex);
            if let Some(usd) = vm.explicit_price_usd_micros {
                meta["price_usd_micros"] = json!(usd.to_string());
            }
        }

        let descriptor: String = req.description.chars().take(32).collect();
        let mut payload = json!({
            "request_id": request_id,
            "amount": money_to_airwallex_major_number(&req.amount),
            "currency": req.amount.currency.as_str(),
            "merchant_order_id": req.order_reference,
            "descriptor": descriptor,
            "metadata": meta,
            "payment_method_options": {
                "card": {
                    "auto_capture": auto_capture
                }
            }
        });
        if let Some(ref cust_id) = req.customer_id {
            payload["customer_id"] = json!(cust_id);
        }
        if let Some(ref return_url) = req.success_url {
            payload["return_url"] = json!(return_url);
        }
        if let Some(extra_map) = req.acquirer_specific_payload.as_object() {
            if let Some(dst) = payload.as_object_mut() {
                for (k, v) in extra_map {
                    dst.insert(k.clone(), v.clone());
                }
            }
        }

        let headers = self
            .token_mgr
            .auth_headers(Some(&merchant.external_merchant_id), true, now_unix_secs)
            .await?;
        let resp = self
            .transport
            .execute(OutboundHttpRequest {
                method: HttpMethod::Post,
                url,
                headers,
                body: serde_json::to_vec(&payload)?,
            })
            .await?;

        if !resp.is_success() {
            return Err(anyhow!(
                "Airwallex payment_intents/create failed with HTTP {}: {}",
                resp.status,
                String::from_utf8_lossy(&resp.body)
            ));
        }

        let val: Value = resp.json()?;
        let pi_id = val["id"]
            .as_str()
            .ok_or_else(|| anyhow!("missing 'id' in Airwallex PaymentIntent response"))?
            .to_string();
        let status = val["status"].as_str().map(String::from);
        let immediate_event = match status.as_deref() {
            Some("REQUIRES_CAPTURE") => Some(CanonicalAcquirerEvent::PaymentAuthorizedOrCaptured(
                self.parse_payment_intent_to_event(
                    &merchant.external_merchant_id,
                    Some(&merchant.settlement_currency),
                    &val,
                    Some(AcquirerPaymentStage::AuthorizedOnly),
                    IngestionSource::ManualSync,
                    now_unix_secs,
                )?,
            )),
            Some("SUCCEEDED") => Some(CanonicalAcquirerEvent::PaymentAuthorizedOrCaptured(
                self.parse_payment_intent_to_event(
                    &merchant.external_merchant_id,
                    Some(&merchant.settlement_currency),
                    &val,
                    Some(AcquirerPaymentStage::CapturedPendingSweep),
                    IngestionSource::ManualSync,
                    now_unix_secs,
                )?,
            )),
            _ => None,
        };

        let token_or_url = val["url"]
            .as_str()
            .or_else(|| val["client_secret"].as_str())
            .unwrap_or("")
            .to_string();

        Ok(MerchantPaymentSession {
            acquirer_id: self.cfg.acquirer_id.clone(),
            acquirer_payment_id: pi_id,
            auth_id: val["latest_payment_attempt"]["authorization_code"]
                .as_str()
                .map(String::from),
            response_code: None,
            txn_status: status,
            checkout_url_or_token: token_or_url,
            immediate_event,
            created_at_unix: now_unix_secs,
        })
    }

    async fn capture_authorized_payment(
        &self,
        merchant: &MerchantProfile,
        acquirer_payment_id: &str,
        merchant_order_ref: &str,
        amount: &Money,
        now_unix_secs: u64,
    ) -> Result<CanonicalAcquirerEvent> {
        let url = format!(
            "{}/api/v1/pa/payment_intents/{}/capture",
            self.token_mgr.base_url(),
            acquirer_payment_id
        );
        let request_id = derive_airwallex_request_id(
            "pi_capture",
            acquirer_payment_id,
            merchant_order_ref,
        );
        let payload = json!({
            "request_id": request_id,
            "amount": money_to_airwallex_major_number(amount),
        });
        let headers = self
            .token_mgr
            .auth_headers(Some(&merchant.external_merchant_id), true, now_unix_secs)
            .await?;
        let resp = self
            .transport
            .execute(OutboundHttpRequest {
                method: HttpMethod::Post,
                url,
                headers,
                body: serde_json::to_vec(&payload)?,
            })
            .await?;

        if !resp.is_success() {
            return Err(anyhow!(
                "Airwallex payment_intents/{}/capture failed with HTTP {}: {}",
                acquirer_payment_id,
                resp.status,
                String::from_utf8_lossy(&resp.body)
            ));
        }

        let val: Value = resp.json()?;
        let mut ev = self.parse_payment_intent_to_event(
            &merchant.external_merchant_id,
            Some(&merchant.settlement_currency),
            &val,
            Some(AcquirerPaymentStage::CapturedPendingSweep),
            IngestionSource::ManualSync,
            now_unix_secs,
        )?;
        if !merchant_order_ref.is_empty() && ev.order_reference == ev.acquirer_payment_id {
            ev.order_reference = merchant_order_ref.to_string();
        }
        Ok(CanonicalAcquirerEvent::PaymentAuthorizedOrCaptured(ev))
    }

    async fn void_payment(
        &self,
        merchant: &MerchantProfile,
        acquirer_payment_id: &str,
        merchant_order_ref: &str,
        amount: &Money,
        now_unix_secs: u64,
    ) -> Result<CanonicalAcquirerEvent> {
        let url = format!(
            "{}/api/v1/pa/payment_intents/{}/cancel",
            self.token_mgr.base_url(),
            acquirer_payment_id
        );
        let request_id = derive_airwallex_request_id(
            "pi_cancel",
            acquirer_payment_id,
            merchant_order_ref,
        );
        let payload = json!({
            "request_id": request_id,
            "cancellation_reason": "Campaign or pre-order authorization released prior to capture"
        });
        let headers = self
            .token_mgr
            .auth_headers(Some(&merchant.external_merchant_id), true, now_unix_secs)
            .await?;
        let resp = self
            .transport
            .execute(OutboundHttpRequest {
                method: HttpMethod::Post,
                url,
                headers,
                body: serde_json::to_vec(&payload)?,
            })
            .await?;

        if !resp.is_success() {
            return Err(anyhow!(
                "Airwallex payment_intents/{}/cancel failed with HTTP {}: {}",
                acquirer_payment_id,
                resp.status,
                String::from_utf8_lossy(&resp.body)
            ));
        }

        let val: Value = resp.json()?;
        let cancel_id = val["id"]
            .as_str()
            .map(|id| format!("{}_void", id))
            .unwrap_or_else(|| format!("{}_void", acquirer_payment_id));
        Ok(CanonicalAcquirerEvent::PaymentRefundedOrDisputed(
            AcquirerRefundEvent {
                acquirer_adapter_id: self.cfg.acquirer_id.clone(),
                external_merchant_id: merchant.external_merchant_id.clone(),
                acquirer_payment_id: acquirer_payment_id.to_string(),
                refund_id: cancel_id,
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
        verify_airwallex_webhook(
            headers,
            raw_body,
            &self.token_mgr.config().webhook_secret,
            now_unix_secs,
            self.token_mgr.config().max_webhook_skew_secs,
        )?;

        let doc: Value = serde_json::from_slice(raw_body)?;
        let acct_id = doc["account_id"]
            .as_str()
            .or_else(|| doc["accountId"].as_str())
            .unwrap_or(&self.cfg.default_account_id)
            .to_string();
        let ev_name = doc["name"].as_str().unwrap_or("");
        let obj = if doc["data"]["object"].is_object() {
            &doc["data"]["object"]
        } else {
            &doc["data"]
        };

        match ev_name {
            "payment_intent.requires_capture" => {
                let ev = self.parse_payment_intent_to_event(
                    &acct_id,
                    None,
                    obj,
                    Some(AcquirerPaymentStage::AuthorizedOnly),
                    IngestionSource::WebhookPush,
                    now_unix_secs,
                )?;
                Ok(vec![CanonicalAcquirerEvent::PaymentAuthorizedOrCaptured(ev)])
            }
            "payment_intent.succeeded" => {
                let ev = self.parse_payment_intent_to_event(
                    &acct_id,
                    None,
                    obj,
                    Some(AcquirerPaymentStage::CapturedPendingSweep),
                    IngestionSource::WebhookPush,
                    now_unix_secs,
                )?;
                Ok(vec![CanonicalAcquirerEvent::PaymentAuthorizedOrCaptured(ev)])
            }
            "refund.accepted" | "refund.succeeded" | "dispute.lost" | "payment_dispute.lost" => {
                let payment_id = obj["payment_intent_id"]
                    .as_str()
                    .or_else(|| obj["payment_intent"].as_str())
                    .or_else(|| obj["id"].as_str())
                    .ok_or_else(|| anyhow!("missing payment_intent_id in Airwallex refund/dispute"))?
                    .to_string();
                let ccy = CurrencyCode::new(obj["currency"].as_str().unwrap_or("USD"))?;
                let refund_minor = parse_airwallex_major_to_minor(&obj["amount"], &ccy)?.abs();
                Ok(vec![CanonicalAcquirerEvent::PaymentRefundedOrDisputed(
                    AcquirerRefundEvent {
                        acquirer_adapter_id: self.cfg.acquirer_id.clone(),
                        external_merchant_id: acct_id,
                        acquirer_payment_id: payment_id,
                        refund_id: obj["id"].as_str().unwrap_or("rfd_airwallex").to_string(),
                        refund_amount: Money::new(refund_minor, ccy),
                        is_chargeback: ev_name.contains("dispute"),
                        deducted_in_batch_id: obj["batch_id"].as_str().map(String::from),
                        occurred_at_unix: now_unix_secs,
                        source: IngestionSource::WebhookPush,
                    },
                )])
            }
            "settlement.settled" | "pa.settlement.settled" => {
                let batch = self
                    .build_settlement_batch(
                        &acct_id,
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
            "{}/api/v1/pa/payment_intents/{}",
            self.token_mgr.base_url(),
            acquirer_payment_id
        );
        let headers = self
            .token_mgr
            .auth_headers(Some(&merchant.external_merchant_id), false, now_unix_secs)
            .await?;
        let resp = self
            .transport
            .execute(OutboundHttpRequest {
                method: HttpMethod::Get,
                url,
                headers,
                body: vec![],
            })
            .await?;

        if !resp.is_success() {
            return Err(anyhow!(
                "Airwallex payment_intents/{} poll failed with HTTP {}",
                acquirer_payment_id,
                resp.status
            ));
        }

        let val: Value = resp.json()?;
        let ev = self.parse_payment_intent_to_event(
            &merchant.external_merchant_id,
            Some(&merchant.settlement_currency),
            &val,
            None,
            IngestionSource::PeriodicPoll,
            now_unix_secs,
        )?;
        Ok(CanonicalAcquirerEvent::PaymentAuthorizedOrCaptured(ev))
    }

    async fn poll_settlement_batches(
        &self,
        merchant: &MerchantProfile,
        cursor: &AcquirerPollCursor,
        now_unix_secs: u64,
    ) -> Result<AcquirerBatchPollResult> {
        let from_iso = Utc
            .timestamp_opt(cursor.last_polled_unix as i64, 0)
            .single()
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| "1970-01-01T00:00:00Z".into());
        let url = format!(
            "{}/api/v1/pa/financial/settlements?status=SETTLED&currency={}&from_settled_at={}",
            self.token_mgr.base_url(),
            merchant.settlement_currency.as_str(),
            from_iso
        );
        let headers = self
            .token_mgr
            .auth_headers(Some(&merchant.external_merchant_id), false, now_unix_secs)
            .await?;
        let resp = self
            .transport
            .execute(OutboundHttpRequest {
                method: HttpMethod::Get,
                url,
                headers,
                body: vec![],
            })
            .await?;

        if !resp.is_success() {
            return Err(anyhow!(
                "Airwallex settlements poll failed with HTTP {}",
                resp.status
            ));
        }

        let val: Value = resp.json()?;
        let items = val["items"]
            .as_array()
            .or_else(|| val["data"].as_array())
            .cloned()
            .unwrap_or_default();
        let mut batches = Vec::with_capacity(items.len());
        for stl in &items {
            batches.push(
                self.build_settlement_batch(
                    &merchant.external_merchant_id,
                    stl,
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
