//! Technical Payment Acquirer Adapter Port (`PaymentAcquirerAdapter`).
//!
//! Models Merchant Payment Interfaces (such as **OCBC Merchant Card Payments API** and **Stripe**),
//! keeping card/payment collection strictly segregated from corporate bank account cash finality
//! and exposing full card transaction operations (`authorize` / `sale` / `capture` / `void` / `query`)
//! plus periodical settlement batch / sweep manifests (`poll_settlement_batches`).

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};

use crate::domain::entities::MerchantProfile;
use crate::domain::events::{
    AcquirerSettlementBatch, CanonicalAcquirerEvent, VoucherOrderMetadata,
};
use crate::domain::money::Money;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AcquirerPollCursor {
    pub last_polled_unix: u64,
    pub cursor_token: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AcquirerBatchPollResult {
    pub settlement_batches: Vec<AcquirerSettlementBatch>,
    pub next_cursor: AcquirerPollCursor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CardCaptureMode {
    /// Authorize hold only (e.g. OCBC `/authorize`); requires subsequent `capture_authorized_payment`.
    AuthorizeOnly,
    /// Immediate authorize + capture sale (e.g. OCBC `/sale`).
    ImmediateSale,
}

impl Default for CardCaptureMode {
    fn default() -> Self {
        Self::ImmediateSale
    }
}

/// Canonical request to execute or open a card/checkout payment via an acquirer (OCBC Card API or Stripe).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerchantPaymentRequest {
    /// Maps to `merchantTranId` in OCBC `merchantcardpayments/1.0` or `client_reference_id` in Stripe.
    pub order_reference: String,
    /// Maps to `customerId` in OCBC `merchantcardpayments/1.0`.
    pub customer_id: Option<String>,
    pub amount: Money,
    pub description: String,
    #[serde(default)]
    pub capture_mode: CardCaptureMode,
    /// Optional tokenized/encrypted card payload fields forwarded verbatim to direct card APIs (`/authorize` or `/sale`).
    #[serde(default)]
    pub acquirer_specific_payload: serde_json::Value,
    pub success_url: Option<String>,
    pub cancel_url: Option<String>,
    pub structured_invoice_id: Option<u64>,
    pub voucher_metadata: Option<VoucherOrderMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerchantPaymentSession {
    pub acquirer_id: String,
    /// Maps to `transactionId` in OCBC `merchantcardpayments/1.0` or `payment_intent` in Stripe.
    pub acquirer_payment_id: String,
    pub auth_id: Option<String>,
    pub response_code: Option<String>,
    pub txn_status: Option<String>,
    pub checkout_url_or_token: String,
    /// If the synchronous API call (`/authorize` or `/sale`) already produced a canonical payment event,
    /// returns it here so the caller immediately records it in the clearing sub-ledger!
    pub immediate_event: Option<CanonicalAcquirerEvent>,
    pub created_at_unix: u64,
}

#[async_trait]
pub trait PaymentAcquirerAdapter: Send + Sync {
    /// Unique acquirer identifier (e.g., `"ocbc_merchant_card"`, `"stripe"`).
    fn acquirer_id(&self) -> &str;

    /// Human-readable acquirer / payment gateway name.
    fn acquirer_name(&self) -> &str;

    /// Execute an outbound merchant card `/authorize` or `/sale` (or create a Stripe Checkout Session).
    async fn create_payment_session(
        &self,
        merchant: &MerchantProfile,
        req: &MerchantPaymentRequest,
        now_unix_secs: u64,
    ) -> Result<MerchantPaymentSession>;

    /// Capture a previously authorized transaction (e.g., `POST /transactional/merchantcardpayments/1.0/capture`).
    async fn capture_authorized_payment(
        &self,
        _merchant: &MerchantProfile,
        _acquirer_payment_id: &str,
        _merchant_order_ref: &str,
        _amount: &Money,
        _now_unix_secs: u64,
    ) -> Result<CanonicalAcquirerEvent> {
        Err(anyhow!(
            "capture_authorized_payment is not supported by acquirer '{}'",
            self.acquirer_id()
        ))
    }

    /// Void/cancel a transaction before settlement (e.g., `POST /transactional/merchantcardpayments/1.0/void`).
    async fn void_payment(
        &self,
        _merchant: &MerchantProfile,
        _acquirer_payment_id: &str,
        _merchant_order_ref: &str,
        _amount: &Money,
        _now_unix_secs: u64,
    ) -> Result<CanonicalAcquirerEvent> {
        Err(anyhow!(
            "void_payment is not supported by acquirer '{}'",
            self.acquirer_id()
        ))
    }

    /// Verify inbound payment/refund/payout webhook signature and translate into `CanonicalAcquirerEvent`s.
    async fn verify_and_parse_webhook(
        &self,
        headers: &HeaderMap,
        raw_body: &[u8],
        now_unix_secs: u64,
    ) -> Result<Vec<CanonicalAcquirerEvent>>;

    /// Poll the acquirer's transaction inquiry API (e.g., `POST /transactional/merchantcardpayments/1.0/query`).
    async fn poll_payment_status(
        &self,
        merchant: &MerchantProfile,
        acquirer_payment_id: &str,
        now_unix_secs: u64,
    ) -> Result<CanonicalAcquirerEvent>;

    /// Poll the acquirer's settlement report / payout sweep API to obtain periodical settlement batches
    /// (`batch_id`, `net_payout_minor`, constituent payment IDs) for matching against bank `AppliedCredit`s.
    async fn poll_settlement_batches(
        &self,
        merchant: &MerchantProfile,
        cursor: &AcquirerPollCursor,
        now_unix_secs: u64,
    ) -> Result<AcquirerBatchPollResult>;
}
