//! Technical Payment Acquirer Adapter Port (`PaymentAcquirerAdapter`).
//!
//! Models Merchant Payment Interfaces (such as **OCBC Merchant Card Payments API** and **Stripe**),
//! keeping card/payment collection strictly segregated from corporate bank account cash finality
//! and exposing periodical settlement batch / sweep manifests (`poll_settlement_batches`) so every
//! processed payment is reconciled against the actual deposit hitting the bank account.

use anyhow::Result;
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

/// Canonical request to open a card/checkout payment session via an acquirer (OCBC Card Gateway or Stripe).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerchantPaymentRequest {
    pub order_reference: String,
    pub amount: Money,
    pub description: String,
    pub success_url: Option<String>,
    pub cancel_url: Option<String>,
    pub structured_invoice_id: Option<u64>,
    pub voucher_metadata: Option<VoucherOrderMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerchantPaymentSession {
    pub acquirer_id: String,
    pub acquirer_payment_id: String,
    pub checkout_url_or_token: String,
    pub created_at_unix: u64,
}

#[async_trait]
pub trait PaymentAcquirerAdapter: Send + Sync {
    /// Unique acquirer identifier (e.g., `"ocbc_merchant_card"`, `"stripe"`).
    fn acquirer_id(&self) -> &str;

    /// Human-readable acquirer / payment gateway name.
    fn acquirer_name(&self) -> &str;

    /// Create an outbound merchant card payment session / payment intent with order & voucher metadata locked.
    async fn create_payment_session(
        &self,
        merchant: &MerchantProfile,
        req: &MerchantPaymentRequest,
        now_unix_secs: u64,
    ) -> Result<MerchantPaymentSession>;

    /// Verify inbound payment/refund/payout webhook signature and translate into `CanonicalAcquirerEvent`s.
    async fn verify_and_parse_webhook(
        &self,
        headers: &HeaderMap,
        raw_body: &[u8],
        now_unix_secs: u64,
    ) -> Result<Vec<CanonicalAcquirerEvent>>;

    /// Poll the acquirer's transaction inquiry API for a specific payment's authorization/capture/refund status.
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
