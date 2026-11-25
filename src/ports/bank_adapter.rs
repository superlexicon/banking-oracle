//! Technical Bank Adapter Port (`BankTechnicalAdapter`).
//!
//! Isolates bank-specific endpoint URLs, OAuth2 / mTLS / JWS / HMAC authentication protocols, and
//! proprietary or ISO 20022 request/response data structures from the Business & Reconciliation Engine.
//! Integrating a new bank requires ONLY implementing this trait.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};

use crate::domain::entities::BankAccount;
use crate::domain::events::{
    AppliedCreditEvent, CanonicalBankEvent, OutboundPaymentState, OutboundPaymentStatusEvent,
    TransferRail, VoucherOrderMetadata,
};
use crate::domain::ledger::OutboundPaymentTracker;
use crate::domain::money::Money;

/// Persisted statement / transaction polling cursor per `BankAccount`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccountPollCursor {
    pub last_polled_unix: u64,
    pub cursor_token: Option<String>,
}

/// Normalized result returned by `BankTechnicalAdapter::poll_incoming_transactions`.
#[derive(Debug, Clone)]
pub struct IncomingPollBatch {
    pub applied_credits: Vec<AppliedCreditEvent>,
    pub next_cursor: AccountPollCursor,
}

/// Canonical instruction to initiate an outbound corporate payment from a specific `BankAccount`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundPaymentInstruction {
    pub client_instruction_id: String,
    pub counterparty_id: Option<String>,
    pub beneficiary_name: String,
    pub beneficiary_account: String,
    pub beneficiary_bank_bic: Option<String>,
    #[serde(default)]
    pub beneficiary_bank_name: Option<String>,
    #[serde(default)]
    pub beneficiary_address: Option<String>,
    #[serde(default)]
    pub value_date: Option<String>,
    pub rail: TransferRail,
    pub amount: Money,
    pub remittance_info: String,
}

/// Immediate submission acknowledgment returned by the bank API upon initiating an outgoing payment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundSubmissionReceipt {
    pub bank_payment_id: Option<String>,
    pub end_to_end_id: Option<String>,
    pub value_date: Option<String>,
    pub initial_state: OutboundPaymentState,
}

/// Canonical instruction to initiate a corporate direct debit / pull collection (such as Singapore
/// Corporate PayNow Collection via UEN + eDDA `POST /transactional/corporate/paynowcollection/1.0`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectCollectionInstruction {
    pub transaction_reference_no: String,
    /// e.g. `"UEN"`
    pub payer_proxy_type: String,
    /// e.g. `"T01LLXXXXA"`
    pub payer_proxy_value: String,
    /// Direct Debit Authorization reference (`DDAReferenceNo`)
    pub dda_reference_no: String,
    /// Industry FAST purpose code (`PurposeCode`, e.g. `"OTHR"`, `"COLL"`, `"GDSV"`)
    pub purpose_code: String,
    pub amount: Money,
    pub description: String,
    pub structured_invoice_id: Option<u64>,
    pub voucher_metadata: Option<VoucherOrderMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectCollectionReceipt {
    pub transaction_reference_no: String,
    pub bank_reference_no: String,
    pub description: String,
}

#[async_trait]
pub trait BankTechnicalAdapter: Send + Sync {
    /// Unique technical adapter identifier (e.g., `"ocbc_corporate"`, `"iso20022_dbs"`, `"iso20022_scb"`).
    fn adapter_id(&self) -> &str;

    /// Human-readable bank institution name.
    fn bank_name(&self) -> &str;

    /// Verify the bank's webhook authentication headers/signatures and parse the callback body into
    /// canonical `AppliedCredit` and/or `OutboundStatusChanged` domain events.
    async fn verify_and_parse_webhook(
        &self,
        headers: &HeaderMap,
        raw_body: &[u8],
        now_unix_secs: u64,
    ) -> Result<Vec<CanonicalBankEvent>>;

    /// Periodically poll the bank's statement / transaction / PayNow enquiry APIs for finalized incoming credits.
    async fn poll_incoming_transactions(
        &self,
        account: &BankAccount,
        cursor: &AccountPollCursor,
        now_unix_secs: u64,
    ) -> Result<IncomingPollBatch>;

    /// Submit an outbound payment instruction to the bank's payment initiation endpoint (e.g. MEPS / pain.001).
    async fn initiate_outbound_payment(
        &self,
        account: &BankAccount,
        instruction: &OutboundPaymentInstruction,
        now_unix_secs: u64,
    ) -> Result<OutboundSubmissionReceipt>;

    /// Poll the bank's payment inquiry endpoint for the latest state of a non-finalized outbound payment.
    async fn poll_outbound_payment_status(
        &self,
        account: &BankAccount,
        tracker: &OutboundPaymentTracker,
        now_unix_secs: u64,
    ) -> Result<OutboundPaymentStatusEvent>;

    /// Initiate an authorized pull collection from a corporate counterparty (e.g. OCBC PayNow UEN Collection).
    async fn initiate_direct_collection(
        &self,
        _account: &BankAccount,
        _instruction: &DirectCollectionInstruction,
        _now_unix_secs: u64,
    ) -> Result<DirectCollectionReceipt> {
        Err(anyhow!(
            "initiate_direct_collection is not supported by bank adapter '{}'",
            self.adapter_id()
        ))
    }
}
