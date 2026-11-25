//! Canonical bank-agnostic and acquirer-agnostic domain events produced by Technical Adapters.
//!
//! All bank-specific endpoints, OAuth2/JWS/HMAC headers, and proprietary or ISO 20022 payloads are
//! normalized into these canonical structures *before* entering the Business & Reconciliation Engine.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use crate::domain::money::{CurrencyCode, Money};

/// How an event entered the oracle: real-time bank/acquirer push webhook vs. parallel periodic poller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngestionSource {
    WebhookPush,
    PeriodicPoll,
    ManualSync,
}

/// Canonical domestic or cross-border clearing rail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferRail {
    InternalBook,
    Fast,
    PayNow,
    Giro,
    MepsPlus,
    SwiftGpi,
    Sepa,
    Fedwire,
    AcquirerSettlementSweep,
    Other(String),
}

/// Optional SuperLexicon hardware voucher order metadata carried through checkout or structured remittance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoucherOrderMetadata {
    /// Hardware SKU code (`1 = SLX-L1 / dongle`, `2 = SLX-V1 / watch`, `3 = SLX-G1 / slate`, etc.).
    pub sku_code: u64,
    /// Reward tier in basis points (`15000` = 150% Early-Bird, `10000` = 100% Standard, `2000` = 20% Kickstarter).
    pub tier_bps: u64,
    /// Buyer-generated blinded commitment `0x...` (`keccak256("SLXR_VOUCHER_V1" || pk_v)`).
    pub voucher_commitment_hex: String,
    /// Explicit USD price override in micro-USD (`$1.00 = 1_000_000`) if priced in USD before FX conversion.
    pub explicit_price_usd_micros: Option<u64>,
}

impl VoucherOrderMetadata {
    pub fn parse_sku_code(sku: &str) -> Result<u64> {
        match sku.trim().to_ascii_lowercase().as_str() {
            "1" | "slx-l1" | "dongle" | "lite" => Ok(1),
            "2" | "slx-v1" | "watch" | "watch_ultra" | "validator" => Ok(2),
            "3" | "slx-g1" | "slate" | "gateway" => Ok(3),
            other => Err(anyhow!("unsupported hardware SKU '{}'", other)),
        }
    }

    pub fn parse_tier_bps(tier: &str) -> Result<u64> {
        match tier.trim().to_ascii_lowercase().as_str() {
            "early_bird" | "earlybird" | "150" | "15000" => Ok(15_000),
            "retail" | "standard" | "100" | "10000" => Ok(10_000),
            "kickstarter" | "20" | "2000" => Ok(2_000),
            other => other
                .parse::<u64>()
                .map_err(|_| anyhow!("unsupported voucher tier '{}'", other)),
        }
    }
}

/// State machine for an outgoing payment on a corporate bank account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboundPaymentState {
    Initiated,
    AcceptedByBank,
    InProcessing,
    Settled,
    Failed,
    Rejected,
    Returned,
}

impl OutboundPaymentState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Failed | Self::Rejected | Self::Returned
        )
    }

    /// Monotonic state progression rank so delayed/out-of-order status polls never regress a finalized state.
    pub fn progression_rank(self) -> u8 {
        match self {
            Self::Initiated => 1,
            Self::AcceptedByBank => 2,
            Self::InProcessing => 3,
            Self::Settled | Self::Failed | Self::Rejected | Self::Returned => 10,
        }
    }
}

/// Finalized / applied incoming credit (deposit, customer remittance, or acquirer batch sweep deposit)
/// confirmed on a corporate `BankAccount`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppliedCreditEvent {
    pub bank_adapter_id: String,
    pub external_account_number: String,
    /// Unique bank-assigned transaction / entry identifier (`AcctSvcrRef` in ISO 20022).
    pub bank_tx_id: String,
    pub end_to_end_id: Option<String>,
    /// Optional structured payout/batch reference (e.g. `"OCBC-MC-STL-20261125-01"` or `"po_1Q9StripeSweep"`).
    pub batch_or_sweep_ref: Option<String>,
    pub rail: TransferRail,
    /// Positive finalized credit amount in the bank account's currency.
    pub amount: Money,
    pub value_date: String,
    pub booked_at_unix: u64,
    pub remittance_info: String,
    pub payer_name: Option<String>,
    pub payer_account: Option<String>,
    /// Optional structured AR invoice reference extracted from remittance info (`INV-10042` -> `10042`).
    pub structured_invoice_id: Option<u64>,
    /// Optional direct PayNow/Wire hardware voucher metadata when buyer pays directly into bank account.
    pub voucher_metadata: Option<VoucherOrderMetadata>,
    pub running_balance_minor: Option<i128>,
    pub source: IngestionSource,
}

/// Status notification or poll update for an outgoing payment initiated from a corporate `BankAccount`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundPaymentStatusEvent {
    pub bank_adapter_id: String,
    pub external_account_number: String,
    /// Client-assigned idempotency / instruction ID (`InstrId` / `ClientRef`).
    pub client_instruction_id: String,
    /// Bank-assigned payment tracking reference (`TxId` / `UETR`).
    pub bank_payment_id: Option<String>,
    pub end_to_end_id: Option<String>,
    pub rail: TransferRail,
    pub state: OutboundPaymentState,
    pub amount: Money,
    /// Actual wire / clearing fee charged by the bank upon settlement (in the account's currency minor units).
    pub bank_fee_minor: i128,
    pub reason_code: Option<String>,
    pub reason_detail: Option<String>,
    pub updated_at_unix: u64,
    pub source: IngestionSource,
}

/// Canonical event union emitted by any `BankTechnicalAdapter`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub enum CanonicalBankEvent {
    AppliedCredit(AppliedCreditEvent),
    OutboundStatusChanged(OutboundPaymentStatusEvent),
}

/// Stage of an individual payment processed through a Merchant Payment Interface (OCBC Card API, Stripe, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcquirerPaymentStage {
    /// Card/payment authorized (hold placed), not yet captured.
    AuthorizedOnly,
    /// Captured by the acquirer/PSP, awaiting asynchronous batch settlement sweep into the bank account.
    CapturedPendingSweep,
}

/// Individual payment authorization or capture reported by a `PaymentAcquirerAdapter`.
/// NOTE: Under strict segregation of payment processing vs. banking finality, this event does NOT book
/// `1010 Cash at Bank`; it books an `AcquirerClearingItem` awaiting bank sweep reconciliation!
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcquirerPaymentEvent {
    pub acquirer_adapter_id: String,
    pub external_merchant_id: String,
    pub acquirer_payment_id: String,
    pub order_reference: String,
    /// Gross amount charged to the customer in presentment currency.
    pub gross_amount: Money,
    /// Processor / MDR fee in presentment currency minor units (estimated or actual).
    pub fee_minor: i128,
    /// Currency in which the acquirer will settle this payment to the corporate bank account.
    pub settlement_currency: CurrencyCode,
    /// Expected net amount in `settlement_currency` minor units if already converted by the acquirer.
    pub expected_settlement_net_minor: Option<i128>,
    pub stage: AcquirerPaymentStage,
    pub occurred_at_unix: u64,
    pub structured_invoice_id: Option<u64>,
    pub voucher_metadata: Option<VoucherOrderMetadata>,
    pub source: IngestionSource,
}

/// Refund or chargeback/dispute event on a previously processed merchant payment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcquirerRefundEvent {
    pub acquirer_adapter_id: String,
    pub external_merchant_id: String,
    pub acquirer_payment_id: String,
    pub refund_id: String,
    pub refund_amount: Money,
    pub is_chargeback: bool,
    /// If deducted from a specific settlement batch/sweep, links to that `batch_id`.
    pub deducted_in_batch_id: Option<String>,
    pub occurred_at_unix: u64,
    pub source: IngestionSource,
}

/// Line item inside an acquirer's periodical settlement sweep / merchant batch report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SweepBatchLine {
    /// Constituent `acquirer_payment_id` (or `refund_id` if `is_refund == true`).
    pub acquirer_payment_id: String,
    pub is_refund: bool,
    /// Gross amount in `settlement_currency` minor units (positive for sales, negative for refunds).
    pub settlement_gross_minor: i128,
    /// MDR / interchange / Stripe processing fee in `settlement_currency` minor units (`>= 0`).
    pub settlement_fee_minor: i128,
    /// Net contribution to the bank deposit sweep (`settlement_gross_minor - settlement_fee_minor`).
    pub settlement_net_minor: i128,
}

/// Periodical settlement batch / sweep manifest emitted by OCBC Merchant Card Settlement or Stripe Payouts.
/// Bridges the $N$ individual payments collected via the payment interface to the single net deposit
/// (`AppliedCreditEvent`) landing asynchronously on the corporate bank account!
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcquirerSettlementBatch {
    pub acquirer_adapter_id: String,
    pub external_merchant_id: String,
    /// Acquirer batch / payout ID (e.g., `"OCBC-MC-BATCH-20261125"` or `"po_1Q9Sweep881"`).
    pub batch_id: String,
    /// Reference string expected in the bank statement credit narrative / `EndToEndId`.
    pub bank_statement_reference: String,
    pub settlement_currency: CurrencyCode,
    pub gross_sales_minor: i128,
    pub refunds_minor: i128,
    pub total_fees_minor: i128,
    /// Exact net cash deposit expected on `MerchantProfile.settlement_bank_account_id`:
    /// `gross_sales_minor - refunds_minor - total_fees_minor == net_payout_minor`.
    pub net_payout_minor: i128,
    pub settlement_date: String,
    pub created_at_unix: u64,
    pub lines: Vec<SweepBatchLine>,
    pub source: IngestionSource,
}

/// Canonical event union emitted by any `PaymentAcquirerAdapter`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub enum CanonicalAcquirerEvent {
    PaymentAuthorizedOrCaptured(AcquirerPaymentEvent),
    PaymentRefundedOrDisputed(AcquirerRefundEvent),
    SettlementSweepManifest(AcquirerSettlementBatch),
}
