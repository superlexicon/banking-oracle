//! Double-entry reconciliation sub-ledger, acquirer clearing state, outbound payment trackers,
//! and transactional on-chain HFS settlement outbox models.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use crate::domain::events::{
    OutboundPaymentState, SweepBatchLine, TransferRail, VoucherOrderMetadata,
};
use crate::domain::money::{CurrencyCode, Money};

/// Sub-ledger Chart of Accounts (aligned with SuperLexicon's codified IFRS `AccountingLedger`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubledgerAccountCode {
    /// `1010` — Confirmed Cash at Bank (debited ONLY on finalized bank `AppliedCreditEvent`, credited ONLY on `Settled` outbound payment).
    CashAtBank1010,
    /// `1140` — Merchant Acquirer Clearing Receivable (in-transit card/PSP captures awaiting bank sweep credit).
    AcquirerClearingReceivable1140,
    /// `1145` — Cross-Currency FX Settlement Bridge (used when presentment currency != bank sweep currency).
    FxSettlementBridge1145,
    /// `1200` — Trade Accounts Receivable (settled when structured customer invoice payment clears in bank).
    TradeReceivables1200,
    /// `2100` — Trade Accounts Payable / Approved Disbursement Obligation.
    TradePayables2100,
    /// `2190` — Outbound Bank Payment In-Transit Clearing (`Initiated` / `AcceptedByBank` / `InProcessing`).
    OutboundInTransitClearing2190,
    /// `2450` — Unsettled Merchant Order Clearing (liability held until acquirer payment sweeps into bank cash).
    UnsettledOrderClearing2450,
    /// `2900` — Unattributed Cash Suspense (quarantined bank deposit or sweep awaiting batch manifest).
    UnattributedCashSuspense2900,
    /// `4000` — Realized Operating / Product Revenue (recognized upon bank cash finality).
    RealizedOperatingRevenue4000,
    /// `6250` — Bank Wire & Merchant Acquiring Fees (MDR, interchange, Stripe fees, SWIFT/MEPS wire fees).
    BankAndAcquirerFees6250,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntrySide {
    Debit,
    Credit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalLine {
    pub account: SubledgerAccountCode,
    pub side: EntrySide,
    pub amount_minor: i128,
    pub sub_account_ref: Option<String>,
}

/// Immutable, strictly balanced double-entry accounting journal posted by the `ReconciliationEngine`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerJournalEntry {
    pub journal_id: String,
    pub entity_id: String,
    pub currency: CurrencyCode,
    pub description: String,
    pub source_event_ref: String,
    pub posted_at_unix: u64,
    pub lines: Vec<JournalLine>,
}

impl LedgerJournalEntry {
    /// Construct and verify `sum(Debit) == sum(Credit) > 0` before any journal can enter the store.
    pub fn new_balanced(
        journal_id: String,
        entity_id: String,
        currency: CurrencyCode,
        description: String,
        source_event_ref: String,
        posted_at_unix: u64,
        lines: Vec<JournalLine>,
    ) -> Result<Self> {
        let mut dr_sum: i128 = 0;
        let mut cr_sum: i128 = 0;
        for line in &lines {
            if line.amount_minor < 0 {
                return Err(anyhow!("journal line amount cannot be negative"));
            }
            match line.side {
                EntrySide::Debit => dr_sum = dr_sum.checked_add(line.amount_minor).unwrap(),
                EntrySide::Credit => cr_sum = cr_sum.checked_add(line.amount_minor).unwrap(),
            }
        }
        if dr_sum != cr_sum || dr_sum == 0 {
            return Err(anyhow!(
                "unbalanced sub-ledger journal '{}': sum(Dr)={} != sum(Cr)={}",
                description,
                dr_sum,
                cr_sum
            ));
        }
        Ok(Self {
            journal_id,
            entity_id,
            currency,
            description,
            source_event_ref,
            posted_at_unix,
            lines,
        })
    }
}

/// Lifecycle state of an individual merchant card / Stripe payment across the 2-stage finality bridge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ClearingItemStatus {
    AuthorizedOnly,
    CapturedPendingBankSweep,
    BankCashFinalized {
        batch_id: String,
        bank_credit_key: String,
        finalized_at_unix: u64,
    },
    RefundedBeforeSweep {
        refund_id: String,
        refunded_at_unix: u64,
    },
    RefundedAfterFinality {
        refund_id: String,
        refunded_at_unix: u64,
    },
    ChargebackDisputed {
        dispute_id: String,
        disputed_at_unix: u64,
    },
}

/// Individual payment tracked in the Merchant Clearing Sub-Ledger (`1140`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcquirerClearingItem {
    pub clearing_key: String,
    pub entity_id: String,
    pub merchant_profile_id: String,
    pub acquirer_adapter_id: String,
    pub acquirer_payment_id: String,
    pub order_reference: String,
    pub gross_amount: Money,
    pub estimated_fee_minor: i128,
    pub settlement_currency: CurrencyCode,
    pub expected_settlement_net_minor: Option<i128>,
    pub structured_invoice_id: Option<u64>,
    pub voucher_metadata: Option<VoucherOrderMetadata>,
    pub status: ClearingItemStatus,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SweepMatchMethod {
    ExactReferenceAndAmount,
    ExactAmountAndSettlementWindow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SweepBatchStatus {
    AwaitingBankCredit,
    ReconciledWithBankCredit {
        bank_credit_key: String,
        bank_tx_id: String,
        match_method: SweepMatchMethod,
        reconciled_at_unix: u64,
    },
}

/// Stored acquirer settlement batch / periodical sweep manifest (`OCBC Merchant Settlement` or `Stripe Payout`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingSweepRecord {
    pub sweep_key: String,
    pub entity_id: String,
    pub merchant_profile_id: String,
    pub target_bank_account_id: String,
    pub acquirer_adapter_id: String,
    pub batch_id: String,
    pub bank_statement_reference: String,
    pub settlement_currency: CurrencyCode,
    pub gross_sales_minor: i128,
    pub refunds_minor: i128,
    pub total_fees_minor: i128,
    pub net_payout_minor: i128,
    pub settlement_date: String,
    pub lines: Vec<SweepBatchLine>,
    pub status: SweepBatchStatus,
    pub created_at_unix: u64,
}

/// Stored incoming bank `AppliedCredit` record, including whether it has been matched to an invoice,
/// direct order, or acquirer settlement sweep (or sits in `2900 Suspense` awaiting a sweep manifest!).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BankCreditRecord {
    pub credit_key: String,
    pub entity_id: String,
    pub account_id: String,
    pub bank_adapter_id: String,
    pub bank_tx_id: String,
    pub batch_or_sweep_ref: Option<String>,
    pub remittance_info: String,
    pub amount: Money,
    pub value_date: String,
    pub booked_at_unix: u64,
    pub matched_counterparty_id: Option<String>,
    pub matched_sweep_key: Option<String>,
    /// True if booked into `2900 Unattributed Cash Suspense` and still eligible to match an arriving `AcquirerSettlementBatch`.
    pub in_unallocated_suspense: bool,
}

/// Persistent tracker for an outgoing corporate bank payment, polled periodically by `PollingSupervisor`
/// until `state.is_terminal()` becomes `true`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundPaymentTracker {
    pub client_instruction_id: String,
    pub entity_id: String,
    pub account_id: String,
    pub bank_adapter_id: String,
    pub bank_payment_id: Option<String>,
    pub end_to_end_id: Option<String>,
    pub counterparty_id: Option<String>,
    pub beneficiary_name: String,
    pub beneficiary_account: String,
    pub beneficiary_bank_bic: Option<String>,
    pub rail: TransferRail,
    pub amount: Money,
    pub bank_fee_minor: i128,
    pub remittance_info: String,
    pub state: OutboundPaymentState,
    pub last_reason_code: Option<String>,
    pub last_reason_detail: Option<String>,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
}

/// Target HFS action queued in the transactional outbox ONLY after bank-level finality (or verified revocation).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OnChainSettlementKind {
    /// Mint tokenized commercial bank cash (`AssetLedger.charterModuleIssue`) upon finalized bank credit.
    MintOperatingBankCash {
        operating_bank_ledger_hex: String,
        treasury_identity_hex: String,
        amount_micros: u64,
    },
    /// Burn tokenized commercial bank cash (`AssetLedger.charterModuleCancel`) upon finalized outbound bank settlement.
    BurnOperatingBankCash {
        operating_bank_ledger_hex: String,
        treasury_identity_hex: String,
        amount_micros: u64,
    },
    /// Settle an open AR credit invoice on `AccountingLedger` (`settleCreditInvoice`).
    SettleIfrsCreditInvoice {
        accounting_ledger_hex: String,
        invoice_id: u64,
        amount_micros: u64,
    },
    /// Quarantine unattributed deposit in `AccountingLedger` (`quarantineSuspenseCash`).
    QuarantineIfrsSuspense {
        accounting_ledger_hex: String,
    },
    /// Issue a 90-day validator-gated `SLXR` voucher (`RewardVoucher.issuePaidVoucher`) once hardware payment cash settles in bank!
    IssuePaidHardwareVoucher {
        reward_voucher_hfs_hex: String,
        payment_ref_hash_hex: String,
        sku_code: u64,
        tier_bps: u64,
        price_usd_micros: u64,
        voucher_commitment_hex: String,
    },
    /// Revoke a pre-claim hardware voucher (`RewardVoucher.revokeRefundedVoucher`) upon refund/chargeback.
    RevokeRefundedHardwareVoucher {
        reward_voucher_hfs_hex: String,
        payment_ref_hash_hex: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum OutboxTaskState {
    Pending,
    Submitted { tx_hash: String, submitted_at_unix: u64 },
    FailedRetryable { attempts: u32, last_error: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnChainOutboxTask {
    pub task_id: String,
    pub entity_id: String,
    pub deduplication_key: String,
    pub action: OnChainSettlementKind,
    pub state: OutboxTaskState,
    pub created_at_unix: u64,
}
