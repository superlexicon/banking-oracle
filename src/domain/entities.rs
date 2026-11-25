//! Multi-entity (`AccountOwner`), Multi-Bank `BankAccount`, `MerchantProfile`, and `Counterparty` domain models.
//!
//! Designed so a single oracle deployment (or federated multi-tenant deployment) simultaneously serves
//! multiple legal entities/account owners, multiple banks, multiple currencies, and multiple counterparties.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::crypto::TxWireFormat;
use crate::domain::money::CurrencyCode;

/// Per-entity SuperLexicon L1 / EVM contract routing configuration.
/// Each `AccountOwner` can bind its bank & acquirer finality events to its own corporate HFS suite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityChainBinding {
    /// Hex-encoded 32-byte `secp256k1` oracle signing key (or resolved from environment at startup).
    pub oracle_private_key_hex: String,
    pub chain_id: u64,
    #[serde(default)]
    pub wire_format: TxWireFormat,
    /// Entity's on-chain `treasuryIdentity` HFS address (`0x...`, 20 bytes) holding operating bank cash.
    pub treasury_identity_hex: Option<String>,
    /// Map of ISO 4217 currency code (`"SGD"`, `"USD"`, ...) -> `AssetLedger` (`operatingBankLedger`) HFS address.
    #[serde(default)]
    pub operating_bank_ledgers: BTreeMap<CurrencyCode, String>,
    /// Optional `AccountingLedger` (`ifrs-accounting`) HFS address for automatic AR invoice settlement & suspense sync.
    pub ifrs_accounting_ledger_hex: Option<String>,
    /// Optional `RewardVoucher` HFS address for finalized hardware `SLXR` paid voucher issuance / refund revocation.
    pub reward_voucher_hfs_hex: Option<String>,
    /// Optional fixed FX conversion rate into USD (in parts-per-million, e.g. `1 SGD = 745_000` micro-USD = `$0.745`)
    /// when a non-USD hardware order is settled and converted into USD micros for `RewardVoucher`.
    #[serde(default)]
    pub fx_to_usd_ppm: BTreeMap<CurrencyCode, u64>,
}

/// A distinct legal entity / corporate account owner whose bank accounts and merchant payment gateways
/// are monitored and reconciled by the oracle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountOwner {
    /// Unique canonical tenant / entity identifier (e.g., `"ent_superlexicon_sg"`, `"ent_immin_io"`).
    pub entity_id: String,
    pub legal_name: String,
    /// Corporate registration number (e.g., Singapore ACRA UEN, LEI, or EIN).
    pub registration_number: String,
    /// Functional / reporting currency of this legal entity under IAS 21.
    pub functional_currency: CurrencyCode,
    /// Optional blockchain HFS binding for this entity.
    pub chain_binding: Option<EntityChainBinding>,
    pub active: bool,
}

/// A corporate bank account (CASA / multi-currency / virtual account) belonging to a specific `AccountOwner`
/// and connected via a specific `BankTechnicalAdapter`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BankAccount {
    /// Canonical internal bank account ID (e.g., `"acct_ocbc_sgd_001"`, `"acct_ocbc_usd_002"`, `"acct_dbs_sgd_001"`).
    pub account_id: String,
    /// Owning legal entity (`AccountOwner.entity_id`).
    pub owner_entity_id: String,
    /// Registered `BankTechnicalAdapter::adapter_id()` handling API protocol & webhooks for this bank.
    pub bank_adapter_id: String,
    /// SWIFT BIC of the holding bank (e.g., `"OCBCSGSG"`, `"DBSSSGSG"`).
    pub bank_bic: String,
    /// Bank-native account number or IBAN (e.g., `"501-889900-001"`).
    pub external_account_number: String,
    /// Single currency of this ledger sub-account (multi-currency MCA accounts register one `BankAccount` per currency pocket).
    pub currency: CurrencyCode,
    pub display_name: String,
    /// Whether the parallel `PollingSupervisor` should periodically poll statements/incoming credits on this account.
    pub poll_enabled: bool,
    pub poll_interval_secs: u64,
}

/// A merchant payment-processing profile (e.g., OCBC Merchant Card Acquiring MID or 3rd-party PSP like Stripe)
/// owned by an `AccountOwner`.
///
/// Even when the payment acquirer is operated by the same bank as the CASA account (e.g. OCBC Merchant Card API
/// settling into an OCBC SGD CASA account), card authorization/capture is segregated from actual bank account
/// cash credit and bridged via asynchronous batch settlement sweeps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerchantProfile {
    /// Canonical internal merchant profile ID (e.g., `"mch_ocbc_card_sg"`, `"mch_stripe_sg"`).
    pub merchant_profile_id: String,
    /// Owning legal entity (`AccountOwner.entity_id`).
    pub owner_entity_id: String,
    /// Registered `PaymentAcquirerAdapter::acquirer_id()` (`"ocbc_merchant_card"`, `"stripe"`, etc.).
    pub acquirer_adapter_id: String,
    /// Acquirer-assigned Merchant ID (`MID` for OCBC Card Gateway, `acct_...` for Stripe).
    pub external_merchant_id: String,
    /// The specific `BankAccount.account_id` (owned by the same `owner_entity_id`) into which this acquirer
    /// deposits periodical net settlement sweeps!
    pub settlement_bank_account_id: String,
    /// Currency in which settlement sweeps hit `settlement_bank_account_id`.
    pub settlement_currency: CurrencyCode,
    /// Presentment currencies accepted at checkout (`SGD`, `USD`, `EUR`, ...).
    pub accepted_currencies: Vec<CurrencyCode>,
    /// Whether `PollingSupervisor` should periodically poll settlement batches and pending payment statuses.
    pub poll_enabled: bool,
    pub poll_interval_secs: u64,
}

/// Classification of external or intercompany counterparties transacting with an `AccountOwner`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CounterpartyRole {
    Customer,
    Supplier,
    PaymentAcquirer,
    IntercompanyEntity,
    InstitutionalLender,
    Shareholder,
}

/// Registered counterparty record for automated payer/payee matching and IAS 24 related-party identification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Counterparty {
    pub counterparty_id: String,
    /// Optional scoping to a single `AccountOwner.entity_id` (`None` = shared across entities).
    pub scoped_entity_id: Option<String>,
    pub legal_name: String,
    pub role: CounterpartyRole,
    #[serde(default)]
    pub known_bank_accounts: Vec<String>,
    pub paynow_uen_or_vpa: Option<String>,
    pub onchain_identity_hex: Option<String>,
    /// Flagged under IAS 24 so related-party cash flows are never commingled with arm's-length revenue.
    pub is_related_party: bool,
}
