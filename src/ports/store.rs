//! Crash-safe persistent & in-memory state repository (`OracleStore`) for multi-entity accounts,
//! cursors, clearing items, sweep batches, outbound trackers, balanced sub-ledger journals, and HFS outbox.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use anyhow::{anyhow, Result};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::adapters::ocbc_auth::OcbcSessionTokenRecord;
use crate::domain::entities::{AccountOwner, BankAccount, Counterparty, MerchantProfile};
use crate::domain::ledger::{
    AcquirerClearingItem, BankCreditRecord, DirectCollectionTracker, EntrySide,
    LedgerJournalEntry, OnChainOutboxTask, OutboxTaskState, OutboundPaymentTracker,
    PendingSweepRecord, SubledgerAccountCode,
};
use crate::domain::money::CurrencyCode;
use crate::ports::acquirer_adapter::AcquirerPollCursor;
use crate::ports::bank_adapter::AccountPollCursor;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct StoreSnapshot {
    pub entities: IndexMap<String, AccountOwner>,
    pub bank_accounts: IndexMap<String, BankAccount>,
    pub merchant_profiles: IndexMap<String, MerchantProfile>,
    pub counterparties: IndexMap<String, Counterparty>,
    pub bank_poll_cursors: BTreeMap<String, AccountPollCursor>,
    pub acquirer_poll_cursors: BTreeMap<String, AcquirerPollCursor>,
    pub bank_credits: IndexMap<String, BankCreditRecord>,
    pub outbound_payments: IndexMap<String, OutboundPaymentTracker>,
    #[serde(default)]
    pub direct_collections: IndexMap<String, DirectCollectionTracker>,
    pub clearing_items: IndexMap<String, AcquirerClearingItem>,
    pub sweep_batches: IndexMap<String, PendingSweepRecord>,
    pub journals: Vec<LedgerJournalEntry>,
    pub outbox: IndexMap<String, OnChainOutboxTask>,
    pub outbox_dedup: HashSet<String>,
    #[serde(default)]
    pub ocbc_tokens: BTreeMap<String, OcbcSessionTokenRecord>,
}

/// Per-account trial balance row (`debit_minor`, `credit_minor`, `net_dr_minus_cr_minor`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrialBalanceRow {
    pub debit_minor: i128,
    pub credit_minor: i128,
    pub net_debit_minus_credit_minor: i128,
}

pub struct OracleStore {
    inner: RwLock<StoreSnapshot>,
    persist_path: Option<PathBuf>,
}

impl OracleStore {
    pub fn in_memory() -> Self {
        Self {
            inner: RwLock::new(StoreSnapshot::default()),
            persist_path: None,
        }
    }

    pub fn open_persistent(path: impl AsRef<Path>) -> Result<Self> {
        let path_buf = path.as_ref().to_path_buf();
        let snap = if path_buf.exists() {
            let raw = fs::read(&path_buf)?;
            serde_json::from_slice(&raw)
                .map_err(|e| anyhow!("corrupt OracleStore snapshot {:?}: {}", path_buf, e))?
        } else {
            StoreSnapshot::default()
        };
        Ok(Self {
            inner: RwLock::new(snap),
            persist_path: Some(path_buf),
        })
    }

    fn flush_locked(&self, snap: &StoreSnapshot) -> Result<()> {
        if let Some(path) = &self.persist_path {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let tmp = path.with_extension("snap.tmp");
            let bytes = serde_json::to_vec_pretty(snap)?;
            fs::write(&tmp, bytes)?;
            fs::rename(&tmp, path)?;
        }
        Ok(())
    }

    pub fn read<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&StoreSnapshot) -> R,
    {
        let guard = self.inner.read().unwrap();
        f(&guard)
    }

    pub fn write<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut StoreSnapshot) -> Result<R>,
    {
        let mut guard = self.inner.write().unwrap();
        let out = f(&mut guard)?;
        self.flush_locked(&guard)?;
        Ok(out)
    }

    pub fn upsert_entity(&self, entity: AccountOwner) -> Result<()> {
        self.write(|s| {
            s.entities.insert(entity.entity_id.clone(), entity);
            Ok(())
        })
    }

    pub fn upsert_bank_account(&self, acct: BankAccount) -> Result<()> {
        self.write(|s| {
            if !s.entities.contains_key(&acct.owner_entity_id) {
                return Err(anyhow!(
                    "cannot register BankAccount '{}': unknown owner_entity_id '{}'",
                    acct.account_id,
                    acct.owner_entity_id
                ));
            }
            s.bank_accounts.insert(acct.account_id.clone(), acct);
            Ok(())
        })
    }

    pub fn upsert_merchant_profile(&self, profile: MerchantProfile) -> Result<()> {
        self.write(|s| {
            if !s.entities.contains_key(&profile.owner_entity_id) {
                return Err(anyhow!(
                    "cannot register MerchantProfile '{}': unknown owner_entity_id '{}'",
                    profile.merchant_profile_id,
                    profile.owner_entity_id
                ));
            }
            let settlement_acct = s
                .bank_accounts
                .get(&profile.settlement_bank_account_id)
                .ok_or_else(|| {
                    anyhow!(
                        "settlement_bank_account_id '{}' does not exist",
                        profile.settlement_bank_account_id
                    )
                })?;
            if settlement_acct.owner_entity_id != profile.owner_entity_id {
                return Err(anyhow!(
                    "entity boundary violation: MerchantProfile '{}' belongs to '{}', but settlement bank account '{}' belongs to '{}'",
                    profile.merchant_profile_id,
                    profile.owner_entity_id,
                    settlement_acct.account_id,
                    settlement_acct.owner_entity_id
                ));
            }
            if settlement_acct.currency != profile.settlement_currency {
                return Err(anyhow!(
                    "settlement currency mismatch: MerchantProfile '{}' settles in {}, but BankAccount '{}' is denominated in {}",
                    profile.merchant_profile_id,
                    profile.settlement_currency,
                    settlement_acct.account_id,
                    settlement_acct.currency
                ));
            }
            s.merchant_profiles
                .insert(profile.merchant_profile_id.clone(), profile);
            Ok(())
        })
    }

    pub fn upsert_counterparty(&self, cp: Counterparty) -> Result<()> {
        self.write(|s| {
            s.counterparties.insert(cp.counterparty_id.clone(), cp);
            Ok(())
        })
    }

    pub fn upsert_ocbc_token(&self, token: OcbcSessionTokenRecord) -> Result<()> {
        self.write(|s| {
            s.ocbc_tokens.insert(token.scope_key.clone(), token);
            Ok(())
        })
    }

    /// Compute the exact per-currency double-entry Trial Balance for a given `entity_id`,
    /// asserting `sum(Dr) == sum(Cr)` for every currency.
    pub fn compute_entity_trial_balance(
        &self,
        entity_id: &str,
    ) -> BTreeMap<CurrencyCode, BTreeMap<SubledgerAccountCode, TrialBalanceRow>> {
        self.read(|s| {
            let mut result: BTreeMap<CurrencyCode, BTreeMap<SubledgerAccountCode, TrialBalanceRow>> =
                BTreeMap::new();
            for j in s.journals.iter().filter(|j| j.entity_id == entity_id) {
                let ccy_map = result.entry(j.currency.clone()).or_default();
                for line in &j.lines {
                    let row = ccy_map.entry(line.account).or_default();
                    match line.side {
                        EntrySide::Debit => row.debit_minor += line.amount_minor,
                        EntrySide::Credit => row.credit_minor += line.amount_minor,
                    }
                    row.net_debit_minus_credit_minor = row.debit_minor - row.credit_minor;
                }
            }
            result
        })
    }

    /// List all pending or retryable on-chain HFS settlement tasks in FIFO creation order.
    pub fn pending_outbox_tasks(&self) -> Vec<OnChainOutboxTask> {
        self.read(|s| {
            s.outbox
                .values()
                .filter(|t| {
                    matches!(
                        t.state,
                        OutboxTaskState::Pending | OutboxTaskState::FailedRetryable { .. }
                    )
                })
                .cloned()
                .collect()
        })
    }
}
