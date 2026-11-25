//! Parallel Periodic Polling Supervisor (`PollingSupervisor`).
//!
//! Runs alongside the inbound webhook server to guarantee completeness and resilience when bank or
//! acquirer webhooks are delayed, dropped, or unsupported on a given rail:
//! 1. Polls every active `BankAccount`'s incoming transaction feed (`poll_incoming_transactions`).
//! 2. Polls every non-finalized `OutboundPaymentTracker` (`!state.is_terminal()`) via `poll_outbound_payment_status`.
//! 3. Polls every active `MerchantProfile` for non-finalized card/gateway authorizations (`AuthorizedOnly`)
//!    and periodical settlement sweep batches (`poll_settlement_batches`).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::domain::events::{CanonicalAcquirerEvent, CanonicalBankEvent};
use crate::domain::ledger::ClearingItemStatus;
use crate::engine::reconciliation::ReconciliationEngine;
use crate::ports::acquirer_adapter::PaymentAcquirerAdapter;
use crate::ports::bank_adapter::BankTechnicalAdapter;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PollCycleReport {
    pub incoming_credits_ingested: usize,
    pub outbound_statuses_checked: usize,
    pub acquirer_payments_checked: usize,
    pub settlement_batches_ingested: usize,
    pub errors: Vec<String>,
}

pub struct PollingSupervisor {
    engine: Arc<ReconciliationEngine>,
    bank_adapters: Arc<HashMap<String, Arc<dyn BankTechnicalAdapter>>>,
    acquirer_adapters: Arc<HashMap<String, Arc<dyn PaymentAcquirerAdapter>>>,
}

impl PollingSupervisor {
    pub fn new(
        engine: Arc<ReconciliationEngine>,
        bank_adapters: Arc<HashMap<String, Arc<dyn BankTechnicalAdapter>>>,
        acquirer_adapters: Arc<HashMap<String, Arc<dyn PaymentAcquirerAdapter>>>,
    ) -> Self {
        Self {
            engine,
            bank_adapters,
            acquirer_adapters,
        }
    }

    /// Execute one complete deterministic poll pass across all registered banks, accounts,
    /// non-finalized outbound payments, and payment acquirers.
    pub async fn run_poll_cycle_once(&self, now_unix: u64) -> PollCycleReport {
        let mut report = PollCycleReport::default();
        let store = self.engine.store();

        // 1. Poll incoming transactions across all poll-enabled corporate bank accounts
        let (accounts, cursors) = store.read(|s| {
            let accts: Vec<_> = s
                .bank_accounts
                .values()
                .filter(|a| a.poll_enabled)
                .cloned()
                .collect();
            (accts, s.bank_poll_cursors.clone())
        });

        for acct in accounts {
            let Some(adapter) = self.bank_adapters.get(&acct.bank_adapter_id) else {
                report.errors.push(format!(
                    "missing BankTechnicalAdapter '{}' for account '{}'",
                    acct.bank_adapter_id, acct.account_id
                ));
                continue;
            };
            let cursor = cursors.get(&acct.account_id).cloned().unwrap_or_default();
            match adapter
                .poll_incoming_transactions(&acct, &cursor, now_unix)
                .await
            {
                Ok(batch) => {
                    for credit in batch.applied_credits {
                        match self
                            .engine
                            .ingest_bank_event(CanonicalBankEvent::AppliedCredit(credit), now_unix)
                        {
                            Ok(_) => report.incoming_credits_ingested += 1,
                            Err(e) => report.errors.push(e.to_string()),
                        }
                    }
                    let _ = store.write(|s| {
                        s.bank_poll_cursors
                            .insert(acct.account_id.clone(), batch.next_cursor);
                        Ok(())
                    });
                }
                Err(e) => report.errors.push(format!(
                    "poll_incoming_transactions('{}'): {}",
                    acct.account_id, e
                )),
            }
        }

        // 2. Poll status of all non-finalized outbound payments across all accounts
        let pending_outbound = store.read(|s| {
            s.outbound_payments
                .values()
                .filter(|t| !t.state.is_terminal())
                .filter_map(|t| {
                    s.bank_accounts
                        .get(&t.account_id)
                        .cloned()
                        .map(|acct| (acct, t.clone()))
                })
                .collect::<Vec<_>>()
        });

        for (acct, tracker) in pending_outbound {
            let Some(adapter) = self.bank_adapters.get(&acct.bank_adapter_id) else {
                continue;
            };
            match adapter
                .poll_outbound_payment_status(&acct, &tracker, now_unix)
                .await
            {
                Ok(status_ev) => {
                    report.outbound_statuses_checked += 1;
                    if let Err(e) = self.engine.ingest_bank_event(
                        CanonicalBankEvent::OutboundStatusChanged(status_ev),
                        now_unix,
                    ) {
                        report.errors.push(e.to_string());
                    }
                }
                Err(e) => report.errors.push(format!(
                    "poll_outbound_payment_status('{}'): {}",
                    tracker.client_instruction_id, e
                )),
            }
        }

        // 3. Poll non-captured acquirer authorizations (`AuthorizedOnly`) + periodical settlement sweeps
        let (merchants, acq_cursors, auth_only_items) = store.read(|s| {
            let mchs: Vec<_> = s
                .merchant_profiles
                .values()
                .filter(|m| m.poll_enabled)
                .cloned()
                .collect();
            let auth_items: Vec<_> = s
                .clearing_items
                .values()
                .filter(|i| i.status == ClearingItemStatus::AuthorizedOnly)
                .filter_map(|i| {
                    s.merchant_profiles
                        .get(&i.merchant_profile_id)
                        .cloned()
                        .map(|m| (m, i.acquirer_payment_id.clone()))
                })
                .collect();
            (mchs, s.acquirer_poll_cursors.clone(), auth_items)
        });

        for (mch, payment_id) in auth_only_items {
            let Some(adapter) = self.acquirer_adapters.get(&mch.acquirer_adapter_id) else {
                continue;
            };
            match adapter.poll_payment_status(&mch, &payment_id, now_unix).await {
                Ok(ev) => {
                    report.acquirer_payments_checked += 1;
                    if let Err(e) = self.engine.ingest_acquirer_event(ev, now_unix) {
                        report.errors.push(e.to_string());
                    }
                }
                Err(e) => report.errors.push(format!(
                    "poll_payment_status('{}'): {}",
                    payment_id, e
                )),
            }
        }

        for mch in merchants {
            let Some(adapter) = self.acquirer_adapters.get(&mch.acquirer_adapter_id) else {
                continue;
            };
            let cursor = acq_cursors
                .get(&mch.merchant_profile_id)
                .cloned()
                .unwrap_or_default();
            match adapter.poll_settlement_batches(&mch, &cursor, now_unix).await {
                Ok(res) => {
                    for batch in res.settlement_batches {
                        match self.engine.ingest_acquirer_event(
                            CanonicalAcquirerEvent::SettlementSweepManifest(batch),
                            now_unix,
                        ) {
                            Ok(_) => report.settlement_batches_ingested += 1,
                            Err(e) => report.errors.push(e.to_string()),
                        }
                    }
                    let _ = store.write(|s| {
                        s.acquirer_poll_cursors
                            .insert(mch.merchant_profile_id.clone(), res.next_cursor);
                        Ok(())
                    });
                }
                Err(e) => report.errors.push(format!(
                    "poll_settlement_batches('{}'): {}",
                    mch.merchant_profile_id, e
                )),
            }
        }

        report
    }

    /// Spawn the background periodic polling task on a Tokio interval until `shutdown_rx` signals stop.
    pub fn spawn_background_loop(
        self: Arc<Self>,
        interval_secs: u64,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs.max(5)));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        let rep = self.run_poll_cycle_once(now).await;
                        tracing::debug!(
                            credits = rep.incoming_credits_ingested,
                            outbound_checked = rep.outbound_statuses_checked,
                            sweeps = rep.settlement_batches_ingested,
                            errs = rep.errors.len(),
                            "PollingSupervisor cycle complete"
                        );
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        })
    }

    pub fn engine(&self) -> &Arc<ReconciliationEngine> {
        &self.engine
    }

    pub fn register_check(&self) -> Result<()> {
        Ok(())
    }
}
