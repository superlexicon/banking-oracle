//! Bank-Agnostic & Acquirer-Agnostic Business, Multi-Entity Sub-Ledger & Sweep Reconciliation Engine.
//!
//! Notice the imports below: ZERO bank URLs, ZERO OAuth2/HMAC/JWS headers, and ZERO adapter modules.
//! All bank webhooks, periodic statement polls, OCBC Merchant Card captures/settlements, and Stripe
//! payment/payout sweeps converge into this single deterministic double-entry state machine.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::compute_salted_payment_ref_hash;
use crate::domain::entities::{AccountOwner, BankAccount, MerchantProfile};
use crate::domain::events::{
    AcquirerPaymentEvent, AcquirerPaymentStage, AcquirerRefundEvent, AcquirerSettlementBatch,
    AppliedCreditEvent, CanonicalAcquirerEvent, CanonicalBankEvent, OutboundPaymentState,
    OutboundPaymentStatusEvent, VoucherOrderMetadata,
};
use crate::domain::ledger::{
    AcquirerClearingItem, BankCreditRecord, ClearingItemStatus, DirectCollectionState,
    DirectCollectionTracker, EntrySide, JournalLine, LedgerJournalEntry, OnChainOutboxTask,
    OnChainSettlementKind, OutboxTaskState, OutboundPaymentTracker, PendingSweepRecord,
    SubledgerAccountCode, SweepBatchStatus, SweepMatchMethod,
};
use crate::domain::money::CurrencyCode;
use crate::ports::bank_adapter::{
    DirectCollectionInstruction, DirectCollectionReceipt, OutboundPaymentInstruction,
    OutboundSubmissionReceipt,
};
use crate::ports::store::{OracleStore, StoreSnapshot};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum IngestOutcome {
    DuplicateIgnored { key: String },
    StaleStatusIgnored { key: String, current_state: OutboundPaymentState },
    AppliedBankCreditProcessed {
        credit_key: String,
        reconciled_sweep_key: Option<String>,
        finalized_payment_count: usize,
        in_suspense: bool,
    },
    OutboundPaymentUpdated {
        client_instruction_id: String,
        new_state: OutboundPaymentState,
    },
    AcquirerPaymentRecorded {
        clearing_key: String,
        stage: AcquirerPaymentStage,
    },
    AcquirerRefundProcessed {
        clearing_key: String,
        was_post_finality: bool,
    },
    SweepBatchProcessed {
        sweep_key: String,
        matched_bank_credit_key: Option<String>,
        finalized_payment_count: usize,
    },
}

pub struct ReconciliationEngine {
    store: Arc<OracleStore>,
    domain_salt: Vec<u8>,
}

impl ReconciliationEngine {
    pub fn new(store: Arc<OracleStore>, domain_salt: Vec<u8>) -> Self {
        Self { store, domain_salt }
    }

    pub fn store(&self) -> &Arc<OracleStore> {
        &self.store
    }

    /// Register a newly initiated outbound bank payment in the sub-ledger (`Dr 2100 AP`, `Cr 2190 Outbound In-Transit`)
    /// so `PollingSupervisor` tracks it automatically until bank finality (`Settled` / `Failed` / `Rejected` / `Returned`).
    pub fn record_outbound_initiated(
        &self,
        account_id: &str,
        instruction: &OutboundPaymentInstruction,
        receipt: &OutboundSubmissionReceipt,
        now_unix: u64,
    ) -> Result<OutboundPaymentTracker> {
        self.store.write(|s| {
            let acct = s
                .bank_accounts
                .get(account_id)
                .ok_or_else(|| anyhow!("unknown bank account '{}'", account_id))?
                .clone();
            if acct.currency != instruction.amount.currency {
                return Err(anyhow!(
                    "outbound currency {} does not match bank account '{}' currency {}",
                    instruction.amount.currency,
                    acct.account_id,
                    acct.currency
                ));
            }
            if instruction.amount.amount_minor <= 0 {
                return Err(anyhow!("outbound payment amount must be positive"));
            }
            if s.outbound_payments
                .contains_key(&instruction.client_instruction_id)
            {
                return Err(anyhow!(
                    "duplicate outbound client_instruction_id '{}'",
                    instruction.client_instruction_id
                ));
            }

            let value_date = receipt
                .value_date
                .clone()
                .or_else(|| instruction.value_date.clone())
                .unwrap_or_else(|| {
                    chrono::TimeZone::timestamp_opt(&chrono::Utc, now_unix as i64, 0)
                        .single()
                        .map(|dt| dt.format("%Y-%m-%d").to_string())
                        .unwrap_or_else(|| "2026-11-26".into())
                });

            let tracker = OutboundPaymentTracker {
                client_instruction_id: instruction.client_instruction_id.clone(),
                entity_id: acct.owner_entity_id.clone(),
                account_id: acct.account_id.clone(),
                bank_adapter_id: acct.bank_adapter_id.clone(),
                bank_payment_id: receipt.bank_payment_id.clone(),
                end_to_end_id: receipt.end_to_end_id.clone(),
                counterparty_id: instruction.counterparty_id.clone(),
                beneficiary_name: instruction.beneficiary_name.clone(),
                beneficiary_account: instruction.beneficiary_account.clone(),
                beneficiary_bank_bic: instruction.beneficiary_bank_bic.clone(),
                beneficiary_bank_name: instruction.beneficiary_bank_name.clone(),
                beneficiary_address: instruction.beneficiary_address.clone(),
                value_date,
                rail: instruction.rail.clone(),
                amount: instruction.amount.clone(),
                bank_fee_minor: 0,
                remittance_info: instruction.remittance_info.clone(),
                state: OutboundPaymentState::Initiated,
                last_reason_code: None,
                last_reason_detail: None,
                created_at_unix: now_unix,
                updated_at_unix: now_unix,
            };

            let j = LedgerJournalEntry::new_balanced(
                format!("jnl_out_init_{}", instruction.client_instruction_id),
                acct.owner_entity_id.clone(),
                acct.currency.clone(),
                format!(
                    "Outbound payment '{}' initiated on account '{}'",
                    instruction.client_instruction_id, acct.account_id
                ),
                instruction.client_instruction_id.clone(),
                now_unix,
                vec![
                    JournalLine {
                        account: SubledgerAccountCode::TradePayables2100,
                        side: EntrySide::Debit,
                        amount_minor: instruction.amount.amount_minor,
                        sub_account_ref: instruction.counterparty_id.clone(),
                    },
                    JournalLine {
                        account: SubledgerAccountCode::OutboundInTransitClearing2190,
                        side: EntrySide::Credit,
                        amount_minor: instruction.amount.amount_minor,
                        sub_account_ref: Some(acct.account_id.clone()),
                    },
                ],
            )?;
            s.journals.push(j);
            s.outbound_payments
                .insert(tracker.client_instruction_id.clone(), tracker.clone());

            // If the synchronous submission response already advanced to AcceptedByBank/InProcessing/Settled, apply transition immediately!
            if receipt.initial_state != OutboundPaymentState::Initiated {
                let synth = OutboundPaymentStatusEvent {
                    bank_adapter_id: acct.bank_adapter_id.clone(),
                    external_account_number: acct.external_account_number.clone(),
                    client_instruction_id: instruction.client_instruction_id.clone(),
                    bank_payment_id: receipt.bank_payment_id.clone(),
                    end_to_end_id: receipt.end_to_end_id.clone(),
                    rail: instruction.rail.clone(),
                    state: receipt.initial_state,
                    amount: instruction.amount.clone(),
                    bank_fee_minor: 0,
                    reason_code: None,
                    reason_detail: None,
                    updated_at_unix: now_unix,
                    source: crate::domain::events::IngestionSource::ManualSync,
                };
                self.apply_outbound_status_locked(s, synth, now_unix)?;
            }

            Ok(s.outbound_payments
                .get(&instruction.client_instruction_id)
                .unwrap()
                .clone())
        })
    }

    /// Record an initiated corporate pull collection (e.g. OCBC PayNow UEN Collection `paynowcollection/1.0`)
    /// so when the corresponding incoming PayNow credit clears on `/ocbc/sg/corp/paynow/1.0` or `corpTransHistory/1.0`,
    /// it automatically resolves the linked AR invoice or hardware `SLXR` voucher!
    pub fn record_direct_collection_initiated(
        &self,
        account_id: &str,
        instruction: &DirectCollectionInstruction,
        receipt: &DirectCollectionReceipt,
        now_unix: u64,
    ) -> Result<DirectCollectionTracker> {
        self.store.write(|s| {
            let acct = s
                .bank_accounts
                .get(account_id)
                .ok_or_else(|| anyhow!("unknown bank account '{}'", account_id))?
                .clone();
            if acct.currency != instruction.amount.currency {
                return Err(anyhow!(
                    "collection currency {} does not match bank account '{}' currency {}",
                    instruction.amount.currency,
                    acct.account_id,
                    acct.currency
                ));
            }
            if instruction.amount.amount_minor <= 0 {
                return Err(anyhow!("collection amount must be positive"));
            }
            if s.direct_collections
                .contains_key(&instruction.transaction_reference_no)
            {
                return Err(anyhow!(
                    "duplicate collection transaction_reference_no '{}'",
                    instruction.transaction_reference_no
                ));
            }

            let tracker = DirectCollectionTracker {
                transaction_reference_no: instruction.transaction_reference_no.clone(),
                bank_reference_no: receipt.bank_reference_no.clone(),
                entity_id: acct.owner_entity_id,
                account_id: acct.account_id,
                bank_adapter_id: acct.bank_adapter_id,
                payer_proxy_type: instruction.payer_proxy_type.clone(),
                payer_proxy_value: instruction.payer_proxy_value.clone(),
                dda_reference_no: instruction.dda_reference_no.clone(),
                purpose_code: instruction.purpose_code.clone(),
                amount: instruction.amount.clone(),
                description: instruction.description.clone(),
                structured_invoice_id: instruction.structured_invoice_id,
                voucher_metadata: instruction.voucher_metadata.clone(),
                state: DirectCollectionState::InitiatedAwaitingCredit,
                created_at_unix: now_unix,
            };
            s.direct_collections
                .insert(tracker.transaction_reference_no.clone(), tracker.clone());
            Ok(tracker)
        })
    }

    /// Ingest any canonical bank event (from either an authenticated bank webhook OR the parallel poller).
    pub fn ingest_bank_event(
        &self,
        event: CanonicalBankEvent,
        now_unix: u64,
    ) -> Result<IngestOutcome> {
        self.store.write(|s| match event {
            CanonicalBankEvent::AppliedCredit(credit) => {
                self.apply_bank_credit_locked(s, credit, now_unix)
            }
            CanonicalBankEvent::OutboundStatusChanged(out_ev) => {
                self.apply_outbound_status_locked(s, out_ev, now_unix)
            }
        })
    }

    /// Ingest any canonical payment acquirer event (OCBC Merchant Card API or Stripe webhook / batch poller).
    pub fn ingest_acquirer_event(
        &self,
        event: CanonicalAcquirerEvent,
        now_unix: u64,
    ) -> Result<IngestOutcome> {
        self.store.write(|s| match event {
            CanonicalAcquirerEvent::PaymentAuthorizedOrCaptured(ev) => {
                self.apply_acquirer_payment_locked(s, ev, now_unix)
            }
            CanonicalAcquirerEvent::PaymentRefundedOrDisputed(ev) => {
                self.apply_acquirer_refund_locked(s, ev, now_unix)
            }
            CanonicalAcquirerEvent::SettlementSweepManifest(batch) => {
                self.apply_settlement_sweep_locked(s, batch, now_unix)
            }
        })
    }

    fn resolve_bank_account(
        s: &StoreSnapshot,
        adapter_id: &str,
        external_account_no: &str,
        currency: &CurrencyCode,
    ) -> Result<BankAccount> {
        s.bank_accounts
            .values()
            .find(|a| {
                a.bank_adapter_id == adapter_id
                    && a.external_account_number == external_account_no
                    && &a.currency == currency
            })
            .cloned()
            .ok_or_else(|| {
                anyhow!(
                    "no registered BankAccount for adapter='{}', external_account='{}', currency={}",
                    adapter_id,
                    external_account_no,
                    currency
                )
            })
    }

    fn resolve_merchant_profile(
        s: &StoreSnapshot,
        acquirer_id: &str,
        external_merchant_id: &str,
    ) -> Result<MerchantProfile> {
        s.merchant_profiles
            .values()
            .find(|m| {
                m.acquirer_adapter_id == acquirer_id
                    && m.external_merchant_id == external_merchant_id
            })
            .cloned()
            .ok_or_else(|| {
                anyhow!(
                    "no registered MerchantProfile for acquirer='{}', external_merchant_id='{}'",
                    acquirer_id,
                    external_merchant_id
                )
            })
    }

    fn match_counterparty_id(
        s: &StoreSnapshot,
        entity_id: &str,
        payer_account: Option<&str>,
        remittance: &str,
    ) -> Option<String> {
        let rem_upper = remittance.to_ascii_uppercase();
        for cp in s.counterparties.values() {
            if let Some(scope) = &cp.scoped_entity_id {
                if scope != entity_id {
                    continue;
                }
            }
            if let Some(pa) = payer_account {
                if cp.known_bank_accounts.iter().any(|k| k == pa) {
                    return Some(cp.counterparty_id.clone());
                }
            }
            if let Some(vpa) = &cp.paynow_uen_or_vpa {
                if !vpa.is_empty() && rem_upper.contains(&vpa.to_ascii_uppercase()) {
                    return Some(cp.counterparty_id.clone());
                }
            }
        }
        None
    }

    fn apply_bank_credit_locked(
        &self,
        s: &mut StoreSnapshot,
        mut credit: AppliedCreditEvent,
        now_unix: u64,
    ) -> Result<IngestOutcome> {
        if credit.amount.amount_minor <= 0 {
            return Err(anyhow!("AppliedCreditEvent amount must be > 0"));
        }
        let acct = Self::resolve_bank_account(
            s,
            &credit.bank_adapter_id,
            &credit.external_account_number,
            &credit.amount.currency,
        )?;
        let credit_key = format!(
            "{}:{}:{}",
            credit.bank_adapter_id, acct.account_id, credit.bank_tx_id
        );
        if s.bank_credits.contains_key(&credit_key) {
            return Ok(IngestOutcome::DuplicateIgnored { key: credit_key });
        }

        // Enrich credit from a matching initiated `DirectCollectionTracker` (e.g. OCBC `paynowcollection/1.0`)
        // when the PayNow enquiry `/ocbc/sg/corp/paynow/1.0` returns `{ AccountCurrency, AccountNo, Amount, CreditDebitIndicator }`:
        let matched_collection_ref = {
            let rem_upper = credit.remittance_info.to_ascii_uppercase();
            let tx_upper = credit.bank_tx_id.to_ascii_uppercase();
            let open_candidates: Vec<&DirectCollectionTracker> = s
                .direct_collections
                .values()
                .filter(|dc| {
                    dc.state == DirectCollectionState::InitiatedAwaitingCredit
                        && dc.account_id == acct.account_id
                        && dc.amount == credit.amount
                })
                .collect();

            let by_ref = open_candidates.iter().find(|dc| {
                let tref = dc.transaction_reference_no.to_ascii_uppercase();
                let bref = dc.bank_reference_no.to_ascii_uppercase();
                (!tref.is_empty() && (rem_upper.contains(&tref) || tx_upper.contains(&tref)))
                    || (!bref.is_empty() && (rem_upper.contains(&bref) || tx_upper.contains(&bref)))
            });

            if let Some(found) = by_ref {
                Some(found.transaction_reference_no.clone())
            } else if open_candidates.len() == 1
                && credit.structured_invoice_id.is_none()
                && credit.voucher_metadata.is_none()
                && credit.batch_or_sweep_ref.is_none()
            {
                Some(open_candidates[0].transaction_reference_no.clone())
            } else {
                None
            }
        };

        if let Some(col_key) = matched_collection_ref {
            if let Some(dc) = s.direct_collections.get_mut(&col_key) {
                if credit.structured_invoice_id.is_none() {
                    credit.structured_invoice_id = dc.structured_invoice_id;
                }
                if credit.voucher_metadata.is_none() {
                    credit.voucher_metadata = dc.voucher_metadata.clone();
                }
                if credit.remittance_info.is_empty() {
                    credit.remittance_info = dc.description.clone();
                }
                dc.state = DirectCollectionState::SettledByBankCredit {
                    credit_key: credit_key.clone(),
                    settled_at_unix: now_unix,
                };
            }
        }

        let owner = s
            .entities
            .get(&acct.owner_entity_id)
            .ok_or_else(|| anyhow!("missing AccountOwner '{}'", acct.owner_entity_id))?
            .clone();

        let matched_cp = Self::match_counterparty_id(
            s,
            &owner.entity_id,
            credit.payer_account.as_deref(),
            &credit.remittance_info,
        );

        // 1. Always enqueue Operating Bank Cash Mint (`AssetLedger.charterModuleIssue`) if entity binds an operatingBankLedger for this currency!
        self.enqueue_mint_bank_cash(
            s,
            &owner,
            &credit.amount.currency,
            credit.amount.to_hfs_micros()?,
            &credit_key,
            now_unix,
        );

        // 2. Check if this incoming bank deposit reconciles a pending `AcquirerSettlementBatch` (OCBC Card Settlement or Stripe Payout)!
        if let Some((sweep_key, match_method)) =
            Self::find_matching_pending_sweep(s, &owner.entity_id, &acct.account_id, &credit)
        {
            let finalized_count = self.reconcile_sweep_with_credit_locked(
                s,
                &owner,
                &acct,
                &sweep_key,
                &credit_key,
                &credit.bank_tx_id,
                match_method,
                false, // credit was NOT previously booked in 2900 Suspense
                now_unix,
            )?;

            s.bank_credits.insert(
                credit_key.clone(),
                BankCreditRecord {
                    credit_key: credit_key.clone(),
                    entity_id: owner.entity_id.clone(),
                    account_id: acct.account_id.clone(),
                    bank_adapter_id: credit.bank_adapter_id,
                    bank_tx_id: credit.bank_tx_id,
                    batch_or_sweep_ref: credit.batch_or_sweep_ref,
                    remittance_info: credit.remittance_info,
                    amount: credit.amount,
                    value_date: credit.value_date,
                    booked_at_unix: credit.booked_at_unix,
                    matched_counterparty_id: matched_cp,
                    matched_sweep_key: Some(sweep_key.clone()),
                    in_unallocated_suspense: false,
                },
            );

            return Ok(IngestOutcome::AppliedBankCreditProcessed {
                credit_key,
                reconciled_sweep_key: Some(sweep_key),
                finalized_payment_count: finalized_count,
                in_suspense: false,
            });
        }

        // 3. Direct Invoice Settlement (`INV-<id>`) via corporate bank wire / FAST / PayNow / GIRO
        if let Some(invoice_id) = credit.structured_invoice_id {
            let j = LedgerJournalEntry::new_balanced(
                format!("jnl_cr_inv_{}", Uuid::new_v4()),
                owner.entity_id.clone(),
                credit.amount.currency.clone(),
                format!(
                    "Direct bank credit '{}' settled AR invoice #{}",
                    credit.bank_tx_id, invoice_id
                ),
                credit_key.clone(),
                now_unix,
                vec![
                    JournalLine {
                        account: SubledgerAccountCode::CashAtBank1010,
                        side: EntrySide::Debit,
                        amount_minor: credit.amount.amount_minor,
                        sub_account_ref: Some(acct.account_id.clone()),
                    },
                    JournalLine {
                        account: SubledgerAccountCode::TradeReceivables1200,
                        side: EntrySide::Credit,
                        amount_minor: credit.amount.amount_minor,
                        sub_account_ref: Some(format!("INV-{}", invoice_id)),
                    },
                ],
            )?;
            s.journals.push(j);
            self.enqueue_settle_invoice(
                s,
                &owner,
                invoice_id,
                credit.amount.to_hfs_micros()?,
                &credit_key,
                now_unix,
            );
            s.bank_credits.insert(
                credit_key.clone(),
                BankCreditRecord {
                    credit_key: credit_key.clone(),
                    entity_id: owner.entity_id,
                    account_id: acct.account_id,
                    bank_adapter_id: credit.bank_adapter_id,
                    bank_tx_id: credit.bank_tx_id,
                    batch_or_sweep_ref: credit.batch_or_sweep_ref,
                    remittance_info: credit.remittance_info,
                    amount: credit.amount,
                    value_date: credit.value_date,
                    booked_at_unix: credit.booked_at_unix,
                    matched_counterparty_id: matched_cp,
                    matched_sweep_key: None,
                    in_unallocated_suspense: false,
                },
            );
            return Ok(IngestOutcome::AppliedBankCreditProcessed {
                credit_key,
                reconciled_sweep_key: None,
                finalized_payment_count: 1,
                in_suspense: false,
            });
        }

        // 4. Direct Bank Wire / PayNow Hardware Purchase carrying Voucher Metadata (already bank-finalized!)
        if let Some(v_meta) = &credit.voucher_metadata {
            let j = LedgerJournalEntry::new_balanced(
                format!("jnl_cr_direct_{}", Uuid::new_v4()),
                owner.entity_id.clone(),
                credit.amount.currency.clone(),
                format!(
                    "Direct finalized bank deposit '{}' for hardware SKU {}",
                    credit.bank_tx_id, v_meta.sku_code
                ),
                credit_key.clone(),
                now_unix,
                vec![
                    JournalLine {
                        account: SubledgerAccountCode::CashAtBank1010,
                        side: EntrySide::Debit,
                        amount_minor: credit.amount.amount_minor,
                        sub_account_ref: Some(acct.account_id.clone()),
                    },
                    JournalLine {
                        account: SubledgerAccountCode::RealizedOperatingRevenue4000,
                        side: EntrySide::Credit,
                        amount_minor: credit.amount.amount_minor,
                        sub_account_ref: Some(format!("SKU-{}", v_meta.sku_code)),
                    },
                ],
            )?;
            s.journals.push(j);
            self.enqueue_issue_voucher(
                s,
                &owner,
                &credit.bank_adapter_id,
                &credit.bank_tx_id,
                &credit.amount.currency,
                credit.amount.amount_minor,
                v_meta,
                now_unix,
            )?;
            s.bank_credits.insert(
                credit_key.clone(),
                BankCreditRecord {
                    credit_key: credit_key.clone(),
                    entity_id: owner.entity_id,
                    account_id: acct.account_id,
                    bank_adapter_id: credit.bank_adapter_id,
                    bank_tx_id: credit.bank_tx_id,
                    batch_or_sweep_ref: credit.batch_or_sweep_ref,
                    remittance_info: credit.remittance_info,
                    amount: credit.amount,
                    value_date: credit.value_date,
                    booked_at_unix: credit.booked_at_unix,
                    matched_counterparty_id: matched_cp,
                    matched_sweep_key: None,
                    in_unallocated_suspense: false,
                },
            );
            return Ok(IngestOutcome::AppliedBankCreditProcessed {
                credit_key,
                reconciled_sweep_key: None,
                finalized_payment_count: 1,
                in_suspense: false,
            });
        }

        // 5. Otherwise quarantine into `2900 Unattributed Cash Suspense` (`in_unallocated_suspense = true`).
        // If this bank deposit is an acquirer batch sweep whose manifest arrives later via poller/webhook,
        // `apply_settlement_sweep_locked` will automatically reclassify `2900` -> `1140` + `6250` and finalize all constituent orders!
        let j = LedgerJournalEntry::new_balanced(
            format!("jnl_cr_susp_{}", Uuid::new_v4()),
            owner.entity_id.clone(),
            credit.amount.currency.clone(),
            format!(
                "Unallocated incoming bank credit '{}' quarantined in 2900 Suspense",
                credit.bank_tx_id
            ),
            credit_key.clone(),
            now_unix,
            vec![
                JournalLine {
                    account: SubledgerAccountCode::CashAtBank1010,
                    side: EntrySide::Debit,
                    amount_minor: credit.amount.amount_minor,
                    sub_account_ref: Some(acct.account_id.clone()),
                },
                JournalLine {
                    account: SubledgerAccountCode::UnattributedCashSuspense2900,
                    side: EntrySide::Credit,
                    amount_minor: credit.amount.amount_minor,
                    sub_account_ref: Some(acct.account_id.clone()),
                },
            ],
        )?;
        s.journals.push(j);
        self.enqueue_quarantine_suspense(s, &owner, &credit_key, now_unix);

        s.bank_credits.insert(
            credit_key.clone(),
            BankCreditRecord {
                credit_key: credit_key.clone(),
                entity_id: owner.entity_id,
                account_id: acct.account_id,
                bank_adapter_id: credit.bank_adapter_id,
                bank_tx_id: credit.bank_tx_id,
                batch_or_sweep_ref: credit.batch_or_sweep_ref,
                remittance_info: credit.remittance_info,
                amount: credit.amount,
                value_date: credit.value_date,
                booked_at_unix: credit.booked_at_unix,
                matched_counterparty_id: matched_cp,
                matched_sweep_key: None,
                in_unallocated_suspense: true,
            },
        );

        Ok(IngestOutcome::AppliedBankCreditProcessed {
            credit_key,
            reconciled_sweep_key: None,
            finalized_payment_count: 0,
            in_suspense: true,
        })
    }

    fn apply_outbound_status_locked(
        &self,
        s: &mut StoreSnapshot,
        ev: OutboundPaymentStatusEvent,
        now_unix: u64,
    ) -> Result<IngestOutcome> {
        let tracker_key = if s.outbound_payments.contains_key(&ev.client_instruction_id) {
            ev.client_instruction_id.clone()
        } else if let Some(bp_id) = &ev.bank_payment_id {
            s.outbound_payments
                .values()
                .find(|t| t.bank_payment_id.as_ref() == Some(bp_id))
                .map(|t| t.client_instruction_id.clone())
                .ok_or_else(|| anyhow!("unknown outbound payment '{}'", ev.client_instruction_id))?
        } else {
            return Err(anyhow!(
                "unknown outbound client_instruction_id '{}'",
                ev.client_instruction_id
            ));
        };

        let existing = s.outbound_payments.get(&tracker_key).unwrap().clone();
        if existing.state.is_terminal() {
            if existing.state == ev.state {
                return Ok(IngestOutcome::DuplicateIgnored { key: tracker_key });
            }
            return Ok(IngestOutcome::StaleStatusIgnored {
                key: tracker_key,
                current_state: existing.state,
            });
        }
        if ev.state.progression_rank() < existing.state.progression_rank() {
            return Ok(IngestOutcome::StaleStatusIgnored {
                key: tracker_key,
                current_state: existing.state,
            });
        }
        if ev.state == existing.state
            && ev.bank_payment_id == existing.bank_payment_id
            && ev.reason_code == existing.last_reason_code
        {
            return Ok(IngestOutcome::DuplicateIgnored { key: tracker_key });
        }

        let owner = s
            .entities
            .get(&existing.entity_id)
            .ok_or_else(|| anyhow!("missing AccountOwner '{}'", existing.entity_id))?
            .clone();

        let fee_minor = ev.bank_fee_minor.max(0);

        match ev.state {
            OutboundPaymentState::Settled => {
                let mut lines = vec![JournalLine {
                    account: SubledgerAccountCode::OutboundInTransitClearing2190,
                    side: EntrySide::Debit,
                    amount_minor: existing.amount.amount_minor,
                    sub_account_ref: Some(existing.account_id.clone()),
                }];
                if fee_minor > 0 {
                    lines.push(JournalLine {
                        account: SubledgerAccountCode::BankAndAcquirerFees6250,
                        side: EntrySide::Debit,
                        amount_minor: fee_minor,
                        sub_account_ref: Some(existing.account_id.clone()),
                    });
                }
                let total_cash_out = existing.amount.amount_minor + fee_minor;
                lines.push(JournalLine {
                    account: SubledgerAccountCode::CashAtBank1010,
                    side: EntrySide::Credit,
                    amount_minor: total_cash_out,
                    sub_account_ref: Some(existing.account_id.clone()),
                });

                let j = LedgerJournalEntry::new_balanced(
                    format!("jnl_out_settled_{}", tracker_key),
                    existing.entity_id.clone(),
                    existing.amount.currency.clone(),
                    format!(
                        "Outbound payment '{}' finalized as SETTLED on account '{}'",
                        tracker_key, existing.account_id
                    ),
                    tracker_key.clone(),
                    now_unix,
                    lines,
                )?;
                s.journals.push(j);

                let cash_out_micros = existing.amount.currency.minor_to_micros(total_cash_out)?;
                self.enqueue_burn_bank_cash(
                    s,
                    &owner,
                    &existing.amount.currency,
                    cash_out_micros,
                    &format!("out_settled:{}", tracker_key),
                    now_unix,
                );
            }
            OutboundPaymentState::Failed
            | OutboundPaymentState::Rejected
            | OutboundPaymentState::Returned => {
                // Reverse 2190 In-Transit Clearing back into 2100 Trade Payables — zero cash leaves 1010!
                let j = LedgerJournalEntry::new_balanced(
                    format!("jnl_out_rev_{}", tracker_key),
                    existing.entity_id.clone(),
                    existing.amount.currency.clone(),
                    format!(
                        "Outbound payment '{}' {:?} — reversed in-transit clearing back to open payable",
                        tracker_key, ev.state
                    ),
                    tracker_key.clone(),
                    now_unix,
                    vec![
                        JournalLine {
                            account: SubledgerAccountCode::OutboundInTransitClearing2190,
                            side: EntrySide::Debit,
                            amount_minor: existing.amount.amount_minor,
                            sub_account_ref: Some(existing.account_id.clone()),
                        },
                        JournalLine {
                            account: SubledgerAccountCode::TradePayables2100,
                            side: EntrySide::Credit,
                            amount_minor: existing.amount.amount_minor,
                            sub_account_ref: existing.counterparty_id.clone(),
                        },
                    ],
                )?;
                s.journals.push(j);
            }
            OutboundPaymentState::Initiated
            | OutboundPaymentState::AcceptedByBank
            | OutboundPaymentState::InProcessing => {
                // Non-terminal progress transition; PollingSupervisor continues polling until terminal!
            }
        }

        let updated = s.outbound_payments.get_mut(&tracker_key).unwrap();
        updated.state = ev.state;
        if ev.bank_payment_id.is_some() {
            updated.bank_payment_id = ev.bank_payment_id;
        }
        if ev.end_to_end_id.is_some() {
            updated.end_to_end_id = ev.end_to_end_id;
        }
        updated.bank_fee_minor = fee_minor;
        updated.last_reason_code = ev.reason_code;
        updated.last_reason_detail = ev.reason_detail;
        updated.updated_at_unix = now_unix;

        Ok(IngestOutcome::OutboundPaymentUpdated {
            client_instruction_id: tracker_key,
            new_state: ev.state,
        })
    }

    fn apply_acquirer_payment_locked(
        &self,
        s: &mut StoreSnapshot,
        ev: AcquirerPaymentEvent,
        now_unix: u64,
    ) -> Result<IngestOutcome> {
        if ev.gross_amount.amount_minor <= 0 {
            return Err(anyhow!("acquirer payment gross_amount must be > 0"));
        }
        let merchant = Self::resolve_merchant_profile(
            s,
            &ev.acquirer_adapter_id,
            &ev.external_merchant_id,
        )?;
        let clearing_key = format!(
            "{}:{}:{}",
            ev.acquirer_adapter_id, merchant.merchant_profile_id, ev.acquirer_payment_id
        );

        if let Some(existing) = s.clearing_items.get(&clearing_key).cloned() {
            // Allow AuthorizedOnly -> CapturedPendingSweep upgrade, otherwise ignore duplicate!
            if existing.status == ClearingItemStatus::AuthorizedOnly
                && ev.stage == AcquirerPaymentStage::CapturedPendingSweep
            {
                let j = Self::build_stage1_capture_journal(
                    &merchant.owner_entity_id,
                    &merchant.merchant_profile_id,
                    &clearing_key,
                    &ev.gross_amount.currency,
                    ev.gross_amount.amount_minor,
                    now_unix,
                )?;
                s.journals.push(j);
                let item = s.clearing_items.get_mut(&clearing_key).unwrap();
                item.status = ClearingItemStatus::CapturedPendingBankSweep;
                item.estimated_fee_minor = ev.fee_minor;
                item.expected_settlement_net_minor = ev.expected_settlement_net_minor;
                item.updated_at_unix = now_unix;
                return Ok(IngestOutcome::AcquirerPaymentRecorded {
                    clearing_key,
                    stage: ev.stage,
                });
            }
            return Ok(IngestOutcome::DuplicateIgnored { key: clearing_key });
        }

        let initial_status = match ev.stage {
            AcquirerPaymentStage::AuthorizedOnly => ClearingItemStatus::AuthorizedOnly,
            AcquirerPaymentStage::CapturedPendingSweep => {
                let j = Self::build_stage1_capture_journal(
                    &merchant.owner_entity_id,
                    &merchant.merchant_profile_id,
                    &clearing_key,
                    &ev.gross_amount.currency,
                    ev.gross_amount.amount_minor,
                    now_unix,
                )?;
                s.journals.push(j);
                ClearingItemStatus::CapturedPendingBankSweep
            }
        };

        s.clearing_items.insert(
            clearing_key.clone(),
            AcquirerClearingItem {
                clearing_key: clearing_key.clone(),
                entity_id: merchant.owner_entity_id,
                merchant_profile_id: merchant.merchant_profile_id,
                acquirer_adapter_id: ev.acquirer_adapter_id,
                acquirer_payment_id: ev.acquirer_payment_id,
                order_reference: ev.order_reference,
                gross_amount: ev.gross_amount,
                estimated_fee_minor: ev.fee_minor,
                settlement_currency: ev.settlement_currency,
                expected_settlement_net_minor: ev.expected_settlement_net_minor,
                structured_invoice_id: ev.structured_invoice_id,
                voucher_metadata: ev.voucher_metadata,
                status: initial_status,
                created_at_unix: now_unix,
                updated_at_unix: now_unix,
            },
        );

        Ok(IngestOutcome::AcquirerPaymentRecorded {
            clearing_key,
            stage: ev.stage,
        })
    }

    fn build_stage1_capture_journal(
        entity_id: &str,
        merchant_profile_id: &str,
        clearing_key: &str,
        ccy: &CurrencyCode,
        gross_minor: i128,
        now_unix: u64,
    ) -> Result<LedgerJournalEntry> {
        LedgerJournalEntry::new_balanced(
            format!("jnl_acq_cap_{}", Uuid::new_v4()),
            entity_id.to_string(),
            ccy.clone(),
            format!(
                "Stage 1 payment capture '{}' booked to 1140 Acquirer Clearing (awaiting bank sweep)",
                clearing_key
            ),
            clearing_key.to_string(),
            now_unix,
            vec![
                JournalLine {
                    account: SubledgerAccountCode::AcquirerClearingReceivable1140,
                    side: EntrySide::Debit,
                    amount_minor: gross_minor,
                    sub_account_ref: Some(merchant_profile_id.to_string()),
                },
                JournalLine {
                    account: SubledgerAccountCode::UnsettledOrderClearing2450,
                    side: EntrySide::Credit,
                    amount_minor: gross_minor,
                    sub_account_ref: Some(clearing_key.to_string()),
                },
            ],
        )
    }

    fn apply_acquirer_refund_locked(
        &self,
        s: &mut StoreSnapshot,
        ev: AcquirerRefundEvent,
        now_unix: u64,
    ) -> Result<IngestOutcome> {
        let merchant = Self::resolve_merchant_profile(
            s,
            &ev.acquirer_adapter_id,
            &ev.external_merchant_id,
        )?;
        let clearing_key = format!(
            "{}:{}:{}",
            ev.acquirer_adapter_id, merchant.merchant_profile_id, ev.acquirer_payment_id
        );
        let existing = s
            .clearing_items
            .get(&clearing_key)
            .ok_or_else(|| anyhow!("cannot refund unknown clearing item '{}'", clearing_key))?
            .clone();

        match &existing.status {
            ClearingItemStatus::RefundedBeforeSweep { .. }
            | ClearingItemStatus::RefundedAfterFinality { .. }
            | ClearingItemStatus::ChargebackDisputed { .. } => {
                return Ok(IngestOutcome::DuplicateIgnored { key: clearing_key });
            }
            ClearingItemStatus::AuthorizedOnly => {
                let item = s.clearing_items.get_mut(&clearing_key).unwrap();
                item.status = ClearingItemStatus::RefundedBeforeSweep {
                    refund_id: ev.refund_id,
                    refunded_at_unix: now_unix,
                };
                item.updated_at_unix = now_unix;
                return Ok(IngestOutcome::AcquirerRefundProcessed {
                    clearing_key,
                    was_post_finality: false,
                });
            }
            ClearingItemStatus::CapturedPendingBankSweep => {
                // Reverse Stage 1 clearing (`Dr 2450 Unsettled Order Clearing`, `Cr 1140 Acquirer Clearing Receivable`).
                // Because the voucher was NEVER issued prior to bank sweep finality, zero voucher ever gets minted!
                let j = LedgerJournalEntry::new_balanced(
                    format!("jnl_acq_ref_pre_{}", Uuid::new_v4()),
                    existing.entity_id.clone(),
                    existing.gross_amount.currency.clone(),
                    format!(
                        "Pre-sweep refund '{}' reversed 1140 Acquirer Clearing for '{}'",
                        ev.refund_id, clearing_key
                    ),
                    clearing_key.clone(),
                    now_unix,
                    vec![
                        JournalLine {
                            account: SubledgerAccountCode::UnsettledOrderClearing2450,
                            side: EntrySide::Debit,
                            amount_minor: existing.gross_amount.amount_minor,
                            sub_account_ref: Some(clearing_key.clone()),
                        },
                        JournalLine {
                            account: SubledgerAccountCode::AcquirerClearingReceivable1140,
                            side: EntrySide::Credit,
                            amount_minor: existing.gross_amount.amount_minor,
                            sub_account_ref: Some(existing.merchant_profile_id.clone()),
                        },
                    ],
                )?;
                s.journals.push(j);
                let item = s.clearing_items.get_mut(&clearing_key).unwrap();
                item.status = if ev.is_chargeback {
                    ClearingItemStatus::ChargebackDisputed {
                        dispute_id: ev.refund_id,
                        disputed_at_unix: now_unix,
                    }
                } else {
                    ClearingItemStatus::RefundedBeforeSweep {
                        refund_id: ev.refund_id,
                        refunded_at_unix: now_unix,
                    }
                };
                item.updated_at_unix = now_unix;
                return Ok(IngestOutcome::AcquirerRefundProcessed {
                    clearing_key,
                    was_post_finality: false,
                });
            }
            ClearingItemStatus::BankCashFinalized { .. } => {
                // Refunded/disputed AFTER bank sweep already settled!
                // 1. Reverse realized revenue against 1140 Acquirer Clearing (acquirer deducts clawback from next sweep).
                // 2. Revoke the pre-claim 90-day SLXR hardware voucher on-chain (`revokeRefundedVoucher`)!
                let j = LedgerJournalEntry::new_balanced(
                    format!("jnl_acq_ref_post_{}", Uuid::new_v4()),
                    existing.entity_id.clone(),
                    existing.gross_amount.currency.clone(),
                    format!(
                        "Post-finality refund/chargeback '{}' booked against 4000 Revenue & 1140 Clearing",
                        ev.refund_id
                    ),
                    clearing_key.clone(),
                    now_unix,
                    vec![
                        JournalLine {
                            account: SubledgerAccountCode::RealizedOperatingRevenue4000,
                            side: EntrySide::Debit,
                            amount_minor: existing.gross_amount.amount_minor,
                            sub_account_ref: Some(clearing_key.clone()),
                        },
                        JournalLine {
                            account: SubledgerAccountCode::AcquirerClearingReceivable1140,
                            side: EntrySide::Credit,
                            amount_minor: existing.gross_amount.amount_minor,
                            sub_account_ref: Some(existing.merchant_profile_id.clone()),
                        },
                    ],
                )?;
                s.journals.push(j);

                if existing.voucher_metadata.is_some() {
                    if let Some(owner) = s.entities.get(&existing.entity_id).cloned() {
                        self.enqueue_revoke_voucher(
                            s,
                            &owner,
                            &existing.acquirer_adapter_id,
                            &existing.acquirer_payment_id,
                            now_unix,
                        );
                    }
                }

                let item = s.clearing_items.get_mut(&clearing_key).unwrap();
                item.status = if ev.is_chargeback {
                    ClearingItemStatus::ChargebackDisputed {
                        dispute_id: ev.refund_id,
                        disputed_at_unix: now_unix,
                    }
                } else {
                    ClearingItemStatus::RefundedAfterFinality {
                        refund_id: ev.refund_id,
                        refunded_at_unix: now_unix,
                    }
                };
                item.updated_at_unix = now_unix;
                return Ok(IngestOutcome::AcquirerRefundProcessed {
                    clearing_key,
                    was_post_finality: true,
                });
            }
        }
    }

    fn apply_settlement_sweep_locked(
        &self,
        s: &mut StoreSnapshot,
        batch: AcquirerSettlementBatch,
        now_unix: u64,
    ) -> Result<IngestOutcome> {
        let merchant = Self::resolve_merchant_profile(
            s,
            &batch.acquirer_adapter_id,
            &batch.external_merchant_id,
        )?;
        if batch.settlement_currency != merchant.settlement_currency {
            return Err(anyhow!(
                "sweep batch currency {} does not match merchant profile '{}' settlement currency {}",
                batch.settlement_currency,
                merchant.merchant_profile_id,
                merchant.settlement_currency
            ));
        }
        let expected_net = batch.gross_sales_minor - batch.refunds_minor - batch.total_fees_minor;
        if expected_net != batch.net_payout_minor {
            return Err(anyhow!(
                "invalid settlement sweep '{}': gross({}) - refunds({}) - fees({}) = {} != net_payout({})",
                batch.batch_id,
                batch.gross_sales_minor,
                batch.refunds_minor,
                batch.total_fees_minor,
                expected_net,
                batch.net_payout_minor
            ));
        }

        let sweep_key = format!(
            "{}:{}:{}",
            batch.acquirer_adapter_id, merchant.merchant_profile_id, batch.batch_id
        );
        if s.sweep_batches.contains_key(&sweep_key) {
            return Ok(IngestOutcome::DuplicateIgnored { key: sweep_key });
        }

        let owner = s
            .entities
            .get(&merchant.owner_entity_id)
            .ok_or_else(|| anyhow!("missing AccountOwner '{}'", merchant.owner_entity_id))?
            .clone();
        let target_acct = s
            .bank_accounts
            .get(&merchant.settlement_bank_account_id)
            .ok_or_else(|| {
                anyhow!(
                    "missing settlement bank account '{}'",
                    merchant.settlement_bank_account_id
                )
            })?
            .clone();

        s.sweep_batches.insert(
            sweep_key.clone(),
            PendingSweepRecord {
                sweep_key: sweep_key.clone(),
                entity_id: owner.entity_id.clone(),
                merchant_profile_id: merchant.merchant_profile_id.clone(),
                target_bank_account_id: target_acct.account_id.clone(),
                acquirer_adapter_id: batch.acquirer_adapter_id,
                batch_id: batch.batch_id,
                bank_statement_reference: batch.bank_statement_reference,
                settlement_currency: batch.settlement_currency,
                gross_sales_minor: batch.gross_sales_minor,
                refunds_minor: batch.refunds_minor,
                total_fees_minor: batch.total_fees_minor,
                net_payout_minor: batch.net_payout_minor,
                settlement_date: batch.settlement_date,
                lines: batch.lines,
                status: SweepBatchStatus::AwaitingBankCredit,
                created_at_unix: now_unix,
            },
        );

        // Bi-directional arrival check: did the corporate bank account `AppliedCreditEvent` ALREADY land in `2900 Suspense`?
        let sweep_snapshot = s.sweep_batches.get(&sweep_key).unwrap().clone();
        if let Some((credit_key, bank_tx_id, match_method)) =
            Self::find_matching_unallocated_bank_credit(s, &sweep_snapshot)
        {
            let finalized_count = self.reconcile_sweep_with_credit_locked(
                s,
                &owner,
                &target_acct,
                &sweep_key,
                &credit_key,
                &bank_tx_id,
                match_method,
                true, // credit WAS previously quarantined in 2900 Suspense!
                now_unix,
            )?;
            let cr = s.bank_credits.get_mut(&credit_key).unwrap();
            cr.in_unallocated_suspense = false;
            cr.matched_sweep_key = Some(sweep_key.clone());

            return Ok(IngestOutcome::SweepBatchProcessed {
                sweep_key,
                matched_bank_credit_key: Some(credit_key),
                finalized_payment_count: finalized_count,
            });
        }

        Ok(IngestOutcome::SweepBatchProcessed {
            sweep_key,
            matched_bank_credit_key: None,
            finalized_payment_count: 0,
        })
    }

    fn find_matching_pending_sweep(
        s: &StoreSnapshot,
        entity_id: &str,
        account_id: &str,
        credit: &AppliedCreditEvent,
    ) -> Option<(String, SweepMatchMethod)> {
        let rem_upper = credit.remittance_info.to_ascii_uppercase();
        let ref_upper = credit
            .batch_or_sweep_ref
            .as_deref()
            .unwrap_or("")
            .to_ascii_uppercase();

        let candidates: Vec<&PendingSweepRecord> = s
            .sweep_batches
            .values()
            .filter(|b| {
                b.status == SweepBatchStatus::AwaitingBankCredit
                    && b.entity_id == entity_id
                    && b.target_bank_account_id == account_id
                    && b.settlement_currency == credit.amount.currency
                    && b.net_payout_minor == credit.amount.amount_minor
            })
            .collect();

        // Tier 1: Deterministic statement reference / batch ID match
        for b in &candidates {
            let b_ref = b.bank_statement_reference.to_ascii_uppercase();
            let b_id = b.batch_id.to_ascii_uppercase();
            if (!b_ref.is_empty() && (ref_upper == b_ref || rem_upper.contains(&b_ref)))
                || (!b_id.is_empty() && (ref_upper == b_id || rem_upper.contains(&b_id)))
            {
                return Some((b.sweep_key.clone(), SweepMatchMethod::ExactReferenceAndAmount));
            }
        }

        // Tier 2: Unambiguous single pending sweep with exact net amount within ±5-day settlement window
        let window_matches: Vec<&&PendingSweepRecord> = candidates
            .iter()
            .filter(|b| credit.booked_at_unix.abs_diff(b.created_at_unix) <= 5 * 86_400)
            .collect();
        if window_matches.len() == 1 {
            return Some((
                window_matches[0].sweep_key.clone(),
                SweepMatchMethod::ExactAmountAndSettlementWindow,
            ));
        }

        None
    }

    fn find_matching_unallocated_bank_credit(
        s: &StoreSnapshot,
        sweep: &PendingSweepRecord,
    ) -> Option<(String, String, SweepMatchMethod)> {
        let b_ref = sweep.bank_statement_reference.to_ascii_uppercase();
        let b_id = sweep.batch_id.to_ascii_uppercase();

        let candidates: Vec<&BankCreditRecord> = s
            .bank_credits
            .values()
            .filter(|c| {
                c.in_unallocated_suspense
                    && c.entity_id == sweep.entity_id
                    && c.account_id == sweep.target_bank_account_id
                    && c.amount.currency == sweep.settlement_currency
                    && c.amount.amount_minor == sweep.net_payout_minor
            })
            .collect();

        for c in &candidates {
            let rem_upper = c.remittance_info.to_ascii_uppercase();
            let ref_upper = c
                .batch_or_sweep_ref
                .as_deref()
                .unwrap_or("")
                .to_ascii_uppercase();
            if (!b_ref.is_empty() && (ref_upper == b_ref || rem_upper.contains(&b_ref)))
                || (!b_id.is_empty() && (ref_upper == b_id || rem_upper.contains(&b_id)))
            {
                return Some((
                    c.credit_key.clone(),
                    c.bank_tx_id.clone(),
                    SweepMatchMethod::ExactReferenceAndAmount,
                ));
            }
        }

        let window_matches: Vec<&&BankCreditRecord> = candidates
            .iter()
            .filter(|c| c.booked_at_unix.abs_diff(sweep.created_at_unix) <= 5 * 86_400)
            .collect();
        if window_matches.len() == 1 {
            return Some((
                window_matches[0].credit_key.clone(),
                window_matches[0].bank_tx_id.clone(),
                SweepMatchMethod::ExactAmountAndSettlementWindow,
            ));
        }
        None
    }

    #[allow(clippy::too_many_arguments)]
    fn reconcile_sweep_with_credit_locked(
        &self,
        s: &mut StoreSnapshot,
        owner: &AccountOwner,
        acct: &BankAccount,
        sweep_key: &str,
        credit_key: &str,
        bank_tx_id: &str,
        match_method: SweepMatchMethod,
        was_in_suspense: bool,
        now_unix: u64,
    ) -> Result<usize> {
        let sweep = s.sweep_batches.get(sweep_key).unwrap().clone();
        let net_gross_after_refunds = sweep.gross_sales_minor - sweep.refunds_minor;

        // 1. Post Stage 2 Sweep Clearing-to-Bank-Cash Journal in `settlement_currency`!
        let mut sweep_lines = Vec::new();
        if was_in_suspense {
            // Reclassify previously quarantined 2900 Suspense into Acquirer Clearing settlement
            sweep_lines.push(JournalLine {
                account: SubledgerAccountCode::UnattributedCashSuspense2900,
                side: EntrySide::Debit,
                amount_minor: sweep.net_payout_minor,
                sub_account_ref: Some(acct.account_id.clone()),
            });
        } else {
            sweep_lines.push(JournalLine {
                account: SubledgerAccountCode::CashAtBank1010,
                side: EntrySide::Debit,
                amount_minor: sweep.net_payout_minor,
                sub_account_ref: Some(acct.account_id.clone()),
            });
        }
        if sweep.total_fees_minor > 0 {
            sweep_lines.push(JournalLine {
                account: SubledgerAccountCode::BankAndAcquirerFees6250,
                side: EntrySide::Debit,
                amount_minor: sweep.total_fees_minor,
                sub_account_ref: Some(sweep.merchant_profile_id.clone()),
            });
        }
        sweep_lines.push(JournalLine {
            account: SubledgerAccountCode::AcquirerClearingReceivable1140,
            side: EntrySide::Credit,
            amount_minor: net_gross_after_refunds,
            sub_account_ref: Some(sweep.merchant_profile_id.clone()),
        });

        let j_sweep = LedgerJournalEntry::new_balanced(
            format!("jnl_sweep_stl_{}", Uuid::new_v4()),
            owner.entity_id.clone(),
            sweep.settlement_currency.clone(),
            format!(
                "Reconciled acquirer sweep '{}' ({}) with bank credit '{}'",
                sweep.batch_id, sweep.acquirer_adapter_id, bank_tx_id
            ),
            sweep_key.to_string(),
            now_unix,
            sweep_lines,
        )?;
        s.journals.push(j_sweep);

        // 2. Fan out bank-cash finality across every non-refunded constituent payment in `sweep.lines`!
        let mut finalized_count = 0usize;
        for line in &sweep.lines {
            if line.is_refund {
                continue;
            }
            let clearing_key = format!(
                "{}:{}:{}",
                sweep.acquirer_adapter_id, sweep.merchant_profile_id, line.acquirer_payment_id
            );
            let Some(item) = s.clearing_items.get(&clearing_key).cloned() else {
                continue;
            };
            if item.status != ClearingItemStatus::CapturedPendingBankSweep {
                // Skip items that were refunded before sweep or already finalized
                continue;
            }

            // If presentment currency != settlement currency, bridge `1140` between presentment & settlement currencies
            if item.gross_amount.currency != sweep.settlement_currency {
                let fx_orig = LedgerJournalEntry::new_balanced(
                    format!("jnl_fx_orig_{}", Uuid::new_v4()),
                    owner.entity_id.clone(),
                    item.gross_amount.currency.clone(),
                    format!("FX clearing bridge (presentment leg) for '{}'", clearing_key),
                    clearing_key.clone(),
                    now_unix,
                    vec![
                        JournalLine {
                            account: SubledgerAccountCode::FxSettlementBridge1145,
                            side: EntrySide::Debit,
                            amount_minor: item.gross_amount.amount_minor,
                            sub_account_ref: Some(clearing_key.clone()),
                        },
                        JournalLine {
                            account: SubledgerAccountCode::AcquirerClearingReceivable1140,
                            side: EntrySide::Credit,
                            amount_minor: item.gross_amount.amount_minor,
                            sub_account_ref: Some(sweep.merchant_profile_id.clone()),
                        },
                    ],
                )?;
                let fx_stl = LedgerJournalEntry::new_balanced(
                    format!("jnl_fx_stl_{}", Uuid::new_v4()),
                    owner.entity_id.clone(),
                    sweep.settlement_currency.clone(),
                    format!("FX clearing bridge (settlement leg) for '{}'", clearing_key),
                    clearing_key.clone(),
                    now_unix,
                    vec![
                        JournalLine {
                            account: SubledgerAccountCode::AcquirerClearingReceivable1140,
                            side: EntrySide::Debit,
                            amount_minor: line.settlement_gross_minor,
                            sub_account_ref: Some(sweep.merchant_profile_id.clone()),
                        },
                        JournalLine {
                            account: SubledgerAccountCode::FxSettlementBridge1145,
                            side: EntrySide::Credit,
                            amount_minor: line.settlement_gross_minor,
                            sub_account_ref: Some(clearing_key.clone()),
                        },
                    ],
                )?;
                s.journals.push(fx_orig);
                s.journals.push(fx_stl);
            }

            // Realize constituent order: `Dr 2450 Unsettled Order Clearing` -> `Cr 1200 Trade AR` or `Cr 4000 Realized Revenue`
            let credit_target = if item.structured_invoice_id.is_some() {
                SubledgerAccountCode::TradeReceivables1200
            } else {
                SubledgerAccountCode::RealizedOperatingRevenue4000
            };
            let j_realize = LedgerJournalEntry::new_balanced(
                format!("jnl_ord_fin_{}", Uuid::new_v4()),
                owner.entity_id.clone(),
                item.gross_amount.currency.clone(),
                format!(
                    "Order '{}' finalized via bank sweep '{}'",
                    item.order_reference, sweep.batch_id
                ),
                clearing_key.clone(),
                now_unix,
                vec![
                    JournalLine {
                        account: SubledgerAccountCode::UnsettledOrderClearing2450,
                        side: EntrySide::Debit,
                        amount_minor: item.gross_amount.amount_minor,
                        sub_account_ref: Some(clearing_key.clone()),
                    },
                    JournalLine {
                        account: credit_target,
                        side: EntrySide::Credit,
                        amount_minor: item.gross_amount.amount_minor,
                        sub_account_ref: Some(item.order_reference.clone()),
                    },
                ],
            )?;
            s.journals.push(j_realize);

            if let Some(inv_id) = item.structured_invoice_id {
                self.enqueue_settle_invoice(
                    s,
                    owner,
                    inv_id,
                    item.gross_amount.to_hfs_micros()?,
                    &clearing_key,
                    now_unix,
                );
            }
            if let Some(v_meta) = &item.voucher_metadata {
                self.enqueue_issue_voucher(
                    s,
                    owner,
                    &item.acquirer_adapter_id,
                    &item.acquirer_payment_id,
                    &item.gross_amount.currency,
                    item.gross_amount.amount_minor,
                    v_meta,
                    now_unix,
                )?;
            }

            let stored_item = s.clearing_items.get_mut(&clearing_key).unwrap();
            stored_item.status = ClearingItemStatus::BankCashFinalized {
                batch_id: sweep.batch_id.clone(),
                bank_credit_key: credit_key.to_string(),
                finalized_at_unix: now_unix,
            };
            stored_item.updated_at_unix = now_unix;
            finalized_count += 1;
        }

        let stored_sweep = s.sweep_batches.get_mut(sweep_key).unwrap();
        stored_sweep.status = SweepBatchStatus::ReconciledWithBankCredit {
            bank_credit_key: credit_key.to_string(),
            bank_tx_id: bank_tx_id.to_string(),
            match_method,
            reconciled_at_unix: now_unix,
        };

        Ok(finalized_count)
    }

    fn push_outbox_deduped(
        s: &mut StoreSnapshot,
        entity_id: &str,
        dedup_key: String,
        action: OnChainSettlementKind,
        now_unix: u64,
    ) {
        if !s.outbox_dedup.insert(dedup_key.clone()) {
            return;
        }
        let task_id = format!("task_{}", Uuid::new_v4());
        s.outbox.insert(
            task_id.clone(),
            OnChainOutboxTask {
                task_id,
                entity_id: entity_id.to_string(),
                deduplication_key: dedup_key,
                action,
                state: OutboxTaskState::Pending,
                created_at_unix: now_unix,
            },
        );
    }

    fn enqueue_mint_bank_cash(
        &self,
        s: &mut StoreSnapshot,
        owner: &AccountOwner,
        ccy: &CurrencyCode,
        amount_micros: u64,
        source_key: &str,
        now_unix: u64,
    ) {
        let Some(binding) = &owner.chain_binding else {
            return;
        };
        let (Some(ledger_hex), Some(treasury_hex)) = (
            binding.operating_bank_ledgers.get(ccy),
            binding.treasury_identity_hex.as_ref(),
        ) else {
            return;
        };
        Self::push_outbox_deduped(
            s,
            &owner.entity_id,
            format!("mint_cash:{}:{}", owner.entity_id, source_key),
            OnChainSettlementKind::MintOperatingBankCash {
                operating_bank_ledger_hex: ledger_hex.clone(),
                treasury_identity_hex: treasury_hex.clone(),
                amount_micros,
            },
            now_unix,
        );
    }

    fn enqueue_burn_bank_cash(
        &self,
        s: &mut StoreSnapshot,
        owner: &AccountOwner,
        ccy: &CurrencyCode,
        amount_micros: u64,
        source_key: &str,
        now_unix: u64,
    ) {
        let Some(binding) = &owner.chain_binding else {
            return;
        };
        let (Some(ledger_hex), Some(treasury_hex)) = (
            binding.operating_bank_ledgers.get(ccy),
            binding.treasury_identity_hex.as_ref(),
        ) else {
            return;
        };
        Self::push_outbox_deduped(
            s,
            &owner.entity_id,
            format!("burn_cash:{}:{}", owner.entity_id, source_key),
            OnChainSettlementKind::BurnOperatingBankCash {
                operating_bank_ledger_hex: ledger_hex.clone(),
                treasury_identity_hex: treasury_hex.clone(),
                amount_micros,
            },
            now_unix,
        );
    }

    fn enqueue_settle_invoice(
        &self,
        s: &mut StoreSnapshot,
        owner: &AccountOwner,
        invoice_id: u64,
        amount_micros: u64,
        source_key: &str,
        now_unix: u64,
    ) {
        let Some(binding) = &owner.chain_binding else {
            return;
        };
        let Some(ifrs_hex) = &binding.ifrs_accounting_ledger_hex else {
            return;
        };
        Self::push_outbox_deduped(
            s,
            &owner.entity_id,
            format!("settle_inv:{}:{}:{}", owner.entity_id, invoice_id, source_key),
            OnChainSettlementKind::SettleIfrsCreditInvoice {
                accounting_ledger_hex: ifrs_hex.clone(),
                invoice_id,
                amount_micros,
            },
            now_unix,
        );
    }

    fn enqueue_quarantine_suspense(
        &self,
        s: &mut StoreSnapshot,
        owner: &AccountOwner,
        source_key: &str,
        now_unix: u64,
    ) {
        let Some(binding) = &owner.chain_binding else {
            return;
        };
        let Some(ifrs_hex) = &binding.ifrs_accounting_ledger_hex else {
            return;
        };
        Self::push_outbox_deduped(
            s,
            &owner.entity_id,
            format!("suspense:{}:{}", owner.entity_id, source_key),
            OnChainSettlementKind::QuarantineIfrsSuspense {
                accounting_ledger_hex: ifrs_hex.clone(),
            },
            now_unix,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn enqueue_issue_voucher(
        &self,
        s: &mut StoreSnapshot,
        owner: &AccountOwner,
        rail: &str,
        external_payment_id: &str,
        ccy: &CurrencyCode,
        amount_minor: i128,
        v_meta: &VoucherOrderMetadata,
        now_unix: u64,
    ) -> Result<()> {
        let Some(binding) = &owner.chain_binding else {
            return Ok(());
        };
        let Some(rv_hex) = &binding.reward_voucher_hfs_hex else {
            return Ok(());
        };
        let price_usd_micros = if let Some(explicit) = v_meta.explicit_price_usd_micros {
            explicit
        } else if ccy == &CurrencyCode::usd() {
            ccy.minor_to_micros(amount_minor)?
        } else if let Some(&fx_ppm) = binding.fx_to_usd_ppm.get(ccy) {
            let local_micros = ccy.minor_to_micros(amount_minor)? as u128;
            ((local_micros * fx_ppm as u128) / 1_000_000u128) as u64
        } else {
            // Default to canonical SKU floor price inside `RewardVoucher` HFS (`0` instructs HFS to use catalog floor)
            0
        };

        let ref_hash = compute_salted_payment_ref_hash(
            &self.domain_salt,
            &owner.entity_id,
            rail,
            external_payment_id,
        );
        let ref_hash_hex = format!("0x{}", hex::encode(ref_hash));

        Self::push_outbox_deduped(
            s,
            &owner.entity_id,
            format!("voucher_issue:{}", ref_hash_hex),
            OnChainSettlementKind::IssuePaidHardwareVoucher {
                reward_voucher_hfs_hex: rv_hex.clone(),
                payment_ref_hash_hex: ref_hash_hex,
                sku_code: v_meta.sku_code,
                tier_bps: v_meta.tier_bps,
                price_usd_micros,
                voucher_commitment_hex: v_meta.voucher_commitment_hex.clone(),
            },
            now_unix,
        );
        Ok(())
    }

    fn enqueue_revoke_voucher(
        &self,
        s: &mut StoreSnapshot,
        owner: &AccountOwner,
        rail: &str,
        external_payment_id: &str,
        now_unix: u64,
    ) {
        let Some(binding) = &owner.chain_binding else {
            return;
        };
        let Some(rv_hex) = &binding.reward_voucher_hfs_hex else {
            return;
        };
        let ref_hash = compute_salted_payment_ref_hash(
            &self.domain_salt,
            &owner.entity_id,
            rail,
            external_payment_id,
        );
        let ref_hash_hex = format!("0x{}", hex::encode(ref_hash));
        Self::push_outbox_deduped(
            s,
            &owner.entity_id,
            format!("voucher_revoke:{}", ref_hash_hex),
            OnChainSettlementKind::RevokeRefundedHardwareVoucher {
                reward_voucher_hfs_hex: rv_hex.clone(),
                payment_ref_hash_hex: ref_hash_hex,
            },
            now_unix,
        );
    }
}
