//! Transactional Outbox Relayer (`ChainOutboxRelayer`) -> SuperLexicon L1 / EVM JSON-RPC.
//!
//! Drains finalized `OnChainOutboxTask`s per `AccountOwner`, signing each transaction with that
//! entity's configured `secp256k1` oracle key (`$0.00` gas on SuperLexicon L1) and broadcasting
//! via `eth_sendRawTransaction` with automatic retry persistence if an RPC node is temporarily unreachable.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use ethereum_types::{Address, U256};
use serde_json::json;
use tokio::sync::{watch, Mutex};

use crate::crypto::{hfs_abi, parse_address20, parse_bytes32, L1TransactionSigner};
use crate::domain::ledger::{OnChainOutboxTask, OnChainSettlementKind, OutboxTaskState};
use crate::ports::http_transport::{HttpMethod, HttpTransport, OutboundHttpRequest};
use crate::ports::store::OracleStore;

pub struct ChainOutboxRelayer {
    store: Arc<OracleStore>,
    transport: Arc<dyn HttpTransport>,
    rpc_url: String,
    submit_lock: Mutex<()>,
}

impl ChainOutboxRelayer {
    pub fn new(
        store: Arc<OracleStore>,
        transport: Arc<dyn HttpTransport>,
        rpc_url: String,
    ) -> Self {
        Self {
            store,
            transport,
            rpc_url,
            submit_lock: Mutex::new(()),
        }
    }

    async fn json_rpc(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }))?;
        let resp = self
            .transport
            .execute(OutboundHttpRequest {
                method: HttpMethod::Post,
                url: self.rpc_url.clone(),
                headers: vec![("Content-Type".into(), "application/json".into())],
                body,
            })
            .await?;
        if !resp.is_success() {
            return Err(anyhow!("JSON-RPC HTTP status {}", resp.status));
        }
        let val: serde_json::Value = resp.json()?;
        if let Some(err) = val.get("error") {
            if !err.is_null() {
                return Err(anyhow!("JSON-RPC error: {}", err));
            }
        }
        Ok(val["result"].clone())
    }

    fn build_target_and_calldata(
        action: &OnChainSettlementKind,
    ) -> Result<(Address, Vec<u8>, Vec<Address>)> {
        match action {
            OnChainSettlementKind::MintOperatingBankCash {
                operating_bank_ledger_hex,
                treasury_identity_hex,
                amount_micros,
            } => {
                let to = parse_address20(operating_bank_ledger_hex)?;
                let treas = parse_address20(treasury_identity_hex)?;
                Ok((
                    to,
                    hfs_abi::encode_operating_bank_issue(treas, *amount_micros),
                    vec![treas],
                ))
            }
            OnChainSettlementKind::BurnOperatingBankCash {
                operating_bank_ledger_hex,
                treasury_identity_hex,
                amount_micros,
            } => {
                let to = parse_address20(operating_bank_ledger_hex)?;
                let treas = parse_address20(treasury_identity_hex)?;
                Ok((
                    to,
                    hfs_abi::encode_operating_bank_cancel(treas, *amount_micros),
                    vec![treas],
                ))
            }
            OnChainSettlementKind::SettleIfrsCreditInvoice {
                accounting_ledger_hex,
                invoice_id,
                amount_micros,
            } => {
                let to = parse_address20(accounting_ledger_hex)?;
                Ok((
                    to,
                    hfs_abi::encode_ifrs_settle_invoice(*invoice_id, *amount_micros),
                    vec![],
                ))
            }
            OnChainSettlementKind::QuarantineIfrsSuspense {
                accounting_ledger_hex,
            } => {
                let to = parse_address20(accounting_ledger_hex)?;
                Ok((to, hfs_abi::encode_ifrs_quarantine_suspense(), vec![]))
            }
            OnChainSettlementKind::IssuePaidHardwareVoucher {
                reward_voucher_hfs_hex,
                payment_ref_hash_hex,
                sku_code,
                tier_bps,
                price_usd_micros,
                voucher_commitment_hex,
            } => {
                let to = parse_address20(reward_voucher_hfs_hex)?;
                let ref_hash = parse_bytes32(payment_ref_hash_hex)?;
                let commit = parse_bytes32(voucher_commitment_hex)?;
                Ok((
                    to,
                    hfs_abi::encode_issue_paid_voucher(
                        &ref_hash,
                        *sku_code,
                        *tier_bps,
                        *price_usd_micros,
                        &commit,
                    ),
                    vec![],
                ))
            }
            OnChainSettlementKind::RevokeRefundedHardwareVoucher {
                reward_voucher_hfs_hex,
                payment_ref_hash_hex,
            } => {
                let to = parse_address20(reward_voucher_hfs_hex)?;
                let ref_hash = parse_bytes32(payment_ref_hash_hex)?;
                Ok((to, hfs_abi::encode_revoke_refunded_voucher(&ref_hash), vec![]))
            }
        }
    }

    async fn submit_single_task(&self, task: &OnChainOutboxTask, now_unix: u64) -> Result<String> {
        let binding = self.store.read(|s| {
            s.entities
                .get(&task.entity_id)
                .and_then(|e| e.chain_binding.clone())
        });
        let binding = binding.ok_or_else(|| {
            anyhow!(
                "AccountOwner '{}' has no EntityChainBinding configured",
                task.entity_id
            )
        })?;

        let signer = L1TransactionSigner::new(
            &binding.oracle_private_key_hex,
            binding.chain_id,
            binding.wire_format,
        )?;
        let sender_hex = format!("0x{}", hex::encode(signer.sender_address().as_bytes()));
        let nonce_res = self
            .json_rpc("eth_getTransactionCount", json!([sender_hex, "latest"]))
            .await?;
        let nonce_str = nonce_res
            .as_str()
            .unwrap_or("0x0")
            .trim_start_matches("0x");
        let nonce = u64::from_str_radix(if nonce_str.is_empty() { "0" } else { nonce_str }, 16)
            .unwrap_or(0);

        let (to, calldata, extra_targets) = Self::build_target_and_calldata(&task.action)?;
        let raw_tx = signer.sign_contract_call(
            nonce,
            to,
            &calldata,
            U256::zero(), // $0.00 gas on SuperLexicon L1
            U256::from(3_000_000u64),
            &extra_targets,
        )?;

        let tx_hash_val = self
            .json_rpc("eth_sendRawTransaction", json!([raw_tx]))
            .await?;
        let tx_hash = tx_hash_val
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| tx_hash_val.to_string());

        self.store.write(|s| {
            if let Some(t) = s.outbox.get_mut(&task.task_id) {
                t.state = OutboxTaskState::Submitted {
                    tx_hash: tx_hash.clone(),
                    submitted_at_unix: now_unix,
                };
            }
            Ok(())
        })?;

        Ok(tx_hash)
    }

    /// Flush all currently pending or retryable outbox tasks to the blockchain node.
    pub async fn flush_pending_outbox(&self, now_unix: u64) -> usize {
        let _guard = self.submit_lock.lock().await;
        let tasks = self.store.pending_outbox_tasks();
        let mut submitted = 0usize;

        for task in tasks {
            match self.submit_single_task(&task, now_unix).await {
                Ok(_) => submitted += 1,
                Err(e) => {
                    let prev_attempts = match &task.state {
                        OutboxTaskState::FailedRetryable { attempts, .. } => *attempts,
                        _ => 0,
                    };
                    let _ = self.store.write(|s| {
                        if let Some(t) = s.outbox.get_mut(&task.task_id) {
                            t.state = OutboxTaskState::FailedRetryable {
                                attempts: prev_attempts + 1,
                                last_error: e.to_string(),
                            };
                        }
                        Ok(())
                    });
                }
            }
        }
        submitted
    }

    pub fn spawn_background_loop(
        self: Arc<Self>,
        interval_secs: u64,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs.max(2)));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        let _ = self.flush_pending_outbox(now).await;
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
}
