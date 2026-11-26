//! Airwallex Multi-Currency Global Accounts, Deposits & Transfers Adapter (`AirwallexBankAdapter`).
//!
//! Implements `BankTechnicalAdapter` over Airwallex's v1 Core Banking & Payout REST APIs:
//! - `GET  /api/v1/deposits` (`status=SETTLED`: incoming SGD `FAST`/`PayNow`, USD `ACH`/`Fedwire`,
//!   EUR `SEPA`, GBP `Faster Payments`, and internal Airwallex card-settlement wallet credits)
//! - `POST /api/v1/transfers/create` (automated domestic `FAST` & cross-border `LOCAL`/`SWIFT` payouts)
//! - `GET  /api/v1/transfers/{id}` (outbound payout status & fee inquiry)
//! - `POST /api/v1/deposits/create` (`DIRECT_DEBIT` pull collections)
//! - Authenticated `x-timestamp` + `x-signature` (`HMAC-SHA256`) webhooks.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use axum::http::HeaderMap;
use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::adapters::airwallex_auth::{
    derive_airwallex_request_id, extract_structured_invoice_id, money_to_airwallex_major_number,
    parse_airwallex_major_to_minor, parse_airwallex_timestamp_secs,
    parse_airwallex_voucher_metadata, verify_airwallex_webhook, AirwallexAuthConfig,
    AirwallexTokenManager,
};
use crate::domain::entities::BankAccount;
use crate::domain::events::{
    AppliedCreditEvent, CanonicalBankEvent, IngestionSource, OutboundPaymentState,
    OutboundPaymentStatusEvent, TransferRail,
};
use crate::domain::ledger::OutboundPaymentTracker;
use crate::domain::money::{CurrencyCode, Money};
use crate::ports::bank_adapter::{
    AccountPollCursor, BankTechnicalAdapter, DirectCollectionInstruction, DirectCollectionReceipt,
    IncomingPollBatch, OutboundPaymentInstruction, OutboundSubmissionReceipt,
};
use crate::ports::http_transport::{HttpMethod, HttpTransport, OutboundHttpRequest};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AirwallexBankConfig {
    pub adapter_id: String,
    #[serde(default)]
    pub auth: AirwallexAuthConfig,
}

impl Default for AirwallexBankConfig {
    fn default() -> Self {
        Self {
            adapter_id: "airwallex_bank".into(),
            auth: AirwallexAuthConfig::default(),
        }
    }
}

pub struct AirwallexBankAdapter {
    cfg: AirwallexBankConfig,
    token_mgr: Arc<AirwallexTokenManager>,
    transport: Arc<dyn HttpTransport>,
}

impl AirwallexBankAdapter {
    pub fn new(
        cfg: AirwallexBankConfig,
        token_mgr: Arc<AirwallexTokenManager>,
        transport: Arc<dyn HttpTransport>,
    ) -> Self {
        Self {
            cfg,
            token_mgr,
            transport,
        }
    }

    pub fn with_own_token_manager(
        cfg: AirwallexBankConfig,
        transport: Arc<dyn HttpTransport>,
    ) -> Self {
        let mgr = Arc::new(AirwallexTokenManager::new(cfg.auth.clone(), transport.clone()));
        Self::new(cfg, mgr, transport)
    }

    fn map_clearing_system_to_rail(raw: &str) -> TransferRail {
        match raw.trim().to_ascii_uppercase().as_str() {
            "FAST" => TransferRail::Fast,
            "PAYNOW" => TransferRail::PayNow,
            "GIRO" => TransferRail::Giro,
            "MEPS" | "MEPS_PLUS" => TransferRail::MepsPlus,
            "SWIFT" => TransferRail::SwiftGpi,
            "SEPA" | "SEPA_INSTANT" => TransferRail::Sepa,
            "FEDWIRE" | "ACH" | "ABA" => TransferRail::Fedwire,
            "SETTLEMENT" | "PA_SETTLEMENT" | "ACQUIRER_SWEEP" => {
                TransferRail::AcquirerSettlementSweep
            }
            "BOOK" | "WALLET" | "INTERNAL" => TransferRail::InternalBook,
            other if !other.is_empty() => TransferRail::Other(other.to_string()),
            _ => TransferRail::Fast,
        }
    }

    fn map_rail_to_transfer_method(rail: &TransferRail) -> &'static str {
        match rail {
            TransferRail::SwiftGpi => "SWIFT",
            _ => "LOCAL",
        }
    }

    fn map_transfer_status(status: &str) -> OutboundPaymentState {
        match status.trim().to_ascii_uppercase().as_str() {
            "NEW" | "CREATED" | "PENDING_APPROVAL" => OutboundPaymentState::AcceptedByBank,
            "PROCESSING" | "SENT" | "IN_TRANSIT" => OutboundPaymentState::InProcessing,
            "PAID" | "SETTLED" | "COMPLETED" | "SUCCEEDED" => OutboundPaymentState::Settled,
            "FAILED" => OutboundPaymentState::Failed,
            "CANCELLED" | "REJECTED" => OutboundPaymentState::Rejected,
            "REFUNDED" | "RETURNED" => OutboundPaymentState::Returned,
            _ => OutboundPaymentState::InProcessing,
        }
    }

    fn parse_deposit_to_credit(
        &self,
        fallback_account_no: Option<&str>,
        obj: &Value,
        source: IngestionSource,
        now_unix_secs: u64,
    ) -> Result<AppliedCreditEvent> {
        let tx_id = obj["id"]
            .as_str()
            .ok_or_else(|| anyhow!("missing 'id' in Airwallex deposit/credit object"))?
            .to_string();
        let ccy = CurrencyCode::new(obj["currency"].as_str().unwrap_or("USD"))?;
        let amount_val = if !obj["settled_amount"].is_null() {
            &obj["settled_amount"]
        } else {
            &obj["amount"]
        };
        let amount_minor = parse_airwallex_major_to_minor(amount_val, &ccy)?;
        if amount_minor <= 0 {
            return Err(anyhow!(
                "Airwallex deposit '{}' has non-positive amount {}",
                tx_id,
                amount_minor
            ));
        }

        let ext_acct = obj["global_account_id"]
            .as_str()
            .or_else(|| obj["account_number"].as_str())
            .or_else(|| obj["wallet_account_id"].as_str())
            .or(fallback_account_no)
            .ok_or_else(|| {
                anyhow!(
                    "missing 'global_account_id' / 'account_number' in Airwallex deposit '{}'",
                    tx_id
                )
            })?
            .to_string();

        let source_type = obj["source_type"]
            .as_str()
            .or_else(|| obj["clearing_system"].as_str())
            .or_else(|| obj["deposit_type"].as_str())
            .unwrap_or("FAST");
        let rail = Self::map_clearing_system_to_rail(source_type);

        let reference = obj["reference"]
            .as_str()
            .or_else(|| obj["remittance_information"].as_str())
            .or_else(|| obj["description"].as_str())
            .unwrap_or("")
            .to_string();
        let batch_ref = obj["settlement_batch_id"]
            .as_str()
            .or_else(|| obj["batch_id"].as_str())
            .or_else(|| {
                if matches!(rail, TransferRail::AcquirerSettlementSweep) && !reference.is_empty() {
                    Some(reference.as_str())
                } else {
                    None
                }
            })
            .map(String::from);

        let booked_at = obj["settled_at"]
            .as_str()
            .or_else(|| obj["created_at"].as_str())
            .and_then(parse_airwallex_timestamp_secs)
            .unwrap_or(now_unix_secs);
        let value_date = obj["settled_at"]
            .as_str()
            .or_else(|| obj["created_at"].as_str())
            .unwrap_or("2026-11-26")
            .chars()
            .take(10)
            .collect::<String>();

        let payer_name = obj["payer"]["name"]
            .as_str()
            .or_else(|| obj["sender"]["name"].as_str())
            .map(String::from);
        let payer_acct = obj["payer"]["account_number"]
            .as_str()
            .or_else(|| obj["sender"]["account_number"].as_str())
            .map(String::from);

        let invoice_id = obj["metadata"]["invoice_id"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .or_else(|| extract_structured_invoice_id(&reference));
        let voucher_meta = parse_airwallex_voucher_metadata(&obj["metadata"])?;

        Ok(AppliedCreditEvent {
            bank_adapter_id: self.cfg.adapter_id.clone(),
            external_account_number: ext_acct,
            bank_tx_id: tx_id,
            end_to_end_id: obj["provider_transaction_id"]
                .as_str()
                .or_else(|| (!reference.is_empty()).then_some(reference.as_str()))
                .map(String::from),
            batch_or_sweep_ref: batch_ref,
            rail,
            amount: Money::new(amount_minor, ccy),
            value_date,
            booked_at_unix: booked_at,
            remittance_info: reference,
            payer_name,
            payer_account: payer_acct,
            structured_invoice_id: invoice_id,
            voucher_metadata: voucher_meta,
            running_balance_minor: None,
            source,
        })
    }

    fn parse_transfer_to_status(
        &self,
        fallback_account_no: Option<&str>,
        fallback_client_id: Option<&str>,
        fallback_rail: Option<TransferRail>,
        obj: &Value,
        source: IngestionSource,
        now_unix_secs: u64,
    ) -> Result<OutboundPaymentStatusEvent> {
        let transfer_id = obj["id"]
            .as_str()
            .ok_or_else(|| anyhow!("missing 'id' in Airwallex transfer object"))?
            .to_string();
        let ccy_str = obj["source_currency"]
            .as_str()
            .or_else(|| obj["transfer_currency"].as_str())
            .unwrap_or("USD");
        let ccy = CurrencyCode::new(ccy_str)?;
        let amt_val = if !obj["source_amount"].is_null() {
            &obj["source_amount"]
        } else {
            &obj["transfer_amount"]
        };
        let amount_minor = parse_airwallex_major_to_minor(amt_val, &ccy)?;
        let fee_minor = if !obj["fee_amount"].is_null() {
            parse_airwallex_major_to_minor(&obj["fee_amount"], &ccy).unwrap_or(0)
        } else {
            0
        };

        let ext_acct = obj["source_account_id"]
            .as_str()
            .or_else(|| obj["global_account_id"].as_str())
            .or_else(|| obj["metadata"]["external_account_number"].as_str())
            .or(fallback_account_no)
            .ok_or_else(|| {
                anyhow!(
                    "missing 'source_account_id' in Airwallex transfer '{}'",
                    transfer_id
                )
            })?
            .to_string();

        let client_instr_id = obj["metadata"]["client_instruction_id"]
            .as_str()
            .or_else(|| obj["reference"].as_str())
            .or(fallback_client_id)
            .unwrap_or(&transfer_id)
            .to_string();

        let state = Self::map_transfer_status(obj["status"].as_str().unwrap_or("PROCESSING"));
        let rail = fallback_rail.unwrap_or_else(|| {
            let method = obj["transfer_method"].as_str().unwrap_or("LOCAL");
            if method.eq_ignore_ascii_case("SWIFT") {
                TransferRail::SwiftGpi
            } else {
                TransferRail::Fast
            }
        });

        Ok(OutboundPaymentStatusEvent {
            bank_adapter_id: self.cfg.adapter_id.clone(),
            external_account_number: ext_acct,
            client_instruction_id: client_instr_id,
            bank_payment_id: Some(transfer_id),
            end_to_end_id: obj["short_reference_id"].as_str().map(String::from),
            rail,
            state,
            amount: Money::new(amount_minor, ccy),
            bank_fee_minor: fee_minor,
            reason_code: obj["failure_type"].as_str().map(String::from),
            reason_detail: obj["failure_reason"].as_str().map(String::from),
            updated_at_unix: now_unix_secs,
            source,
        })
    }
}

#[async_trait]
impl BankTechnicalAdapter for AirwallexBankAdapter {
    fn adapter_id(&self) -> &str {
        &self.cfg.adapter_id
    }

    fn bank_name(&self) -> &str {
        "Airwallex Global Accounts & Multi-Currency Wallet"
    }

    async fn verify_and_parse_webhook(
        &self,
        headers: &HeaderMap,
        raw_body: &[u8],
        now_unix_secs: u64,
    ) -> Result<Vec<CanonicalBankEvent>> {
        verify_airwallex_webhook(
            headers,
            raw_body,
            &self.token_mgr.config().webhook_secret,
            now_unix_secs,
            self.token_mgr.config().max_webhook_skew_secs,
        )?;

        let doc: Value = serde_json::from_slice(raw_body)?;
        let ev_name = doc["name"].as_str().unwrap_or("");
        let obj = if doc["data"]["object"].is_object() {
            &doc["data"]["object"]
        } else {
            &doc["data"]
        };

        match ev_name {
            "deposit.settled"
            | "global_account.transaction.succeeded"
            | "financial_transaction.settled" => {
                let status = obj["status"].as_str().unwrap_or("SETTLED");
                if !status.eq_ignore_ascii_case("SETTLED")
                    && !status.eq_ignore_ascii_case("SUCCEEDED")
                {
                    return Ok(vec![]);
                }
                let credit = self.parse_deposit_to_credit(
                    None,
                    obj,
                    IngestionSource::WebhookPush,
                    now_unix_secs,
                )?;
                Ok(vec![CanonicalBankEvent::AppliedCredit(credit)])
            }
            "transfer.new"
            | "transfer.processing"
            | "transfer.paid"
            | "transfer.settled"
            | "transfer.failed"
            | "transfer.cancelled"
            | "transfer.refunded" => {
                let st = self.parse_transfer_to_status(
                    None,
                    None,
                    None,
                    obj,
                    IngestionSource::WebhookPush,
                    now_unix_secs,
                )?;
                Ok(vec![CanonicalBankEvent::OutboundStatusChanged(st)])
            }
            _ => Ok(vec![]),
        }
    }

    async fn poll_incoming_transactions(
        &self,
        account: &BankAccount,
        cursor: &AccountPollCursor,
        now_unix_secs: u64,
    ) -> Result<IncomingPollBatch> {
        let from_iso = Utc
            .timestamp_opt(cursor.last_polled_unix as i64, 0)
            .single()
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| "1970-01-01T00:00:00Z".into());
        let url = format!(
            "{}/api/v1/deposits?status=SETTLED&from_created_at={}",
            self.token_mgr.base_url(),
            from_iso
        );
        let headers = self
            .token_mgr
            .auth_headers(None, false, now_unix_secs)
            .await?;
        let resp = self
            .transport
            .execute(OutboundHttpRequest {
                method: HttpMethod::Get,
                url,
                headers,
                body: vec![],
            })
            .await?;

        if !resp.is_success() {
            return Err(anyhow!(
                "Airwallex deposits poll for '{}' failed with HTTP {}",
                account.external_account_number,
                resp.status
            ));
        }

        let doc: Value = resp.json()?;
        let items = doc["items"]
            .as_array()
            .or_else(|| doc["data"].as_array())
            .cloned()
            .unwrap_or_default();

        let mut credits = Vec::new();
        for item in &items {
            if let Some(item_ccy) = item["currency"].as_str() {
                if !item_ccy.eq_ignore_ascii_case(account.currency.as_str()) {
                    continue;
                }
            }
            if let Some(ga_id) = item["global_account_id"]
                .as_str()
                .or_else(|| item["account_number"].as_str())
            {
                if ga_id != account.external_account_number {
                    continue;
                }
            }
            if let Ok(credit) = self.parse_deposit_to_credit(
                Some(&account.external_account_number),
                item,
                IngestionSource::PeriodicPoll,
                now_unix_secs,
            ) {
                credits.push(credit);
            }
        }

        Ok(IncomingPollBatch {
            applied_credits: credits,
            next_cursor: AccountPollCursor {
                last_polled_unix: now_unix_secs,
                cursor_token: None,
            },
        })
    }

    async fn initiate_outbound_payment(
        &self,
        account: &BankAccount,
        instruction: &OutboundPaymentInstruction,
        now_unix_secs: u64,
    ) -> Result<OutboundSubmissionReceipt> {
        let url = format!("{}/api/v1/transfers/create", self.token_mgr.base_url());
        let request_id = derive_airwallex_request_id(
            "transfer_create",
            &account.external_account_number,
            &instruction.client_instruction_id,
        );
        let transfer_method = Self::map_rail_to_transfer_method(&instruction.rail);

        let mut payload = json!({
            "request_id": request_id,
            "reference": instruction.remittance_info,
            "reason": "supplier_or_operating_payment",
            "source_currency": account.currency.as_str(),
            "transfer_currency": instruction.amount.currency.as_str(),
            "transfer_amount": money_to_airwallex_major_number(&instruction.amount),
            "transfer_method": transfer_method,
            "metadata": {
                "client_instruction_id": instruction.client_instruction_id,
                "external_account_number": account.external_account_number,
            }
        });
        if let Some(ref vd) = instruction.value_date {
            payload["transfer_date"] = json!(vd);
        }

        if let Some(ref cp_id) = instruction.counterparty_id {
            if cp_id.starts_with("bene_") || cp_id.starts_with("ben_") {
                payload["beneficiary_id"] = json!(cp_id);
            }
        }
        if payload.get("beneficiary_id").is_none() {
            let mut bank_details = json!({
                "account_name": instruction.beneficiary_name,
                "account_number": instruction.beneficiary_account,
                "account_currency": instruction.amount.currency.as_str(),
            });
            if let Some(ref bic) = instruction.beneficiary_bank_bic {
                bank_details["swift_code"] = json!(bic);
            }
            if let Some(ref bname) = instruction.beneficiary_bank_name {
                bank_details["bank_name"] = json!(bname);
            }
            payload["beneficiary"] = json!({
                "entity_type": "COMPANY",
                "company_name": instruction.beneficiary_name,
                "bank_details": bank_details,
            });
        }

        let headers = self
            .token_mgr
            .auth_headers(None, true, now_unix_secs)
            .await?;
        let resp = self
            .transport
            .execute(OutboundHttpRequest {
                method: HttpMethod::Post,
                url,
                headers,
                body: serde_json::to_vec(&payload)?,
            })
            .await?;

        if !resp.is_success() {
            return Err(anyhow!(
                "Airwallex transfers/create failed with HTTP {}: {}",
                resp.status,
                String::from_utf8_lossy(&resp.body)
            ));
        }

        let val: Value = resp.json()?;
        let initial_state =
            Self::map_transfer_status(val["status"].as_str().unwrap_or("NEW"));
        Ok(OutboundSubmissionReceipt {
            bank_payment_id: val["id"].as_str().map(String::from),
            end_to_end_id: val["short_reference_id"].as_str().map(String::from),
            value_date: val["transfer_date"].as_str().map(String::from),
            initial_state,
        })
    }

    async fn poll_outbound_payment_status(
        &self,
        account: &BankAccount,
        tracker: &OutboundPaymentTracker,
        now_unix_secs: u64,
    ) -> Result<OutboundPaymentStatusEvent> {
        let transfer_id = tracker
            .bank_payment_id
            .as_deref()
            .unwrap_or(&tracker.client_instruction_id);
        let url = format!(
            "{}/api/v1/transfers/{}",
            self.token_mgr.base_url(),
            transfer_id
        );
        let headers = self
            .token_mgr
            .auth_headers(None, false, now_unix_secs)
            .await?;
        let resp = self
            .transport
            .execute(OutboundHttpRequest {
                method: HttpMethod::Get,
                url,
                headers,
                body: vec![],
            })
            .await?;

        if !resp.is_success() {
            return Err(anyhow!(
                "Airwallex transfers/{} poll failed with HTTP {}",
                transfer_id,
                resp.status
            ));
        }

        let val: Value = resp.json()?;
        self.parse_transfer_to_status(
            Some(&account.external_account_number),
            Some(&tracker.client_instruction_id),
            Some(tracker.rail.clone()),
            &val,
            IngestionSource::PeriodicPoll,
            now_unix_secs,
        )
    }

    async fn initiate_direct_collection(
        &self,
        account: &BankAccount,
        instruction: &DirectCollectionInstruction,
        now_unix_secs: u64,
    ) -> Result<DirectCollectionReceipt> {
        let url = format!("{}/api/v1/deposits/create", self.token_mgr.base_url());
        let request_id = derive_airwallex_request_id(
            "deposit_dd",
            &account.external_account_number,
            &instruction.transaction_reference_no,
        );
        let payload = json!({
            "request_id": request_id,
            "deposit_type": "DIRECT_DEBIT",
            "amount": money_to_airwallex_major_number(&instruction.amount),
            "currency": instruction.amount.currency.as_str(),
            "linked_account_id": instruction.payer_proxy_value,
            "mandate_id": instruction.dda_reference_no,
            "reference": instruction.description,
        });
        let headers = self
            .token_mgr
            .auth_headers(None, true, now_unix_secs)
            .await?;
        let resp = self
            .transport
            .execute(OutboundHttpRequest {
                method: HttpMethod::Post,
                url,
                headers,
                body: serde_json::to_vec(&payload)?,
            })
            .await?;

        if !resp.is_success() {
            return Err(anyhow!(
                "Airwallex deposits/create failed with HTTP {}: {}",
                resp.status,
                String::from_utf8_lossy(&resp.body)
            ));
        }

        let val: Value = resp.json()?;
        Ok(DirectCollectionReceipt {
            transaction_reference_no: instruction.transaction_reference_no.clone(),
            bank_reference_no: val["id"]
                .as_str()
                .unwrap_or(&instruction.transaction_reference_no)
                .to_string(),
            description: instruction.description.clone(),
        })
    }
}
