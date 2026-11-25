//! Generic ISO 20022 Corporate Banking Adapter (`Iso20022BankAdapter`).
//!
//! Reusable across ISO 20022 JSON corporate gateways (e.g., DBS RAPID, Standard Chartered Straight2Bank,
//! HSBCnet, CitiConnect, SEPA gateways):
//! - Inbound Webhooks: ISO 20022 `camt.054` (`BkToCstmrDbtCdtNtfctn`) & `pain.002` (`CstmrPmtStsRpt`).
//! - Periodic Statement Polling: ISO 20022 `camt.052` / `camt.053` (`BkToCstmrStmt` booked entries).
//! - Outbound Initiation & Status Polling: ISO 20022 `pain.001` & `pain.002`.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::crypto::{verify_jws_hs256, verify_timestamped_hmac_header};
use crate::domain::entities::BankAccount;
use crate::domain::events::{
    AppliedCreditEvent, CanonicalBankEvent, IngestionSource, OutboundPaymentState,
    OutboundPaymentStatusEvent, TransferRail,
};
use crate::domain::ledger::OutboundPaymentTracker;
use crate::domain::money::{CurrencyCode, Money};
use crate::ports::bank_adapter::{
    AccountPollCursor, BankTechnicalAdapter, IncomingPollBatch, OutboundPaymentInstruction,
    OutboundSubmissionReceipt,
};
use crate::ports::http_transport::{HttpMethod, HttpTransport, OutboundHttpRequest};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Iso20022BankConfig {
    pub adapter_id: String,
    pub bank_name: String,
    pub base_url: String,
    pub bearer_or_api_key: String,
    pub webhook_secret: String,
    pub max_webhook_skew_secs: u64,
}

pub struct Iso20022BankAdapter {
    cfg: Iso20022BankConfig,
    transport: Arc<dyn HttpTransport>,
}

impl Iso20022BankAdapter {
    pub fn new(cfg: Iso20022BankConfig, transport: Arc<dyn HttpTransport>) -> Self {
        Self { cfg, transport }
    }

    fn map_pain002_status(tx_sts: &str) -> Result<OutboundPaymentState> {
        match tx_sts.trim().to_ascii_uppercase().as_str() {
            "RCVD" => Ok(OutboundPaymentState::Initiated),
            "ACCP" | "ACTC" | "ACWC" => Ok(OutboundPaymentState::AcceptedByBank),
            "PDNG" | "ACSP" => Ok(OutboundPaymentState::InProcessing),
            "ACSC" | "ACCC" => Ok(OutboundPaymentState::Settled),
            "RJCT" => Ok(OutboundPaymentState::Rejected),
            "CANC" | "FAIL" => Ok(OutboundPaymentState::Failed),
            "RTRN" => Ok(OutboundPaymentState::Returned),
            other => Err(anyhow!("unsupported ISO 20022 pain.002 status '{}'", other)),
        }
    }

    fn parse_camt_entries(
        &self,
        ntfctn_or_stmt: &serde_json::Value,
        source: IngestionSource,
        now_unix_secs: u64,
    ) -> Result<Vec<AppliedCreditEvent>> {
        let acct_id = ntfctn_or_stmt["Acct"]["Id"]["Othr"]["Id"]
            .as_str()
            .or_else(|| ntfctn_or_stmt["Acct"]["Id"]["IBAN"].as_str())
            .ok_or_else(|| anyhow!("missing Acct.Id in ISO 20022 camt payload"))?
            .to_string();

        let entries = ntfctn_or_stmt
            .get("Ntry")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let mut out = Vec::new();
        for ntry in entries {
            let ind = ntry["CdtDbtInd"].as_str().unwrap_or("");
            if !ind.eq_ignore_ascii_case("CRDT") {
                continue;
            }
            // Strictly enforce `Sts == "BOOK"` (finalized booked credit; ignore `PDNG` float!)
            let sts = ntry["Sts"]["Cd"]
                .as_str()
                .or_else(|| ntry["Sts"].as_str())
                .unwrap_or("BOOK");
            if !sts.eq_ignore_ascii_case("BOOK") {
                continue;
            }

            let ccy_str = ntry["Amt"]["Ccy"]
                .as_str()
                .ok_or_else(|| anyhow!("missing Amt.Ccy in camt entry"))?;
            let ccy = CurrencyCode::new(ccy_str)?;
            let val_str = ntry["Amt"]["Val"]
                .as_str()
                .ok_or_else(|| anyhow!("missing Amt.Val in camt entry"))?;
            let amount = Money::new(ccy.parse_decimal_to_minor(val_str)?, ccy);

            let bank_tx_id = ntry["AcctSvcrRef"]
                .as_str()
                .ok_or_else(|| anyhow!("missing AcctSvcrRef in camt entry"))?
                .to_string();
            let refs = &ntry["NtryDtls"]["TxDtls"]["Refs"];
            let end_to_end_id = refs["EndToEndId"].as_str().map(|s| s.to_string());
            let batch_ref = refs["PmtInfId"]
                .as_str()
                .or_else(|| refs["MsgId"].as_str())
                .map(|s| s.to_string());
            let remittance = ntry["NtryDtls"]["TxDtls"]["RmtInf"]["Ustrd"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let payer_name = ntry["NtryDtls"]["TxDtls"]["RltdPties"]["Dbtr"]["Nm"]
                .as_str()
                .map(|s| s.to_string());
            let payer_acct = ntry["NtryDtls"]["TxDtls"]["RltdPties"]["DbtrAcct"]["Id"]["Othr"]
                ["Id"]
                .as_str()
                .or_else(|| {
                    ntry["NtryDtls"]["TxDtls"]["RltdPties"]["DbtrAcct"]["Id"]["IBAN"].as_str()
                })
                .map(|s| s.to_string());

            let structured_invoice_id = remittance
                .to_ascii_uppercase()
                .find("INV-")
                .and_then(|idx| {
                    let digits: String = remittance[idx + 4..]
                        .chars()
                        .take_while(|c| c.is_ascii_digit())
                        .collect();
                    digits.parse::<u64>().ok()
                });

            out.push(AppliedCreditEvent {
                bank_adapter_id: self.cfg.adapter_id.clone(),
                external_account_number: acct_id.clone(),
                bank_tx_id,
                end_to_end_id,
                batch_or_sweep_ref: batch_ref,
                rail: TransferRail::Other("iso20022".into()),
                amount,
                value_date: ntry["ValDt"]["Dt"]
                    .as_str()
                    .unwrap_or("2026-11-25")
                    .to_string(),
                booked_at_unix: now_unix_secs,
                remittance_info: remittance,
                payer_name,
                payer_account: payer_acct,
                structured_invoice_id,
                voucher_metadata: None,
                running_balance_minor: None,
                source,
            });
        }
        Ok(out)
    }
}

#[async_trait]
impl BankTechnicalAdapter for Iso20022BankAdapter {
    fn adapter_id(&self) -> &str {
        &self.cfg.adapter_id
    }

    fn bank_name(&self) -> &str {
        &self.cfg.bank_name
    }

    async fn verify_and_parse_webhook(
        &self,
        headers: &HeaderMap,
        raw_body: &[u8],
        now_unix_secs: u64,
    ) -> Result<Vec<CanonicalBankEvent>> {
        if let Some(jws) = headers.get("x-jws-signature").and_then(|v| v.to_str().ok()) {
            verify_jws_hs256(jws, Some(raw_body), self.cfg.webhook_secret.as_bytes())?;
        } else {
            let sig = headers
                .get("x-iso20022-signature")
                .or_else(|| headers.get("x-bank-signature"))
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| anyhow!("missing X-ISO20022-Signature or X-JWS-Signature header"))?;
            verify_timestamped_hmac_header(
                sig,
                raw_body,
                self.cfg.webhook_secret.as_bytes(),
                now_unix_secs,
                self.cfg.max_webhook_skew_secs,
            )?;
        }

        let doc: serde_json::Value = serde_json::from_slice(raw_body)?;
        if let Some(ntfctn) = doc["BkToCstmrDbtCdtNtfctn"]["Ntfctn"].as_object() {
            let credits = self.parse_camt_entries(
                &serde_json::Value::Object(ntfctn.clone()),
                IngestionSource::WebhookPush,
                now_unix_secs,
            )?;
            return Ok(credits
                .into_iter()
                .map(CanonicalBankEvent::AppliedCredit)
                .collect());
        }

        if let Some(rpt) = doc.get("CstmrPmtStsRpt") {
            let tx_inf = &rpt["OrgnlPmtInfAndSts"]["TxInfAndSts"];
            let ccy = CurrencyCode::new(
                tx_inf["OrgnlTxRef"]["Amt"]["InstdAmt"]["Ccy"]
                    .as_str()
                    .unwrap_or("SGD"),
            )?;
            let amt_str = tx_inf["OrgnlTxRef"]["Amt"]["InstdAmt"]["Val"]
                .as_str()
                .unwrap_or("0.00");
            let fee_str = tx_inf["ChrgsInf"]["Amt"]["Val"].as_str().unwrap_or("0.00");
            let ev = OutboundPaymentStatusEvent {
                bank_adapter_id: self.cfg.adapter_id.clone(),
                external_account_number: tx_inf["OrgnlTxRef"]["DbtrAcct"]["Id"]["Othr"]["Id"]
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
                client_instruction_id: tx_inf["OrgnlInstrId"]
                    .as_str()
                    .ok_or_else(|| anyhow!("missing OrgnlInstrId in pain.002"))?
                    .to_string(),
                bank_payment_id: tx_inf["StsId"].as_str().map(|s| s.to_string()),
                end_to_end_id: tx_inf["OrgnlEndToEndId"].as_str().map(|s| s.to_string()),
                rail: TransferRail::Other("iso20022".into()),
                state: Self::map_pain002_status(
                    tx_inf["TxSts"]
                        .as_str()
                        .ok_or_else(|| anyhow!("missing TxSts in pain.002"))?,
                )?,
                amount: Money::new(ccy.parse_decimal_to_minor(amt_str)?, ccy.clone()),
                bank_fee_minor: ccy.parse_decimal_to_minor(fee_str)?,
                reason_code: tx_inf["StsRsnInf"]["Rsn"]["Cd"]
                    .as_str()
                    .map(|s| s.to_string()),
                reason_detail: tx_inf["StsRsnInf"]["AddtlInf"]
                    .as_str()
                    .map(|s| s.to_string()),
                updated_at_unix: now_unix_secs,
                source: IngestionSource::WebhookPush,
            };
            return Ok(vec![CanonicalBankEvent::OutboundStatusChanged(ev)]);
        }

        Err(anyhow!(
            "unrecognized ISO 20022 document root (expected BkToCstmrDbtCdtNtfctn or CstmrPmtStsRpt)"
        ))
    }

    async fn poll_incoming_transactions(
        &self,
        account: &BankAccount,
        cursor: &AccountPollCursor,
        now_unix_secs: u64,
    ) -> Result<IncomingPollBatch> {
        let url = format!(
            "{}/iso20022/v1/accounts/{}/statements?since={}",
            self.cfg.base_url.trim_end_matches('/'),
            account.external_account_number,
            cursor.last_polled_unix
        );
        let resp = self
            .transport
            .execute(OutboundHttpRequest {
                method: HttpMethod::Get,
                url,
                headers: vec![
                    (
                        "Authorization".into(),
                        format!("Bearer {}", self.cfg.bearer_or_api_key),
                    ),
                    ("Accept".into(), "application/json".into()),
                ],
                body: vec![],
            })
            .await?;

        if !resp.is_success() {
            return Err(anyhow!(
                "ISO 20022 statement poll failed with HTTP {}",
                resp.status
            ));
        }

        let doc: serde_json::Value = resp.json()?;
        let stmt = &doc["BkToCstmrStmt"]["Stmt"];
        let credits = if stmt.is_object() {
            self.parse_camt_entries(stmt, IngestionSource::PeriodicPoll, now_unix_secs)?
        } else {
            vec![]
        };

        Ok(IncomingPollBatch {
            applied_credits: credits,
            next_cursor: AccountPollCursor {
                last_polled_unix: now_unix_secs,
                cursor_token: doc.get("NextCursor").and_then(|v| v.as_str()).map(String::from),
            },
        })
    }

    async fn initiate_outbound_payment(
        &self,
        account: &BankAccount,
        instruction: &OutboundPaymentInstruction,
        _now_unix_secs: u64,
    ) -> Result<OutboundSubmissionReceipt> {
        let url = format!(
            "{}/iso20022/v1/payments/pain001",
            self.cfg.base_url.trim_end_matches('/')
        );
        let decimals = instruction.amount.currency.minor_decimals() as usize;
        let factor = 10f64.powi(decimals as i32);
        let amt_str = format!(
            "{:.*}",
            decimals,
            (instruction.amount.amount_minor as f64) / factor
        );

        let body = serde_json::to_vec(&json!({
            "CstmrCdtTrfInitn": {
                "PmtInf": {
                    "PmtInfId": instruction.client_instruction_id,
                    "DbtrAcct": { "Id": { "Othr": { "Id": account.external_account_number } } },
                    "CdtTrfTxInf": {
                        "PmtId": { "InstrId": instruction.client_instruction_id },
                        "Amt": { "InstdAmt": { "Ccy": instruction.amount.currency.as_str(), "Val": amt_str } },
                        "Cdtr": { "Nm": instruction.beneficiary_name },
                        "CdtrAcct": { "Id": { "Othr": { "Id": instruction.beneficiary_account } } },
                        "RmtInf": { "Ustrd": instruction.remittance_info }
                    }
                }
            }
        }))?;

        let resp = self
            .transport
            .execute(OutboundHttpRequest {
                method: HttpMethod::Post,
                url,
                headers: vec![
                    (
                        "Authorization".into(),
                        format!("Bearer {}", self.cfg.bearer_or_api_key),
                    ),
                    ("Content-Type".into(), "application/json".into()),
                ],
                body,
            })
            .await?;

        if !resp.is_success() {
            return Err(anyhow!("ISO 20022 pain.001 failed with HTTP {}", resp.status));
        }

        let val: serde_json::Value = resp.json()?;
        Ok(OutboundSubmissionReceipt {
            bank_payment_id: val["StsId"].as_str().map(String::from),
            end_to_end_id: val["EndToEndId"].as_str().map(String::from),
            value_date: instruction.value_date.clone(),
            initial_state: Self::map_pain002_status(val["TxSts"].as_str().unwrap_or("ACCP"))?,
        })
    }

    async fn poll_outbound_payment_status(
        &self,
        account: &BankAccount,
        tracker: &OutboundPaymentTracker,
        now_unix_secs: u64,
    ) -> Result<OutboundPaymentStatusEvent> {
        let url = format!(
            "{}/iso20022/v1/payments/{}/status",
            self.cfg.base_url.trim_end_matches('/'),
            tracker.client_instruction_id
        );
        let resp = self
            .transport
            .execute(OutboundHttpRequest {
                method: HttpMethod::Get,
                url,
                headers: vec![(
                    "Authorization".into(),
                    format!("Bearer {}", self.cfg.bearer_or_api_key),
                )],
                body: vec![],
            })
            .await?;

        if !resp.is_success() {
            return Err(anyhow!(
                "ISO 20022 pain.002 status poll failed with HTTP {}",
                resp.status
            ));
        }

        let doc: serde_json::Value = resp.json()?;
        let tx_inf = &doc["CstmrPmtStsRpt"]["OrgnlPmtInfAndSts"]["TxInfAndSts"];
        let fee_str = tx_inf["ChrgsInf"]["Amt"]["Val"].as_str().unwrap_or("0.00");

        Ok(OutboundPaymentStatusEvent {
            bank_adapter_id: self.cfg.adapter_id.clone(),
            external_account_number: account.external_account_number.clone(),
            client_instruction_id: tracker.client_instruction_id.clone(),
            bank_payment_id: tx_inf["StsId"]
                .as_str()
                .map(String::from)
                .or_else(|| tracker.bank_payment_id.clone()),
            end_to_end_id: tx_inf["OrgnlEndToEndId"]
                .as_str()
                .map(String::from)
                .or_else(|| tracker.end_to_end_id.clone()),
            rail: tracker.rail.clone(),
            state: Self::map_pain002_status(
                tx_inf["TxSts"]
                    .as_str()
                    .ok_or_else(|| anyhow!("missing TxSts in pain.002 poll"))?,
            )?,
            amount: tracker.amount.clone(),
            bank_fee_minor: tracker.amount.currency.parse_decimal_to_minor(fee_str)?,
            reason_code: tx_inf["StsRsnInf"]["Rsn"]["Cd"].as_str().map(String::from),
            reason_detail: tx_inf["StsRsnInf"]["AddtlInf"].as_str().map(String::from),
            updated_at_unix: now_unix_secs,
            source: IngestionSource::PeriodicPoll,
        })
    }
}
