//! Standalone cryptographic primitives, webhook authenticators, and SuperLexicon L1 / EIP-155 RLP signer.
//!
//! Zero dependency on the core `lexicon` node crate so `banking-oracle` compiles into a lightweight,
//! dependency-isolated microservice container.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ethereum_types::{Address, U256};
use hmac::{Hmac, Mac};
use rlp::RlpStream;
use secp256k1::{Message, Secp256k1, SecretKey};
use sha2::Sha256;
use sha3::{Digest, Keccak256};

type HmacSha256 = Hmac<Sha256>;

/// Compute 32-byte Keccak-256 digest.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

/// Compute 4-byte Solidity / HFS function selector `keccak256(sig)[0..4]`.
pub fn selector4(sig: &str) -> [u8; 4] {
    let h = keccak256(sig.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

/// Compute RFC 2104 `HMAC-SHA256(secret, message)`.
pub fn hmac_sha256(secret: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts arbitrary key length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// Constant-time slice equality check to prevent timing side-channels on MAC verification.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Verify a timestamped HMAC-SHA256 webhook signature header (`t=<unix_secs>,v1=<hex_mac>` or
/// `ts=<unix_secs>,sig=<hex_mac>`) over `"<timestamp>.<raw_body>"` with replay-window enforcement.
pub fn verify_timestamped_hmac_header(
    sig_header: &str,
    raw_body: &[u8],
    secret: &[u8],
    now_unix_secs: u64,
    max_skew_secs: u64,
) -> Result<u64> {
    if secret.is_empty() {
        return Err(anyhow!("webhook HMAC secret is empty"));
    }
    let mut ts_opt: Option<u64> = None;
    let mut candidate_sigs: Vec<[u8; 32]> = Vec::new();

    for part in sig_header.split(',') {
        let part = part.trim();
        if let Some(t_str) = part.strip_prefix("t=").or_else(|| part.strip_prefix("ts=")) {
            ts_opt = Some(
                t_str
                    .parse::<u64>()
                    .map_err(|_| anyhow!("invalid webhook timestamp '{}'", t_str))?,
            );
        } else if let Some(v_hex) = part
            .strip_prefix("v1=")
            .or_else(|| part.strip_prefix("sig="))
            .or_else(|| part.strip_prefix("sha256="))
        {
            let raw = hex::decode(v_hex.trim())
                .map_err(|_| anyhow!("invalid hex webhook signature tag"))?;
            if raw.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&raw);
                candidate_sigs.push(arr);
            }
        }
    }

    let ts = ts_opt.ok_or_else(|| anyhow!("missing timestamp ('t=' or 'ts=') in signature header"))?;
    if candidate_sigs.is_empty() {
        return Err(anyhow!("missing signature tag ('v1=' or 'sig=') in signature header"));
    }

    let skew = now_unix_secs.abs_diff(ts);
    if skew > max_skew_secs {
        return Err(anyhow!(
            "webhook timestamp skew {}s exceeds maximum allowed {}s",
            skew,
            max_skew_secs
        ));
    }

    let mut signed_payload = Vec::with_capacity(24 + raw_body.len());
    signed_payload.extend_from_slice(ts.to_string().as_bytes());
    signed_payload.push(b'.');
    signed_payload.extend_from_slice(raw_body);

    let expected = hmac_sha256(secret, &signed_payload);
    if candidate_sigs.iter().any(|cand| constant_time_eq(cand, &expected)) {
        Ok(ts)
    } else {
        Err(anyhow!("HMAC-SHA256 webhook signature verification failed"))
    }
}

/// Verify an RFC 7515 compact or detached JWS (`HS256`) header commonly used by corporate banking
/// webhook gateways (`<b64url_hdr>.<b64url_payload>.<b64url_sig>` or detached `<b64url_hdr>..<b64url_sig>`).
pub fn verify_jws_hs256(
    jws_token: &str,
    detached_body: Option<&[u8]>,
    secret: &[u8],
) -> Result<()> {
    let parts: Vec<&str> = jws_token.trim().split('.').collect();
    if parts.len() != 3 {
        return Err(anyhow!("invalid JWS format: expected 3 dot-separated segments"));
    }
    let hdr_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| anyhow!("invalid base64url JWS header"))?;
    let hdr_json: serde_json::Value =
        serde_json::from_slice(&hdr_bytes).map_err(|_| anyhow!("invalid JSON in JWS header"))?;
    if hdr_json.get("alg").and_then(|v| v.as_str()) != Some("HS256") {
        return Err(anyhow!("unsupported JWS alg (expected HS256)"));
    }

    let payload_b64 = if parts[1].is_empty() {
        let body = detached_body.ok_or_else(|| anyhow!("detached JWS requires raw HTTP body"))?;
        URL_SAFE_NO_PAD.encode(body)
    } else {
        parts[1].to_string()
    };

    let signing_input = format!("{}.{}", parts[0], payload_b64);
    let expected = hmac_sha256(secret, signing_input.as_bytes());
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| anyhow!("invalid base64url JWS signature"))?;

    if constant_time_eq(&sig_bytes, &expected) {
        Ok(())
    } else {
        Err(anyhow!("JWS HS256 signature verification failed"))
    }
}

/// Compute a tenant-isolated, domain-salted `paymentRefHash` so zero raw bank account numbers,
/// card IDs, or customer PII ever appear in public on-chain state:
/// `keccak256("SLX_PAYMENT_REF_V2|" || salt || "|" || entity_id || "|" || rail || "|" || external_id)`.
pub fn compute_salted_payment_ref_hash(
    domain_salt: &[u8],
    entity_id: &str,
    rail: &str,
    external_id: &str,
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(
        24 + domain_salt.len() + entity_id.len() + rail.len() + external_id.len(),
    );
    buf.extend_from_slice(b"SLX_PAYMENT_REF_V2|");
    buf.extend_from_slice(domain_salt);
    buf.push(b'|');
    buf.extend_from_slice(entity_id.as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(rail.as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(external_id.as_bytes());
    keccak256(&buf)
}

pub fn parse_address20(hex_str: &str) -> Result<Address> {
    let clean = hex_str.trim().trim_start_matches("0x");
    let raw = hex::decode(clean).map_err(|e| anyhow!("invalid hex address '{}': {}", hex_str, e))?;
    if raw.len() != 20 {
        return Err(anyhow!("expected 20-byte address, got {} bytes", raw.len()));
    }
    Ok(Address::from_slice(&raw))
}

pub fn parse_bytes32(hex_str: &str) -> Result<[u8; 32]> {
    let clean = hex_str.trim().trim_start_matches("0x");
    let raw = hex::decode(clean).map_err(|e| anyhow!("invalid bytes32 '{}': {}", hex_str, e))?;
    if raw.len() != 32 {
        return Err(anyhow!("expected 32 bytes, got {} bytes", raw.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

/// Wire RLP encoding mode for signed blockchain transactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TxWireFormat {
    /// SuperLexicon L1 10-field parallel-shard RLP (`contract_addresses` included for deterministic shard lock-free scheduling).
    SuperLexiconL1,
    /// Standard Ethereum EIP-155 9-field RLP (`SlxrRewardVault` / `SlxrRedemptionPool`).
    StandardEip155,
}

impl Default for TxWireFormat {
    fn default() -> Self {
        Self::SuperLexiconL1
    }
}

/// Standalone `secp256k1` transaction signer supporting both SuperLexicon L1 (`$0.00` gas) and EVM EIP-155.
pub struct L1TransactionSigner {
    secret_key: SecretKey,
    chain_id: u64,
    wire_format: TxWireFormat,
}

impl L1TransactionSigner {
    pub fn new(private_key_hex: &str, chain_id: u64, wire_format: TxWireFormat) -> Result<Self> {
        let clean = private_key_hex.trim().trim_start_matches("0x");
        let raw = hex::decode(clean).map_err(|e| anyhow!("invalid private key hex: {}", e))?;
        if raw.len() != 32 {
            return Err(anyhow!("private key must be 32 bytes"));
        }
        let secret_key =
            SecretKey::from_slice(&raw).map_err(|e| anyhow!("invalid secp256k1 key: {}", e))?;
        Ok(Self {
            secret_key,
            chain_id,
            wire_format,
        })
    }

    pub fn sender_address(&self) -> Address {
        let secp = Secp256k1::new();
        let pk = self.secret_key.public_key(&secp);
        let uncompressed = pk.serialize_uncompressed();
        let digest = keccak256(&uncompressed[1..]);
        Address::from_slice(&digest[12..])
    }

    /// Sign a contract call (`$0.00` gas on SuperLexicon L1 by default) with optional `extra_targets`
    /// for cross-HFS synchronous subcalls (e.g., `RewardVoucher` -> `AssetLedger`).
    pub fn sign_contract_call(
        &self,
        nonce: u64,
        to: Address,
        calldata: &[u8],
        gas_price: U256,
        gas_limit: U256,
        extra_targets: &[Address],
    ) -> Result<String> {
        let value = U256::zero();
        let mut contract_addresses = vec![to];
        for extra in extra_targets {
            if !extra.is_zero() && !contract_addresses.contains(extra) {
                contract_addresses.push(*extra);
            }
        }

        let signing_hash = match self.wire_format {
            TxWireFormat::SuperLexiconL1 => {
                let mut s = RlpStream::new();
                s.begin_list(10);
                s.append(&nonce);
                s.append(&gas_price);
                s.append(&gas_limit);
                s.append(&to);
                s.append(&value);
                s.append(&calldata);
                s.append_list(&contract_addresses);
                s.append(&self.chain_id);
                s.append(&0u8);
                s.append(&0u8);
                keccak256(&s.out())
            }
            TxWireFormat::StandardEip155 => {
                let mut s = RlpStream::new();
                s.begin_list(9);
                s.append(&nonce);
                s.append(&gas_price);
                s.append(&gas_limit);
                s.append(&to);
                s.append(&value);
                s.append(&calldata);
                s.append(&self.chain_id);
                s.append(&0u8);
                s.append(&0u8);
                keccak256(&s.out())
            }
        };

        let secp = Secp256k1::new();
        let msg = Message::from_digest_slice(&signing_hash)
            .map_err(|e| anyhow!("invalid signing digest: {}", e))?;
        let rec_sig = secp.sign_ecdsa_recoverable(&msg, &self.secret_key);
        let (rec_id, sig64) = rec_sig.serialize_compact();
        let r = U256::from_big_endian(&sig64[0..32]);
        let s_val = U256::from_big_endian(&sig64[32..64]);
        let v = rec_id.to_i32() as u64 + self.chain_id * 2 + 35;

        let encoded = match self.wire_format {
            TxWireFormat::SuperLexiconL1 => {
                let mut out = RlpStream::new();
                out.begin_list(10);
                out.append(&nonce);
                out.append(&gas_price);
                out.append(&gas_limit);
                out.append(&to);
                out.append(&value);
                out.append(&calldata);
                out.append(&v);
                out.append(&r);
                out.append(&s_val);
                out.append_list(&contract_addresses);
                out.out()
            }
            TxWireFormat::StandardEip155 => {
                let mut out = RlpStream::new();
                out.begin_list(9);
                out.append(&nonce);
                out.append(&gas_price);
                out.append(&gas_limit);
                out.append(&to);
                out.append(&value);
                out.append(&calldata);
                out.append(&v);
                out.append(&r);
                out.append(&s_val);
                out.out()
            }
        };

        Ok(format!("0x{}", hex::encode(encoded)))
    }
}

/// ABI calldata builders for SuperLexicon Haltproof Subroutines (`AssetLedger`, `AccountingLedger`, `RewardVoucher`).
pub mod hfs_abi {
    use super::selector4;
    use ethereum_types::Address;

    fn push_u64_word(out: &mut Vec<u8>, v: u64) {
        let mut word = [0u8; 32];
        word[24..32].copy_from_slice(&v.to_be_bytes());
        out.extend_from_slice(&word);
    }

    fn push_address_word(out: &mut Vec<u8>, addr: Address) {
        let mut word = [0u8; 32];
        word[12..32].copy_from_slice(addr.as_bytes());
        out.extend_from_slice(&word);
    }

    /// `RewardVoucher.issuePaidVoucher(bytes32,uint64,uint64,uint64,bytes32)`
    pub fn encode_issue_paid_voucher(
        payment_ref_hash: &[u8; 32],
        sku_code: u64,
        tier_bps: u64,
        price_usd_micros: u64,
        voucher_commitment: &[u8; 32],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 32 * 5);
        out.extend_from_slice(&selector4(
            "issuePaidVoucher(bytes32,uint64,uint64,uint64,bytes32)",
        ));
        out.extend_from_slice(payment_ref_hash);
        push_u64_word(&mut out, sku_code);
        push_u64_word(&mut out, tier_bps);
        push_u64_word(&mut out, price_usd_micros);
        out.extend_from_slice(voucher_commitment);
        out
    }

    /// `RewardVoucher.revokeRefundedVoucher(bytes32)`
    pub fn encode_revoke_refunded_voucher(payment_ref_hash: &[u8; 32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(36);
        out.extend_from_slice(&selector4("revokeRefundedVoucher(bytes32)"));
        out.extend_from_slice(payment_ref_hash);
        out
    }

    /// `AssetLedger.charterModuleIssue(address,uint64)` — mints tokenized commercial bank cash into
    /// an entity's `treasuryIdentity` when an incoming bank credit or batch sweep is finalized.
    pub fn encode_operating_bank_issue(treasury_identity: Address, amount_units: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 64);
        out.extend_from_slice(&selector4("charterModuleIssue(address,uint64)"));
        push_address_word(&mut out, treasury_identity);
        push_u64_word(&mut out, amount_units);
        out
    }

    /// `AssetLedger.charterModuleCancel(address,uint64)` — retires tokenized commercial bank cash
    /// when an outbound bank payment transitions to finalized `Settled`.
    pub fn encode_operating_bank_cancel(treasury_identity: Address, amount_units: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 64);
        out.extend_from_slice(&selector4("charterModuleCancel(address,uint64)"));
        push_address_word(&mut out, treasury_identity);
        push_u64_word(&mut out, amount_units);
        out
    }

    /// `AccountingLedger.settleCreditInvoice(uint64,uint64)` — settles an open AR credit invoice upon finalized bank cash receipt.
    pub fn encode_ifrs_settle_invoice(invoice_id: u64, amount_units: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 64);
        out.extend_from_slice(&selector4("settleCreditInvoice(uint64,uint64)"));
        push_u64_word(&mut out, invoice_id);
        push_u64_word(&mut out, amount_units);
        out
    }

    /// `AccountingLedger.quarantineSuspenseCash()` — syncs unattributed bank deposits into `2900 Unattributed Cash Suspense`.
    pub fn encode_ifrs_quarantine_suspense() -> Vec<u8> {
        selector4("quarantineSuspenseCash()").to_vec()
    }
}
