//! Squads V4 multisig integration — fetch the multisig account, walk its
//! transaction index, and surface pending proposals so the TUI can decode
//! them through the existing inspector and sign via FROST + Telegram.
//!
//! Scope (v0.4 demo): READ-ONLY proposal listing + decode. Submitting a
//! `proposal_approve` instruction back to the multisig is v0.5 — the demo's
//! headline is "Sentinel picks up a wrapper-attack proposal, surfaces the
//! recursive decode, user rejects in Telegram." The user's reject IS the
//! signal; on-chain Approve submission is the follow-on.
//!
//! All state lives on-chain; this module is pure RPC + binary parsing.
//! No daemon, no subscription — we poll the cluster every N seconds via
//! getProgramAccounts / getAccountInfo. 30s default poll interval.

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;
use std::time::Duration;

/// Default mainnet RPC. Kept inline (rather than `use crate::rpc`) so this
/// module stays usable from both the binary and the library compilation
/// roots without needing a shared parent module.
// Public mainnet RPC by default; override with `SOVEREIGN_RPC_URL` to point at
// Helius / QuickNode / your own node. Highly recommended for any real use —
// the public endpoint rate-limits at ~10 req/sec across all callers and the
// Squads watch makes ~2 RPCs per proposal per poll.
fn rpc_url() -> String {
    std::env::var("SOVEREIGN_RPC_URL")
        .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".to_string())
}

/// Squads V4 program ID. Mainnet canonical address.
pub const SQUADS_V4_PROGRAM_ID: &str = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf";

/// Anchor account discriminators — first 8 bytes of `sha256("account:<TypeName>")`.
/// Hardcoded here so we don't pull in the Anchor codegen runtime; verified
/// against the Squads V4 program's IDL.
pub const DISC_MULTISIG:           [u8; 8] = [224, 116, 121, 186, 68, 161, 79, 236];
pub const DISC_VAULT_TRANSACTION:  [u8; 8] = [168, 250, 162, 100, 81, 14, 162, 207];
// Verified on-chain against a live Squads V4 multisig. The value previously
// hardcoded (`[80, 167, 207, 80, 178, 184, 169, 26]`) was wrong; on-chain
// account data starts with `0x5e08042371...`.
pub const DISC_CONFIG_TRANSACTION: [u8; 8] = [94, 8, 4, 35, 113, 139, 139, 112];
pub const DISC_PROPOSAL:           [u8; 8] = [26, 94, 189, 187, 116, 136, 53, 33];

/// Anchor instruction discriminators — first 8 bytes of `sha256("global:<method>")`.
pub const IX_DISC_PROPOSAL_APPROVE: [u8; 8] = [144, 37, 164, 136, 188, 216, 42, 248];
pub const IX_DISC_PROPOSAL_REJECT:  [u8; 8] = [243, 62, 134, 156, 230, 106, 246, 135];

#[derive(Debug, Clone)]
pub struct Multisig {
    pub address:           Pubkey,
    pub create_key:        Pubkey,
    pub config_authority:  Pubkey,
    pub threshold:         u16,
    pub time_lock:         u32,
    pub transaction_index: u64,
    pub stale_index:       u64,
    pub members:           Vec<MultisigMember>,
}

#[derive(Debug, Clone)]
pub struct MultisigMember {
    pub key:         Pubkey,
    pub permissions: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProposalStatus {
    Draft,
    Active,
    Approved,
    Rejected,
    Cancelled,
    Executing,
    Executed,
    Other(u8),
}

impl ProposalStatus {
    pub fn label(&self) -> &'static str {
        match self {
            ProposalStatus::Draft     => "draft",
            ProposalStatus::Active    => "ACTIVE — your approval needed",
            ProposalStatus::Approved  => "approved",
            ProposalStatus::Rejected  => "rejected",
            ProposalStatus::Cancelled => "cancelled",
            ProposalStatus::Executing => "executing",
            ProposalStatus::Executed  => "executed",
            ProposalStatus::Other(_)  => "unknown",
        }
    }
    pub fn is_actionable(&self) -> bool {
        matches!(self, ProposalStatus::Active | ProposalStatus::Draft)
    }
}

#[derive(Debug, Clone)]
pub struct PendingProposal {
    pub multisig:           Pubkey,
    pub index:              u64,
    pub status:             ProposalStatus,
    pub kind:               ProposalKind,
    pub approved_by:        Vec<Pubkey>,
    pub rejected_by:        Vec<Pubkey>,
    /// Address of the underlying VaultTransaction or ConfigTransaction account.
    pub tx_account:         Pubkey,
    /// Inner Solana Message bytes for VaultTransaction (None for ConfigTransaction
    /// since those don't wrap a Solana message — they're config struct mutations).
    /// This is what gets fed into the inspector for decoding.
    pub inner_message:      Option<Vec<u8>>,
    /// Generic summary of the kind+contents (e.g. "VaultTransaction (vault 0,
    /// 143 byte inner Message)"). Useful as a fallback when decode fails.
    pub summary:            String,
    /// Decoded human-readable summary of what the proposal does. Populated by
    /// the binary side after fetching, by running `inner_message` through the
    /// inspector. Format: "Transfer 0.001 SOL → 8aDT…vFdH" or similar.
    /// `None` for proposals whose type or content can't be decoded yet.
    pub decoded_summary:    Option<String>,
    /// Worst risk severity present in the decoded inner instructions.
    /// Drives the row color/glyph in the proposal list. None = no risks /
    /// undecoded.
    pub worst_severity:     Option<u8>,  // 0=Low,1=Medium,2=High,3=Critical
}

#[derive(Debug, Clone)]
pub enum ProposalKind {
    VaultTransaction { vault_index: u8 },
    ConfigTransaction,
}

// ── Public API ───────────────────────────────────────────────────────────────

pub fn fetch_multisig(multisig_pda: &str, rpc_url: &str) -> Result<Multisig> {
    let pk = Pubkey::from_str(multisig_pda).context("parsing multisig PDA")?;
    let raw = rpc_get_account_data(rpc_url, multisig_pda)?
        .ok_or_else(|| anyhow!("multisig account {} not found on-chain", multisig_pda))?;
    parse_multisig(pk, &raw)
}

/// Fetch all proposals for the given multisig, ordered newest → oldest.
/// Stops after `max_lookback` indexes from the current transaction_index.
/// Default 20 lookback is enough for the demo; production would page.
pub fn fetch_recent_proposals(multisig: &Multisig, rpc_url: &str, max_lookback: u64) -> Result<Vec<PendingProposal>> {
    let mut out = Vec::new();
    if multisig.transaction_index == 0 { return Ok(out); }

    let lookback_to = multisig.transaction_index.saturating_sub(max_lookback).max(1);

    for idx in (lookback_to..=multisig.transaction_index).rev() {
        match fetch_proposal_at(multisig, idx, rpc_url) {
            Ok(Some(p)) => out.push(p),
            Ok(None) => continue, // Proposal account doesn't exist for this index — skip
            Err(e) => {
                tracing_log_warn(&format!("squads: error fetching proposal {}: {}", idx, e));
                continue;
            }
        }
    }
    Ok(out)
}

fn fetch_proposal_at(multisig: &Multisig, index: u64, rpc_url: &str) -> Result<Option<PendingProposal>> {
    let proposal_pda = derive_proposal_pda(&multisig.address, index);
    let proposal_pda_str = proposal_pda.to_string();
    let proposal_raw = match rpc_get_account_data(rpc_url, &proposal_pda_str)? {
        Some(d) => d,
        None    => return Ok(None),
    };
    let (status, approved, rejected) = parse_proposal_status(&proposal_raw)?;

    // Skip terminal-state proposals — the demo cares about Active and Draft.
    // (We still LIST Executed/Rejected for completeness, but the bot's "your
    // approval is needed" framing only applies to Active.)

    // Fetch the underlying tx account. Try VaultTransaction first, then
    // ConfigTransaction. The PDA is the same for both — it's the discriminator
    // in the account data that distinguishes them.
    let tx_pda = derive_transaction_pda(&multisig.address, index);
    let tx_pda_str = tx_pda.to_string();
    let tx_raw = match rpc_get_account_data(rpc_url, &tx_pda_str)? {
        Some(d) => d,
        None    => return Ok(None),
    };

    let (kind, inner_message, summary) = if tx_raw.len() >= 8
        && tx_raw[0..8] == DISC_VAULT_TRANSACTION
    {
        let (vault_index, msg_bytes) = parse_vault_transaction(&tx_raw)?;
        let summary = format!(
            "VaultTransaction (vault {}, {} byte inner Message)",
            vault_index, msg_bytes.len()
        );
        (ProposalKind::VaultTransaction { vault_index }, Some(msg_bytes), summary)
    } else if tx_raw.len() >= 8 && tx_raw[0..8] == DISC_CONFIG_TRANSACTION {
        let actions = parse_config_transaction_action_count(&tx_raw)?;
        let summary = format!("ConfigTransaction ({} action(s) — multisig config change)", actions);
        (ProposalKind::ConfigTransaction, None, summary)
    } else {
        // Unknown / future account type (Batch, VaultBatchTransaction, etc).
        // Surface in the list rather than crashing the poller — operator can
        // see it exists, even if v0.4 can't decode its inner instructions.
        let disc_hex = tx_raw.get(0..8).map(hex::encode).unwrap_or_default();
        let summary = format!("Unsupported account type (disc=0x{}) — v0.5", disc_hex);
        (ProposalKind::ConfigTransaction, None, summary)
    };

    Ok(Some(PendingProposal {
        multisig: multisig.address,
        index,
        status,
        kind,
        approved_by: approved,
        rejected_by: rejected,
        tx_account: tx_pda,
        inner_message,
        summary,
        // Decoded summary + severity get filled in by the binary side after
        // fetch completes — squads.rs intentionally doesn't depend on
        // inspector to keep this module's dependency graph tiny.
        decoded_summary: None,
        worst_severity: None,
    }))
}

// ── Building proposal_approve / proposal_reject Solana transactions ─────────

/// Build a serialized Solana `Message` containing a `proposal_approve` (or
/// `proposal_reject`) instruction targeting the given proposal. The fee
/// payer is the FROST `member` — this is the tx the FROST flow will sign,
/// resulting in an on-chain vote registered against the proposal.
///
/// `vote = true` → approve; `vote = false` → reject.
///
/// Squads V4 ProposalVote accounts (verified against upstream source):
///   1. multisig (read-only)
///   2. member  (mut, signer)        ← the FROST address; this is the fee payer
///   3. proposal (mut)
///
/// Args: `ProposalVoteArgs { memo: Option<String> }`
///   - Empty memo (None) → 1 byte: `0x00`
pub fn build_proposal_vote_tx(
    multisig: &Pubkey,
    proposal_index: u64,
    member: &Pubkey,
    vote: bool,
    recent_blockhash: solana_sdk::hash::Hash,
) -> Result<Vec<u8>> {
    use solana_sdk::instruction::{AccountMeta, Instruction};
    use solana_sdk::message::Message;

    let program = Pubkey::from_str(SQUADS_V4_PROGRAM_ID).context("Squads program ID")?;
    let proposal_pda = derive_proposal_pda(multisig, proposal_index);

    let accounts = vec![
        AccountMeta::new_readonly(*multisig, false),  // multisig: read-only
        AccountMeta::new(*member, true),              // member: writable + signer (paying for own vote)
        AccountMeta::new(proposal_pda, false),        // proposal: writable
    ];

    let mut data = Vec::with_capacity(9);
    data.extend_from_slice(if vote { &IX_DISC_PROPOSAL_APPROVE } else { &IX_DISC_PROPOSAL_REJECT });
    data.push(0u8);  // ProposalVoteArgs::memo = None

    let ix = Instruction { program_id: program, accounts, data };
    let mut msg = Message::new(&[ix], Some(member));
    msg.recent_blockhash = recent_blockhash;

    bincode::serialize(&msg).context("serialize proposal_vote Message")
}

/// Fetch a fresh recent blockhash from mainnet. Returns the parsed Hash.
/// Uses commitment=confirmed for the right balance of freshness vs propagation
/// (same lesson learned in rpc.rs broadcast).
pub fn fetch_latest_blockhash() -> Result<solana_sdk::hash::Hash> {
    use std::time::Duration;
    let body = serde_json::json!({
        "jsonrpc":"2.0","id":1,"method":"getLatestBlockhash",
        "params":[{"commitment":"confirmed"}]
    });
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10)).build()
        .context("build reqwest client")?;
    let resp: serde_json::Value = client.post(rpc_url())
        .json(&body).send().context("POST getLatestBlockhash")?
        .json().context("parse RPC response")?;
    let bh = resp["result"]["value"]["blockhash"].as_str()
        .ok_or_else(|| anyhow!("no blockhash in: {}", resp))?;
    solana_sdk::hash::Hash::from_str(bh).map_err(|e| anyhow!("parse blockhash: {e}"))
}

// ── PDA derivation (matches Squads V4 source) ───────────────────────────────

pub fn derive_proposal_pda(multisig: &Pubkey, index: u64) -> Pubkey {
    Pubkey::find_program_address(
        &[
            b"multisig",
            multisig.as_ref(),
            b"transaction",
            &index.to_le_bytes(),
            b"proposal",
        ],
        &Pubkey::from_str(SQUADS_V4_PROGRAM_ID).expect("Squads program ID parses"),
    ).0
}

pub fn derive_transaction_pda(multisig: &Pubkey, index: u64) -> Pubkey {
    Pubkey::find_program_address(
        &[
            b"multisig",
            multisig.as_ref(),
            b"transaction",
            &index.to_le_bytes(),
        ],
        &Pubkey::from_str(SQUADS_V4_PROGRAM_ID).expect("Squads program ID parses"),
    ).0
}

// ── Account parsing — Multisig ──────────────────────────────────────────────

fn parse_multisig(address: Pubkey, raw: &[u8]) -> Result<Multisig> {
    if raw.len() < 8 { bail!("multisig account too short: {} bytes", raw.len()); }
    if raw[0..8] != DISC_MULTISIG {
        bail!("multisig discriminator mismatch — got {:?}, expected {:?}", &raw[0..8], DISC_MULTISIG);
    }
    let mut p = Cursor::new(&raw[8..]);

    let create_key       = p.pubkey().context("create_key")?;
    let config_authority = p.pubkey().context("config_authority")?;
    let threshold        = p.u16().context("threshold")?;
    let time_lock        = p.u32().context("time_lock")?;
    let transaction_index = p.u64().context("transaction_index")?;
    let stale_index      = p.u64().context("stale_transaction_index")?;
    let _rent_collector  = p.option_pubkey().context("rent_collector")?;
    let _bump            = p.u8().context("bump")?;

    let n_members = p.u32().context("members.len")? as usize;
    let mut members = Vec::with_capacity(n_members);
    for _ in 0..n_members {
        let key         = p.pubkey().context("member.key")?;
        let permissions = p.u8().context("member.permissions")?;
        members.push(MultisigMember { key, permissions });
    }

    Ok(Multisig {
        address, create_key, config_authority, threshold, time_lock,
        transaction_index, stale_index, members,
    })
}

// ── Account parsing — Proposal ──────────────────────────────────────────────

fn parse_proposal_status(raw: &[u8]) -> Result<(ProposalStatus, Vec<Pubkey>, Vec<Pubkey>)> {
    if raw.len() < 8 { bail!("proposal account too short"); }
    if raw[0..8] != DISC_PROPOSAL {
        bail!("proposal discriminator mismatch");
    }
    let mut p = Cursor::new(&raw[8..]);
    let _multisig          = p.pubkey().context("multisig")?;
    let _transaction_index = p.u64().context("transaction_index")?;

    // ProposalStatus enum: 1-byte tag + variant data
    let status_tag = p.u8().context("status tag")?;
    let status = match status_tag {
        0 => ProposalStatus::Draft,
        1 => ProposalStatus::Active,
        2 => ProposalStatus::Rejected,
        3 => ProposalStatus::Approved,
        4 => ProposalStatus::Executing,
        5 => ProposalStatus::Executed,
        6 => ProposalStatus::Cancelled,
        n => ProposalStatus::Other(n),
    };
    // Each variant carries a `timestamp: i64` (8 bytes), so skip it. (Some
    // variants in newer versions carry more data — if we hit a discriminator
    // mismatch on the next field we'll bail, but for v0.4 demo this works.)
    let _timestamp = p.i64().context("status.timestamp")?;
    let _bump      = p.u8().context("bump")?;

    let n_approved = p.u32().context("approved.len")? as usize;
    let mut approved = Vec::with_capacity(n_approved);
    for _ in 0..n_approved { approved.push(p.pubkey()?); }

    let n_rejected = p.u32().context("rejected.len")? as usize;
    let mut rejected = Vec::with_capacity(n_rejected);
    for _ in 0..n_rejected { rejected.push(p.pubkey()?); }

    // cancelled vec follows but we don't surface it — stop parsing here.

    Ok((status, approved, rejected))
}

// Map u8 to ProposalStatus is above; add Executing variant
// (Anchor enum order is what Squads source defines; verified against IDL.)

// ── Account parsing — VaultTransaction ──────────────────────────────────────

fn parse_vault_transaction(raw: &[u8]) -> Result<(u8, Vec<u8>)> {
    if raw.len() < 8 || raw[0..8] != DISC_VAULT_TRANSACTION {
        bail!("not a VaultTransaction");
    }
    let mut p = Cursor::new(&raw[8..]);
    let _multisig                = p.pubkey().context("multisig")?;
    let _creator                 = p.pubkey().context("creator")?;
    let _index                   = p.u64().context("index")?;
    let _bump                    = p.u8().context("bump")?;
    let vault_index              = p.u8().context("vault_index")?;
    let _vault_bump              = p.u8().context("vault_bump")?;
    let n_eph                    = p.u32().context("ephemeral_signer_bumps.len")? as usize;
    p.skip(n_eph).context("skip ephemeral_signer_bumps")?;

    // Squads V4 stores the VaultTransactionMessage inline at the end of the
    // account data with no separate length prefix — the rest of the account
    // bytes are the Borsh-serialized message. The shape matches what
    // inspector::parse_squads_inner_message expects (`num_signers: u8`
    // first byte, then num_writable_signers, etc).
    //
    // Earlier I had a u32 length prefix here that doesn't exist in the
    // upstream account layout, which is why every VaultTx parse was failing
    // with "message bytes" — we were reading num_signers + num_writable_signers
    // + num_writable_non_signers + account_keys.len()_byte_0 as a u32 and
    // then trying to skip that-many bytes into the void.
    let msg_bytes = raw[8 + p.pos..].to_vec();

    Ok((vault_index, msg_bytes))
}

fn parse_config_transaction_action_count(raw: &[u8]) -> Result<u32> {
    if raw.len() < 8 || raw[0..8] != DISC_CONFIG_TRANSACTION {
        bail!("not a ConfigTransaction");
    }
    let mut p = Cursor::new(&raw[8..]);
    let _multisig = p.pubkey()?;
    let _creator  = p.pubkey()?;
    let _index    = p.u64()?;
    let _bump     = p.u8()?;
    let n_actions = p.u32().context("actions.len")?;
    Ok(n_actions)
}

// ── RPC plumbing ────────────────────────────────────────────────────────────

fn rpc_get_account_data(rpc_url: &str, pubkey_b58: &str) -> Result<Option<Vec<u8>>> {
    let body = serde_json::json!({
        "jsonrpc":"2.0","id":1,"method":"getAccountInfo",
        "params":[pubkey_b58, {"encoding":"base64", "commitment":"confirmed"}]
    });
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("building reqwest client")?;
    let resp: serde_json::Value = client.post(rpc_url).json(&body)
        .send().context("POST getAccountInfo")?
        .json().context("parsing RPC response")?;

    if let Some(err) = resp.get("error") {
        bail!("RPC error: {}", err);
    }
    let value = &resp["result"]["value"];
    if value.is_null() { return Ok(None); }
    let data_arr = value.get("data").and_then(|d| d.as_array())
        .ok_or_else(|| anyhow!("getAccountInfo: missing data array"))?;
    let b64 = data_arr.first().and_then(|s| s.as_str())
        .ok_or_else(|| anyhow!("getAccountInfo: data[0] not string"))?;
    let raw = B64.decode(b64).context("decoding account base64")?;
    Ok(Some(raw))
}

// Squads RPC failures should NOT pollute the TUI render — eprintln to stderr
// gets overlaid on the ratatui frame and looks like a bug. Append to a log
// file instead. Operators who want to debug can `tail -f` it; the TUI itself
// stays clean. Use SOVEREIGN_LOG_FILE to override path.
fn tracing_log_warn(msg: &str) {
    use std::io::Write as _;
    let path = std::env::var("SOVEREIGN_LOG_FILE")
        .unwrap_or_else(|_| "/tmp/sovereign-vault.log".to_string());
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true).append(true).open(&path)
    {
        let _ = writeln!(f, "[{}] [squads warn] {}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs()).unwrap_or(0),
            msg);
    }
    // Fall-through silent — never write to stderr while the TUI is alive.
}

// Single place to read the RPC URL (env-overridable). Returns an owned String
// because the env var lookup needs to happen at call time, not compile time.
pub fn default_rpc_url() -> String { rpc_url() }

// ── Tiny binary cursor (Anchor's Borsh wire format) ─────────────────────────

struct Cursor<'a> { buf: &'a [u8], pos: usize }
impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self { Self { buf, pos: 0 } }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.buf.len() {
            bail!("cursor: tried to read {} bytes at pos {} (have {})", n, self.pos, self.buf.len());
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn skip(&mut self, n: usize) -> Result<()> {
        if self.pos + n > self.buf.len() {
            bail!("cursor: tried to skip {} bytes at pos {}", n, self.pos);
        }
        self.pos += n;
        Ok(())
    }
    fn u8(&mut self) -> Result<u8>   { Ok(self.take(1)?[0]) }
    fn u16(&mut self) -> Result<u16> { Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap())) }
    fn u32(&mut self) -> Result<u32> { Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap())) }
    fn u64(&mut self) -> Result<u64> { Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap())) }
    fn i64(&mut self) -> Result<i64> { Ok(i64::from_le_bytes(self.take(8)?.try_into().unwrap())) }
    fn pubkey(&mut self) -> Result<Pubkey> {
        let bytes: [u8; 32] = self.take(32)?.try_into().context("pubkey 32 bytes")?;
        Ok(Pubkey::from(bytes))
    }
    fn option_pubkey(&mut self) -> Result<Option<Pubkey>> {
        let tag = self.u8()?;
        match tag {
            0 => Ok(None),
            1 => Ok(Some(self.pubkey()?)),
            n => bail!("invalid Option tag: {}", n),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_reads_primitives() {
        let buf = [0x01u8, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00];
        let mut c = Cursor::new(&buf);
        assert_eq!(c.u16().unwrap(), 1);
        assert_eq!(c.u16().unwrap(), 2);
        assert_eq!(c.u16().unwrap(), 3);
        assert_eq!(c.u16().unwrap(), 4);
    }

    #[test]
    fn proposal_pda_is_deterministic() {
        let m = Pubkey::new_unique();
        let a = derive_proposal_pda(&m, 7);
        let b = derive_proposal_pda(&m, 7);
        assert_eq!(a, b);
        let c = derive_proposal_pda(&m, 8);
        assert_ne!(a, c);
    }
}
