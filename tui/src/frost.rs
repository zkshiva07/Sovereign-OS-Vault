//! FROST 2-of-2 ed25519 client — laptop side of the Telegram-bot cosigner.
//!
//! This mirrors the API shape of `vultisig.rs` so the TUI can swap backends
//! with one match arm. The wire protocol lives in the `sovereign-frost-bot`
//! crate (path-dep at `../frost-bot`); we import its `protocol` and `share`
//! modules directly to avoid duplicating types.
//!
//! Threat-model boundaries this module is responsible for:
//!   - Loads the laptop's FROST share (KeyPackage) from disk. The share is
//!     useless without the bot's share + the user's Telegram approval, so a
//!     theft of just this file does not produce signatures. v0.5 will wrap
//!     the file with the existing Argon2id keystore so theft of the file
//!     also requires the unlock passphrase.
//!   - The HTTPS client to the bot is `reqwest::blocking` — sync I/O on a
//!     worker thread, so the ratatui event loop stays responsive (same
//!     pattern as vultisig.rs).
//!   - We NEVER ship our share to the bot. We ship: a SigningCommitment
//!     (round-1, no secret material), the message bytes, and the inspector's
//!     decoded summary + decision. The bot replies with its own commitment +
//!     signature share, which on its own cannot be turned into a full
//!     signature without our share — and vice versa.

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use ed25519_dalek::Verifier;
use frost_ed25519 as frost;
use sovereign_frost_bot::{
    protocol::{LaptopDecision, SignError, SignRequest, SignResponse},
    share,
};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

/// Default URL the bot binds — matches `frost-bot/config.toml`.
pub const DEFAULT_BOT_URL: &str = "http://127.0.0.1:7777";
pub const HEALTH_TIMEOUT: Duration = Duration::from_secs(2);
pub const SIGN_TIMEOUT: Duration   = Duration::from_secs(150);

/// The laptop's FROST identity (loaded once at backend selection).
#[derive(Clone)]
pub struct LaptopFrost {
    pub key_package:    frost::keys::KeyPackage,
    pub pubkey_package: frost::keys::PublicKeyPackage,
}

impl LaptopFrost {
    /// Load the share and group public-key package from the default location.
    pub fn load() -> Result<Self> {
        let dir = laptop_keystore_dir()?;
        Self::load_from(&dir)
    }

    pub fn load_from(dir: &std::path::Path) -> Result<Self> {
        let kp_path = dir.join("frost-share1.bin");
        let pk_path = dir.join("frost-pubkey.bin");
        let key_package = share::load_key_package(&kp_path)
            .with_context(|| format!(
                "loading laptop FROST share from {} — run `frost-keygen` if missing",
                kp_path.display(),
            ))?;
        let pubkey_package = share::load_pubkey_package(&pk_path)?;
        Ok(Self { key_package, pubkey_package })
    }

    /// Solana base58 address of the FROST group public key.
    pub fn solana_address(&self) -> Result<String> {
        let bytes = self.pubkey_package.verifying_key().serialize()
            .context("serializing FROST verifying key")?;
        Ok(bs58::encode(bytes).into_string())
    }
}

/// Synchronous client to the local FROST bot.
pub struct FrostClient {
    bot_url: String,
}

impl FrostClient {
    pub fn new(bot_url: impl Into<String>) -> Self {
        Self { bot_url: bot_url.into() }
    }

    pub fn default_url() -> Self {
        Self::new(DEFAULT_BOT_URL)
    }

    /// Quick connectivity check: GET /health, expect 200 within a few seconds.
    pub fn is_running(&self) -> bool {
        let client = match reqwest::blocking::Client::builder()
            .timeout(HEALTH_TIMEOUT).build() { Ok(c) => c, Err(_) => return false };
        client.get(format!("{}/health", self.bot_url))
            .send()
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    /// Sign a serialized Solana `Message` (legacy or v0) via the bot.
    ///
    /// Round-trip:
    ///   1. Generate FROST round-1 commitments (laptop side, fresh per call)
    ///   2. POST /sign with: message_b64, decoded_summary, GREEN decision,
    ///      laptop's commitments, laptop's identifier
    ///   3. Bot DMs the user with the decoded summary + Approve/Reject buttons,
    ///      waits up to 120s for the user's tap
    ///   4. On Approve: bot computes its own commitments + signature share,
    ///      returns them. On Reject/Timeout: bot returns 4xx with a SignError.
    ///   5. Laptop computes its round-2 share, aggregates, verifies via FROST
    ///      and via ed25519-dalek (which is what Solana uses).
    ///   6. Returns the **base58-encoded full signed VersionedTransaction**
    ///      ready to broadcast — same return shape as VultisigClient::sign_solana.
    /// `assemble_into_tx`: if true, wrap the sig + message into a broadcastable
    /// VersionedTransaction (paste flow — message is a real Solana Message).
    /// If false, return the raw 64-byte FROST signature as base58 — used for
    /// Squads proposal approval where the message bytes are Squads' inline
    /// VaultTransactionMessage format (not a Solana Message). v0.5 will use
    /// the raw sig to construct a `proposal_approve` instruction on-chain.
    pub fn sign_solana(
        &self,
        laptop: &LaptopFrost,
        message_bytes: &[u8],
        decoded_summary: &str,
        assemble_into_tx: bool,
    ) -> Result<String> {
        let mut rng = rand::thread_rng();
        let laptop_identifier = *laptop.key_package.identifier();

        let (laptop_nonces, laptop_commitments) = frost::round1::commit(
            laptop.key_package.signing_share(),
            &mut rng,
        );

        let req = SignRequest {
            message_b64: base64::engine::general_purpose::STANDARD.encode(message_bytes),
            decoded_summary: decoded_summary.to_string(),
            laptop_decision: LaptopDecision::Green,
            laptop_commitments_hex: hex::encode(
                laptop_commitments.serialize().context("serialize laptop commitments")?
            ),
            laptop_identifier_hex: hex::encode(laptop_identifier.serialize()),
        };

        let client = reqwest::blocking::Client::builder()
            .timeout(SIGN_TIMEOUT).build()
            .context("building reqwest client")?;
        let resp = client.post(format!("{}/sign", self.bot_url))
            .json(&req).send()
            .context("POST /sign — is the bot running?")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body: serde_json::Value = resp.json()
                .unwrap_or_else(|_| serde_json::json!({"error":"(non-JSON body)"}));
            let parsed: SignError = serde_json::from_value(body.clone())
                .unwrap_or(SignError {
                    kind: sovereign_frost_bot::protocol::SignErrorKind::Internal,
                    message: body.to_string(),
                });
            bail!("bot returned {} — {:?}: {}", status, parsed.kind, parsed.message);
        }

        let sign_resp: SignResponse = resp.json().context("parsing bot response")?;

        let bot_commitments = frost::round1::SigningCommitments::deserialize(
            &hex::decode(&sign_resp.bot_commitments_hex).context("hex decode bot commitments")?
        ).map_err(|e| anyhow!("deserialize bot commitments: {e}"))?;
        let bot_signature_share = frost::round2::SignatureShare::deserialize(
            hex::decode(&sign_resp.bot_signature_share_hex)
                .context("hex decode bot share")?
                .as_slice().try_into()
                .map_err(|_| anyhow!("bot signature share: bad length"))?
        ).map_err(|e| anyhow!("deserialize bot signature share: {e}"))?;
        let bot_identifier = frost::Identifier::deserialize(
            &hex::decode(&sign_resp.bot_identifier_hex).context("hex decode bot identifier")?
        ).map_err(|e| anyhow!("deserialize bot identifier: {e}"))?;

        let mut commitments_map = BTreeMap::new();
        commitments_map.insert(laptop_identifier, laptop_commitments);
        commitments_map.insert(bot_identifier, bot_commitments);
        let signing_package = frost::SigningPackage::new(commitments_map, message_bytes);

        let laptop_share = frost::round2::sign(&signing_package, &laptop_nonces, &laptop.key_package)
            .map_err(|e| anyhow!("FROST round 2 (laptop): {e}"))?;

        let mut signature_shares = BTreeMap::new();
        signature_shares.insert(laptop_identifier, laptop_share);
        signature_shares.insert(bot_identifier, bot_signature_share);

        let group_signature = frost::aggregate(&signing_package, &signature_shares, &laptop.pubkey_package)
            .map_err(|e| anyhow!("FROST aggregate: {e}"))?;
        let sig_bytes = group_signature.serialize()
            .map_err(|e| anyhow!("serialize aggregate signature: {e}"))?;

        // Belt-and-suspenders verify with the same crate Solana uses.
        let pk_bytes = laptop.pubkey_package.verifying_key().serialize()
            .map_err(|e| anyhow!("serialize verifying key: {e}"))?;
        let dalek_pk = ed25519_dalek::VerifyingKey::from_bytes(
            pk_bytes.as_slice().try_into().context("vk len")?
        ).context("ed25519-dalek VerifyingKey::from_bytes")?;
        let dalek_sig = ed25519_dalek::Signature::from_bytes(
            sig_bytes.as_slice().try_into().map_err(|_| anyhow!("sig len"))?
        );
        dalek_pk.verify(message_bytes, &dalek_sig)
            .context("ed25519-dalek post-aggregate verify failed — refusing to broadcast")?;

        if assemble_into_tx {
            // Paste flow: message is a real Solana Message. Wrap into a
            // broadcastable VersionedTransaction.
            assemble_signed_tx(message_bytes, &sig_bytes)
        } else {
            // Squads-approval flow: message is Squads' inline
            // VaultTransactionMessage format, not directly broadcastable.
            // Return the raw 64-byte FROST signature so the caller can
            // (in v0.5) embed it in a `proposal_approve` instruction.
            // For v0.4 the signature is the cryptographic proof that the
            // user explicitly approved via their Telegram session.
            Ok(bs58::encode(&sig_bytes).into_string())
        }
    }
}

fn laptop_keystore_dir() -> Result<PathBuf> {
    let base = if let Some(d) = std::env::var_os("XDG_DATA_HOME") {
        PathBuf::from(d)
    } else {
        let home = std::env::var_os("HOME").ok_or_else(|| anyhow!("$HOME not set"))?;
        PathBuf::from(home).join(".local/share")
    };
    Ok(base.join("sovereign-os-vault/keystore"))
}

/// Build a broadcastable VersionedTransaction (same logic main.rs uses for
/// the Vultisig path's signature, but with raw signature bytes instead of bs58).
/// Returns the full signed tx in base58.
fn assemble_signed_tx(message_bytes: &[u8], sig_bytes: &[u8]) -> Result<String> {
    use solana_sdk::message::{Message, VersionedMessage};
    use solana_sdk::signature::Signature;
    use solana_sdk::transaction::VersionedTransaction;

    let vmsg: VersionedMessage = bincode::deserialize(message_bytes)
        .or_else(|_| bincode::deserialize::<Message>(message_bytes).map(VersionedMessage::Legacy))
        .context("deserialize Solana message")?;

    if sig_bytes.len() != 64 {
        bail!("FROST aggregate produced signature of unexpected length: {}", sig_bytes.len());
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(sig_bytes);
    let sig = Signature::from(arr);

    let tx = VersionedTransaction { signatures: vec![sig], message: vmsg };
    let serialized = bincode::serialize(&tx).context("bincode serialize VersionedTransaction")?;
    Ok(bs58::encode(serialized).into_string())
}
