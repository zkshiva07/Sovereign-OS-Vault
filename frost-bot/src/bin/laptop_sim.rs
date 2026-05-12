//! Laptop-side simulator. Replaces the real sovereign-vault TUI for the
//! phase-1 round-trip de-risk: load the laptop FROST share, generate round-1
//! commitments, ship them to the bot with a fake decoded summary, wait for
//! the bot's response, finish round-2 and aggregate, verify with
//! ed25519-dalek (Solana's verifier), print the final signature in base58.
//!
//! Usage:
//!   cargo run --release --bin frost-laptop-sim -- "your fake decoded summary"
//!
//! Once this works end-to-end we wire it into tui/src/frost.rs as a real
//! `Backend::TelegramFrost` variant.

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

const BOT_URL: &str = "http://127.0.0.1:7777/sign";

#[tokio::main]
async fn main() -> Result<()> {
    let summary = std::env::args().nth(1).unwrap_or_else(|| {
        "Solana legacy Message — Transfer 0.001 SOL\n\
         From: 8VhF...kXoP (sovereign vault)\n\
         To:   3rNm...zYpA (treasury hot wallet)\n\
         Inspector decision: GREEN — recipient on allowlist, amount within cap"
            .to_string()
    });

    let laptop_dir = laptop_keystore_dir()?;
    let laptop_share_path = laptop_dir.join("frost-share1.bin");
    let laptop_pubkey_path = laptop_dir.join("frost-pubkey.bin");

    let laptop_kp = share::load_key_package(&laptop_share_path)
        .with_context(|| format!("loading laptop FROST share from {}", laptop_share_path.display()))?;
    let pubkey_package = share::load_pubkey_package(&laptop_pubkey_path)?;

    let laptop_identifier = *laptop_kp.identifier();

    let message = b"hello sovereign-os-vault FROST-Telegram demo";
    println!("Laptop: signing message ({} bytes): {:?}", message.len(), std::str::from_utf8(message).unwrap_or("(binary)"));

    let mut rng = rand::thread_rng();
    let (laptop_nonces, laptop_commitments) = frost::round1::commit(
        laptop_kp.signing_share(),
        &mut rng,
    );

    let req = SignRequest {
        message_b64: base64::engine::general_purpose::STANDARD.encode(message),
        decoded_summary: summary,
        laptop_decision: LaptopDecision::Green,
        laptop_commitments_hex: hex::encode(laptop_commitments.serialize()
            .context("serialize laptop commitments")?),
        laptop_identifier_hex: hex::encode(laptop_identifier.serialize()),
    };

    println!("Laptop: POST {} ...", BOT_URL);
    println!("Laptop: waiting for you to tap Approve in Telegram (timeout 120s)...");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(150))
        .build()?;
    let resp = client.post(BOT_URL).json(&req).send().await
        .context("POST to bot — is it running on 127.0.0.1:7777?")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.unwrap_or_else(|_| serde_json::json!({"error":"(non-JSON body)"}));
        let pretty: SignError = serde_json::from_value(body.clone()).unwrap_or(SignError {
            kind: sovereign_frost_bot::protocol::SignErrorKind::Internal,
            message: body.to_string(),
        });
        bail!("bot returned {} — kind={:?} message={}", status, pretty.kind, pretty.message);
    }

    let sign_resp: SignResponse = resp.json().await.context("parsing bot response")?;
    println!("Laptop: bot returned commitments + share, finishing round 2...");

    let bot_commitments = frost::round1::SigningCommitments::deserialize(
        &hex::decode(&sign_resp.bot_commitments_hex)?
    ).map_err(|e| anyhow!("deserialize bot commitments: {e}"))?;
    let bot_signature_share = frost::round2::SignatureShare::deserialize(
        hex::decode(&sign_resp.bot_signature_share_hex)?.as_slice().try_into()
            .map_err(|_| anyhow!("bot signature share: bad length"))?
    ).map_err(|e| anyhow!("deserialize bot signature share: {e}"))?;
    let bot_identifier = frost::Identifier::deserialize(
        &hex::decode(&sign_resp.bot_identifier_hex)?
    ).map_err(|e| anyhow!("deserialize bot identifier: {e}"))?;

    let mut commitments_map = BTreeMap::new();
    commitments_map.insert(laptop_identifier, laptop_commitments);
    commitments_map.insert(bot_identifier, bot_commitments);
    let signing_package = frost::SigningPackage::new(commitments_map, message);

    let laptop_share = frost::round2::sign(&signing_package, &laptop_nonces, &laptop_kp)
        .context("FROST round 2 sign (laptop side)")?;

    let mut signature_shares = BTreeMap::new();
    signature_shares.insert(laptop_identifier, laptop_share);
    signature_shares.insert(bot_identifier, bot_signature_share);

    let group_signature = frost::aggregate(&signing_package, &signature_shares, &pubkey_package)
        .context("FROST aggregate")?;
    let sig_bytes = group_signature.serialize().context("serialize group sig")?;

    println!();
    println!("┌─ Signature complete ────────────────────────────────────────────────");
    println!("│ Final ed25519 signature ({} bytes):", sig_bytes.len());
    println!("│   hex   : {}", hex::encode(&sig_bytes));
    println!("│   base58: {}", bs58::encode(&sig_bytes).into_string());

    pubkey_package.verifying_key().verify(message, &group_signature)
        .context("FROST self-verify")?;
    println!("│ FROST self-verify           : PASS");

    let pk_bytes = pubkey_package.verifying_key().serialize()?;
    let dalek_pk = ed25519_dalek::VerifyingKey::from_bytes(
        pk_bytes.as_slice().try_into().context("pk len")?
    )?;
    let dalek_sig = ed25519_dalek::Signature::from_bytes(
        sig_bytes.as_slice().try_into().map_err(|_| anyhow!("sig len"))?
    );
    dalek_pk.verify(message, &dalek_sig).context("ed25519-dalek verify")?;
    println!("│ ed25519-dalek (Solana) verify: PASS");
    println!("└─────────────────────────────────────────────────────────────────────");

    Ok(())
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
