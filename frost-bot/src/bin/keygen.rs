//! Trusted-dealer FROST 2-of-2 keygen for the v0.4 demo.
//!
//! Writes:
//!   - Laptop share → ~/.local/share/sovereign-os-vault/keystore/frost-share1.bin
//!   - Laptop pubkey → ~/.local/share/sovereign-os-vault/keystore/frost-pubkey.bin
//!   - Bot share + pubkey → paths from frost-bot's config.toml
//!
//! v0.5 will replace this with distributed key generation (DKG) so neither
//! party ever sees both shares. For the demo, trusted-dealer is the honest
//! starting point — the README will explicitly call out that the keygen step
//! has a moment of trust that DKG removes.

use anyhow::{Context, Result};
use frost_ed25519 as frost;
use sovereign_frost_bot::{config::BotConfig, share};
use std::path::PathBuf;

fn main() -> Result<()> {
    let cfg = BotConfig::load_default()
        .context("loading bot config — generate one at ~/.local/share/sovereign-os-vault/frost-bot/config.toml first")?;

    let mut rng = rand::thread_rng();
    let (shares, pubkey_package) = frost::keys::generate_with_dealer(
        2, 2,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )?;

    // BTreeMap iteration is ordered by Identifier — first share = laptop, second = bot.
    let mut kps: std::collections::BTreeMap<_, _> = shares
        .into_iter()
        .map(|(id, s)| {
            let kp = frost::keys::KeyPackage::try_from(s)?;
            Ok::<_, frost::Error>((id, kp))
        })
        .collect::<Result<_, _>>()?;

    let (laptop_id, laptop_kp) = kps.pop_first()
        .ok_or_else(|| anyhow::anyhow!("keygen produced no laptop share"))?;
    let (bot_id, bot_kp) = kps.pop_first()
        .ok_or_else(|| anyhow::anyhow!("keygen produced no bot share"))?;

    let laptop_dir = laptop_keystore_dir()?;
    std::fs::create_dir_all(&laptop_dir)
        .with_context(|| format!("creating {}", laptop_dir.display()))?;
    let laptop_share_path = laptop_dir.join("frost-share1.bin");
    let laptop_pubkey_path = laptop_dir.join("frost-pubkey.bin");

    share::save_key_package(&laptop_share_path, &laptop_kp)?;
    share::save_pubkey_package(&laptop_pubkey_path, &pubkey_package)?;
    share::save_key_package(&cfg.share_path, &bot_kp)?;
    share::save_pubkey_package(&cfg.pubkey_path, &pubkey_package)?;

    let pubkey_bytes = pubkey_package.verifying_key().serialize()?;
    let solana_addr = bs58::encode(&pubkey_bytes).into_string();

    println!();
    println!("┌─ FROST 2-of-2 keygen complete ──────────────────────────────────────");
    println!("│ Laptop share : {}", laptop_share_path.display());
    println!("│ Laptop pubkey: {}", laptop_pubkey_path.display());
    println!("│ Bot share    : {}", cfg.share_path.display());
    println!("│ Bot pubkey   : {}", cfg.pubkey_path.display());
    println!("│");
    println!("│ Group public key (hex)    : {}", hex::encode(&pubkey_bytes));
    println!("│ Solana address (base58)   : {}", solana_addr);
    println!("│ Laptop FROST identifier   : {}", hex::encode(laptop_id.serialize()));
    println!("│ Bot FROST identifier      : {}", hex::encode(bot_id.serialize()));
    println!("└─────────────────────────────────────────────────────────────────────");
    println!();
    println!("Next: start the bot with `cargo run --release --bin frost-bot`,");
    println!("then drive a sign with  `cargo run --release --bin frost-laptop-sim`.");

    Ok(())
}

fn laptop_keystore_dir() -> Result<PathBuf> {
    let base = if let Some(d) = std::env::var_os("XDG_DATA_HOME") {
        PathBuf::from(d)
    } else {
        let home = std::env::var_os("HOME")
            .ok_or_else(|| anyhow::anyhow!("$HOME not set"))?;
        PathBuf::from(home).join(".local/share")
    };
    Ok(base.join("sovereign-os-vault/keystore"))
}
