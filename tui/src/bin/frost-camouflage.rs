//! Camouflage your FROST shares inside a normal-looking PNG.
//!
//! Usage:
//!   frost-camouflage embed   --party laptop --cover photo.png --out vault.png
//!   frost-camouflage embed   --party bot    --cover photo.png --out vault-bot.png
//!   frost-camouflage extract               vault.png
//!
//! Then store `vault.png` anywhere normal photos go — cloud photos, an SD
//! card in a drawer, family album backup. The PNG looks identical to your
//! cover image (LSBs are imperceptible), and recovery requires both the PNG
//! AND your passphrase. Lose the PNG → still safe under the passphrase
//! barrier. Lose the passphrase → image is unrecoverable, plan accordingly.
//!
//! For the laptop side this packages `frost-share1.bin` + `frost-pubkey.bin`.
//! For the bot side it packages `share2.bin` + `pubkey.bin` + the bot's
//! `config.toml` (which contains the bot token — back this PNG up to a
//! place you'd back up password manager exports, not photo cloud).

use anyhow::{anyhow, bail, Context, Result};
use sovereign_os_vault::stego::{embed, extract, BackupPayload};
use std::io::Write;
use std::path::{Path, PathBuf};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("");
    match cmd {
        "embed"   => cmd_embed(&args[2..]),
        "extract" => cmd_extract(&args[2..]),
        _ => {
            eprintln!("Sovereign OS Vault — FROST share camouflage backup\n");
            eprintln!("Usage:");
            eprintln!("  frost-camouflage embed --party (laptop|bot) --cover <png> --out <png>");
            eprintln!("    Encrypts your FROST share + pubkey package under a passphrase,");
            eprintln!("    embeds it in the LSBs of <cover>, writes <out>. The output PNG");
            eprintln!("    looks identical to <cover> to the eye.");
            eprintln!();
            eprintln!("  frost-camouflage extract <png>");
            eprintln!("    Reads a sovereign-stego PNG, asks for the passphrase,");
            eprintln!("    writes the recovered share files into the appropriate keystore.");
            std::process::exit(2);
        }
    }
}

fn cmd_embed(args: &[String]) -> Result<()> {
    let mut party: Option<String> = None;
    let mut cover: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--party" => { party = args.get(i + 1).cloned(); i += 2; }
            "--cover" => { cover = args.get(i + 1).map(PathBuf::from); i += 2; }
            "--out"   => { out   = args.get(i + 1).map(PathBuf::from); i += 2; }
            other => bail!("unknown flag: {other}"),
        }
    }
    let party = party.ok_or_else(|| anyhow!("--party laptop|bot required"))?;
    let cover = cover.ok_or_else(|| anyhow!("--cover <png> required"))?;
    let out   = out.ok_or_else(|| anyhow!("--out <png> required"))?;

    let payload = build_payload(&party)?;
    eprintln!("Backing up:");
    eprintln!("  party       : {}", payload.party);
    eprintln!("  pubkey      : {}", payload.pubkey_hex);
    eprintln!("  Solana addr : {}", payload.solana_address);
    eprintln!("  cover image : {}", cover.display());
    eprintln!("  output PNG  : {}", out.display());
    eprintln!();
    let pass1 = prompt_passphrase("Passphrase (8+ chars): ")?;
    let pass2 = prompt_passphrase("Confirm passphrase   : ")?;
    if pass1 != pass2 {
        bail!("passphrases do not match");
    }
    embed(&payload, &pass1, &cover, &out)?;
    eprintln!();
    eprintln!("✓ Wrote camouflaged backup to {}", out.display());
    eprintln!("  Test recovery: frost-camouflage extract {}", out.display());
    Ok(())
}

fn cmd_extract(args: &[String]) -> Result<()> {
    let png = args.first().ok_or_else(|| anyhow!("usage: frost-camouflage extract <png>"))?;
    let png_path = Path::new(png);
    let pass = prompt_passphrase("Passphrase: ")?;
    let payload = extract(png_path, &pass)?;
    eprintln!();
    eprintln!("Recovered:");
    eprintln!("  party       : {}", payload.party);
    eprintln!("  pubkey      : {}", payload.pubkey_hex);
    eprintln!("  Solana addr : {}", payload.solana_address);
    eprintln!("  created at  : {}", payload.created_at);
    eprintln!();
    eprintln!("Confirm before writing to disk? [y/N]");
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    if !matches!(buf.trim(), "y" | "Y" | "yes") {
        eprintln!("Aborted — no files written.");
        return Ok(());
    }
    write_recovered(&payload)?;
    eprintln!("✓ Recovery complete. The TUI's BackendSelect screen should now show FROST as available.");
    Ok(())
}

fn build_payload(party: &str) -> Result<BackupPayload> {
    use sovereign_frost_bot::{config::BotConfig, share};
    use frost_ed25519 as frost;

    let (kp, pk, bot_config_toml) = match party {
        "laptop" => {
            let dir = laptop_keystore_dir()?;
            let kp = share::load_key_package(&dir.join("frost-share1.bin"))
                .context("loading laptop FROST share — run frost-keygen first")?;
            let pk = share::load_pubkey_package(&dir.join("frost-pubkey.bin"))?;
            (kp, pk, None)
        }
        "bot" => {
            let cfg = BotConfig::load_default().context("loading bot config")?;
            let kp = share::load_key_package(&cfg.share_path)
                .context("loading bot FROST share — run frost-keygen first")?;
            let pk = share::load_pubkey_package(&cfg.pubkey_path)?;
            // Read the raw config.toml so the recovered bot has its token + allowlist
            // back. WARNING: anyone with this PNG + passphrase has the bot token.
            let cfg_toml = std::fs::read_to_string(
                sovereign_frost_bot::config::default_config_path()?
            )?;
            (kp, pk, Some(cfg_toml))
        }
        other => bail!("unknown party '{other}' — must be 'laptop' or 'bot'"),
    };

    let pubkey_hex = pk.verifying_key().serialize().map(hex::encode)
        .map_err(|e| anyhow!("serialize verifying_key: {e}"))?;
    let solana_address = pk.verifying_key().serialize()
        .map(|b| bs58::encode(b).into_string())
        .map_err(|e| anyhow!("solana addr: {e}"))?;
    let key_package_hex = hex::encode(kp.serialize().map_err(|e| anyhow!("kp serialize: {e}"))?);
    let pubkey_package_hex = hex::encode(pk.serialize().map_err(|e| anyhow!("pk serialize: {e}"))?);

    Ok(BackupPayload {
        party: party.to_string(),
        pubkey_hex,
        solana_address,
        key_package_hex,
        pubkey_package_hex,
        bot_config_toml,
        created_at: now_iso8601(),
    })
}

fn write_recovered(payload: &BackupPayload) -> Result<()> {
    use sovereign_frost_bot::share;
    use frost_ed25519 as frost;

    let kp_bytes = hex::decode(&payload.key_package_hex)?;
    let pk_bytes = hex::decode(&payload.pubkey_package_hex)?;
    let kp = frost::keys::KeyPackage::deserialize(&kp_bytes)
        .map_err(|e| anyhow!("deserialize KeyPackage: {e}"))?;
    let pk = frost::keys::PublicKeyPackage::deserialize(&pk_bytes)
        .map_err(|e| anyhow!("deserialize PublicKeyPackage: {e}"))?;

    match payload.party.as_str() {
        "laptop" => {
            let dir = laptop_keystore_dir()?;
            std::fs::create_dir_all(&dir)?;
            share::save_key_package(&dir.join("frost-share1.bin"), &kp)?;
            share::save_pubkey_package(&dir.join("frost-pubkey.bin"), &pk)?;
            eprintln!("  wrote {}", dir.join("frost-share1.bin").display());
            eprintln!("  wrote {}", dir.join("frost-pubkey.bin").display());
        }
        "bot" => {
            use sovereign_frost_bot::config::{default_config_path, BotConfig};
            // If config.toml is present in the payload, write it (after asking).
            // We don't auto-write it because it contains the bot token and the
            // user might want to inspect first.
            if let Some(toml_str) = &payload.bot_config_toml {
                let cfg_path = default_config_path()?;
                std::fs::create_dir_all(cfg_path.parent().unwrap())?;
                if cfg_path.exists() {
                    eprintln!("  warning: {} already exists; not overwriting", cfg_path.display());
                    eprintln!("           manually merge the recovered config below if needed:");
                    eprintln!("---");
                    eprintln!("{}", toml_str);
                    eprintln!("---");
                } else {
                    std::fs::write(&cfg_path, toml_str)?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600))?;
                    }
                    eprintln!("  wrote {}", cfg_path.display());
                }
            }
            let cfg = BotConfig::load_default().context("after recovery, reloading bot config")?;
            std::fs::create_dir_all(cfg.share_path.parent().unwrap())?;
            share::save_key_package(&cfg.share_path, &kp)?;
            share::save_pubkey_package(&cfg.pubkey_path, &pk)?;
            eprintln!("  wrote {}", cfg.share_path.display());
            eprintln!("  wrote {}", cfg.pubkey_path.display());
        }
        _ => bail!("unknown party in recovered payload"),
    }
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

fn prompt_passphrase(prompt: &str) -> Result<String> {
    eprint!("{}", prompt);
    std::io::stderr().flush()?;
    // For v0.4 we use plain stdin (no termios echo-off). Recording the demo
    // is cleaner; v0.5 should use rpassword crate for hidden input.
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    Ok(buf.trim_end_matches('\n').trim_end_matches('\r').to_string())
}

fn now_iso8601() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Quick-and-dirty ISO 8601. v0.5: use chrono. For v0.4 demo, this is
    // fine — the timestamp is a sanity-check field, not a load-bearing one.
    let secs = now as i64;
    let days = secs / 86400;
    let mut year = 1970i64;
    let mut remaining_days = days;
    loop {
        let year_days = if is_leap(year) { 366 } else { 365 };
        if remaining_days < year_days { break; }
        remaining_days -= year_days;
        year += 1;
    }
    // Crude — v0.5 will use a real lib.
    format!("{:04}-{:02}-{:02}T??:??:??Z (epoch {})", year, 1, 1, now)
}

fn is_leap(y: i64) -> bool { (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 }
