//! Bot-side TOML config loader.
//!
//! The bot reads `~/.local/share/sovereign-os-vault/frost-bot/config.toml`
//! (mode 600). The token + allowlist live there, outside the source tree.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
pub struct BotConfig {
    pub bot_token:        String,
    pub authorized_users: Vec<i64>,
    pub listen_addr:      String,
    pub share_path:       PathBuf,
    pub pubkey_path:      PathBuf,
}

impl BotConfig {
    pub fn load_default() -> Result<Self> {
        let path = default_config_path()?;
        Self::load_from(&path)
    }

    pub fn load_from(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("reading bot config at {}", path.display()))?;
        let cfg: BotConfig = toml::from_str(&raw)
            .with_context(|| format!("parsing bot config at {}", path.display()))?;
        if cfg.bot_token.is_empty() {
            bail!("bot_token is empty in {}", path.display());
        }
        if cfg.authorized_users.is_empty() {
            bail!("authorized_users is empty in {} — at least one Telegram user ID required", path.display());
        }
        Ok(cfg)
    }
}

pub fn default_config_path() -> Result<PathBuf> {
    let base = dirs_local_share()?;
    Ok(base.join("sovereign-os-vault/frost-bot/config.toml"))
}

fn dirs_local_share() -> Result<PathBuf> {
    if let Some(d) = std::env::var_os("XDG_DATA_HOME") {
        return Ok(PathBuf::from(d));
    }
    let home = std::env::var_os("HOME")
        .ok_or_else(|| anyhow::anyhow!("$HOME not set"))?;
    Ok(PathBuf::from(home).join(".local/share"))
}
