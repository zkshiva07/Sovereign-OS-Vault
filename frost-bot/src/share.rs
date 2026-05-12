//! FROST share storage on disk.
//!
//! For the v0.4 demo we serialize the FROST `KeyPackage` and `PublicKeyPackage`
//! using `bincode` and write to disk. v0.5 will wrap these with the existing
//! Argon2id-encrypted keystore from `tui/src/keystore.rs`. Keep this module
//! deliberately small so swapping persistence layers later is one file.

use anyhow::{Context, Result};
use frost_ed25519 as frost;
use std::fs;
use std::path::Path;

pub fn save_key_package(path: &Path, kp: &frost::keys::KeyPackage) -> Result<()> {
    let bytes = kp.serialize().context("serializing FROST KeyPackage")?;
    write_secure(path, &bytes)
}

pub fn load_key_package(path: &Path) -> Result<frost::keys::KeyPackage> {
    let bytes = fs::read(path)
        .with_context(|| format!("reading KeyPackage from {}", path.display()))?;
    frost::keys::KeyPackage::deserialize(&bytes)
        .with_context(|| format!("deserializing FROST KeyPackage from {}", path.display()))
}

pub fn save_pubkey_package(path: &Path, pk: &frost::keys::PublicKeyPackage) -> Result<()> {
    let bytes = pk.serialize().context("serializing FROST PublicKeyPackage")?;
    write_secure(path, &bytes)
}

pub fn load_pubkey_package(path: &Path) -> Result<frost::keys::PublicKeyPackage> {
    let bytes = fs::read(path)
        .with_context(|| format!("reading PublicKeyPackage from {}", path.display()))?;
    frost::keys::PublicKeyPackage::deserialize(&bytes)
        .with_context(|| format!("deserializing FROST PublicKeyPackage from {}", path.display()))
}

/// Write bytes to `path`, creating parent dirs and chmod-ing the file 0600
/// (owner-only) on Unix. Replaces any existing file atomically.
fn write_secure(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating dir {}", parent.display()))?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)
        .with_context(|| format!("writing {}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 600 {}", tmp.display()))?;
    }
    fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}
