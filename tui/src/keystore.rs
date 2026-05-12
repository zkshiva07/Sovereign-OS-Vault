//! Encrypted Solana keystore with **duress mode** (plausible deniability).
//!
//! The keystore on disk holds TWO independently encrypted ed25519 keypairs:
//!   - sovereign: your real key (full signing authority)
//!   - decoy:     a bait key with hard-capped signing limits
//!
//! At unlock time, ONE passphrase is entered. The unlock routine derives BOTH
//! candidate keys (always, regardless of which one matches) and attempts decryption
//! of BOTH slots before deciding which mode is active. This makes the unlock
//! latency identical whether sovereign or decoy was supplied — a coercer watching
//! the screen cannot tell which mode they coerced you into.
//!
//! The caller (signing flow) consults `UnlockedKey::mode` and `caps` to enforce
//! per-tx and cumulative lamport-outflow limits when in decoy mode. The attacker
//! sees a normal-looking signing UI and a single-tx success; the caps prevent
//! repeated draining beyond the bait amount.
//!
//! At rest:   Argon2id(passphrase, salt) → 32-byte key → ChaCha20-Poly1305 AEAD.
//! At runtime: keypair lives in Zeroizing<[u8;64]>; mlockall'd at startup.

use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use solana_sdk::signature::{Keypair, Signer};
use std::fs;
use std::path::PathBuf;
use zeroize::{Zeroize, Zeroizing};

const KEYSTORE_VERSION: u32 = 2;          // bumped: v1 = single key, v2 = duress

const ARGON2_M_COST: u32 = 65536;          // 64 MiB
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 4;
const ARGON2_TAGLEN: usize = 32;

// Default duress caps. The user can edit keystore.json to raise these later, but
// the defaults are intentionally tight: a coercer can move at most 0.05 SOL in
// any single transaction, and at most 0.1 SOL total within a single session.
pub const DEFAULT_DECOY_MAX_PER_TX_LAMPORTS:    u64 =  50_000_000;  // 0.05 SOL
pub const DEFAULT_DECOY_MAX_CUMULATIVE_LAMPORTS:u64 = 100_000_000;  // 0.1 SOL

#[derive(Serialize, Deserialize)]
struct EncryptedSlot {
    pubkey:         String,    // base58 — display only, not security-critical
    kdf_salt_b64:   String,    // 16 bytes
    nonce_b64:      String,    // 12 bytes
    ciphertext_b64: String,    // 64-byte keypair + 16-byte tag
}

#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct DuressCaps {
    pub max_per_tx_lamports:    u64,
    pub max_cumulative_lamports: u64,
}

#[derive(Serialize, Deserialize)]
struct OnDiskKeystore {
    version:    u32,
    kdf:        String,         // "argon2id"
    kdf_m_cost: u32,
    kdf_t_cost: u32,
    kdf_p_cost: u32,
    aead:       String,         // "chacha20-poly1305"

    sovereign:   EncryptedSlot,
    decoy:       EncryptedSlot,
    duress_caps: DuressCaps,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum UnlockMode {
    Sovereign,
    Decoy,
}

/// In-memory unlocked keypair. Zeroizes on drop.
pub struct UnlockedKey {
    keypair_bytes:   Zeroizing<[u8; 64]>,
    pub mode:        UnlockMode,
    pub caps:        DuressCaps,
    /// Lamport outflow signed in this session. Updated by the sign flow.
    pub session_spent_lamports: u64,
}

// Custom Debug — never print key bytes. Only mode + spend tracking.
impl std::fmt::Debug for UnlockedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockedKey")
            .field("mode", &(match self.mode {
                UnlockMode::Sovereign => "<redacted>",
                UnlockMode::Decoy     => "<redacted>",
            }))
            .field("session_spent_lamports", &self.session_spent_lamports)
            .field("keypair_bytes", &"<zeroized-on-drop>")
            .finish()
    }
}

impl UnlockedKey {
    pub fn keypair(&self) -> Keypair {
        Keypair::try_from(self.keypair_bytes.as_slice())
            .expect("keypair bytes were validated at unlock time")
    }
    pub fn pubkey_base58(&self) -> String {
        self.keypair().pubkey().to_string()
    }
    /// Note a successful signing's lamport outflow. Used for cumulative caps.
    pub fn note_spent(&mut self, lamports: u64) {
        self.session_spent_lamports = self.session_spent_lamports.saturating_add(lamports);
    }
}

// ── Paths ────────────────────────────────────────────────────────────────────

pub fn keystore_dir() -> Result<PathBuf> {
    let base = dirs::data_local_dir()
        .ok_or_else(|| anyhow!("could not resolve XDG_DATA_HOME / LOCALAPPDATA"))?;
    Ok(base.join("sovereign-os-vault"))
}

pub fn keystore_path() -> Result<PathBuf> {
    Ok(keystore_dir()?.join("keystore.json"))
}

pub fn signed_dir() -> Result<PathBuf> {
    Ok(keystore_dir()?.join("signed"))
}

pub fn keystore_exists() -> bool {
    keystore_path().map(|p| p.exists()).unwrap_or(false)
}

// ── Create (duress: BOTH keys at once) ───────────────────────────────────────

/// Generate a fresh sovereign + decoy keypair, encrypt each under its own
/// passphrase, and persist them in a single duress-mode keystore.
///
/// Returns the unlocked SOVEREIGN key — the caller is the legitimate operator
/// who just set everything up; the decoy keypair is generated in memory and
/// immediately wiped after encryption.
pub fn create_new_duress(
    sovereign_pass: &str,
    decoy_pass:     &str,
) -> Result<UnlockedKey> {
    if sovereign_pass.len() < 8 || decoy_pass.len() < 8 {
        bail!("both passphrases must be at least 8 characters");
    }
    if sovereign_pass == decoy_pass {
        bail!(
            "sovereign and decoy passphrases must differ — \
             a single passphrase defeats the purpose of duress mode"
        );
    }

    // Generate keypairs.
    let sov_kp = Keypair::new();
    let dec_kp = Keypair::new();

    let mut sov_bytes = Zeroizing::new([0u8; 64]);
    sov_bytes.copy_from_slice(&sov_kp.to_bytes());
    let mut dec_bytes = Zeroizing::new([0u8; 64]);
    dec_bytes.copy_from_slice(&dec_kp.to_bytes());

    // Per-slot salt + nonce.
    let mut sov_salt = [0u8; 16]; OsRng.fill_bytes(&mut sov_salt);
    let mut dec_salt = [0u8; 16]; OsRng.fill_bytes(&mut dec_salt);
    let mut sov_nonce = [0u8; 12]; OsRng.fill_bytes(&mut sov_nonce);
    let mut dec_nonce = [0u8; 12]; OsRng.fill_bytes(&mut dec_nonce);

    let mut sov_key = Zeroizing::new([0u8; 32]);
    let mut dec_key = Zeroizing::new([0u8; 32]);
    derive_key(sovereign_pass, &sov_salt, ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, &mut sov_key)?;
    derive_key(decoy_pass,     &dec_salt, ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, &mut dec_key)?;

    let sov_cipher = ChaCha20Poly1305::new(Key::from_slice(&*sov_key));
    let dec_cipher = ChaCha20Poly1305::new(Key::from_slice(&*dec_key));

    let sov_ct = sov_cipher
        .encrypt(Nonce::from_slice(&sov_nonce), sov_bytes.as_slice())
        .map_err(|_| anyhow!("encrypting sovereign slot failed"))?;
    let dec_ct = dec_cipher
        .encrypt(Nonce::from_slice(&dec_nonce), dec_bytes.as_slice())
        .map_err(|_| anyhow!("encrypting decoy slot failed"))?;

    let on_disk = OnDiskKeystore {
        version:    KEYSTORE_VERSION,
        kdf:        "argon2id".into(),
        kdf_m_cost: ARGON2_M_COST,
        kdf_t_cost: ARGON2_T_COST,
        kdf_p_cost: ARGON2_P_COST,
        aead:       "chacha20-poly1305".into(),
        sovereign:  EncryptedSlot {
            pubkey:         sov_kp.pubkey().to_string(),
            kdf_salt_b64:   b64_encode(&sov_salt),
            nonce_b64:      b64_encode(&sov_nonce),
            ciphertext_b64: b64_encode(&sov_ct),
        },
        decoy:      EncryptedSlot {
            pubkey:         dec_kp.pubkey().to_string(),
            kdf_salt_b64:   b64_encode(&dec_salt),
            nonce_b64:      b64_encode(&dec_nonce),
            ciphertext_b64: b64_encode(&dec_ct),
        },
        duress_caps: DuressCaps {
            max_per_tx_lamports:    DEFAULT_DECOY_MAX_PER_TX_LAMPORTS,
            max_cumulative_lamports: DEFAULT_DECOY_MAX_CUMULATIVE_LAMPORTS,
        },
    };

    write_keystore_atomic(&on_disk)?;

    // Wipe the decoy bytes from memory; we don't return them.
    drop(dec_bytes);

    Ok(UnlockedKey {
        keypair_bytes:          sov_bytes,
        mode:                   UnlockMode::Sovereign,
        caps:                   on_disk.duress_caps,
        session_spent_lamports: 0,
    })
}

// ── Unlock (constant-time-ish across slots) ──────────────────────────────────

/// Unlock with a passphrase. Tries the sovereign slot first, then the decoy slot
/// — but ALWAYS performs both Argon2id derivations and both AEAD verifications,
/// regardless of which one matches. This means the wall-clock time of unlock is
/// (modulo CPU jitter) the same whether sovereign or decoy was entered, so an
/// attacker watching cannot tell which mode just unlocked.
pub fn unlock(passphrase: &str) -> Result<UnlockedKey> {
    let path = keystore_path()?;
    let raw  = fs::read_to_string(&path)
        .with_context(|| format!("reading {}", path.display()))?;
    let ks: OnDiskKeystore = serde_json::from_str(&raw)
        .context("parsing keystore.json")?;

    if ks.version != KEYSTORE_VERSION {
        bail!("unsupported keystore version: {}", ks.version);
    }
    if ks.kdf != "argon2id" {
        bail!("unsupported KDF: {}", ks.kdf);
    }
    if ks.aead != "chacha20-poly1305" {
        bail!("unsupported AEAD: {}", ks.aead);
    }

    let sov_salt  = b64_decode(&ks.sovereign.kdf_salt_b64)?;
    let sov_nonce = b64_decode(&ks.sovereign.nonce_b64)?;
    let sov_ct    = b64_decode(&ks.sovereign.ciphertext_b64)?;
    let dec_salt  = b64_decode(&ks.decoy.kdf_salt_b64)?;
    let dec_nonce = b64_decode(&ks.decoy.nonce_b64)?;
    let dec_ct    = b64_decode(&ks.decoy.ciphertext_b64)?;
    if sov_nonce.len() != 12 || dec_nonce.len() != 12 {
        bail!("invalid nonce length in keystore");
    }

    // Derive BOTH candidate keys regardless of which slot matches. This makes
    // unlock latency uniform across modes (~2× single-slot latency).
    let mut sov_key = Zeroizing::new([0u8; 32]);
    let mut dec_key = Zeroizing::new([0u8; 32]);
    derive_key(passphrase, &sov_salt, ks.kdf_m_cost, ks.kdf_t_cost, ks.kdf_p_cost, &mut sov_key)?;
    derive_key(passphrase, &dec_salt, ks.kdf_m_cost, ks.kdf_t_cost, ks.kdf_p_cost, &mut dec_key)?;

    let sov_cipher = ChaCha20Poly1305::new(Key::from_slice(&*sov_key));
    let dec_cipher = ChaCha20Poly1305::new(Key::from_slice(&*dec_key));

    let sov_pt = sov_cipher.decrypt(Nonce::from_slice(&sov_nonce), sov_ct.as_slice());
    let dec_pt = dec_cipher.decrypt(Nonce::from_slice(&dec_nonce), dec_ct.as_slice());

    let (mut plaintext, mode, expected_pubkey) = match (sov_pt, dec_pt) {
        (Ok(pt), _)  => (pt, UnlockMode::Sovereign, &ks.sovereign.pubkey),
        (_, Ok(pt))  => (pt, UnlockMode::Decoy,     &ks.decoy.pubkey),
        (Err(_), Err(_)) => bail!("unlock failed — wrong passphrase"),
    };

    if plaintext.len() != 64 {
        plaintext.zeroize();
        bail!("decrypted plaintext is not 64 bytes (corrupted keystore?)");
    }

    let mut bytes = Zeroizing::new([0u8; 64]);
    bytes.copy_from_slice(&plaintext);
    plaintext.zeroize();

    let kp = Keypair::try_from(bytes.as_slice())
        .map_err(|e| anyhow!("decrypted bytes are not a valid keypair: {e}"))?;
    if kp.pubkey().to_string() != *expected_pubkey {
        bail!("integrity check failed — pubkey mismatch (keystore tampered?)");
    }

    Ok(UnlockedKey {
        keypair_bytes:          bytes,
        mode,
        caps:                   ks.duress_caps,
        session_spent_lamports: 0,
    })
}

// ── Internals ────────────────────────────────────────────────────────────────

fn write_keystore_atomic(on_disk: &OnDiskKeystore) -> Result<()> {
    let dir = keystore_dir()?;
    fs::create_dir_all(&dir)?;
    let path = keystore_path()?;
    if path.exists() {
        bail!(
            "keystore already exists at {} — refusing to overwrite. \
             Move it aside if you want to start fresh.",
            path.display()
        );
    }

    let json = serde_json::to_string_pretty(&on_disk)?;

    use std::os::unix::fs::OpenOptionsExt;
    use std::io::Write;
    let mut f = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(json.as_bytes())?;
    f.sync_all()?;
    Ok(())
}

fn derive_key(
    passphrase: &str,
    salt:       &[u8],
    m_cost:     u32,
    t_cost:     u32,
    p_cost:     u32,
    out:        &mut [u8; 32],
) -> Result<()> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(ARGON2_TAGLEN))
        .map_err(|e| anyhow!("argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, out)
        .map_err(|e| anyhow!("argon2 derive: {e}"))?;
    Ok(())
}

fn b64_encode(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(bytes)
}

fn b64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.decode(s).context("invalid base64")
}

// ── Tests ────────────────────────────────────────────────────────────────────
//
// Tests redirect XDG_DATA_HOME to a tempdir per-test so we don't touch the real
// keystore. The serial mutex prevents tests from racing on the env var.

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::signature::Signer;
    use std::sync::Mutex;
    use tempfile::TempDir;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Returns (lock_guard, tempdir). Drop both at end of test.
    fn isolate() -> (std::sync::MutexGuard<'static, ()>, TempDir) {
        let guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("XDG_DATA_HOME", dir.path());
        (guard, dir)
    }

    #[test]
    fn create_then_unlock_with_sovereign_returns_sovereign_mode() {
        let (_lock, _dir) = isolate();
        assert!(!keystore_exists());

        let unlocked = create_new_duress("sovereign-pass-strong", "decoy-pass-different")
            .expect("create");
        let sov_pubkey = unlocked.pubkey_base58();
        drop(unlocked);

        assert!(keystore_exists());

        let unlocked2 = unlock("sovereign-pass-strong").expect("unlock sovereign");
        assert_eq!(unlocked2.mode, UnlockMode::Sovereign);
        assert_eq!(unlocked2.pubkey_base58(), sov_pubkey);
    }

    #[test]
    fn unlock_with_decoy_returns_decoy_mode_and_different_pubkey() {
        let (_lock, _dir) = isolate();
        let sov_unlocked = create_new_duress("real-passphrase-1", "bait-passphrase-2")
            .expect("create");
        let sov_pubkey = sov_unlocked.pubkey_base58();
        drop(sov_unlocked);

        let dec_unlocked = unlock("bait-passphrase-2").expect("unlock decoy");
        assert_eq!(dec_unlocked.mode, UnlockMode::Decoy);
        assert_ne!(dec_unlocked.pubkey_base58(), sov_pubkey,
            "decoy must have a different pubkey from sovereign");
    }

    #[test]
    fn unlock_with_wrong_passphrase_fails_uniformly() {
        let (_lock, _dir) = isolate();
        let _ = create_new_duress("the-only-real-passphrase", "the-decoy-pass-other")
            .expect("create");
        let err = unlock("nope-not-the-passphrase").expect_err("must fail");
        // Error message should NOT betray *which* slot failed (sovereign vs decoy).
        let msg = format!("{}", err);
        assert!(msg.to_lowercase().contains("wrong passphrase") || msg.to_lowercase().contains("unlock failed"),
            "expected uniform failure msg, got: {}", msg);
        assert!(!msg.contains("sovereign"), "msg leaks 'sovereign'");
        assert!(!msg.contains("decoy"), "msg leaks 'decoy'");
    }

    #[test]
    fn create_refuses_short_passphrase() {
        let (_lock, _dir) = isolate();
        let err = create_new_duress("short", "longer-passphrase-here").unwrap_err();
        assert!(format!("{}", err).contains("at least 8 characters"));
    }

    #[test]
    fn create_refuses_identical_passphrases() {
        let (_lock, _dir) = isolate();
        let err = create_new_duress("samesame-pass", "samesame-pass").unwrap_err();
        assert!(format!("{}", err).contains("must differ"));
    }

    #[test]
    fn create_refuses_to_overwrite_existing_keystore() {
        let (_lock, _dir) = isolate();
        let _ = create_new_duress("first-pass-attempt", "first-pass-decoy").expect("first");
        let err = create_new_duress("second-pass-attempt", "second-pass-decoy").unwrap_err();
        assert!(format!("{}", err).contains("already exists"));
    }

    #[test]
    fn unlocked_key_signs_consistent_with_pubkey() {
        let (_lock, _dir) = isolate();
        let unlocked = create_new_duress("sovereign-correctness", "decoy-correctness").expect("create");
        let kp = unlocked.keypair();
        let pk = kp.pubkey().to_string();
        assert_eq!(pk, unlocked.pubkey_base58());

        // Round-trip a signature against the message-bytes test vector.
        use solana_sdk::signature::Signature;
        let msg = b"test-message-for-round-trip";
        let sig: Signature = kp.sign_message(msg);
        // Verify the signature with ed25519-dalek directly to confirm the
        // keypair bytes are actually a valid ed25519 keypair.
        let pubkey_bytes = bs58::decode(&pk).into_vec().expect("b58");
        use solana_sdk::pubkey::Pubkey as SolPubkey;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&pubkey_bytes);
        let pubkey = SolPubkey::from(arr);
        assert!(sig.verify(pubkey.as_ref(), msg), "signature must verify");
    }

    #[test]
    fn keystore_dir_layout_uses_data_local_dir() {
        let (_lock, dir) = isolate();
        let path = keystore_path().unwrap();
        // Every component of `dir.path()` should be a prefix of `path`.
        assert!(path.starts_with(dir.path()),
            "keystore_path {} must be inside XDG dir {}", path.display(), dir.path().display());
        assert!(path.ends_with("keystore.json"));
    }

    #[test]
    fn note_spent_accumulates_across_calls() {
        let (_lock, _dir) = isolate();
        let mut unlocked = create_new_duress("acc-test-sov-pass", "acc-test-dec-pass").expect("create");
        assert_eq!(unlocked.session_spent_lamports, 0);
        unlocked.note_spent(100);
        unlocked.note_spent(250);
        assert_eq!(unlocked.session_spent_lamports, 350);
    }
}
