//! PNG steganography for FROST-share camouflage backup.
//!
//! Goals:
//!   - Make a wallet backup look like a kid's photo, not a bin file someone
//!     might mistake for a virus and clean off the disk.
//!   - Encrypt under a passphrase so possession of the PNG is not enough —
//!     someone who finds the image still needs the unlock phrase.
//!   - Be readable from any tool that can do LSB-decode + Argon2id +
//!     ChaCha20Poly1305, not just our binary. Format documented below.
//!
//! Wire format (after Argon2id+ChaCha20Poly1305 unwrap):
//!   bytes  | meaning
//!   -------+--------
//!   0..4   | magic           = "SOV1"
//!   4      | version         = 1
//!   5..9   | payload_len LE  = number of payload bytes that follow
//!   9..    | payload bytes (TOML-encoded BackupPayload, see below)
//!
//! Encryption envelope (what's actually LSB-embedded into the image):
//!   bytes  | meaning
//!   -------+--------
//!   0..4   | magic           = "SVST" (sovereign-stego)
//!   4      | version         = 1
//!   5..21  | argon2 salt     (16 bytes random)
//!   21..33 | chacha20 nonce  (12 bytes random)
//!   33..37 | ciphertext_len LE (u32)
//!   37..   | ciphertext (= encrypted inner format above + 16-byte poly1305 tag)
//!
//! LSB embedding: for each byte of the envelope above, set the LSBs of 8
//! consecutive image bytes (R/G/B channels of consecutive pixels). One byte
//! of payload per 8 pixel bytes ≈ 8 bits per pixel of payload (RGB modifies
//! 8 channels per ~3 pixels). A 256x256 RGB image holds ~24 KB of payload —
//! a backup is <1 KB, so any modest cover image works.

use anyhow::{anyhow, bail, Context, Result};
use argon2::Argon2;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use image::ImageReader;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::Path;

const MAGIC_INNER: &[u8; 4] = b"SOV1";
const MAGIC_OUTER: &[u8; 4] = b"SVST";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

/// What we backup. TOML so the recovery side is readable by humans before
/// they pipe it back to disk — useful for sanity-checking ("yes that's my
/// FROST address, not someone else's") before clobbering files.
#[derive(Debug, Serialize, Deserialize)]
pub struct BackupPayload {
    /// What kind of share this is — "laptop" or "bot". Used by the recovery
    /// CLI to decide which keystore directory to write into.
    pub party: String,
    /// Hex of the FROST group public key. The user can read this off the
    /// PNG before recovery to confirm "yes, this is the wallet I think it is."
    pub pubkey_hex: String,
    /// Solana base58 address of the group public key (just for human display).
    pub solana_address: String,
    /// FROST KeyPackage bytes, hex-encoded. (Laptop-side or bot-side share.)
    pub key_package_hex: String,
    /// FROST PublicKeyPackage bytes, hex-encoded.
    pub pubkey_package_hex: String,
    /// Optional: bot config (token, allowlist) for the bot-party backup.
    /// `None` for laptop-party backups since the laptop doesn't hold the bot
    /// token. If you back up a bot share, the bot token is in here too —
    /// treat the PNG accordingly.
    pub bot_config_toml: Option<String>,
    /// When this backup was made (ISO 8601). For "is this fresh?" sanity.
    pub created_at: String,
}

/// Public entry: encode `payload` into `cover_image`, write to `out_path`.
/// Encrypts under `passphrase` first.
pub fn embed(
    payload: &BackupPayload,
    passphrase: &str,
    cover_image: &Path,
    out_path: &Path,
) -> Result<()> {
    if passphrase.len() < 8 {
        bail!("passphrase must be at least 8 chars (matches keystore.rs minimum)");
    }
    let payload_bytes = encode_inner_payload(payload)
        .context("encoding inner payload")?;
    let envelope = encrypt_to_envelope(&payload_bytes, passphrase)
        .context("encrypting payload to envelope")?;

    let img = ImageReader::open(cover_image)
        .with_context(|| format!("opening cover image {}", cover_image.display()))?
        .decode()
        .with_context(|| format!("decoding cover image {}", cover_image.display()))?;
    let mut rgb = img.to_rgb8();

    let max_capacity_bytes = (rgb.width() as usize * rgb.height() as usize * 3) / 8;
    if envelope.len() > max_capacity_bytes {
        bail!("cover image too small: have {} byte capacity, envelope is {} bytes",
            max_capacity_bytes, envelope.len());
    }

    lsb_embed(rgb.as_mut(), &envelope);
    rgb.save(out_path)
        .with_context(|| format!("saving stego image to {}", out_path.display()))?;
    Ok(())
}

/// Public entry: decode the envelope from `image`, decrypt under `passphrase`,
/// return the recovered payload.
pub fn extract(image_path: &Path, passphrase: &str) -> Result<BackupPayload> {
    let img = ImageReader::open(image_path)
        .with_context(|| format!("opening stego image {}", image_path.display()))?
        .decode()?;
    let rgb = img.to_rgb8();

    let envelope = lsb_extract(rgb.as_raw())
        .context("LSB-extracting envelope from image")?;
    let payload_bytes = decrypt_envelope(&envelope, passphrase)
        .context("decrypting envelope (wrong passphrase or not a sovereign-stego image?)")?;
    decode_inner_payload(&payload_bytes)
        .context("decoding inner payload")
}

// ── Inner payload codec ─────────────────────────────────────────────────────

fn encode_inner_payload(p: &BackupPayload) -> Result<Vec<u8>> {
    let toml_str = toml::to_string(p).context("toml::to_string")?;
    let body = toml_str.as_bytes();
    let mut out = Vec::with_capacity(9 + body.len());
    out.extend_from_slice(MAGIC_INNER);
    out.push(VERSION);
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

fn decode_inner_payload(bytes: &[u8]) -> Result<BackupPayload> {
    if bytes.len() < 9 { bail!("inner payload too short"); }
    if &bytes[0..4] != MAGIC_INNER {
        bail!("inner payload magic mismatch (got {:?}, expected SOV1)", &bytes[0..4]);
    }
    if bytes[4] != VERSION {
        bail!("inner payload version mismatch (got {}, expected {})", bytes[4], VERSION);
    }
    let len = u32::from_le_bytes(bytes[5..9].try_into().unwrap()) as usize;
    if bytes.len() < 9 + len { bail!("inner payload truncated: have {}, need {}", bytes.len() - 9, len); }
    let body = &bytes[9..9 + len];
    let s = std::str::from_utf8(body).context("inner payload not valid UTF-8")?;
    let p: BackupPayload = toml::from_str(s).context("inner payload not valid TOML")?;
    Ok(p)
}

// ── Encryption envelope ─────────────────────────────────────────────────────

fn encrypt_to_envelope(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let key = derive_key(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("aead encrypt: {e}"))?;

    let mut out = Vec::with_capacity(37 + ciphertext.len());
    out.extend_from_slice(MAGIC_OUTER);
    out.push(VERSION);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt_envelope(envelope: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    if envelope.len() < 37 { bail!("envelope too short ({} bytes)", envelope.len()); }
    if &envelope[0..4] != MAGIC_OUTER {
        bail!("envelope magic mismatch — this image doesn't contain a sovereign-stego envelope");
    }
    if envelope[4] != VERSION {
        bail!("envelope version mismatch (got {}, expected {})", envelope[4], VERSION);
    }
    let salt: [u8; SALT_LEN] = envelope[5..21].try_into().unwrap();
    let nonce_bytes: [u8; NONCE_LEN] = envelope[21..33].try_into().unwrap();
    let ct_len = u32::from_le_bytes(envelope[33..37].try_into().unwrap()) as usize;
    if envelope.len() < 37 + ct_len {
        bail!("envelope truncated: have {} bytes after header, need {}", envelope.len() - 37, ct_len);
    }
    let ciphertext = &envelope[37..37 + ct_len];

    let key = derive_key(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher.decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("aead decrypt (wrong passphrase?): {e}"))
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    let mut key = [0u8; KEY_LEN];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("argon2 hash: {e}"))?;
    Ok(key)
}

// ── LSB embed/extract ───────────────────────────────────────────────────────

fn lsb_embed(image_bytes: &mut [u8], payload: &[u8]) {
    // Embed payload length first (4 bytes, big-endian) so extract knows how
    // far to read. Then the payload itself.
    let header = (payload.len() as u32).to_be_bytes();
    let mut bit_iter = header.iter().chain(payload.iter())
        .flat_map(|&b| (0..8).rev().map(move |i| (b >> i) & 1));

    for px in image_bytes.iter_mut() {
        if let Some(bit) = bit_iter.next() {
            *px = (*px & 0xFE) | bit;
        } else {
            return;
        }
    }
}

fn lsb_extract(image_bytes: &[u8]) -> Result<Vec<u8>> {
    if image_bytes.len() < 32 { bail!("image too small to contain even a length header"); }
    // Read 32 bits (4 bytes) of length first.
    let mut header = [0u8; 4];
    for byte_i in 0..4 {
        let mut b: u8 = 0;
        for bit_i in 0..8 {
            let pixel_idx = byte_i * 8 + bit_i;
            b = (b << 1) | (image_bytes[pixel_idx] & 1);
        }
        header[byte_i] = b;
    }
    let payload_len = u32::from_be_bytes(header) as usize;
    if payload_len == 0 { bail!("extracted length is zero — image likely doesn't contain stego data"); }
    if payload_len > 1024 * 1024 { bail!("extracted length is suspiciously large: {} bytes", payload_len); }
    let needed_pixels = (4 + payload_len) * 8;
    if image_bytes.len() < needed_pixels {
        bail!("image too small for declared payload length: need {} pixels, have {}",
            needed_pixels, image_bytes.len());
    }

    let mut payload = Vec::with_capacity(payload_len);
    for byte_i in 0..payload_len {
        let mut b: u8 = 0;
        for bit_i in 0..8 {
            let pixel_idx = (4 + byte_i) * 8 + bit_i;
            b = (b << 1) | (image_bytes[pixel_idx] & 1);
        }
        payload.push(b);
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_payload() -> BackupPayload {
        BackupPayload {
            party: "laptop".into(),
            pubkey_hex: "70840eaa53a66dae455421445feeac490400728feb26a3e6ecbd73aa9f702ce8".into(),
            solana_address: "8aDTMD3JBjXd2SJcE9FYQ7Pqb4tX8cDdksdhCs8avFdH".into(),
            key_package_hex: "deadbeef".repeat(16),
            pubkey_package_hex: "cafebabe".repeat(16),
            bot_config_toml: None,
            created_at: "2026-05-09T14:00:00Z".into(),
        }
    }

    #[test]
    fn inner_payload_roundtrip() {
        let p = fake_payload();
        let bytes = encode_inner_payload(&p).unwrap();
        let p2 = decode_inner_payload(&bytes).unwrap();
        assert_eq!(p.party, p2.party);
        assert_eq!(p.pubkey_hex, p2.pubkey_hex);
    }

    #[test]
    fn envelope_roundtrip() {
        let pt = b"hello secret world".to_vec();
        let env = encrypt_to_envelope(&pt, "test-passphrase-1234").unwrap();
        let dec = decrypt_envelope(&env, "test-passphrase-1234").unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn envelope_wrong_passphrase_fails() {
        let pt = b"x".to_vec();
        let env = encrypt_to_envelope(&pt, "right-passphrase").unwrap();
        let r = decrypt_envelope(&env, "wrong-passphrase");
        assert!(r.is_err());
    }

    #[test]
    fn lsb_roundtrip() {
        let payload = b"the quick brown fox jumps over the lazy dog".to_vec();
        let mut canvas = vec![100u8; payload.len() * 8 + 32]; // plenty of capacity
        lsb_embed(&mut canvas, &payload);
        let extracted = lsb_extract(&canvas).unwrap();
        assert_eq!(extracted, payload);
    }
}
