//! Wire protocol between the laptop (sovereign-vault TUI) and the bot service.
//!
//! Single round-trip:
//!   POST /sign  →  { message_b64, decoded_summary, laptop_commitments }
//!   response    →  { bot_commitments, bot_signature_share, bot_identifier }
//!
//! The laptop is the FROST coordinator. It generates round-1 commitments
//! locally, ships them to the bot along with the message + a human-readable
//! decoded summary (the recursive Squads decode output). The bot prompts the
//! user via Telegram, waits for approval, then computes its round-1
//! commitments + round-2 signature share and returns both.
//!
//! The laptop computes its own round-2 share and aggregates → standard
//! ed25519 signature. ed25519-dalek (and therefore Solana) verifies this
//! without modification — proven empirically in scratch/frost-interop-test.

use serde::{Deserialize, Serialize};

/// POST /sign request body.
#[derive(Debug, Serialize, Deserialize)]
pub struct SignRequest {
    /// Raw message bytes the user is being asked to sign, base64-encoded.
    /// For Solana this is the serialized `Message` (legacy or v0).
    pub message_b64: String,

    /// Human-readable summary of what the message *does*. This is what the
    /// user sees in their Telegram approve/reject prompt — it's the only
    /// part the user actually inspects, so it MUST come from the inspector
    /// (recursive Squads decode), not be self-reported by the laptop.
    pub decoded_summary: String,

    /// Inspector decision the laptop reached locally. The bot can refuse to
    /// even prompt the user if this isn't GREEN — defense-in-depth so a
    /// compromised laptop can't bypass the inspector by lying about its
    /// decision and hoping the user rubber-stamps.
    pub laptop_decision: LaptopDecision,

    /// FROST round-1 commitments from the laptop, hex-encoded
    /// (frost::round1::SigningCommitments::serialize()).
    pub laptop_commitments_hex: String,

    /// Laptop's FROST identifier, hex-encoded.
    pub laptop_identifier_hex: String,
}

/// What the laptop's inspector concluded BEFORE sending here.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LaptopDecision {
    Green,  // safe — proceed
    Yellow, // suspicious — proceed with extra scrutiny
    Red,    // refused — laptop won't even ask the bot to prompt
}

/// POST /sign response body (after user approves in Telegram).
#[derive(Debug, Serialize, Deserialize)]
pub struct SignResponse {
    pub bot_commitments_hex: String,
    pub bot_signature_share_hex: String,
    pub bot_identifier_hex: String,
}

/// Error response (non-2xx).
#[derive(Debug, Serialize, Deserialize)]
pub struct SignError {
    pub kind: SignErrorKind,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum SignErrorKind {
    /// User tapped Reject in Telegram.
    UserRejected,
    /// User didn't respond before the bot's timeout.
    UserTimeout,
    /// Laptop's decision was RED — bot refused to prompt the user.
    LaptopRefused,
    /// Bot couldn't reach the user's Telegram (offline, blocked, etc).
    TelegramUnreachable,
    /// Bot's FROST share wasn't loaded or was corrupted.
    ShareUnavailable,
    /// Wire-format / encoding error in the request.
    BadRequest,
    /// Anything else.
    Internal,
}
