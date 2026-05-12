//! Mainnet RPC client — submit signed transactions and read balances.
//!
//! The TUI is otherwise offline-only; this module is the one place we talk
//! to the chain. Used from `Screen::Signed` when the user presses `[b]` to
//! broadcast. Sync calls via `reqwest::blocking` on a worker thread so the
//! ratatui event loop stays responsive (same pattern as vultisig and frost
//! signing flows).
//!
//! v0.4: hardcoded public mainnet RPC. v0.5: configurable RPC URL (Helius /
//! QuickNode / self-hosted) read from a TUI config file or env var.

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use std::time::Duration;

pub const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
pub const SOLSCAN_TX_BASE: &str = "https://solscan.io/tx";

/// Submit a signed VersionedTransaction (base58) to mainnet via JSON-RPC
/// `sendTransaction`. Returns the transaction signature (base58 string).
///
/// Uses `preflightCommitment: confirmed` so the validator simulates against
/// confirmed state; that catches the common "I built against a stale blockhash"
/// failure mode before we waste a slot on a tx the cluster can't accept.
pub fn broadcast(signed_tx_b58: &str) -> Result<String> {
    let signed_bytes = bs58::decode(signed_tx_b58.trim()).into_vec()
        .context("decoding signed tx as base58")?;
    let signed_b64 = B64.encode(&signed_bytes);

    // skipPreflight=false: the RPC simulates against its local validator's
    // recent_blockhashes cache before forwarding to the leader. Catches
    // BlockhashNotFound + InsufficientFunds + invalid instructions immediately
    // instead of the leader silently dropping the tx and us thinking it landed
    // (which is what happens with skipPreflight=true — RPC returns the
    // deterministic signature regardless of whether the leader could land it).
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "sendTransaction",
        "params": [
            signed_b64,
            {
                "encoding": "base64",
                "skipPreflight": false,
                "preflightCommitment": "confirmed",
                "maxRetries": 5
            }
        ],
    });

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("building reqwest client")?;
    let resp: serde_json::Value = client.post(DEFAULT_RPC_URL)
        .json(&body)
        .send()
        .context("POST sendTransaction")?
        .json()
        .context("parsing RPC response")?;

    if let Some(err) = resp.get("error") {
        let msg = err.get("message").and_then(|m| m.as_str()).unwrap_or("(no message)");
        let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
        bail!("RPC error {}: {}", code, msg);
    }

    let sig = resp.get("result").and_then(|r| r.as_str())
        .ok_or_else(|| anyhow!("RPC response missing result.signature: {}", resp))?
        .to_string();

    // sendTransaction returning a signature does NOT mean the tx landed — it just
    // means the RPC's simulation passed and the leader was forwarded the bytes.
    // Poll getSignatureStatuses until we see at least "processed" status, or
    // until our patience runs out. Only THEN do we declare broadcast confirmed.
    confirm_landed(&client, &sig)?;
    Ok(sig)
}

/// Poll getSignatureStatuses until the cluster confirms it has the tx, or
/// give up after ~30s with a clear error. This converts "RPC said OK" into
/// "the chain actually accepted it."
fn confirm_landed(client: &reqwest::blocking::Client, signature: &str) -> Result<()> {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let body = serde_json::json!({
        "jsonrpc":"2.0","id":1,"method":"getSignatureStatuses",
        "params":[[signature], {"searchTransactionHistory": true}]
    });

    while std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(700));
        let resp: serde_json::Value = match client.post(DEFAULT_RPC_URL).json(&body).send()
            .and_then(|r| r.json()) {
            Ok(v) => v,
            Err(_) => continue, // transient — keep polling
        };
        let status = &resp["result"]["value"][0];
        if status.is_null() { continue; }

        // Status object means a validator has the tx. Check if it succeeded.
        if let Some(err) = status.get("err") {
            if !err.is_null() {
                bail!("tx landed but failed on-chain: {}", err);
            }
        }
        // If we're here, status is non-null and err is null → tx landed cleanly.
        return Ok(());
    }
    bail!("tx not confirmed within 30s — leader likely dropped it (blockhash too old or network issue). \
           Balance unchanged. Try again with a freshly built message.")
}

/// Build a Solscan URL for a transaction signature.
pub fn solscan_tx(signature: &str) -> String {
    format!("{}/{}", SOLSCAN_TX_BASE, signature)
}
