//! Tiny mainnet bridge for the FROST + Telegram demo flow.
//!
//! Subcommands:
//!   build   <from_b58> <to_b58> <lamports>   prints a base64 unsigned message
//!                                            ready to paste into the TUI
//!   broadcast <signed_b58>                   sends the signed VersionedTransaction
//!                                            to mainnet, prints the signature +
//!                                            Solscan URL
//!
//! Why this exists: tx-fixtures.rs uses a placeholder blockhash (all zeros) so
//! the inspector can decode without an RPC connection. For *broadcasting* we
//! need a current `recent_blockhash` (good for ~60 seconds) and a sendTransaction
//! call. Sovereign OS Vault's TUI is offline-only by design — this helper is
//! a thin bridge, not part of the vault.

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use solana_sdk::{
    hash::Hash,
    message::Message,
    pubkey::Pubkey,
    system_instruction,
};
use std::str::FromStr;
use std::time::Duration;

const RPC_URL: &str = "https://api.mainnet-beta.solana.com";

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("");
    match cmd {
        "build" => {
            if args.len() < 5 {
                bail!("usage: mainnet-helper build <from_b58> <to_b58> <lamports>");
            }
            cmd_build(&args[2], &args[3], &args[4])
        }
        "broadcast" => {
            if args.len() < 3 {
                bail!("usage: mainnet-helper broadcast <signed_tx_b58>");
            }
            cmd_broadcast(&args[2])
        }
        "balance" => {
            if args.len() < 3 {
                bail!("usage: mainnet-helper balance <address_b58>");
            }
            cmd_balance(&args[2])
        }
        _ => {
            eprintln!("Sovereign OS Vault — mainnet bridge for FROST signing demo\n");
            eprintln!("Usage:");
            eprintln!("  mainnet-helper build     <from_b58> <to_b58> <lamports>");
            eprintln!("    Build an unsigned System::Transfer message with a current");
            eprintln!("    mainnet blockhash. Paste the base64 output into the TUI.");
            eprintln!();
            eprintln!("  mainnet-helper broadcast <signed_tx_b58>");
            eprintln!("    Send a signed VersionedTransaction (base58, as printed on");
            eprintln!("    the TUI's Signed screen) to mainnet. Returns the tx sig");
            eprintln!("    and a Solscan URL.");
            eprintln!();
            eprintln!("  mainnet-helper balance   <address_b58>");
            eprintln!("    Quick balance check (in SOL).");
            std::process::exit(2);
        }
    }
}

fn cmd_build(from_b58: &str, to_b58: &str, lamports_str: &str) -> Result<()> {
    let from = Pubkey::from_str(from_b58).context("parsing from address")?;
    let to   = Pubkey::from_str(to_b58).context("parsing to address")?;
    let lamports: u64 = lamports_str.parse().context("parsing lamports (u64)")?;

    let blockhash = fetch_blockhash()?;
    let ix = system_instruction::transfer(&from, &to, lamports);
    let mut msg = Message::new(&[ix], Some(&from));
    msg.recent_blockhash = blockhash;

    let bytes = bincode::serialize(&msg).context("bincode serialize Message")?;

    eprintln!("From:           {}", from);
    eprintln!("To:             {}", to);
    eprintln!("Lamports:       {} ({} SOL)", lamports, lamports as f64 / 1e9);
    eprintln!("Blockhash:      {}", blockhash);
    eprintln!("Message bytes:  {} bytes", bytes.len());
    eprintln!();
    eprintln!("Paste this base64 into the TUI's PasteTx screen:");
    eprintln!();
    println!("{}", B64.encode(&bytes));
    Ok(())
}

fn cmd_broadcast(signed_b58: &str) -> Result<()> {
    let signed_bytes = bs58::decode(signed_b58.trim()).into_vec()
        .context("decoding signed tx as base58")?;
    let signed_b64 = B64.encode(&signed_bytes);

    eprintln!("Submitting {} bytes to {} ...", signed_bytes.len(), RPC_URL);

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "sendTransaction",
        "params": [
            signed_b64,
            { "encoding": "base64", "skipPreflight": false, "preflightCommitment": "confirmed" }
        ],
    });

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30)).build()?;
    let resp: serde_json::Value = client.post(RPC_URL)
        .json(&body).send().context("POST sendTransaction")?
        .json().context("parsing RPC response")?;

    if let Some(err) = resp.get("error") {
        bail!("RPC error: {}", err);
    }
    let sig = resp.get("result").and_then(|r| r.as_str())
        .ok_or_else(|| anyhow!("no result.signature in RPC response: {}", resp))?;

    eprintln!();
    eprintln!("Submitted! Signature:");
    println!("{}", sig);
    eprintln!();
    eprintln!("Solscan: https://solscan.io/tx/{}", sig);
    eprintln!();
    eprintln!("It may take a few seconds for the tx to confirm. If you don't see it");
    eprintln!("on Solscan within ~30 seconds, check the RPC response above for an error.");
    Ok(())
}

fn cmd_balance(addr_b58: &str) -> Result<()> {
    let _ = Pubkey::from_str(addr_b58).context("parsing address")?;
    let body = serde_json::json!({
        "jsonrpc":"2.0","id":1,"method":"getBalance","params":[addr_b58]
    });
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10)).build()?;
    let resp: serde_json::Value = client.post(RPC_URL).json(&body).send()?.json()?;
    let lamports = resp["result"]["value"].as_u64()
        .ok_or_else(|| anyhow!("no result.value in: {}", resp))?;
    println!("{} lamports ({:.9} SOL)", lamports, lamports as f64 / 1e9);
    Ok(())
}

fn fetch_blockhash() -> Result<Hash> {
    // commitment=confirmed picks a blockhash that's been confirmed by the
    // cluster (delay ~1-2s after slot production, vs ~12-32s for finalized).
    // This is the right balance: well-propagated across validators (so
    // sendTransaction simulation won't false-fail on a load-balanced node)
    // while still leaving us most of the 150-slot validity window.
    //
    // We tried "processed" first and it failed: leader dropped the tx because
    // by the time it landed, the freshly-processed blockhash hadn't yet been
    // accepted as a valid recent_blockhash by the slot's leader.
    let body = serde_json::json!({
        "jsonrpc":"2.0","id":1,"method":"getLatestBlockhash",
        "params":[{"commitment":"confirmed"}]
    });
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10)).build()?;
    let resp: serde_json::Value = client.post(RPC_URL).json(&body).send()?.json()?;
    let bh = resp["result"]["value"]["blockhash"].as_str()
        .ok_or_else(|| anyhow!("no blockhash in: {}", resp))?;
    Hash::from_str(bh).map_err(|e| anyhow!("parse blockhash: {e}"))
}
