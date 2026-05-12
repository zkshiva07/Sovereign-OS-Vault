//! Generate test-fixture transactions for the sovereign-vault inspector.
//!
//! Run:
//!   cargo run --bin tx-fixtures -- <your-mpc-pubkey>
//!
//! Prints a menu of unsigned mainnet messages in base64, each labelled with
//! what the inspector should show when you paste it. None of these are
//! broadcastable on their own — they're for exercising the decoder.
//!
//! The fee payer is your pubkey so signing path tests (with the actual
//! Vultisig daemon paired) won't refuse on fee-payer mismatch. None of these
//! transfer real funds anywhere except to/from your own pubkey.

use base64::{engine::general_purpose::STANDARD, Engine};
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::message::Message;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::system_instruction;
use std::str::FromStr;

const SYSTEM:        &str = "11111111111111111111111111111111";
const TOKEN:         &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const SQUADS_V4:     &str = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf";
const JUPITER_V6:    &str = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";

const SQUADS_VAULT_TRANSACTION_CREATE:  [u8; 8] = [48, 250, 78, 168, 208, 226, 218, 211];
const SQUADS_CONFIG_TRANSACTION_CREATE: [u8; 8] = [155, 236, 87, 228, 137, 75, 81, 39];

fn b64(bytes: &[u8]) -> String { STANDARD.encode(bytes) }

fn serialize(ixs: Vec<Instruction>, payer: &Pubkey) -> Vec<u8> {
    let msg = Message::new(&ixs, Some(payer));
    bincode::serialize(&msg).expect("serialize")
}

/// Squads inner TransactionMessage format — same shape parsed by inspector.rs.
fn serialize_squads_inner(
    keys: &[Pubkey],
    instructions: &[(u8, Vec<u8>, Vec<u8>)],
) -> Vec<u8> {
    // Borsh format — matches the on-chain Squads V4 VaultTransactionMessage
    // layout. Vec<T> = u32 LE length prefix + serialized items. Earlier
    // versions used u8 length prefixes which were self-consistent with the
    // (then-buggy) inspector parser but didn't match real chain data.
    let mut out = Vec::new();
    out.push(1u8);  // num_signers
    out.push(1u8);  // num_writable_signers
    out.push(0u8);  // num_writable_non_signers
    out.extend_from_slice(&(keys.len() as u32).to_le_bytes());
    for k in keys { out.extend_from_slice(k.as_ref()); }
    out.extend_from_slice(&(instructions.len() as u32).to_le_bytes());
    for (prog, accts, data) in instructions {
        out.push(*prog);
        out.extend_from_slice(&(accts.len() as u32).to_le_bytes());
        out.extend_from_slice(accts);
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(data);
    }
    out.extend_from_slice(&0u32.to_le_bytes());  // address_table_lookups: empty Vec
    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: cargo run --bin tx-fixtures -- <your-mpc-pubkey>");
        eprintln!();
        eprintln!("Get your pubkey from one of:");
        eprintln!("  - sovereign-vault Home screen (Identity panel)");
        eprintln!("  - vultisig address --network sol");
        eprintln!("  - the Vultisig mobile app vault Solana row");
        std::process::exit(2);
    }
    let payer = Pubkey::from_str(&args[1])
        .unwrap_or_else(|_| { eprintln!("invalid pubkey: {}", args[1]); std::process::exit(2); });

    println!("\nFixtures for fee_payer = {}\n", payer);
    println!("─────────────────────────────────────────────────────────────────");
    println!(" Paste any of these base64 strings into sovereign-vault's");
    println!(" PasteTx screen ([s] from Home), press [enter] to inspect.");
    println!(" None of these are signed; they exercise the decoder paths only.");
    println!("─────────────────────────────────────────────────────────────────\n");

    // ── 1. Benign self-transfer ────────────────────────────────────────────
    let ix = system_instruction::transfer(&payer, &payer, 100_000); // 0.0001 SOL
    print_fixture(
        "1. BENIGN — System Transfer 0.0001 SOL → yourself",
        "Expected: System Program / Transfer 0.0001 SOL → <you>, NO risk flags",
        &serialize(vec![ix], &payer),
    );

    // ── 2. Large transfer (LargeTransfer flag) ─────────────────────────────
    let dest = Pubkey::from_str("11111111111111111111111111111111").unwrap();
    let ix = system_instruction::transfer(&payer, &dest, 5_000_000_000); // 5 SOL
    print_fixture(
        "2. LARGE TRANSFER — System Transfer 5.0 SOL to nowhere",
        "Expected: [REVIEW] Transferring 5.0000 SOL flag (would be HIGH at 10+ SOL, CRITICAL at 100+)",
        &serialize(vec![ix], &payer),
    );

    // ── 3. Infinite Token Approve (drainer pattern — May 2025 Phantom hack) ─
    let token = Pubkey::from_str(TOKEN).unwrap();
    let token_acct = Pubkey::new_unique();
    let attacker   = Pubkey::from_str("DRA1neRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR")
        .unwrap_or_else(|_| Pubkey::new_unique());
    let mut data = Vec::with_capacity(9);
    data.push(4); // SPL Token Approve discriminant
    data.extend_from_slice(&u64::MAX.to_le_bytes());
    let ix = Instruction {
        program_id: token,
        accounts: vec![
            AccountMeta::new(token_acct, false),
            AccountMeta::new_readonly(attacker, false),
            AccountMeta::new_readonly(payer, true),
        ],
        data,
    };
    print_fixture(
        "3. WALLET DRAINER — Infinite Token Approve to attacker",
        "Expected: [WARN] Approving u64::MAX tokens to delegate <attacker>. \
         This is the May 2025 Phantom $1.5M drainer pattern.",
        &serialize(vec![ix], &payer),
    );

    // ── 4. SystemProgram::Assign (ownership change → Critical) ─────────────
    let new_owner = Pubkey::from_str("DRA1neRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR")
        .unwrap_or_else(|_| Pubkey::new_unique());
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(&1u32.to_le_bytes()); // Assign discriminant
    data.extend_from_slice(new_owner.as_ref());
    let ix = Instruction {
        program_id: Pubkey::from_str(SYSTEM).unwrap(),
        accounts: vec![AccountMeta::new(payer, true)],
        data,
    };
    print_fixture(
        "4. OWNERSHIP CHANGE — SystemProgram::Assign on your account",
        "Expected: [DANGER] Account being assigned new owner. \
         This is the CLINKSINK / owner-reassignment drainer (Google Cloud blog 2024).",
        &serialize(vec![ix], &payer),
    );

    // ── 5. Squads vault_transaction_create wrapping malicious Token Approve ─
    //     This is the DRIFT-CLASS ATTACK PATTERN (April 1, 2026, $285M).
    //     The outer call looks like routine Squads governance. The inner
    //     instruction is the real payload — only visible via recursive decode.
    let inner_token   = Pubkey::from_str(TOKEN).unwrap();
    let inner_acct    = Pubkey::new_unique();
    let inner_drainer = Pubkey::from_str("DRA1neRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR")
        .unwrap_or_else(|_| Pubkey::new_unique());
    let mut approve_data = Vec::with_capacity(9);
    approve_data.push(4);
    approve_data.extend_from_slice(&u64::MAX.to_le_bytes());
    let inner_msg = serialize_squads_inner(
        &[inner_token, inner_acct, inner_drainer, payer],
        &[(0, vec![1, 2, 3], approve_data)],
    );
    let mut outer_data = Vec::with_capacity(8 + 6 + inner_msg.len() + 1);
    outer_data.extend_from_slice(&SQUADS_VAULT_TRANSACTION_CREATE);
    outer_data.push(0);  // vault_index
    outer_data.push(0);  // ephemeral_signers
    outer_data.extend_from_slice(&(inner_msg.len() as u32).to_le_bytes());
    outer_data.extend_from_slice(&inner_msg);
    outer_data.push(0);  // memo: None
    let ix = Instruction {
        program_id: Pubkey::from_str(SQUADS_V4).unwrap(),
        accounts: vec![AccountMeta::new(payer, true)],
        data: outer_data,
    };
    print_fixture(
        "5. DRIFT-CLASS ATTACK — Squads vault_transaction_create wrapping infinite Token Approve",
        "Expected: outer call decodes as Squads V4 VaultTransactionCreate; \
         underneath, the inspector recursively walks the wrapped TransactionMessage and shows: \
         '└─ inner 1 call(s) — what you are actually approving:' followed by the SPL Token Approve. \
         This is what the Drift Security Council needed to see on April 1, 2026.",
        &serialize(vec![ix], &payer),
    );

    // ── 6. Squads config_transaction_create — multisig config tampering ────
    let mut data = Vec::new();
    data.extend_from_slice(&SQUADS_CONFIG_TRANSACTION_CREATE);
    let ix = Instruction {
        program_id: Pubkey::from_str(SQUADS_V4).unwrap(),
        accounts: vec![AccountMeta::new(payer, true)],
        data,
    };
    print_fixture(
        "6. SQUADS CONFIG CHANGE — proposes multisig member/threshold change",
        "Expected: [DANGER] Squads multisig config change flag. \
         This is what an attacker proposes to add themselves as a member or lower the threshold.",
        &serialize(vec![ix], &payer),
    );

    // ── 7. Jupiter swap (known program, decoded cleanly) ───────────────────
    let jupiter = Pubkey::from_str(JUPITER_V6).unwrap();
    let ix = Instruction {
        program_id: jupiter,
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(Pubkey::new_unique(), false),
            AccountMeta::new(Pubkey::new_unique(), false),
        ],
        data: vec![0xe5, 0x17, 0xcb, 0x97, 0x7a, 0xe3, 0xad, 0x2a],  // shared_accounts_route discrim
    };
    print_fixture(
        "7. KNOWN DEFI — Jupiter Aggregator swap (no risks)",
        "Expected: Jupiter Aggregator interaction, KNOWN program (green), no risk flags.",
        &serialize(vec![ix], &payer),
    );

    // ── 8. Dense transaction (10 transfers — DenseTransaction flag) ────────
    let mut ixs = Vec::new();
    for _ in 0..10 {
        ixs.push(system_instruction::transfer(&payer, &Pubkey::new_unique(), 1_000));
    }
    print_fixture(
        "8. DENSE TX — 10 System transfers in one tx (DenseTransaction flag)",
        "Expected: [REVIEW] N instructions in one tx — review carefully.",
        &serialize(ixs, &payer),
    );

    println!();
    println!("─────────────────────────────────────────────────────────────────");
    println!(" Pasting tip: most terminals support pasting long strings with");
    println!(" Ctrl+Shift+V (Linux) or Cmd+V (Mac). The TUI accepts both base64");
    println!(" and base58 — these are base64.");
    println!("─────────────────────────────────────────────────────────────────");
}

fn print_fixture(title: &str, expected: &str, bytes: &[u8]) {
    println!("════════════════════════════════════════════════════════════════");
    println!(" {}", title);
    println!("────────────────────────────────────────────────────────────────");
    println!(" Expected: {}", expected);
    println!();
    println!(" {} bytes → base64:", bytes.len());
    println!();
    // Print without wrapping so it copy-pastes cleanly.
    println!("{}", b64(bytes));
    println!();
}
