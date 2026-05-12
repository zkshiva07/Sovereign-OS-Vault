# Sovereign OS Vault

> **The safest member in your Multisig.**
> A hardened, two-key signing console for Solana that runs on a Linux laptop (or WSL on Windows) and uses your Telegram as the second key.

Sovereign OS Vault is an open-source signing tool for people who care about not getting drained. You install it on a Linux machine (or WSL2 on Windows), you make a small Telegram bot of your own, and from then on **no transaction is ever signed unless you tap "Approve" in your Telegram chat** — even if your laptop is fully compromised.

It is designed to be **one member of a Squads multisig**, but it also works on its own.

---

## Install (3 commands)

On Linux or WSL2 with Ubuntu:

```bash
git clone https://github.com/zkshiva07/Sovereign-OS-Vault.git
cd Sovereign-OS-Vault
./quickstart.sh
```

That's it. The wizard installs Rust + Zig if you don't have them, builds the binaries, walks you through creating a Telegram bot with `@BotFather`, generates your two-key wallet, backs it up, and installs a `sov` launcher.

**Don't have WSL yet?** From **PowerShell as Administrator** on Windows: `wsl --install`. Restart, then launch the Ubuntu app and run the three commands above.

## Use it (1 command, every day)

```bash
sov                          # launch the TUI (auto-starts the bot)
sov --connect <squads-url>   # save a Squads multisig pointer
sov status                   # what's configured
sov stop                     # stop the background bot
```

That's the entire daily interface. The wizard installed `sov` to your PATH; one command starts everything and shuts the bot down when you exit the TUI.

---

## Why this matters

A few of the biggest 2025-26 hacks all had the same shape: **a signing flow you couldn't fully trust.**

- **Bybit, Feb 2025 — $1.5 B.** Cold-wallet signers approved a transaction whose UI showed one thing and on-chain payload did another. Blind-signing a wrapped call.
- **Drift, April 2026 — $285 M.** A Squads multisig member approved a `vault_transaction_create` whose inner instruction was a `Token::Approve(u64::MAX)` to an attacker delegate. Wrapper attack — the outer call looked routine.
- **Seedify, June 2025 — $1.2 M.** Compromised deployer keys.

Across all three: the signer never saw what they were actually approving, and a single compromised signing flow was enough.

**Sovereign OS Vault changes that.** The signing key is split between your laptop and a Telegram bot you control. Neither can sign alone. Every signature requires:

1. A **recursive decode** on your laptop — wrapped Squads instructions get their inner risks lifted to the top, in red.
2. A **physical tap** on your phone in Telegram — the bot's share never leaves until you approve.

Compromise the laptop? You can't sign without the bot's share AND your tap. Compromise the bot host? You can't sign without the laptop's share AND your tap. Compromise both? You **still** can't sign without your in-the-moment Telegram approval.

The output is a normal ed25519 signature. The Solana network can't tell it was produced by two parties. The proof transaction below was signed by exactly this flow.

---

## Is this for you?

Read this if any of these are true:

- You hold meaningful funds on Solana and you've been clicking "Sign" with a browser wallet.
- You're a member of a Squads multisig and you sign proposals other people build.
- You operate validator stake-authority keys and you're scared of fat-fingering an approval.
- You don't have a hardware wallet, or you do but you don't trust closed-source firmware with everything.
- You want a self-custody setup with **two trust domains** (laptop + your phone) without paying a monthly fee to a custody company.

**Skip this if** you're brand new to crypto and just want to swap tokens — this is overkill. Start with a regular wallet, learn the basics, then come back.

---

## Proof it works

Here's a real, finalized Solana mainnet transaction signed using the exact flow this repo ships:

**`3EKyf6ubk8rfQL61gQ9P4Ts7Z2eo6vwofm8wuqrd67ehkK237ZGRwL5wq8qDi3cYLWcbGQkUgwTG325YBjn6zsrE`**

[View it on Solscan](https://solscan.io/tx/3EKyf6ubk8rfQL61gQ9P4Ts7Z2eo6vwofm8wuqrd67ehkK237ZGRwL5wq8qDi3cYLWcbGQkUgwTG325YBjn6zsrE)

- The signer (`8aDTMD…vFdH`) is a **two-key** address. One key lives on a laptop, one lives in a Telegram bot. Neither can sign alone.
- The transaction paid a normal one-signature fee (5,000 lamports). That means the Solana network verified it as a single, ordinary ed25519 signature — observers cannot tell it was produced by two parties.
- The signature was only produced after a human tapped "Approve" in Telegram.

---

## What you'll have when you're done

After setup (about 10–20 minutes if WSL and Rust are already installed; up to an hour from scratch):

- A **terminal app** on your laptop that you launch when you need to sign. It looks like this:

```
  ╭──────────────────────────────────────────────────────────────────╮
  │  SOVEREIGN OS VAULT  ● ARMED   ⚠ MAINNET                          │
  ╰──────────────────────────────────────────────────────────────────╯
   Identity                              Hardening
   ─────────                              ─────────
   8aDTMD…vFdH                            Security 100% ████████████
   FROST 2-of-2 (laptop + your Telegram)  ✓ Zig vault-armor
                                          ✓ PR_SET_DUMPABLE
   Actions                                ✓ mlockall
   ──────                                 ✓ MADV_DONTDUMP
   [s] Sign a transaction                 ✓ Non-root UID
   [m] Squads proposals                   ✓ No debugger
   [a] Re-arm    [q] Quit                 ✓ Yama LSM
```

- A **Telegram bot you control** that messages you whenever a signature is requested, with a plain-English summary of what's about to happen and Approve / Reject buttons.
- A **Solana address** that can hold funds, sit inside a Squads multisig, or operate stand-alone.
- A **backup workflow** that hides your share inside an ordinary-looking photo file, encrypted under a passphrase you choose.

---

## Before you start

You need:

1. **A computer running Linux, or Windows with WSL2.** If you're on Windows, this whole guide assumes WSL2 with Ubuntu. (Mac is not supported in v0.4 — some of the Linux-kernel hardening calls don't exist on macOS. PRs welcome.)
2. **A Telegram account** on your phone. The free one is fine.
3. **A bit of SOL** (about 0.01 SOL, $1–$2 at typical prices) on any wallet you control, only if you want to send a real on-chain test transaction at the end. You can skip this and test offline.
4. **Internet access** for the install (build dependencies pull from crates.io and Zig's mirrors).

You do **not** need a hardware wallet, an account with a custody company, a paid Solana RPC, or any closed-source software. Everything runs on your machine.

### Don't have WSL yet? Install it first.

Open PowerShell **as Administrator** on Windows and run:

```powershell
wsl --install
```

That installs WSL2 + Ubuntu by default. Restart Windows when it asks you to. After restart, Ubuntu's first launch will ask you to pick a Linux username and password — pick anything memorable.

From now on, "open WSL" means: launch the **Ubuntu** app from Start, or open Windows Terminal and pick the Ubuntu tab.

> **Important:** do all the work **inside your WSL home directory** (anything under `~/`). Do NOT clone or build inside `/mnt/c/...` or `/mnt/d/...` — that's the Windows filesystem mounted into WSL, and it's much slower for compilation. Builds that should take 3 minutes can take 30+ minutes there.

---

## Set it up — three steps

Setup is driven by a guided wizard. From clone to a working vault in **5–10 minutes** (plus build time on first run).

### 1. Clone the repo

In your WSL Ubuntu terminal (or native Linux terminal), inside your home directory:

```bash
cd ~
git clone https://github.com/zkshiva07/Sovereign-OS-Vault.git
cd Sovereign-OS-Vault
```

>
> ⚠️ **Important on WSL:** stay in your Linux home (`~/`). Do **not** clone into `/mnt/c/` or `/mnt/d/` — the wizard will refuse to build there because compilation is ~10× slower.

### 2. Run the wizard

```bash
./quickstart.sh
```

That's the whole setup. The wizard will:

1. **Detect your environment** — Linux vs WSL, distro, filesystem. Refuses bad setups.
2. **Install missing toolchains** — offers to install Rust, Zig, and build dependencies if they're missing. Asks before each install.
3. **Build the binaries** — `vault-armor` (Zig hardening engine), `sovereign-vault` (TUI), `frost-bot` (Telegram cosigner), plus backup/test helpers. First build takes **3–5 minutes**; later runs skip what's already built.
4. **Grant `cap_ipc_lock`** — one-time sudo so memory locking works without `sudo` each launch.
5. **Walk you through `@BotFather`** — step-by-step instructions in the terminal, then asks you to paste the token. Validates it live against Telegram's API before continuing.
6. **Auto-detect your Telegram user ID** — asks you to send `/start` to your bot once, then captures your numeric ID from the Telegram Bot API. **No `@userinfobot` trip needed.**
7. **Write the bot config** with the right paths and `mode 0600`.
8. **Run FROST keygen** — produces your two key shares and prints your combined Solana address.
9. **Offer a smoke test** — starts the bot, generates a fake transaction, walks you through the full Inspect → Approve-in-Telegram → Signed round-trip. No SOL required.
10. **Print next-step commands** — exact paths to launch the bot and TUI, plus your Solana address and Solscan link.

The wizard is **idempotent**. If it fails halfway, fix the error and re-run — it picks up where it left off without redoing finished work.

### 3. (Optional) Fund the address and / or add to a Squads multisig

After the wizard finishes, you have a working two-key signer with a real Solana address. Day-to-day use is now just:

```bash
sov                          # launches bot + TUI together
sov status                   # shows what's configured and running
sov --connect <url-or-pda>   # save a Squads multisig pointer
sov stop                     # stop the bot
sov help                     # all commands
```

Optional next steps:

- **Send ~0.01 SOL** to the address if you want to broadcast real mainnet transactions from the TUI.
- **Open [squads.so](https://squads.so)** in your browser, add the address as a member of any V4 multisig.
- **Save the multisig pointer** so the `[m]` proposal-watch screen activates automatically:

  ```bash
  sov --connect https://app.squads.so/squads/<your-multisig-pda>/home
  # or just:
  sov --connect <your-multisig-pda>
  ```

### Don't have WSL yet? Install it first.

Open **PowerShell as Administrator** on Windows and run:

```powershell
wsl --install
```

Restart Windows when it asks. After restart, launch the **Ubuntu** app from Start and pick a Linux username + password. From then on, "open WSL" means launch that Ubuntu app (or Windows Terminal's Ubuntu tab) and proceed with step 1 above.

### Manual setup (for power users)

If you'd rather drive each step by hand — to audit what the wizard does, or because you don't want it touching your toolchains — see [SETUP.md](./SETUP.md). Same flow, every command spelled out.

---

## Using it day-to-day — your signatures go to mainnet

Setup produces a real Solana address and a real two-key signer. **Every signature this vault produces is a normal ed25519 signature** that any Solana RPC accepts and any explorer shows like any other transaction. The proof artifact at the top of this README — [`3EKyf6ub…zsrE`](https://solscan.io/tx/3EKyf6ubk8rfQL61gQ9P4Ts7Z2eo6vwofm8wuqrd67ehkK237ZGRwL5wq8qDi3cYLWcbGQkUgwTG325YBjn6zsrE) — was produced by exactly the flow described below.

### Scenario A — Sign and broadcast a single transaction

The simplest case: you want this address to send SOL, vote on a governance program, claim rewards, anything that isn't routed through a multisig.

1. Run `sov` — bot starts in the background, TUI launches.
2. Press `s` from the Home screen.
3. Paste any base64-encoded mainnet transaction where your vault address is the fee payer.
4. Press Enter — the **inspector** decodes every instruction recursively, with risk flags.
5. Press `y` — the FROST round-1 commitments plus a human-readable summary ship to your bot over HTTPS.
6. **Your phone vibrates** — Telegram message from your bot showing the decoded summary and Approve / Reject buttons.
7. Tap **Approve** → bot releases its share contribution. Tap **Reject** → no signature is produced.
8. TUI combines both shares → finished ed25519 signature → Signed screen.
9. Press `b` on the Signed screen → TUI submits via `sendTransaction` JSON-RPC → polls `getSignatureStatuses` until finalized (up to 30 s) → footer shows the Solscan URL.

You now have a confirmed mainnet transaction signed by two trust domains.

### Scenario B — Approve a Squads V4 multisig proposal

The hero case: your vault is one of N members of a Squads treasury multisig. Someone (you or a co-member) just submitted a proposal in [squads.so](https://squads.so).

1. One-time: run `sov --connect <squads.so-URL-or-PDA>` to tell the launcher about the multisig.
2. Run `sov` — bot starts, TUI launches with the [m] Squads-watch screen now active.
3. Press `m` from Home — TUI polls the multisig every 30 s. Any new `VaultTransaction` / `ConfigTransaction` proposals appear with a decoded summary line.
4. Pick a proposal, press Enter → loads it into the inspector.
5. **Critical step — recursive decode:** Squads' `vault_transaction_create` wraps an inner `TransactionMessage`. The inspector walks the wrapper, decodes the inner instruction, and propagates the inner risk flags to the top-level Risk panel.
   - A benign inner transfer renders all-green.
   - A **wrapper attack** (`Token::Approve(u64::MAX)` to an attacker delegate — the April 2026 Drift drainer pattern) renders `🛑 [CRITICAL] Approving UNLIMITED tokens to delegate ...` in red. The DECISION box turns red.
6. Press `y` → FROST round starts → Telegram message arrives on your phone with the **same** risk-flagged summary.
7. Tap Approve or Reject on your phone.
8. On Approve → signature combines → Signed screen → press `b` to broadcast the inner-transaction signature, OR the on-chain `proposal_approve` vote (v0.5 wires the latter automatically; in v0.4 you submit the inner signature manually if you want to record the approval on-chain).

### What's actually happening cryptographically

- **No one party holds the signing key.** Each side has a *share* — neither share alone can produce a valid signature.
- During signing, the laptop generates a round-1 commitment, sends it to the bot, the bot generates its round-1 commitment, both parties exchange and run round-2, then the laptop aggregates both round-2 contributions into one ed25519 signature.
- **The Solana network sees a single 64-byte ed25519 signature** identical in shape to anything Phantom or a Ledger would produce. There is no on-chain trace of the MPC underneath. Fees are normal one-signature fees (5,000 lamports for the proof tx).
- **The Telegram tap is the gate, not the bot's share.** Even if an attacker compromises both your laptop AND your bot host, they still cannot produce a signature without you tapping Approve in your live Telegram session.

### Funding the vault

Your new vault address holds zero SOL on day one. To use it for real:

- **Direct transfer**: send SOL from any wallet to the address. ~0.01 SOL is plenty to cover tx fees for testing.
- **Squads member**: if your vault is a multisig member, the multisig holds the funds — your individual address only needs enough SOL to pay fees for your `proposal_approve` votes (a few cents).

The address shown by the wizard's Phase 4 / Phase 6 banner is the canonical address. It also appears in the TUI's Home screen Identity panel and is logged by the bot on startup (`solana_addr=…`).

---

## Setting up with Claude Code

If you're using Claude Code (Anthropic's terminal coding agent), you can hand it the wheel:

1. Open Claude Code from inside the repo: `cd ~/sovereign-os-vault && claude`
2. Tell it:

> Set up Sovereign OS Vault for me on WSL. I have a Telegram account, I'm on Ubuntu, and I want to do the offline test (no real SOL yet). Walk me through each step and verify it worked before moving on.

Claude Code can run `quickstart.sh`, check that Rust and Zig are installed, watch the build for errors, help you write the config, prompt you for the BotFather token without storing it, and verify the FROST round-trip end-to-end.

If something fails, ask Claude Code to read `SETUP.md`, the relevant source file (e.g., `tui/src/frost.rs`), or this README's "If something breaks" section below — it's much faster to debug with the actual files in context than to copy-paste error messages into a generic chat.

---

## Backing up your shares

The single sharpest failure mode of two-key signing is **losing a share permanently**. Without one share, you cannot sign — ever. So you back up both sides.

This repo ships a backup tool called **`frost-camouflage`** that hides your encrypted share inside an ordinary-looking PNG image. Recovery needs **both** the PNG **and** the passphrase you chose. One without the other is useless.

### Back up the laptop side

Find any photo you like (a JPG converted to PNG, a screenshot, anything). Then:

```bash
./tui/target/release/frost-camouflage embed --party laptop \
  --cover /path/to/any-photo.png --out laptop-backup.png
```

You'll be asked for a passphrase twice. **Use a strong passphrase** — six random Diceware words, or a long random string from your password manager. The minimum length enforced is 8 characters, but minimum ≠ recommended.

The output PNG (`laptop-backup.png`) **looks identical** to the cover photo at the pixel level, but contains your encrypted share. Store it where you'd store an ordinary photo:

- Cloud photo storage (iCloud, Google Photos)
- A USB stick
- Print as photo paper (yes, this works — re-scan to recover)

Possession alone reveals nothing without the passphrase.

### Back up the bot side

```bash
./tui/target/release/frost-camouflage embed --party bot \
  --cover /path/to/any-photo.png --out bot-backup.png
```

> ⚠️ **The bot backup is different.** It contains the bot token, which is a credential. If someone gets both the bot PNG and the passphrase, they can impersonate your bot. Store the bot backup the way you'd store a password manager export — encrypted vault, hardware-encrypted USB, **not** the same cloud as the laptop backup.

### Where to store passphrases

Same rules as wallet seed phrases: paper backup, metal backup, or a password manager you genuinely trust. Do not type your backup passphrase into a website. Do not photograph it. Tell at least one trusted person where the passphrase is stored, in case you become incapacitated.

---

## Recovering

| What you lost | Can you recover? | How |
|---|---|---|
| **The laptop** (share 1 gone) | ✅ Yes | On a new Linux/WSL install, redo steps 1–4 above, then `frost-camouflage extract laptop-backup.png` |
| **The bot host** (share 2 + token gone) | ✅ Yes | On a new bot host, `frost-camouflage extract bot-backup.png` — restores share, pubkey, AND the bot config (token + allowlist) |
| **One backup PNG** (you still have the other) | ⚠️ Partial | The remaining backup + the other side's live share = you can still sign. But you're now one mistake away from total loss. Re-embed a fresh PNG immediately. |
| **Your backup passphrase** | ❌ No | Same as a wallet seed phrase. Document the passphrase out-of-band. |
| **Both backup PNGs AND both shares** | ❌ No | Treat the camouflage PNG as your seed phrase — at least one offline copy of each side, ideally two. |

### Recovery walkthrough — laptop

On a fresh Ubuntu/WSL install:

```bash
# Steps 1-4 from "Set it up" above (install tools, install Rust, install Zig, clone repo)
# Then:
cd ~/sovereign-os-vault
./run.sh                                    # builds the binaries
# Don't run quickstart's keygen — you're recovering, not generating new keys

# Copy your backup PNG to the machine. Then:
./tui/target/release/frost-camouflage extract laptop-backup.png
# Enter the passphrase when asked. Type 'y' to confirm.
```

This writes your laptop share back to `~/.local/share/sovereign-os-vault/keystore/frost-share1.bin`. The pubkey is restored too. You're done with the laptop side.

### Recovery walkthrough — bot

```bash
./tui/target/release/frost-camouflage extract bot-backup.png
# Passphrase, 'y' to confirm.
```

This writes the bot's share, pubkey, **and** the bot config (with the BotFather token) into `~/.local/share/sovereign-os-vault/frost-bot/`. Now start the bot:

```bash
./frost-bot/target/release/frost-bot
```

Open Telegram, send `/start` to your bot — it should reply normally with the original Solana address. You're recovered.

### Verified recovery (the test we ran ourselves)

We tested both sides on 2026-05-11 against shipped binaries. The recovered share files are **byte-identical** to the originals (`sha256sum` matches). Wrong-passphrase attempts and non-stego PNGs are rejected cleanly without leaking data.

---

## If something breaks

### Build fails

| Error | What it means | Fix |
|---|---|---|
| `error: package requires Rust 1.81+` | Old toolchain | `rustup update stable` |
| `cargo: command not found` | Rust env not loaded | `source $HOME/.cargo/env`, or restart your shell |
| `error: linker 'cc' not found` | No C compiler | `sudo apt install build-essential` |
| `Could not find pkg-config` | Missing pkg-config | `sudo apt install pkg-config libssl-dev` |
| `zig: command not found` | Zig not on PATH | Re-source `~/.bashrc`, or open a new terminal |
| Build is incredibly slow | You cloned into `/mnt/c/` or `/mnt/d/` | Move the repo into `~/` and rebuild |

### Bot won't reply on Telegram

- **Bot prints "HTTP server listening" but no Telegram reply:** Double-check the `bot_token` in your config. If you accidentally pasted with whitespace or quotes, the bot connects but Telegram silently drops the connection.
- **Bot replies "you are not authorized":** the `authorized_users` list doesn't include your Telegram user ID. Re-check via @userinfobot.
- **Telegram says "bot not found":** you searched for the wrong `@username`. The username is what you picked during `/newbot`, not the bot's display name.

### TUI says "FROST share missing or unreadable"

Keygen didn't run, or the bot config's `share_path` points to the wrong place. Run:

```bash
ls -la ~/.local/share/sovereign-os-vault/keystore/
ls -la ~/.local/share/sovereign-os-vault/frost-bot/
```

If those directories are empty, re-run `./quickstart.sh` and let it do the keygen step.

### TUI says "FROST bot not reachable"

The bot process isn't running. Start it: `./frost-bot/target/release/frost-bot` in a separate terminal.

### "mlockall: Operation not permitted"

The TUI binary doesn't have the `cap_ipc_lock` capability. Fix:

```bash
sudo setcap cap_ipc_lock=ep ./tui/target/release/sovereign-vault
```

### Signing fails with "fee payer mismatch"

You pasted a transaction whose fee payer is a different address. Either generate fresh fixtures with your address (`tx-fixtures <YOUR_ADDRESS>`), or use a real transaction where you are the fee payer.

### Telegram bot stops working after closing the terminal (WSL)

WSL terminals are not background services. When you close the tab, your processes die. Options:

- **Easy:** keep the Windows Terminal tab running the bot open. Don't close it while you're using the vault.
- **Better:** run the bot inside `tmux`:

  ```bash
  sudo apt install tmux
  tmux new -s vault-bot
  # tmux session opens — inside it:
  ./frost-bot/target/release/frost-bot
  # Press Ctrl-b then d to detach. Tmux keeps running.
  # To return later: tmux attach -t vault-bot
  ```

- **Power user:** create a systemd user service. WSL2 supports systemd since 2023 (enable it in `/etc/wsl.conf` with `[boot]\nsystemd=true`, then `wsl --shutdown` in PowerShell, then reopen). See `SETUP.md` for a sample unit file.

### Squads watch screen empty

You didn't set `SQUADS_MULTISIG`, or the multisig has no open proposals, or the address is wrong. Set the env var with your Squads multisig PDA — that's the address Squads itself shows on the multisig's settings page.

---

## The headline demo — the proposal you almost approved

Squads' great strength is that no single member can move treasury funds alone. Its great weakness is that members approve proposals built by *other people* — and the canonical "approve" instruction takes a reference to a wrapped inner transaction the member never directly sees.

This is how the **Drift-class wrapper attack** works. A malicious proposer constructs a `vault_transaction_create` whose **inner** instruction is a `Token::Approve` granting *unlimited* spend authority to a delegate they control. The outer wrapper looks innocuous. Members who blind-sign just authorized the drain.

Sovereign OS Vault defends against this on three layers:

1. **The inspector** decodes the outer Squads instruction, then recursively decodes the inner transaction, and runs every inner instruction through the same risk pipeline as a top-level transaction. The unlimited Token Approve gets flagged as **🛑 CRITICAL** in red — the same severity it would get if it were the top-level transaction.
2. **The signing decision box** turns red and warns you. You can still override (`y` to sign anyway), but —
3. **Telegram** shows you the same risks on your phone. One tap → Reject → the bot returns 403 → **no signature is ever produced.** The attack reaches your phone screen and dies there.

For a benign proposal, the same flow runs green, no flags, one tap to approve.

---

## What it actually does (the technical version)

If you want to verify or extend this, here's what's running under the hood.

1. **Inspects every transaction before signing** with a mainnet program registry:
   - Decodes System, SPL Token, Token-2022, ATA, Compute Budget, Memo, Stake, Vote
   - Recognises Jupiter, Raydium, Orca, Meteora, Drift, Marinade, Jito, Squads
   - **Recursively decodes Squads wrapped instructions** and lifts inner risk flags up to the top-level Risk panel
   - Refuses to sign transactions where you're not the fee payer

2. **2-of-2 FROST ed25519 signing** with Telegram as the second trust domain:
   - `frost-ed25519` from the Zcash Foundation, v2.2, RFC 9591, audited
   - Laptop holds share 1, bot holds share 2 — neither can sign alone
   - HTTPS-only wire between laptop and bot (works fine in WSL2)
   - Bot uses `teloxide` to deliver Approve/Reject prompts to Telegram
   - On-chain output is indistinguishable from a single-key ed25519 signature

3. **Squads V4 multisig watch.** Press `[m]` from Home, the TUI polls your configured multisig every 30 seconds, lists open proposals with decoded summaries, lets you sign through the same FROST + Telegram flow.

4. **Kernel-grade laptop hardening** (the Zig `vault-armor` binary + Rust-side mirror):
   - `PR_SET_DUMPABLE=0` — blocks same-UID `/proc/[pid]/mem` reads and ptrace
   - `mlockall(MCL_CURRENT|MCL_FUTURE)` — key pages never hit swap
   - `MADV_DONTDUMP` — keys excluded from any core dump
   - `PR_SET_PTRACER=0` — Yama LSM ptracer lock
   - Refuses to run as root
   - Kills itself on debugger attach (polls `TracerPid` every 200ms)

5. **At-rest encryption** for the legacy single-key keystore: Argon2id (64 MiB, t=3) + ChaCha20-Poly1305. FROST shares are protected by the FROST architecture itself plus the kernel hardening above.

6. **Built-in mainnet broadcast.** After signing, press `[b]` on the Signed screen → TUI submits via `sendTransaction` JSON-RPC, polls `getSignatureStatuses` until finalized, shows the Solscan URL.

7. **PNG-camouflaged backup** via `frost-camouflage`. Embeds an Argon2id + ChaCha20Poly1305 envelope into a cover PNG's least-significant bits. Visually identical output; recovery needs both image and passphrase.

For deeper detail on any of these, see [`DEMO.md`](./DEMO.md) (pitch + use cases), and the source code itself (`tui/src/` for the TUI, `frost-bot/src/` for the bot, `src/` for the Zig hardening engine).

---

## Threat model

| Threat | Status | Mitigation |
|---|---|---|
| Disk theft / cold boot / lost laptop | Defended | FROST share alone is useless without bot share + Telegram approval |
| Same-UID `/proc/[pid]/mem` read | Defended | `PR_SET_DUMPABLE=0` |
| Same-UID `ptrace` attach | Defended | `PR_SET_DUMPABLE=0` + Yama scope |
| Swap leakage | Defended | `mlockall(MCL_CURRENT \| MCL_FUTURE)` |
| Core dump capturing key memory | Defended | `MADV_DONTDUMP` per buffer |
| Compiler optimizing away secure-wipe | Defended | `Zeroize` (volatile writes) |
| Blind signing of malicious payload | Defended | Inspector + risk flags + program registry |
| **Wrapped instruction (Drift-class attack)** | **Defended** | **Recursive decoder lifts inner risks; Telegram prompt shows same severities; reject is one tap** |
| Signing for the wrong fee payer | Defended | Pubkey-mismatch check before signing |
| Clipboard sniffer | Defended | Signed output written to file, never clipboard |
| Compromised laptop forces signature | Defended | FROST aggregation requires bot's share; bot requires your Telegram approval |
| Compromised bot host forces signature | Defended | Bot's share alone cannot sign; needs laptop's share AND your tap |
| Lost FROST share (either side) | Recoverable | `frost-camouflage` |
| Lost backup PNG passphrase | Out of scope | Document the passphrase out-of-band, same as a seed |
| Malicious code running as you | Out of scope | Sign nothing you don't trust |
| Root or kernel-level compromise | Out of scope | You've already lost |

The core property: **three trust domains must all cooperate to produce a signature** — laptop, bot host, and your Telegram session on your phone. Compromise of any one (or even any two) does not produce a signature without your in-the-moment Telegram tap.

---

## Architecture

```
  ╭─ vault-armor (Zig) ──────────────────────────────────╮
  │  - independently hardens its own address space       │
  │  - emits one JSON line confirming kernel acceptance  │
  │  - 11 unit tests including adversarial fork+/proc    │
  ╰────────────────────────┬─────────────────────────────╯
                           │ stdout JSON
  ╭─ sovereign-vault (Rust TUI) ────────────────────────╮
  │  ┌─ armor.rs    ── Rust-side hardening + Zig bridge │
  │  ├─ keystore.rs ── Argon2id + ChaCha20-Poly1305     │
  │  ├─ inspector.rs── tx decoder + recursive Squads    │
  │  ├─ frost.rs    ── FROST 2-of-2 client (laptop side)│
  │  ├─ rpc.rs      ── mainnet sendTransaction +        │
  │  │                  confirmation polling            │
  │  ├─ squads.rs   ── Squads V4 proposal poll/decode   │
  │  └─ main.rs     ── ratatui screens + state machine  │
  ╰─────────────────────────┬───────────────────────────╯
                            │ HTTPS (FROST round messages)
  ╭─ sovereign-frost-bot (Rust, separate process) ──────╮
  │  ┌─ main.rs    ── teloxide dispatcher + axum HTTP   │
  │  ├─ share.rs   ── FROST share IO                    │
  │  ├─ config.rs  ── bot token + allowlist             │
  │  └─ protocol.rs── wire format (snake_case JSON)     │
  ╰─────────────────────────┬───────────────────────────╯
                            │ Telegram MTProto
                            │
                       Your phone ── tap Approve / Reject
```

The two-binary split between `vault-armor` (Zig) and `sovereign-vault` (Rust) is deliberate — the Zig binary has a smaller trusted code base (no async runtime, no JSON parser) and can be audited independently. The Rust TUI re-runs equivalent hardening internally as a defense-in-depth measure.

The further split between `sovereign-vault` (laptop) and `sovereign-frost-bot` (Telegram cosigner) is the FROST architecture: each party holds one share, no party can sign alone, the wire contract is a small documented HTTPS protocol.

Test coverage: **34 Rust tests** in the TUI crate, **4 tests** for the camouflage module, **11 Zig tests** for the armor engine.

---

## v0.4 honest disclosures

Everything we ship vs. everything that's planned, with no hand-waving.

- **Trusted-dealer keygen** in v0.4. During keygen, both shares momentarily exist on the same machine before being written to their separate paths. v0.5 will replace this with distributed key generation (DKG) so neither party ever sees the other's share. The cryptography is correct either way — this is a deployment-hygiene improvement.
- **Bot runs locally** on the same laptop as the TUI in the v0.4 demo. The architecture supports running the bot on a separate host (Fly.io free tier, a Raspberry Pi at home, your phone via Termux); deployment recipes are v0.5 README work.
- **Squads watch is read-and-inspect-only** in v0.4. Selecting a proposal loads it into the inspector and signs through the FROST + Telegram flow, but the resulting signature is of the *inner* transaction, not an on-chain `proposal_approve` vote. v0.5 will submit the proper on-chain vote.
- **No DKG share refresh** yet. After any recovery event where both shares briefly touched the same machine (e.g., disaster-recovery drill), best practice is to re-share against the same group public key. v0.5 will ship `frost-keygen refresh`.
- **No Shamir-split backup passphrase** yet. A single passphrase is a single point of failure. v0.5 will optionally split the backup passphrase across N pieces with M-of-N recovery.

---

## Glossary

| Term | What it means in plain English |
|---|---|
| **FROST** | A cryptographic protocol that lets two parties cooperate to produce a single Solana signature. Neither party can sign alone. Output looks like a normal signature. |
| **Squads** | The most popular multisig program on Solana. Holds funds; lets a group of members approve proposals. This vault is designed to be one of those members. |
| **TUI** | "Terminal User Interface" — a keyboard-driven app that runs in your terminal. Like `htop` or `git tig`. |
| **MPC** | "Multi-party computation" — multiple parties cooperate to compute something (like a signature) without any one of them learning the full secret. FROST is one kind of MPC. |
| **Trust domain** | Something that has to be separately compromised. Your laptop is one. Your phone is another. Your Telegram account on Telegram's servers is a third. |
| **PDA** | "Program-derived address" — a deterministic Solana address controlled by a program. Squads uses these for both the multisig settings and the vault that holds funds. |
| **Wrapper attack** | An attack class where a malicious proposal hides a dangerous instruction inside an outer wrapper that looks benign. The Drift exploit was a wrapper attack. |
| **Camouflage** / **stego** | Steganography — hiding data inside other data (here, a key inside a PNG image). |

---

## License

MIT — see [LICENSE](./LICENSE). Copyright © 2026 ZKAGI Ecosystem Association, Switzerland.

## Acknowledgements

- **Zcash Foundation FROST** — `frost-ed25519` v2.2, RFC 9591, the cryptographic core of v0.4
- **Squads Protocol** — V4 multisig program, the upstream multisig this vault joins
- **teloxide** — the Rust Telegram bot framework
- **ratatui** — the Rust TUI framework powering the signing console

The Zig hardening engine borrows ideas from systemd's `SystemCallFilter` and OpenBSD's `pledge`/`unveil` model. The TUI takes design cues from `magit` and `lazygit`.

---

*Sovereign OS Vault is software security tooling. It does not eliminate risk — it raises the cost of attack. Use multisig thresholds, hardware wallets at the highest tier, and threshold schemes for genuinely high-value accounts.*
