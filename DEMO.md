# Sovereign OS Vault — Demo Script + Positioning

> Read this once before recording. Pitch lines are bolded so you can
> read them off the page if needed. Total recording target: **5–7 minutes**.

---

## Pre-flight checklist (do BEFORE hitting record)

1. ✅ FROST keys generated (`frost-keygen` ran once)
2. ✅ Bot config exists at `~/.local/share/sovereign-os-vault/frost-bot/config.toml` (mode 600)
3. ✅ Bot running in a background terminal: `frost-bot &`
4. ✅ Bot greeted you in Telegram via `/start` to its `@username`
5. ✅ Squads V4 multisig exists with `8aDTMD…vFdH` (FROST address) added as a member
6. ✅ Multisig threshold is **2 or higher** — otherwise the proposer's auto-vote alone approves and FROST is decoration
7. ✅ FROST address funded with at least 0.01 SOL on mainnet for `proposal_approve` fees
8. ✅ At least one **Active** proposal in the multisig that FROST hasn't yet voted on
9. ✅ TUI binary has `cap_ipc_lock`: `sudo setcap cap_ipc_lock=ep ~/sovereign-os-vault/tui/target/release/sovereign-vault`
10. ✅ Phone visible to camera + Telegram open on your bot's chat
11. ✅ Recovery dry-run completed once (see "Recovery" in README) — embed laptop+bot shares to test PNGs, wipe a copy, extract, sha256sum matches. If a judge asks "what happens if your laptop dies?" you want the answer cached.

---

## Suggested terminal layout (for screen recording)

- **Top-left:** Sentinel TUI — full screen
- **Top-right:** Squads UI (browser) — multisig page
- **Bottom-left:** Bot logs (`tail -f /tmp/frost-bot.log` or wherever)
- **Phone:** held in frame, screen visible — Telegram open

---

## Script (5–7 minutes)

### Open (45 seconds) — the problem

> **"In February 2025, Bybit lost $1.5 billion because their Safe multisig
> signers approved what looked like a normal transaction. The UI showed
> them one thing; the bytes they signed did something else.**
>
> **In April 2026, Drift's Security Council narrowly avoided the same
> attack — a malicious member proposed a Squads vault transaction that
> wrapped an unlimited Token Approve. If even one council member had
> rubber-stamped, the protocol's treasury would have been drained.**
>
> **In 2024, Seedify Bridge's deployer key got compromised and a single
> private key cost users $7M.**
>
> **All three failures share one shape: a key that should have been
> distributed wasn't, and a signature happened that the human owner never
> actually authorized."**
>
> *[gesture to TUI]*
>
> **"Sovereign OS Vault is the Squads multisig member that physically
> cannot produce a signature without you tapping a button on your phone."**

### Architecture (45 seconds)

> **"Three trust domains. Three independent failures required to forge
> a signature."**
>
> *[point at each region of the TUI / bot terminal / phone]*
>
> 1. **"Laptop"** — kernel-hardened TUI, holds FROST share 1, encrypted at rest
> 2. **"Bot host"** — separate process, holds FROST share 2, also encrypted at rest
> 3. **"Your phone via Telegram"** — the human approval gate
>
> **"FROST is RFC 9591 threshold Schnorr — same crypto family Solana already
> uses. The on-chain signature is an ordinary 64-byte ed25519 signature.
> Squads, validators, explorers — nothing knows the difference. But
> production of that signature requires both shares AND your physical tap."**

### TUI walkthrough (60 seconds)

*Cold-launch the TUI.*

> **"This is the Sentinel. Boots straight into the FROST backend — no
> backend selection in v0.4 because there's only one. Identity panel
> shows the FROST group public key, which is a regular Solana address
> Squads accepts as a member."**
>
> *[point to Sentinel panel]*
>
> **"Bottom left, the Sentinel pet — it's polling our Squads multisig
> every 30 seconds in the background. Right now it's calm. When a
> Critical-severity proposal lands, the face goes alarmed and the border
> turns red."**
>
> *[point to security panel]*
>
> **"Right side, hardening status — mlockall on, dump-protected, Yama
> LSM ptracer lock active, refuses to run as root, kills itself on
> debugger attach. Same-UID malware can't read the FROST share while
> the vault is unlocked. And even if it could, the share alone is
> useless without the bot's share AND the Telegram tap."**

### The hero demo (90 seconds) — wrapper attack rejected

*Switch to Squads UI. Show the multisig page with proposals.*

> **"I'm going to put on the attacker's hat. From a member wallet that's
> been compromised, I'm proposing a Squads vault transaction. To Range's
> risk scanner — and probably to the casual reader — this looks like
> any other vault transaction call."**
>
> *[propose Recipe 2 via Tx Builder — the SPL Token Approve UNLIMITED]*

*Switch back to Sentinel TUI.*

> **"Within 30 seconds the Sentinel picks it up."**
>
> *[wait for the new proposal to appear]*
>
> *[Sentinel panel pet face flips to (=✗ω✗=)!, border red, badge 🛑 CRIT]*
>
> **"Recursive Squads decode. The outer call is just a wrapper. Sentinel
> walked into the inner instruction and found an unlimited token Approve
> to a delegate — that's the Phantom $1.5M drainer pattern from May 2025.
> Notice the marker on the inner instruction is a red ✗, not a green ✓.
> The risk panel says CRITICAL with the drainer-pattern attribution
> spelled out."**
>
> *[press y to "approve"]*
>
> *[hold up phone — Telegram shows the same risks]*
>
> **"And the same risks are now in front of me on Telegram. Bot host,
> separate device, separate network from the laptop. Even if my browser
> were compromised, even if my laptop session were compromised, even if
> the bot host were compromised — to forge this signature, an attacker
> would also need my phone unlocked, my Telegram open, and my finger
> on the screen."**
>
> *[tap Reject]*
>
> *[TUI shows "user rejected"]*
>
> **"On-chain, FROST's vote is registered as a rejection. The proposal
> can't reach threshold. The wrapper attack reached as far as my phone
> screen and died there."**

### The benign approval (60 seconds) — full on-chain

*Either pick an existing benign Active proposal or propose Recipe 1.*

> **"Same flow on a benign tx — small SOL transfer."**
>
> *[Sentinel: select benign proposal → Inspect screen]*
>
> **"Inspector shows it cleanly. No risks flagged. Decision box green."**
>
> *[press y, phone shows clean prompt]*
>
> *[tap Approve in Telegram]*
>
> **"Bot returns its FROST share. Laptop aggregates. We have a real
> ed25519 signature of a Squads `proposal_approve` instruction with
> the FROST address as fee payer + signer."**
>
> *[Signed screen shows base58 signed tx]*
>
> *[press b]*
>
> **"Broadcast to mainnet. Confirmation polling — we wait until the
> cluster actually has the tx, not just until the RPC accepts it."**
>
> *[wait for confirmed → Solscan link]*
>
> **"There's the Solscan URL. The FROST member's vote is now on-chain.
> Squads UI will show our address as a confirmed approver."**

### Why this matters (60 seconds) — vs Range, vs hardware wallets

> **"You might have noticed Squads UI itself shows a 'Risk Scanner powered
> by Range' that says 'no risk detected.' Range is fine — they catch the
> obvious patterns. But Range is a UI warning. It runs in your browser.
> If your browser is compromised, the 'no risk' you see is whatever the
> attacker wants you to see. And even when Range warns you, you're still
> the one who clicks Approve in the same compromised browser."**
>
> **"Sovereign OS Vault is different in kind. Range tells you. We refuse
> to sign. The signature physically cannot exist until you tap a button
> on a separate device. That's not a UI improvement. That's a
> cryptographic property."**
>
> **"Hardware wallets give you a similar property — a separate device
> for approval. But Ledger and Trezor have $79–$200 cost, 1–2 week
> shipping, browser-bridge attack surface, and a screen too small to
> render a recursive Squads decode. Sovereign OS Vault uses your phone's
> Telegram session as the hardware wallet. Setup in an afternoon, no
> shipping wait, full recursive decode rendered on a screen you can
> actually read."**

### Use cases (45 seconds)

> **"Three use cases this is ready for today:"**
>
> 1. **"DAO and protocol treasuries"** — be the FROST member on your
>    Squads multisig that can't be coerced or socially engineered into
>    rubber-stamping. Drift Security Council, Bybit's signers, every
>    treasury that's ever been wrapper-attacked.
>
> 2. **"Protocol deployers"** — the Seedify Bridge hack happened because
>    a single deployer key got compromised. Make your deployer key a
>    FROST 2-of-2 member of a Squads multisig. The single-key compromise
>    drains nothing because the bot won't release its share without
>    your phone tap.
>
> 3. **"Validator operators with stake-authority multisigs"** — wrapper
>    attacks against validator config changes get the same recursive
>    decode + Telegram approval gate.

### Close (30 seconds)

> **"Open source, MIT-licensed. The FROST crypto is
> ZcashFoundation/frost — RFC 9591, audited. The Squads V4 integration
> targets the canonical mainnet program. The bot is ~300 lines of Rust
> using teloxide. Camouflage backup ships either share as an
> innocuous-looking PNG, encrypted under your passphrase. Both sides'
> recovery paths are round-trip tested — see the Recovery section of
> the README; lose a laptop or lose the bot host, you walk it back."**
>
> **"It's the safest member in your Multisig."**
>
> *[end on the Sentinel TUI Home screen, pet calm]*

---

## Pitch positioning — one-liners by audience

### For Squads / Solana Foundation judges
> *"We are not competing with Squads — we ARE a Squads member. We're the
> v0.4 reference implementation of what 'good Squads member hygiene' looks
> like for the operators billions of dollars in TVL flow through."*

### For accelerator scouts
> *"Treasury custody for protocol DAOs is currently a $79 hardware wallet
> + a browser tab + hope. We replace that with a FROST 2-of-2 + your
> phone, ship in an afternoon. Recurring revenue is enterprise-tier
> hosted bot infrastructure for treasury managers who don't want to
> run a Telegram bot themselves."*

### For Range / security firms
> *"Range catches the patterns. We refuse to release the signature.
> Different layers. We integrate cleanly — Range data could feed our
> inspector's risk pipeline as another source."*

### For founders / DAO contributors
> *"You know that moment in a Squads UI when you click Approve on a
> proposal and a small voice says 'wait, did I read that carefully
> enough?' We make the proposal go through your phone first. The voice
> can stop worrying."*

---

## Hack post-mortems — what Sovereign OS Vault would have changed

### Bybit (Feb 2025, $1.5B)

**What happened:** Lazarus Group compromised the front-end of Bybit's
Safe (Gnosis) multisig signing UI via a malicious dependency. Cold-wallet
signers thought they were approving a routine sweep; they were actually
signing a contract upgrade that handed control to attacker-owned logic.

**What Sovereign OS Vault changes:**
- Recursive decode runs on the laptop, not in the browser. Even if the
  Safe UI is compromised, the inspector reads the actual message bytes
  and renders the decoded summary in a kernel-hardened process the
  browser malware can't reach.
- Telegram prompt shows the inspector's decoded summary, not the UI's
  representation. Signer compares the two before approving.
- Even after pressing `y` on a poisoned UI, the signature requires the
  Telegram tap. The compromised UI can't fake the phone tap on a
  different device.

### Drift Security Council (Apr 2026, prevented)

**What happened (almost):** A council member submitted a Squads vault
transaction whose inner instruction was a token Approve granting unlimited
spend authority to a delegate. Other council members would have approved
the wrapper without inspecting the inner ix. Caught manually before
execution.

**What Sovereign OS Vault changes:**
- Recursive Squads decode is the v0.3 hero feature. Inner Token Approve
  with `u64::MAX` to a non-self delegate is automatically flagged as
  Critical risk in the outer proposal's risk panel.
- Telegram prompt shows "🛑 [CRITICAL] Approving UNLIMITED tokens to
  delegate <addr> — drainer pattern (Phantom $1.5M, May 2025)"
- One tap to Reject. No human pattern-matching required.

### Seedify Bridge (2024, $7M)

**What happened:** The deployer key for the Seedify Bridge contract was
compromised (likely via phishing or supply-chain attack on the deployer's
machine). Attacker used the key to upgrade contract logic and drain
liquidity.

**What Sovereign OS Vault changes:**
- Make the deployer "key" a FROST 2-of-2 group public key, registered
  as a member of a Squads multisig with threshold 2. Even compromise of
  the deployer machine doesn't get the attacker the bot's share.
- Without the bot's share, the FROST aggregation can't produce a
  signature. Without a signature, the multisig can't approve. Without
  approval, the upgrade tx never lands.
- Even if BOTH the deployer machine AND the bot host are compromised,
  the attacker still needs the user to tap Approve in their Telegram —
  and the Telegram prompt shows what they're approving.

---

## Submission copy (Colosseum)

### Tagline
> The safest member in your Multisig — FROST 2-of-2 ed25519 with your Telegram as the second trust domain.

### Problem statement (200 words)
Multisig wallets like Squads V4 secure billions in Solana TVL, but their
security depends on individual members signing carefully. The most
expensive recent hacks — Bybit's $1.5B in February 2025, Drift Security
Council's narrow miss in April 2026, Seedify Bridge's $7M in 2024 — all
involved a single signer or deployer being tricked or compromised into
producing a signature that the human owner never meaningfully approved.

Hardware wallets help but ship slowly, cost $79–$200, and have proposal-
decode UX limited by their tiny screens. Browser wallets are completely
unsuitable for high-value multisig duties — they live in the most-attacked
surface in the operator's stack. Custodians require trusting third parties
with the keys.

### Solution (200 words)
Sovereign OS Vault is a kernel-hardened Squads V4 member that uses
FROST 2-of-2 ed25519 (RFC 9591) with the user's Telegram session as the
second trust domain. The signing key is split between a hardened laptop
process and a small bot service the user creates via @BotFather. Neither
party can sign alone. Every signature requires the user to physically
tap an Approve button on their phone, where the bot displays the
inspector's recursive decode of what's being signed.

The on-chain output is an ordinary 64-byte ed25519 signature
indistinguishable from a single-key signer; Squads accepts the FROST
group address as any other member. v0.4 ships read+vote: the Sentinel
auto-polls the configured multisig every 30 seconds, surfaces new
proposals on the Home screen with severity-aware visuals (recursive
decode + risk lift catches the Drift-class wrapper attack), and writes
on-chain `proposal_approve` / `proposal_reject` instructions through
the FROST flow when the user taps Approve / Reject in Telegram.
