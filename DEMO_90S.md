# Sovereign OS Vault — 90-second demo

> Tight cut. Every line earns its seconds. Read it once, then record.

---

## Pre-record checklist (5 minutes before)

- [ ] FROST bot running, phone has greeted it via `/start`
- [ ] Squads multisig threshold = 2 (so FROST's vote actually matters)
- [ ] One **Active** malicious proposal already proposed (Recipe 2 — Token Approve `u64::MAX` to `1nc1nerator…`)
- [ ] Sentinel TUI launched, Home screen visible, Sentinel panel showing the Active proposal as 🛑 CRIT with red border
- [ ] Phone in frame with Telegram open on bot chat
- [ ] Solscan tab open in browser to your FROST address: `https://solscan.io/account/8aDTMD3JBjXd2SJcE9FYQ7Pqb4tX8cDdksdhCs8avFdH`
- [ ] OBS / screen recorder configured: laptop screen split with phone-cam picture-in-picture

---

## The script (90 seconds, ~260 words)

### `0:00 – 0:08` — Hook (8s)
**[On-screen: dark slide "$1.5B · Feb 2025 · Bybit" → cut to Sentinel TUI Home]**

> *"In February 2025, Bybit's multisig signers approved a transaction
> that didn't match what their UI showed them. They lost one and a
> half billion dollars."*

### `0:08 – 0:25` — Three trust domains, kernel hardening included (17s)
**[On-screen: Sentinel TUI Home — quickly POINT at three things in sequence:**
**(1) FROST address, (2) Sentinel panel bottom-left, (3) Hardening panel top-right with green ARMED status]**

> *"Sovereign OS Vault splits its signing key across three independent
> trust domains: a kernel-hardened laptop process where the share is
> mlocked and dump-protected, a Telegram bot you control, and your
> phone. Compromising any one — or any two — isn't enough."*

### `0:25 – 0:40` — Wrapper attack arrives (15s)
**[On-screen: Squads UI malicious proposal → cut back to Sentinel where it appears as 🛑 CRIT with red border + alarmed pet face]**

> *"From a member wallet, I just proposed a vault transaction wrapping
> an unlimited Token Approve. To the risk scanner Squads ships with,
> it looks fine. Sentinel sees the inner instruction."*

### `0:40 – 0:58` — The hero shot: recursive decode (18s)
**[On-screen: hit `m` → Enter on the proposal → Inspect screen, zoom on inner ix red ✗ + risk panel]**

> *"Recursive Squads decode. The outer call is a wrapper. Inside is an
> unlimited Token Approve to an unknown delegate — the Phantom drainer
> pattern from May 2025. Same class that almost hit Drift Security
> Council last month. Flagged Critical automatically."*

### `0:58 – 1:18` — The cryptographic gate (20s)
**[On-screen: press y → cut to phone showing Telegram prompt with the same risks → tap Reject → cut back to TUI showing rejection → cut to Solscan showing the on-chain rejection tx]**

> *"I press approve on the laptop. The bot still won't release its
> share until I tap on my phone. Different device, different network.
> I tap Reject. On-chain, my member vote is registered as a rejection.
> The attack reached as far as my phone screen and died there."*

### `1:18 – 1:30` — Range differentiation + close (12s)
**[On-screen: TUI Home, pet calm again, point at Hardening panel]**

> *"Range runs in your browser — and so does your wallet. Sovereign
> OS Vault doesn't. We move the share out of the browser, into a
> hardened process, then refuse to sign unless your phone agrees.
> The safest member in your Multisig."*

---

## Why the kernel-hardening beat is non-negotiable

Range catches risky patterns. **But Range runs in your browser** — same
process boundary as your wallet extension, your password manager, your
malicious tab. Even when Range warns you, you're clicking Approve in
the same compromised environment that holds your private key. Range is
a UI hint with no enforcement power.

**Kernel hardening is what makes the laptop's third of the trust model
real.** Without it, the FROST share lives in a process that any other
program running as your user could read via `/proc/[pid]/mem` or
ptrace, swap could leak it to disk, a core dump could capture it, a
debugger could attach mid-operation. With it (`PR_SET_DUMPABLE=0`,
`mlockall(MCL_CURRENT|MCL_FUTURE)`, `MADV_DONTDUMP`, Yama LSM ptracer
lock, debugger-detection kill switch, refusal to run as root):

- `/proc/[pid]/mem` returns "permission denied" even to your own UID
- `ptrace` attach is blocked by the dumpable flag + Yama scope
- The share's pages are locked in RAM and never swapped to disk
- Core dumps exclude the share's pages
- Attaching a debugger triggers immediate process exit

The 90-second pitch ends with *"we move the share out of the browser,
into a hardened process"* because that's the actual cryptographic
boundary. Range's warning + a browser-resident wallet = no boundary at
all. Sovereign OS Vault + the Telegram tap = three boundaries that an
attacker has to cross, each independent.

---

## What you cut to make it 90 seconds

(in case judges ask for "the long version" — this is what's omitted)

- Setup walkthrough (covered in README)
- The full hardening flag list (covered in README + threat model)
- PNG camouflage backup (covered in README, mentioned in submission copy)
- Comparison with hardware wallets, Privy, Lit (covered in `DEMO.md`)
- Seedify Bridge use case for protocol deployers (covered in `DEMO.md`)
- The benign-proposal Approve flow ending in a real on-chain `proposal_approve` Solscan link (covered in `DEMO.md` long version)

The 90-second cut keeps **only** what makes the cryptographic property
visceral: a malicious proposal lands → it's flagged → user taps Reject
on a separate device → on-chain proof. The kernel hardening is the
explanation for *why* the laptop is even worth trusting as one of the
three trust domains.

---

## Filming tips

1. **One take, no cuts.** Edited demos look like they could be faked.
   Single take is more credible.
2. **Phone in frame the whole time** — judges should see you physically
   tap Reject on the actual device, not "and then I tapped reject."
3. **Speak over the action, don't pause for it.** The script timing
   assumes you talk while clicking.
4. **Don't read off the screen.** Glance at TUI, narrate from memory.
   It reads as "this person actually built this."
5. **Show the Solscan URL clearly at the end.** That's the on-chain
   receipt — the one piece judges can verify themselves after the
   recording ends.

---

## Title card / thumbnail copy (optional)

**Title:** Sovereign OS Vault — the safest member in your Multisig

**Subtitle:** FROST 2-of-2 ed25519 with your Telegram as the second
trust domain. Catches Drift/Bybit-class wrapper attacks. Open source.

**Solana Frontier 2026 submission**
