# Setup — Sovereign OS Vault

Manual-step reference. If you just want the guided tutorial with screenshots,
copy-pasteable commands, and WSL-specific advice, **read [README.md](./README.md)
first** — this doc is for people who'd rather see every step laid out without
the prose.

Works on Linux (Ubuntu / Debian / Arch / Fedora) and on Windows via WSL2 with
Ubuntu. Instructions assume `apt`; swap your package manager where relevant.

> **TL;DR** — run `./quickstart.sh` from the repo root. It detects what's
> missing, prints install commands, and walks you through each step
> interactively. The steps below explain what it's doing if you prefer to
> run each step manually.

---

## Quick start (WSL on Windows)

If you're on Windows, you need WSL2 with Ubuntu before anything else here works.

**One-time setup from PowerShell (Administrator):**

```powershell
wsl --install
```

Restart Windows when it asks. After restart, Ubuntu's first launch will ask you
to pick a Linux username and password — anything memorable is fine.

**Everything else in this document runs inside the Ubuntu (WSL2) terminal**,
not PowerShell.

> ⚠️ **Critical:** keep this repo under your **WSL home directory** (`~/`).
> Do **NOT** put it under `/mnt/c/` or `/mnt/d/` — those are the Windows
> filesystem mounted into WSL, and compilation is roughly 10x slower there.
> A clone that builds in 3 minutes from `~/` can take 30+ minutes from
> `/mnt/c/`.

To enable systemd-based persistence (so the bot can keep running across
terminal sessions), enable it once:

```bash
sudo tee /etc/wsl.conf <<'EOF'
[boot]
systemd=true
EOF
```

Then from **PowerShell**: `wsl --shutdown`, wait 10 seconds, reopen Ubuntu.

---

## 0. Prerequisites

You need:
- **Linux** with kernel ≥ 5.10 (Yama LSM scope checks)
- **Rust** ≥ 1.81
- **Zig** ≥ 0.13
- **A Telegram account** + a bot you control via `@BotFather`
- **A bit of SOL** on a wallet you own (for testing the on-chain broadcast path; ~0.01 SOL is plenty)

If `rustc --version` and `zig version` both work, skip to step 1.

### Install Rust (if missing)
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustc --version  # should print 1.81+
```

### Install Zig (if missing)

**Recommended (works everywhere including WSL2):** install from the tarball.

```bash
cd ~
curl -LO https://ziglang.org/download/0.13.0/zig-linux-x86_64-0.13.0.tar.xz
tar -xf zig-linux-x86_64-0.13.0.tar.xz
echo 'export PATH="$HOME/zig-linux-x86_64-0.13.0:$PATH"' >> ~/.bashrc
source ~/.bashrc
zig version  # should print 0.13.0
```

**Alternative (Linux only, NOT WSL2):**

```bash
sudo snap install zig --classic --beta    # Ubuntu/Debian with snap
sudo pacman -S zig                         # Arch
# Or: download from https://ziglang.org/download/ and put on PATH
zig version  # should print 0.13+
```

Snap doesn't work out of the box in WSL2 (WSL2 doesn't enable snap by default).
If you went the snap route by mistake, fall back to the tarball method above.

---

## 1. Clone and build

```bash
git clone https://github.com/zkshiva07/Sovereign-OS-Vault
cd Sovereign-OS-Vault

# Builds the Zig hardening engine + Rust TUI + grants the cap_ipc_lock
# capability so mlockall works without sudo each launch.
./run.sh
```

First build takes ~3-5 minutes (pulls Solana SDK + frost-ed25519 +
ratatui). Subsequent builds are seconds.

Then build the FROST bot crate:
```bash
cd frost-bot && cargo build --release && cd ..
```

---

## 2. Create your Telegram bot

1. Open Telegram, search for **@BotFather**, send `/newbot`
2. Follow the prompts — pick a name like `sov_vault_<yourhandle>_bot`
3. Copy the bot token he hands you (looks like `1234567890:AAFmsd...`)
4. Search for **@userinfobot** in Telegram, send any message — it replies
   with your numeric Telegram user ID

---

## 3. Configure the bot

```bash
mkdir -p ~/.local/share/sovereign-os-vault/frost-bot
cp frost-bot/config.example.toml \
   ~/.local/share/sovereign-os-vault/frost-bot/config.toml
chmod 600 ~/.local/share/sovereign-os-vault/frost-bot/config.toml
$EDITOR ~/.local/share/sovereign-os-vault/frost-bot/config.toml
```

Fill in:
- `bot_token` — from @BotFather above
- `authorized_users` — your Telegram numeric ID (and any other allowlist members)
- `share_path` and `pubkey_path` — replace `YOUR_USERNAME` with your Linux username

---

## 4. Generate FROST keyshares (trusted-dealer)

```bash
./frost-bot/target/release/frost-keygen
```

This runs trusted-dealer FROST 2-of-2 keygen and writes:

- `~/.local/share/sovereign-os-vault/keystore/frost-share1.bin` — laptop's share
- `~/.local/share/sovereign-os-vault/frost-bot/share2.bin` — bot's share
- `~/.local/share/sovereign-os-vault/keystore/frost-pubkey.bin` and
  `~/.local/share/sovereign-os-vault/frost-bot/pubkey.bin` — group pubkey
  (identical copies on both sides)

It prints your **group public key** and **Solana address**. Both are real;
the Solana address can hold SOL and be added as a Squads multisig member.

> v0.4 uses trusted-dealer keygen. The keygen process briefly sees both
> shares before writing them to their separate destinations — which is
> fine if you run it once on a hardened machine. v0.5 will replace this
> with distributed key generation (DKG) so neither party ever sees the
> other's share.

---

## 5. Start the bot

```bash
./frost-bot/target/release/frost-bot
```

In Telegram, find your bot by its `@username` and send `/start`. The bot
should immediately reply with your group public key + Solana address —
that's your proof the bot can DM you.

If the bot doesn't reply: check the token in `config.toml`, verify your
user ID is in `authorized_users`, check the bot is running.

---

## 6. Launch the TUI

In a separate terminal:

```bash
# Optional: set this if you want the [m] Squads watch screen active
export SQUADS_MULTISIG="YOUR_SQUADS_MULTISIG_PDA"

./tui/target/release/sovereign-vault
```

The BackendSelect screen should show FROST as ready. Press Enter to
launch. You should land on the Home screen with your FROST address
displayed in the Identity panel and the Sentinel panel showing
"watching for proposals."

---

## 7. Test the round-trip

Generate a test transaction (uses your FROST address as fee payer):

```bash
./tui/target/release/tx-fixtures YOUR_FROST_ADDRESS
```

Pick the first benign fixture (System Transfer), copy the base64 string.

In the TUI:
1. Press `s` from Home
2. Paste the base64 → Enter
3. Inspector shows the recursive decode
4. Press `y` to sign
5. Telegram pings your phone — tap **Approve**
6. Signed screen shows the base58-encoded VersionedTransaction

That signature is real — it would broadcast successfully if you fund the
FROST address with SOL and use the `[b]` broadcast hotkey from the
Signed screen. (For a fixture-generated tx you do NOT want to broadcast,
since it's a self-transfer with placeholder data.)



---

## 8. Optional: PNG-camouflaged backup

```bash
./tui/target/release/frost-camouflage embed \
  --party laptop --cover any-photo.png --out vault.png
```

You'll be prompted for a passphrase. The output PNG looks identical to
the cover image but contains your encrypted FROST share. Recovery:

```bash
./tui/target/release/frost-camouflage extract vault.png
```

Same flow with `--party bot` for the bot side (the bot backup PNG also
contains the bot token — back it up like password-manager exports, not
photo cloud).

---

## 9. Keep the bot running across terminal sessions

The bot is a foreground process. If you close the terminal, the bot dies. Three options:

### Option A — `tmux` (works everywhere, easy)

```bash
sudo apt install tmux
tmux new -s vault-bot
# inside the tmux session:
./frost-bot/target/release/frost-bot
# Press Ctrl-b then d to detach. The bot keeps running.
# To return later: tmux attach -t vault-bot
# To kill it cleanly: tmux attach -t vault-bot, then Ctrl-c, then exit
```

### Option B — `systemd` user service (Linux + WSL2 with systemd enabled)

Make sure systemd is enabled in WSL2 (`/etc/wsl.conf` has `[boot]\nsystemd=true`,
followed by `wsl --shutdown` from PowerShell). Then:

```bash
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/sov-frost-bot.service <<'EOF'
[Unit]
Description=Sovereign OS Vault FROST cosigner bot
After=network.target

[Service]
Type=simple
ExecStart=%h/sovereign-os-vault/frost-bot/target/release/frost-bot
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable --now sov-frost-bot.service
systemctl --user status sov-frost-bot.service
```

Logs: `journalctl --user -u sov-frost-bot.service -f`

### Option C — separate host (Fly.io, Raspberry Pi, your phone via Termux)

This is the production answer. Run the bot on a host you control that's
independent of your laptop. Update the TUI's bot URL to point at the new host
(see `tui/src/frost.rs` constant `DEFAULT_BOT_URL`). HTTPS-only — no inbound
ports needed if you front the bot behind a tunnel (e.g., Tailscale, Cloudflare
Tunnel).

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `mlockall: Operation not permitted` on TUI launch | `cap_ipc_lock` missing | `sudo setcap cap_ipc_lock=ep ./tui/target/release/sovereign-vault` |
| TUI says "FROST share missing or unreadable" | Keygen didn't run, or wrong path in config | Re-run `frost-keygen`; check `share_path` in the bot config |
| TUI says "FROST bot not reachable" | Bot process not running | Start it: `./frost-bot/target/release/frost-bot &` |
| Telegram never sends a prompt | Bot token wrong, or you haven't `/start`'d the bot | Check token; send `/start` to the bot in Telegram once |
| Sign fails with "fee payer mismatch" | Pasted tx's fee payer ≠ FROST address | Generate the test fixture with your actual FROST address as the argument |
| Squads watch screen empty | `SQUADS_MULTISIG` env var not set, or the multisig has no proposals | Set the env var; propose a tx in the Squads UI |
| Build fails on `frost-ed25519` version | Older Rust toolchain | `rustup update stable` (need ≥ 1.81) |
| Build is 10x slower than expected (WSL) | Repo lives on `/mnt/c/` or `/mnt/d/` | Move repo into `~/` (WSL home), rebuild |
| `snap: command not found` (Zig install) | WSL2 doesn't ship snap by default | Install Zig from the tarball instead (see "Install Zig" above) |
| Bot dies when I close the terminal | Foreground process | Use `tmux` or the systemd service (see section 9) |
| `wsl --install` says "feature not available" | Old Windows version, or virtualization disabled in BIOS | Update Windows 10/11; enable virtualization in BIOS/UEFI |

---

## Architecture quick map

```
┌─ Your laptop ─────────────────────────────────┐    ┌─ Your phone ───────┐
│  ┌─ vault-armor (Zig)                         │    │   Telegram         │
│  │   independent kernel hardening             │    │   (your bot's chat)│
│  ├─ sovereign-vault (Rust TUI)                │    └────────▲───────────┘
│  │   - inspector.rs (recursive Squads decode) │             │ MTProto
│  │   - frost.rs (laptop FROST share)          │             │ tap Approve
│  │   - squads.rs (multisig watch / vote ix)   │             │
│  │   - rpc.rs (mainnet broadcast)             │             │
│  └─ frost-camouflage (PNG-stego backup)       │             │
└──────────────────┬────────────────────────────┘             │
                   │ HTTPS (FROST round messages)             │
┌─ Your bot host (laptop / Fly.io / RPi) ───────┐    ┌────────┴───────────┐
│  sovereign-frost-bot (Rust)                   │    │ teloxide HTTP API  │
│   - holds FROST share 2                       │────▶ talks to Telegram  │
│   - authorizes signs only after Telegram tap  │    └────────────────────┘
└───────────────────────────────────────────────┘
```

---

For the longer pitch / threat model / hack post-mortems, see [DEMO.md](./DEMO.md).
For the 90-second demo recording walkthrough, see [DEMO_90S.md](./DEMO_90S.md).

