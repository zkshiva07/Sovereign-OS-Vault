#!/usr/bin/env bash
# Sovereign OS Vault — guided setup wizard
#
# Run this from anywhere after cloning:
#   git clone https://github.com/<repo>/sovereign-os-vault
#   ./sovereign-os-vault/quickstart.sh
#
# What it does, in order:
#   0. Detects your environment (Linux / WSL / distro / filesystem)
#   1. Installs Rust + Zig if missing (asks first)
#   2. Installs apt build deps if missing
#   3. Builds vault-armor (Zig) + sovereign-vault (Rust) + frost-bot (Rust)
#   4. Grants cap_ipc_lock so mlockall works without sudo
#   5. Walks you through making a Telegram bot via @BotFather
#   6. Auto-detects your Telegram user ID by asking you to /start the bot
#   7. Runs FROST keygen, prints your Solana address
#   8. Offers a smoke test (sign a fake transaction, no money required)
#   9. Prints next-step commands
#
# Idempotent — re-running is safe. Each phase detects existing state.

set -uo pipefail

# ── Self-locate ──────────────────────────────────────────────────────────────
PROJ="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJ"

# ── Cleanup trap (B6) ────────────────────────────────────────────────────────
# If the wizard exits with a backgrounded bot running, kill it.
BOT_PID=""
cleanup() {
    if [[ -n "$BOT_PID" ]] && kill -0 "$BOT_PID" 2>/dev/null; then
        kill "$BOT_PID" 2>/dev/null
        wait "$BOT_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

# ── Style ────────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    BOLD=$'\e[1m'; DIM=$'\e[2m'
    GRN=$'\e[32m'; YEL=$'\e[33m'; RED=$'\e[31m'; CYN=$'\e[36m'; MAG=$'\e[35m'
    RST=$'\e[0m'
else
    BOLD=''; DIM=''; GRN=''; YEL=''; RED=''; CYN=''; MAG=''; RST=''
fi

banner() {
    printf "\n${BOLD}${MAG}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}\n"
    printf "${BOLD}${MAG} %s${RST}\n" "$*"
    printf "${BOLD}${MAG}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}\n"
}
say()  { printf "${CYN}${BOLD}==>${RST} %s\n" "$*"; }
ok()   { printf "    ${GRN}✓${RST} %s\n" "$*"; }
warn() { printf "    ${YEL}!${RST} %s\n" "$*"; }
err()  { printf "    ${RED}✗${RST} %s\n" "$*"; }
die()  { err "$*"; exit 1; }
hint() { printf "    ${DIM}%s${RST}\n" "$*"; }

ask() {
    # ask "prompt"  -> sets REPLY
    local _r
    read -r -p "$(printf "${BOLD}? %s${RST} " "$*")" _r
    REPLY="$_r"
}
ask_yes() {
    # ask_yes "prompt" [default=Y]  -> returns 0 if yes
    local default="${2:-Y}" hint_str
    if [[ "$default" == "Y" ]]; then hint_str="[Y/n]"; else hint_str="[y/N]"; fi
    ask "$1 $hint_str"
    if [[ -z "$REPLY" ]]; then REPLY="$default"; fi
    [[ "$REPLY" =~ ^[Yy]$ ]]
}
ask_secret() {
    # ask_secret "prompt"  -> sets REPLY (no echo)
    local _r
    read -r -s -p "$(printf "${BOLD}? %s${RST} " "$*")" _r
    echo
    REPLY="$_r"
}

# prompt_cover OUTVAR PARTY  — prompt for a PNG path, looping on bad input.
#   OUTVAR : name of variable to set (e.g. LAPTOP_COVER)
#   PARTY  : "laptop" or "bot" — used for prompt text and generated filename
# Returns 0 if user picked or generated a cover, 1 if user chose to skip.
# Recognizes: empty input or 'g' = generate, 's' = skip, anything else = path.
prompt_cover() {
    local _outvar="$1"
    local _party="$2"
    local _cand
    local _party_upper
    _party_upper=$(echo "$_party" | tr '[:lower:]' '[:upper:]')
    while true; do
        ask "Path to a PNG cover for $_party_upper backup (Enter = auto-generate, 's' = skip):"
        case "$REPLY" in
            ""|g|G|generate)
                _cand="$BACKUP_DIR/cover-${_party}.png"
                say "generating a random placeholder cover at $_cand..."
                python3 - "$_cand" <<'PYEOF'
import sys, zlib, struct, os
out = sys.argv[1]
W, H = 512, 512
def chunk(ty, data):
    return struct.pack('>I', len(data)) + ty + data + struct.pack('>I', zlib.crc32(ty + data))
rows = b''.join(b'\x00' + os.urandom(W*3) for _ in range(H))
png  = b'\x89PNG\r\n\x1a\n'
png += chunk(b'IHDR', struct.pack('>IIBBBBB', W, H, 8, 2, 0, 0, 0))
png += chunk(b'IDAT', zlib.compress(rows, 6))
png += chunk(b'IEND', b'')
open(out, 'wb').write(png)
PYEOF
                if [[ -f "$_cand" ]]; then
                    printf -v "$_outvar" '%s' "$_cand"
                    ok "generated $_cand"
                    return 0
                else
                    err "placeholder generation failed (is python3 working?)"
                fi
                ;;
            s|S|skip|Skip|SKIP)
                return 1
                ;;
            *)
                if [[ -f "$REPLY" ]]; then
                    printf -v "$_outvar" '%s' "$REPLY"
                    return 0
                else
                    err "file not found: $REPLY"
                    hint "try again, hit Enter to auto-generate, or type 's' to skip backup"
                fi
                ;;
        esac
    done
}

# ── Phase 0: Environment ─────────────────────────────────────────────────────
banner "Sovereign OS Vault — setup wizard"

# Refuse root immediately
if [[ $EUID -eq 0 ]]; then
    die "do not run as root — root bypasses the hardening this vault depends on. Run as a regular user; the wizard will sudo only when needed."
fi

say "Phase 0 — Environment check"

# OS
case "$(uname -s)" in
    Linux) ok "OS: Linux" ;;
    Darwin) die "macOS is not supported in v0.4 (some kernel hardening calls don't exist). Use a Linux VM or wait for v0.5." ;;
    *) die "Unsupported OS: $(uname -s)" ;;
esac

# WSL detection
IS_WSL=false
if grep -qi "microsoft\|wsl" /proc/version 2>/dev/null; then
    IS_WSL=true
    ok "Running under WSL"
fi

# Filesystem location (B8 — detect any /mnt/<drive> and 9p/drvfs)
WIN_MOUNT=false
case "$PROJ" in
    /mnt/[a-z]/*) WIN_MOUNT=true ;;
esac
if ! $WIN_MOUNT && command -v findmnt &>/dev/null; then
    FS_TYPE=$(findmnt -no FSTYPE --target "$PROJ" 2>/dev/null || echo "")
    case "$FS_TYPE" in
        9p|drvfs|cifs) WIN_MOUNT=true ;;
    esac
fi
if $WIN_MOUNT; then
    err "Repo is on a Windows-mounted filesystem ($PROJ)."
    err "Build will be ~10x slower and some operations may fail."
    hint "Move the repo into your WSL home: mv \"$PROJ\" ~/$(basename "$PROJ") && cd ~/$(basename "$PROJ")"
    ask_yes "Continue anyway (NOT recommended)" N || die "aborted; move the repo and re-run"
else
    ok "Filesystem: $PROJ (OK)"
fi

# Distro detection (apt / pacman / dnf)
PKG_MGR=""
if command -v apt &>/dev/null; then PKG_MGR="apt"
elif command -v pacman &>/dev/null; then PKG_MGR="pacman"
elif command -v dnf &>/dev/null; then PKG_MGR="dnf"
fi
if [[ -n "$PKG_MGR" ]]; then ok "Package manager: $PKG_MGR"
else warn "no known package manager found — you'll need to install build deps yourself"
fi

# Basic tools we need just to run the wizard
for tool in curl python3 sed grep tar; do
    command -v "$tool" &>/dev/null || die "$tool is required but not installed"
done
ok "wizard dependencies present (curl, python3, sed, grep, tar)"

# ── Phase 1: Toolchains ──────────────────────────────────────────────────────
say "Phase 1 — Toolchains"

# apt build deps (Ubuntu/Debian + WSL)
if [[ "$PKG_MGR" == "apt" ]]; then
    APT_NEEDED=()
    for pkg in build-essential pkg-config libssl-dev libcap2-bin; do
        if ! dpkg -s "$pkg" &>/dev/null; then APT_NEEDED+=("$pkg"); fi
    done
    if (( ${#APT_NEEDED[@]} > 0 )); then
        warn "Missing apt packages: ${APT_NEEDED[*]}"
        if ask_yes "Install them now (uses sudo)" Y; then
            sudo apt update
            sudo apt install -y "${APT_NEEDED[@]}" || die "apt install failed"
            ok "apt deps installed"
        else
            die "cannot continue without those packages"
        fi
    else
        ok "apt build deps already present"
    fi
fi

# Rust
if ! command -v cargo &>/dev/null; then
    if [[ -f "$HOME/.cargo/env" ]]; then . "$HOME/.cargo/env"; fi
fi
if command -v cargo &>/dev/null; then
    ok "rust: $(rustc --version)"
else
    warn "Rust not found"
    hint "rustup is the standard installer (https://rustup.rs)"
    if ask_yes "Install Rust now via rustup" Y; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable || die "rustup install failed"
        # shellcheck disable=SC1091
        . "$HOME/.cargo/env"
        ok "rust installed: $(rustc --version)"
    else
        die "cannot continue without Rust"
    fi
fi

# Zig (B5 — also export to current shell; B7 — detect arch)
ZIG=""
if command -v zig &>/dev/null; then ZIG=$(command -v zig)
elif [[ -x /snap/bin/zig ]]; then ZIG=/snap/bin/zig
elif [[ -x "$HOME/zig/zig" ]]; then ZIG="$HOME/zig/zig"
elif compgen -G "$HOME/zig-linux-*/zig" >/dev/null 2>&1; then
    ZIG=$(compgen -G "$HOME/zig-linux-*/zig" | head -1)
fi

if [[ -n "$ZIG" ]]; then
    ok "zig: $($ZIG version) ($ZIG)"
else
    # Detect architecture for the right tarball
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)         ZIG_ARCH="x86_64" ;;
        aarch64|arm64)  ZIG_ARCH="aarch64" ;;
        *) die "unsupported architecture for Zig auto-install: $ARCH. Install Zig 0.13+ manually (https://ziglang.org/download) and re-run." ;;
    esac
    ZIG_DIR="zig-linux-${ZIG_ARCH}-0.13.0"
    warn "Zig 0.13+ not found"
    hint "We'll download the official $ZIG_ARCH tarball to ~/$ZIG_DIR/"
    if ask_yes "Install Zig 0.13.0 now" Y; then
        (
            cd ~
            curl -L --fail -o "${ZIG_DIR}.tar.xz" \
                "https://ziglang.org/download/0.13.0/${ZIG_DIR}.tar.xz" \
                || exit 1
            tar -xf "${ZIG_DIR}.tar.xz"
            rm -f "${ZIG_DIR}.tar.xz"
        ) || die "Zig download/extract failed"
        ZIG="$HOME/${ZIG_DIR}/zig"
        # Export to current shell so future commands in THIS run find zig
        export PATH="$HOME/${ZIG_DIR}:$PATH"
        # Persist for future shells
        if ! grep -q "${ZIG_DIR}" ~/.bashrc 2>/dev/null; then
            echo "export PATH=\"\$HOME/${ZIG_DIR}:\$PATH\"" >> ~/.bashrc
            hint "added Zig to your PATH in ~/.bashrc (takes effect in new shells)"
        fi
        ok "zig installed: $($ZIG version)"
    else
        die "cannot continue without Zig"
    fi
fi

# ── Phase 2: Build ───────────────────────────────────────────────────────────
say "Phase 2 — Build"

# vault-armor (Zig)
ARMOR_BIN="$PROJ/zig-out/bin/vault-armor"
if [[ -x "$ARMOR_BIN" ]]; then
    ok "vault-armor already built ($ARMOR_BIN)"
else
    say "Building Zig hardening engine (vault-armor)..."
    if ! "$ZIG" build -Doptimize=ReleaseSafe 2>&1 | sed 's/^/    /'; then
        die "vault-armor build failed"
    fi
    [[ -x "$ARMOR_BIN" ]] || die "vault-armor not produced"
    ok "vault-armor → $ARMOR_BIN"
fi

# TUI (Rust)
TUI_BIN="$PROJ/tui/target/release/sovereign-vault"
CAMOUFLAGE_BIN="$PROJ/tui/target/release/frost-camouflage"
FIXTURES_BIN="$PROJ/tui/target/release/tx-fixtures"
if [[ -x "$TUI_BIN" && -x "$CAMOUFLAGE_BIN" && -x "$FIXTURES_BIN" ]]; then
    ok "TUI binaries already built"
else
    say "Building Rust TUI (sovereign-vault) — first build pulls Solana SDK + FROST crates (~3–5 min)"
    (
        cd "$PROJ/tui"
        cargo build --release 2>&1 | sed 's/^/    /'
    ) || die "TUI build failed"
    [[ -x "$TUI_BIN" ]] || die "sovereign-vault binary not produced"
    ok "sovereign-vault → $TUI_BIN"
    ok "frost-camouflage → $CAMOUFLAGE_BIN"
    ok "tx-fixtures      → $FIXTURES_BIN"
fi

# frost-bot (Rust)
BOT_BIN="$PROJ/frost-bot/target/release/frost-bot"
KEYGEN_BIN="$PROJ/frost-bot/target/release/frost-keygen"
if [[ -x "$BOT_BIN" && -x "$KEYGEN_BIN" ]]; then
    ok "frost-bot binaries already built"
else
    say "Building frost-bot crate"
    (
        cd "$PROJ/frost-bot"
        cargo build --release 2>&1 | sed 's/^/    /'
    ) || die "frost-bot build failed"
    [[ -x "$BOT_BIN" ]] || die "frost-bot binary not produced"
    ok "frost-bot    → $BOT_BIN"
    ok "frost-keygen → $KEYGEN_BIN"
fi

# cap_ipc_lock
say "Granting cap_ipc_lock (so mlockall works without sudo each launch)"
NEEDS_CAP=true
if command -v getcap &>/dev/null; then
    if getcap "$TUI_BIN" 2>/dev/null | grep -q "cap_ipc_lock"; then
        ok "cap_ipc_lock already set on $TUI_BIN"
        NEEDS_CAP=false
    fi
fi
if $NEEDS_CAP; then
    warn "sudo password required (one-time)"
    if sudo setcap cap_ipc_lock=ep "$TUI_BIN"; then
        ok "cap_ipc_lock granted"
    else
        warn "setcap failed — vault will fail mlockall unless run as sudo"
        hint "manual fix: sudo setcap cap_ipc_lock=ep $TUI_BIN"
    fi
fi

# ── Paths used by Phase R, Phase 3, Phase 4 ──────────────────────────────────
BOT_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/sovereign-os-vault/frost-bot"
KEYSTORE_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/sovereign-os-vault/keystore"
BOT_CONFIG="$BOT_DIR/config.toml"
LAPTOP_SHARE="$KEYSTORE_DIR/frost-share1.bin"
BOT_SHARE="$BOT_DIR/share2.bin"
PUBKEY="$KEYSTORE_DIR/frost-pubkey.bin"
mkdir -p "$BOT_DIR" "$KEYSTORE_DIR"

# Track whether we generated fresh keys this run (affects Phase B logic)
DID_FRESH_KEYGEN=false
SOL_ADDR=""

# ── Phase R: Recover from existing backup (optional) ─────────────────────────
say "Phase R — Recover from existing backup (optional)"

if [[ -f "$LAPTOP_SHARE" && -f "$BOT_SHARE" && -f "$PUBKEY" ]]; then
    ok "FROST shares already exist locally — recovery not needed"
    hint "(skipping Phase R; later phases will see the existing shares)"
else
    cat <<EOF

    If you've previously set up Sovereign OS Vault and have backup PNGs
    (one for laptop side, one for bot side), you can restore from them
    now instead of generating fresh keys.

    You need BOTH PNGs and the passphrase you chose when you made them.
    Without either side, you cannot sign — FROST is 2-of-2.

EOF
    if ask_yes "Recover from existing backup PNGs?" N; then
        ask "Path to LAPTOP backup PNG:"
        LAPTOP_PNG="$REPLY"
        [[ -f "$LAPTOP_PNG" ]] || die "file not found: $LAPTOP_PNG"

        say "Extracting laptop share (you'll be prompted for the backup passphrase)..."
        RECOVER_LOG=$(mktemp)
        "$CAMOUFLAGE_BIN" extract "$LAPTOP_PNG" 2>&1 | tee "$RECOVER_LOG" | sed 's/^/    /'
        if [[ "${PIPESTATUS[0]}" != "0" ]]; then
            rm -f "$RECOVER_LOG"
            die "laptop extract failed — wrong passphrase or corrupted PNG"
        fi
        SOL_ADDR=$(grep "Solana addr" "$RECOVER_LOG" \
            | sed -E 's/.*: *([1-9A-HJ-NP-Za-km-z]+).*/\1/' \
            | head -1 | tr -d ' ')
        rm -f "$RECOVER_LOG"
        [[ -f "$LAPTOP_SHARE" ]] || die "extract ran but laptop share not produced (did you confirm 'y' when prompted?)"
        ok "laptop share recovered → $LAPTOP_SHARE"

        ask "Path to BOT backup PNG:"
        BOT_PNG="$REPLY"
        [[ -f "$BOT_PNG" ]] || die "file not found: $BOT_PNG"

        say "Extracting bot share + config..."
        "$CAMOUFLAGE_BIN" extract "$BOT_PNG" 2>&1 | sed 's/^/    /'
        if [[ "${PIPESTATUS[0]}" != "0" ]]; then
            die "bot extract failed"
        fi
        [[ -f "$BOT_SHARE" ]] || die "extract ran but bot share not produced"
        ok "bot share recovered → $BOT_SHARE"

        if [[ -f "$BOT_CONFIG" ]]; then
            ok "bot config restored → $BOT_CONFIG"
        else
            warn "bot config not restored — Phase 3 will help you re-create it"
        fi

        [[ -n "$SOL_ADDR" ]] && ok "recovered Solana address: $SOL_ADDR"
        say "Recovery complete — Phases 3 (bot config) and 4 (keygen) will skip if state is good"
    fi
fi

# ── Phase 3: Telegram bot ────────────────────────────────────────────────────
say "Phase 3 — Telegram bot"

CONFIG_VALID=false
if [[ -f "$BOT_CONFIG" ]]; then
    if grep -q "REPLACE_WITH_YOUR_BOTFATHER_TOKEN\|123456789" "$BOT_CONFIG"; then
        warn "bot config exists but contains placeholder values — re-running setup"
    else
        ok "bot config already filled in ($BOT_CONFIG)"
        CONFIG_VALID=true
    fi
fi

if ! $CONFIG_VALID; then
    cat <<EOF

    ${BOLD}Step 3a — Create your Telegram bot${RST}

    1. Open Telegram on your phone or desktop
    2. Search for ${BOLD}@BotFather${RST} (the official Telegram bot)
    3. Send him ${BOLD}/newbot${RST}
    4. Follow the prompts. Pick a display name ("My Vault") and a
       username that ends in "bot" (e.g. ${DIM}sov_vault_$(whoami)_bot${RST})
    5. He'll reply with a ${BOLD}token${RST} that looks like:
       ${DIM}1234567890:AAFmsd-veryLongRandomString${RST}
    6. Copy that token and paste it below.

    Treat the token like a password. If you ever leak it, message
    @BotFather and use /revoke to get a fresh one.

EOF
    BOT_TOKEN=""
    while [[ -z "$BOT_TOKEN" ]]; do
        ask_secret "Paste the BotFather token"
        BOT_TOKEN="$REPLY"
        # Basic shape check
        if ! [[ "$BOT_TOKEN" =~ ^[0-9]+:[A-Za-z0-9_-]{30,}$ ]]; then
            warn "that doesn't look like a Telegram bot token (expected: digits:35-char-string)"
            BOT_TOKEN=""
            continue
        fi
        # Live validate with getMe (B4 — distinguish network from auth errors)
        say "Validating token with Telegram..."
        GETME_FILE=$(mktemp)
        HTTP_STATUS=$(curl -s --max-time 10 -o "$GETME_FILE" \
            -w '%{http_code}' \
            "https://api.telegram.org/bot${BOT_TOKEN}/getMe" 2>/dev/null || echo "000")
        CURL_EXIT=$?
        GETME_BODY=$(cat "$GETME_FILE" 2>/dev/null || echo '{}')
        rm -f "$GETME_FILE"
        if [[ "$CURL_EXIT" != "0" ]] || [[ "$HTTP_STATUS" == "000" ]] || [[ -z "$HTTP_STATUS" ]]; then
            err "Could not reach Telegram (network error). Check your internet connection and try again."
            hint "If you're on WSL, also check Windows-side firewall / VPN."
            BOT_TOKEN=""
            continue
        fi
        OK_FIELD=$(printf '%s' "$GETME_BODY" | python3 -c "import json,sys
try:
    d = json.load(sys.stdin)
    print('yes' if d.get('ok') else 'no')
except Exception:
    print('parse_err')" 2>/dev/null)
        if [[ "$OK_FIELD" != "yes" ]]; then
            err "Telegram rejected the token (HTTP $HTTP_STATUS). Response: $GETME_BODY"
            hint "Make sure you pasted the entire token. If you regenerated it via /revoke, the old one is invalid."
            BOT_TOKEN=""
            continue
        fi
        BOT_USERNAME=$(printf '%s' "$GETME_BODY" | python3 -c "import json,sys; print(json.load(sys.stdin)['result']['username'])")
        ok "token valid — bot is @$BOT_USERNAME"
    done

    cat <<EOF

    ${BOLD}Step 3b — Auto-detecting your Telegram user ID${RST}

    Open Telegram, find ${BOLD}@${BOT_USERNAME}${RST}, send it ${BOLD}/start${RST}.
    The wizard will detect your user ID from that message automatically.

    (Waiting up to 2 minutes...)

EOF

    # B2 — clear any webhook that would block getUpdates with 409 Conflict.
    # Idempotent: no-op on bots without a webhook set. drop_pending_updates=true
    # also discards any /start sent BEFORE we started polling so we only see
    # the fresh one the user is about to send.
    curl -s --max-time 10 \
        "https://api.telegram.org/bot${BOT_TOKEN}/deleteWebhook?drop_pending_updates=true" \
        >/dev/null 2>&1 || true

    # Clear any prior updates so we only see fresh ones
    LAST_UPDATE_ID=0
    INITIAL_UPDATES=$(curl -s --max-time 10 "https://api.telegram.org/bot${BOT_TOKEN}/getUpdates?timeout=0&limit=100")
    LAST_UPDATE_ID=$(printf '%s' "$INITIAL_UPDATES" | python3 -c "import json,sys
try:
    d = json.load(sys.stdin)
    ids = [u['update_id'] for u in d.get('result', [])]
    print(max(ids) if ids else 0)
except Exception:
    print(0)" 2>/dev/null)
    # Skip past them
    OFFSET=$((LAST_UPDATE_ID + 1))

    USER_ID=""
    DEADLINE=$(( $(date +%s) + 120 ))
    while [[ -z "$USER_ID" ]]; do
        if (( $(date +%s) > DEADLINE )); then
            warn "timed out waiting for /start"
            ask "Enter your numeric Telegram user ID manually (from @userinfobot)"
            USER_ID="$REPLY"
            if [[ ! "$USER_ID" =~ ^[0-9]+$ ]]; then
                die "that's not a numeric user ID"
            fi
            break
        fi
        printf "    ${DIM}polling Telegram...${RST}\r"
        UPDATES=$(curl -s --max-time 30 "https://api.telegram.org/bot${BOT_TOKEN}/getUpdates?offset=${OFFSET}&timeout=20")
        USER_ID=$(printf '%s' "$UPDATES" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    for u in d.get('result', []):
        msg = u.get('message') or u.get('edited_message')
        if msg and msg.get('chat', {}).get('type') == 'private':
            print(msg['from']['id'])
            break
except Exception:
    pass
" 2>/dev/null)
        if [[ -n "$USER_ID" ]]; then
            printf "                                  \r"
            ok "detected user ID: $USER_ID"
            break
        fi
    done

    # Write config
    cat > "$BOT_CONFIG" <<EOF
# Sovereign OS Vault — FROST bot config
# Generated by quickstart.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Treat this file like a password — never commit, mode 600.

bot_token        = "$BOT_TOKEN"
authorized_users = [$USER_ID]
listen_addr      = "127.0.0.1:7777"
share_path       = "$BOT_DIR/share2.bin"
pubkey_path      = "$BOT_DIR/pubkey.bin"
EOF
    chmod 600 "$BOT_CONFIG"
    ok "bot config written to $BOT_CONFIG (mode 600)"
    # B9 — token is now persisted to the (mode-600) config file; clear from env
    # so subsequent child processes (cargo, zig) don't see it.
    unset BOT_TOKEN
fi

# ── Phase 4: Keygen ──────────────────────────────────────────────────────────
say "Phase 4 — FROST keygen"

if [[ -f "$LAPTOP_SHARE" && -f "$BOT_SHARE" && -f "$PUBKEY" ]]; then
    ok "FROST shares already exist:"
    ok "  laptop: $LAPTOP_SHARE"
    ok "  bot:    $BOT_SHARE"
    ok "  pubkey: $PUBKEY"
    if [[ -n "$SOL_ADDR" ]]; then
        ok "Solana address (from recovery): $SOL_ADDR"
    else
        warn "skipping keygen (re-running would generate a brand-new address)"
        hint "Your Solana address was printed during your first keygen run."
        hint "If you've lost it, look at your previous terminal scrollback,"
        hint "or remove the shares above and re-run this wizard for a fresh keygen."
    fi
else
    if [[ -f "$LAPTOP_SHARE" || -f "$BOT_SHARE" ]]; then
        err "Partial keystate detected — one share exists, the other doesn't."
        err "This usually means a failed previous run."
        err "Investigate manually before continuing. To start fresh:"
        hint "  rm '$LAPTOP_SHARE' '$BOT_SHARE' '$PUBKEY' '$BOT_DIR/pubkey.bin' 2>/dev/null"
        die "refusing to overwrite partial keystate"
    fi
    say "Running trusted-dealer FROST 2-of-2 keygen..."
    # B1 — capture keygen stdout so we can extract the Solana address line.
    # keygen.rs prints: "│ Solana address (base58)   : <addr>"
    KEYGEN_LOG=$(mktemp)
    "$KEYGEN_BIN" 2>&1 | tee "$KEYGEN_LOG" | sed 's/^/    /'
    KEYGEN_EXIT=${PIPESTATUS[0]}
    if [[ "$KEYGEN_EXIT" != "0" ]]; then
        rm -f "$KEYGEN_LOG"
        die "keygen failed (exit $KEYGEN_EXIT)"
    fi
    if [[ ! -f "$LAPTOP_SHARE" || ! -f "$BOT_SHARE" ]]; then
        rm -f "$KEYGEN_LOG"
        die "keygen ran but shares missing"
    fi
    # Extract base58 address; trim leading "│ Solana address (base58) : " and any trailing whitespace.
    SOL_ADDR=$(grep "Solana address" "$KEYGEN_LOG" \
        | sed -E 's/.*: *([1-9A-HJ-NP-Za-km-z]+).*/\1/' \
        | head -1 \
        | tr -d ' ')
    rm -f "$KEYGEN_LOG"
    DID_FRESH_KEYGEN=true
    ok "shares written"
    if [[ -n "$SOL_ADDR" ]]; then
        ok "Solana address: $SOL_ADDR"
    else
        warn "could not parse Solana address from keygen output (look at the box above)"
    fi
fi

# ── Phase B: Backup shares (CRITICAL) ────────────────────────────────────────
say "Phase B — Back up your shares (CRITICAL)"

if [[ ! -f "$LAPTOP_SHARE" || ! -f "$BOT_SHARE" ]]; then
    warn "Shares missing — can't back up"
else
    # Default to Y on fresh keygen, N if shares pre-existed (likely already backed up).
    if $DID_FRESH_KEYGEN; then
        cat <<EOF

    Without backups, losing your laptop or your bot host means losing
    access to your funds PERMANENTLY. FROST 2-of-2 has no escape hatch.

    The wizard can embed your encrypted shares into ordinary-looking PNGs.
    Recovery later needs both the PNG and a passphrase you choose now.

EOF
        _BACKUP_DEFAULT=Y
    else
        cat <<EOF

    Your FROST shares already existed before this run (no fresh keygen
    happened). You can still create / re-create backup PNGs right now if
    you don't have them already.

EOF
        _BACKUP_DEFAULT=N
    fi

    if ask_yes "Create encrypted PNG backups now?" $_BACKUP_DEFAULT; then
        BACKUP_DIR="$HOME/sovereign-os-vault-backups"
        mkdir -p "$BACKUP_DIR"
        ok "backups will go to $BACKUP_DIR"

        # ── Laptop cover + backup ──
        LAPTOP_COVER=""
        if prompt_cover LAPTOP_COVER laptop; then
            LAPTOP_BACKUP="$BACKUP_DIR/laptop-backup.png"
            echo
            echo "    ${BOLD}frost-camouflage will now prompt you for a passphrase, twice.${RST}"
            echo "    Use a STRONG passphrase: 6+ random words, or a long random string."
            echo "    Write it down somewhere safe. Without it, the backup is useless."
            echo
            if "$CAMOUFLAGE_BIN" embed --party laptop --cover "$LAPTOP_COVER" --out "$LAPTOP_BACKUP"; then
                ok "laptop backup → $LAPTOP_BACKUP"
            else
                warn "laptop backup FAILED — re-run wizard to retry"
                LAPTOP_BACKUP=""
            fi
        else
            warn "Skipping laptop backup."
            LAPTOP_BACKUP=""
        fi

        # ── Bot cover + backup ──
        BOT_COVER=""
        if prompt_cover BOT_COVER bot; then
            BOT_BACKUP="$BACKUP_DIR/bot-backup.png"
            echo
            echo "    ${BOLD}${YEL}The bot backup also contains your bot token.${RST}"
            echo "    ${BOLD}${YEL}Anyone with this PNG + passphrase can impersonate your bot.${RST}"
            echo "    Store it like a password-manager export — NOT the same place as the laptop backup."
            echo
            if "$CAMOUFLAGE_BIN" embed --party bot --cover "$BOT_COVER" --out "$BOT_BACKUP"; then
                ok "bot backup → $BOT_BACKUP"
            else
                warn "bot backup FAILED — re-run wizard to retry"
                BOT_BACKUP=""
            fi
        else
            warn "Skipping bot backup."
            BOT_BACKUP=""
        fi

        if [[ -n "$LAPTOP_BACKUP" || -n "$BOT_BACKUP" ]]; then
            cat <<EOF

    ${BOLD}What to do with these files:${RST}

EOF
            [[ -n "$LAPTOP_BACKUP" ]] && cat <<EOF
    1. ${BOLD}$LAPTOP_BACKUP${RST}
       Copy to where you'd store an ordinary photo — cloud photos, USB,
       even a printed photo (re-scan to recover).

EOF
            [[ -n "$BOT_BACKUP" ]] && cat <<EOF
    2. ${BOLD}$BOT_BACKUP${RST}
       Copy to where you'd store a password-manager export — encrypted
       vault, hardware-encrypted USB. NOT the same cloud as the laptop
       backup.

EOF
            cat <<EOF
    3. ${BOLD}Your passphrase${RST}
       Write it down. Paper, metal, or a password manager you trust.
       Tell at least one trusted person where it lives, in case you can't.

EOF
        fi

        if [[ -z "$LAPTOP_BACKUP" || -z "$BOT_BACKUP" ]]; then
            warn "One or both backups are still missing. Run the wizard again any time to retry."
            hint "Manual fallback:"
            hint "  $CAMOUFLAGE_BIN embed --party laptop --cover any.png --out laptop-backup.png"
            hint "  $CAMOUFLAGE_BIN embed --party bot    --cover any.png --out bot-backup.png"
        fi
    else
        warn "Skipping backups — run frost-camouflage embed manually before you risk losing access"
        hint "  $CAMOUFLAGE_BIN embed --party laptop --cover any.png --out laptop-backup.png"
        hint "  $CAMOUFLAGE_BIN embed --party bot    --cover any.png --out bot-backup.png"
    fi
fi

# ── Phase 5: Smoke test ──────────────────────────────────────────────────────
say "Phase 5 — Smoke test (optional)"

cat <<EOF

    The smoke test signs a fake transaction end-to-end. You don't need
    any SOL. It proves the laptop ↔ bot ↔ Telegram round-trip works.

    Steps the test will walk you through:
      1. Starts the bot in the background
      2. Generates a test transaction
      3. You launch the TUI, paste the test tx, approve in Telegram
      4. Bot delivers the round-trip; TUI shows a real signed transaction
      5. Test ends — you exit the TUI

EOF

if ask_yes "Run the smoke test now" Y; then
    # Pre-check: is anything already on 127.0.0.1:7777?
    # Use `ss` (kernel netlink, instant, no timeout risk). Fallback to /dev/tcp
    # with a 2s timeout if ss isn't available.
    port_in_use() {
        if command -v ss &>/dev/null; then
            ss -tln 2>/dev/null | grep -qE '(127\.0\.0\.1|\*):7777[[:space:]]'
        else
            timeout 2 bash -c '(echo > /dev/tcp/127.0.0.1/7777) 2>/dev/null'
        fi
    }
    if port_in_use; then
        err "Port 127.0.0.1:7777 is already in use."
        err "Another bot process is bound there — most likely a leftover or a separate production bot."
        hint "Find it:"
        hint "  ss -tlnp 2>/dev/null | grep :7777"
        hint "  pgrep -af frost-bot"
        hint "Kill it (replace PID):"
        hint "  kill <PID>"
        warn "Skipping smoke test. Kill the conflicting process and re-run if you want it."
        # Set BOT_PID empty so the EXIT trap doesn't try to clean up something we never started.
        BOT_PID=""
    else

    # Start bot in background, capture PID. BOT_PID is read by the EXIT trap.
    say "Starting bot in background..."
    "$BOT_BIN" >/tmp/sov-bot.log 2>&1 &
    BOT_PID=$!

    # B10 — retry loop with visible progress so the wait doesn't look like a hang.
    # On slow WSL hosts, first-time Tokio init can take 2-5s; we poll up to 8s.
    BOT_READY=false
    printf "    waiting for bot to bind 127.0.0.1:7777 "
    for i in 1 2 3 4 5 6 7 8; do
        sleep 1
        printf "."
        if ! kill -0 "$BOT_PID" 2>/dev/null; then
            printf " [died]\n"
            break   # bot died, fall through to error path
        fi
        if port_in_use; then
            printf " [ready in ${i}s]\n"
            BOT_READY=true
            break
        fi
    done
    if ! $BOT_READY && kill -0 "$BOT_PID" 2>/dev/null; then
        printf " [timeout]\n"
    fi

    if ! kill -0 "$BOT_PID" 2>/dev/null; then
        err "bot failed to start; tail of /tmp/sov-bot.log:"
        tail -20 /tmp/sov-bot.log 2>/dev/null | sed 's/^/    /'
        BOT_PID=""   # so EXIT trap doesn't try to kill a dead pid
        warn "skipping smoke test"
    elif ! $BOT_READY; then
        warn "bot running (pid $BOT_PID) but port 7777 not accepting connections after 8s"
        warn "skipping smoke test — investigate /tmp/sov-bot.log"
    else
        ok "bot running (pid $BOT_PID), port 7777 listening"

        if [[ -n "$SOL_ADDR" ]]; then
            say "Generating a benign test transaction for $SOL_ADDR..."
            FIXTURES_FILE=$(mktemp)
            "$FIXTURES_BIN" "$SOL_ADDR" > "$FIXTURES_FILE" 2>&1 || warn "tx-fixtures had issues"
            # B3 — actual output format from tx-fixtures.rs print_fixture():
            #   <title>
            #   ────
            #    Expected: ...
            #
            #    N bytes → base64:
            #
            #   <BASE64>
            #
            # Find the first non-empty base64-looking line AFTER "→ base64:".
            FIRST_TX=$(awk '
                /→ base64:/ { found=1; next }
                found && /^[A-Za-z0-9+\/=]+$/ && length($0) > 40 { print; exit }
            ' "$FIXTURES_FILE")
            rm -f "$FIXTURES_FILE"
            if [[ -n "$FIRST_TX" ]]; then
                echo
                echo "    ${BOLD}Test transaction (base64) — paste this into the TUI's [s] screen:${RST}"
                echo
                printf '%s\n' "$FIRST_TX" | fold -w 60 -s | sed 's/^/      /'
                echo
            else
                warn "could not extract a fixture from tx-fixtures output"
                hint "run '$FIXTURES_BIN $SOL_ADDR' yourself to see options"
            fi
        else
            warn "no Solana address available — skipping fixture generation"
            hint "you can still test the TUI's empty-state flow"
        fi
        echo
        echo "    ${BOLD}Launching the TUI now.${RST} In the TUI:"
        echo "      1. Press ${BOLD}Enter${RST} on the FROST + Telegram backend"
        echo "      2. Press ${BOLD}s${RST} from Home, paste the transaction above"
        echo "      3. Press ${BOLD}Enter${RST} to inspect, ${BOLD}y${RST} to request signature"
        echo "      4. Tap ${BOLD}Approve${RST} in your Telegram chat with the bot"
        echo "      5. TUI shows the signed transaction"
        echo "      6. Press ${BOLD}q${RST} to quit when done"
        echo
        read -r -p "$(printf "${BOLD}Press Enter to launch the TUI...${RST}")" _
        VAULT_ARMOR_PATH="$ARMOR_BIN" "$TUI_BIN" || warn "TUI exited with non-zero status"

        # Clean up bot (EXIT trap will catch it too, but cleaner to do it here)
        if kill -0 "$BOT_PID" 2>/dev/null; then
            kill "$BOT_PID" 2>/dev/null
            wait "$BOT_PID" 2>/dev/null || true
            ok "bot stopped"
        fi
        BOT_PID=""
    fi
    fi   # close the port-check else
fi

# ── Phase S: Add to a Squads multisig (guided) ───────────────────────────────
say "Phase S — Add this vault to a Squads multisig (optional)"

if [[ -z "$SOL_ADDR" ]]; then
    warn "no Solana address captured — skipping Squads guidance"
    hint "Re-run the wizard or check your keystore to find it"
else
    cat <<EOF

    Your Sovereign OS Vault address is a standard Solana ed25519 address.
    To use it inside a Squads multisig, add it as a member from squads.so.

    ${BOLD}Your address (paste this into Squads):${RST}

        ${BOLD}${GRN}$SOL_ADDR${RST}

EOF

    # Optional ASCII QR for scanning the address from a phone
    if command -v qrencode &>/dev/null; then
        echo "    Scan-friendly QR (your address):"
        echo
        qrencode -t ANSIUTF8 "$SOL_ADDR" 2>/dev/null | sed 's/^/    /'
        echo
    else
        hint "Install 'qrencode' (apt install qrencode) to get a scannable QR here"
        echo
    fi

    cat <<EOF
    ${BOLD}Two common workflows:${RST}

    A) ${BOLD}Solo self-custody — your vault IS the multisig${RST}
       1. Open https://app.squads.so in your browser
       2. Click "Create Multisig"
       3. Paste the address above as the only member
       4. Set threshold = 1
       5. After creation, copy the URL from your browser bar OR the
          multisig settings address

    B) ${BOLD}Join an existing team multisig${RST}
       1. Send your address (above) to the multisig admin
       2. They propose adding you via Squads UI
       3. Other members approve
       4. They send you back the multisig URL or its settings address

    ${BOLD}Once you're in (either path), come back here and run:${RST}

        ${BOLD}sov --connect <paste-the-squads.so-URL>${RST}

    (You can also pass the raw multisig PDA. The launcher extracts
     the address from either form and saves it. From then on, just
     run 'sov' and the [m] proposal-watch screen will be active.)

EOF

    if $IS_WSL && command -v cmd.exe &>/dev/null; then
        if ask_yes "Open https://app.squads.so in your Windows browser now?" N; then
            (cd /mnt/c 2>/dev/null && cmd.exe /c start "https://app.squads.so" >/dev/null 2>&1) || \
                cmd.exe /c start "https://app.squads.so" >/dev/null 2>&1 || true
            ok "asked Windows to open https://app.squads.so"
        fi
    elif command -v xdg-open &>/dev/null; then
        if ask_yes "Open https://app.squads.so in your browser now?" N; then
            xdg-open "https://app.squads.so" >/dev/null 2>&1 &
            ok "asked your desktop to open https://app.squads.so"
        fi
    fi
fi

# ── Phase L: Install the `sov` launcher to PATH (optional) ───────────────────
say "Phase L — Install the 'sov' launcher (recommended)"

LAUNCHER="$PROJ/sov"

# Record whether we ran in a non-default XDG sandbox so 'sov' picks up
# the same keystore on subsequent runs. Production users don't set
# XDG_DATA_HOME → no sandbox line is written → sov uses defaults.
SOV_CFG_DIR="$HOME/.config/sovereign-os-vault"
SOV_CFG_FILE="$SOV_CFG_DIR/launcher.conf"
mkdir -p "$SOV_CFG_DIR"
chmod 700 "$SOV_CFG_DIR" 2>/dev/null || true

DEFAULT_XDG="$HOME/.local/share"
CURRENT_XDG="${XDG_DATA_HOME:-$DEFAULT_XDG}"

# Persist REPO and SANDBOX_XDG (only if non-default) into launcher.conf,
# preserving anything already there (e.g. SQUADS_MULTISIG).
{
    grep -v -E '^(REPO|SANDBOX_XDG)=' "$SOV_CFG_FILE" 2>/dev/null || true
    echo "REPO=\"$PROJ\""
    if [[ "$CURRENT_XDG" != "$DEFAULT_XDG" ]]; then
        echo "SANDBOX_XDG=\"$CURRENT_XDG\""
    fi
} > "$SOV_CFG_FILE.tmp"
mv "$SOV_CFG_FILE.tmp" "$SOV_CFG_FILE"
chmod 600 "$SOV_CFG_FILE"

if [[ "$CURRENT_XDG" != "$DEFAULT_XDG" ]]; then
    ok "recorded sandbox in launcher.conf: SANDBOX_XDG=$CURRENT_XDG"
    hint "'sov' will use this same sandbox from now on. Remove the SANDBOX_XDG line"
    hint "in $SOV_CFG_FILE to switch back to production paths."
fi

if [[ ! -x "$LAUNCHER" ]]; then
    warn "launcher not found at $LAUNCHER — skipping"
else
    chmod +x "$LAUNCHER"
    # Pick a target on PATH if possible
    PATH_DEST=""
    for cand in "$HOME/.local/bin" "$HOME/bin"; do
        if [[ -d "$cand" ]] && [[ ":$PATH:" == *":$cand:"* ]]; then
            PATH_DEST="$cand/sov"
            break
        fi
    done

    if [[ -z "$PATH_DEST" ]] && [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
        cat <<EOF

    ~/.local/bin is not on your PATH yet. Add this to your ~/.bashrc:
        export PATH="\$HOME/.local/bin:\$PATH"

    Then either open a new terminal, or:
        source ~/.bashrc

EOF
        if ask_yes "Add ~/.local/bin to PATH in ~/.bashrc now?" Y; then
            if ! grep -q '.local/bin' ~/.bashrc 2>/dev/null; then
                echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
                ok "added to ~/.bashrc"
            fi
            mkdir -p "$HOME/.local/bin"
            PATH_DEST="$HOME/.local/bin/sov"
            export PATH="$HOME/.local/bin:$PATH"
        fi
    fi

    if [[ -n "$PATH_DEST" ]]; then
        if [[ -L "$PATH_DEST" || -f "$PATH_DEST" ]]; then
            warn "$PATH_DEST already exists — leaving it alone"
            hint "If you want to point it at this repo: ln -sf $LAUNCHER $PATH_DEST"
        else
            ln -sf "$LAUNCHER" "$PATH_DEST"
            ok "symlinked $PATH_DEST → $LAUNCHER"
            ok "you can now run 'sov' from anywhere"
        fi
    else
        hint "Skipping symlink. You can still run the launcher with: $LAUNCHER"
    fi
fi

# ── Phase 6: Finish ──────────────────────────────────────────────────────────
banner "Setup complete"

cat <<EOF

  ${BOLD}Your Solana address:${RST}
EOF
if [[ -n "$SOL_ADDR" ]]; then
    echo "    ${BOLD}${GRN}$SOL_ADDR${RST}"
    echo "    ${DIM}Solscan: https://solscan.io/account/$SOL_ADDR${RST}"
else
    warn "could not derive address; re-run keygen output is in your terminal scrollback"
fi

# Pick the right command to print, based on whether the symlink installed
SOV_CMD="$PROJ/sov"
if command -v sov &>/dev/null && [[ "$(readlink -f "$(command -v sov)")" == "$LAUNCHER" ]]; then
    SOV_CMD="sov"
fi

cat <<EOF

  ${BOLD}Next time you want to use the vault, just run:${RST}

      ${BOLD}${GRN}$SOV_CMD${RST}

  That single command starts the bot in the background, launches the
  TUI, and shuts the bot down when you exit. No two-terminal dance.

  ${BOLD}To connect a Squads multisig${RST} (after you've added your address
  above as a member): paste either the squads.so URL or the multisig PDA:

      ${BOLD}$SOV_CMD --connect <squads.so-URL-or-PDA>${RST}

  From then on, '$SOV_CMD' will activate the [m] proposal-watch screen
  automatically. To see saved state at any time: '$SOV_CMD status'.

  ${BOLD}Back up your shares (if you skipped Phase B)${RST}:

      ${BOLD}$CAMOUFLAGE_BIN embed --party laptop --cover any.png --out laptop-backup.png${RST}
      ${BOLD}$CAMOUFLAGE_BIN embed --party bot    --cover any.png --out bot-backup.png${RST}

  ${BOLD}Funding the vault for mainnet:${RST} send a small amount of SOL to
  the address above (~0.01 SOL is plenty for testing broadcasts).

EOF
