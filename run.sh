#!/usr/bin/env bash
# Sovereign OS Vault — one-command setup + launch.
#
# This script is intentionally simple. If you can read bash, you can audit it.
#
# Steps:
#   1. Detect Zig + Rust toolchains; suggest install if missing.
#   2. Build the Zig hardening engine (vault-armor) — release, stripped.
#   3. Build the Rust TUI (sovereign-vault) — release.
#   4. Allow mlockall without sudo each run via a one-time setcap.
#   5. Launch.
#
# Idempotent: re-running is safe and only rebuilds what changed.

set -euo pipefail

PROJ="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJ"

# ── Colors ──────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    BOLD=$'\e[1m'; DIM=$'\e[2m'; CYAN=$'\e[36m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'; RED=$'\e[31m'; RESET=$'\e[0m'
else
    BOLD=''; DIM=''; CYAN=''; GREEN=''; YELLOW=''; RED=''; RESET=''
fi
say()   { printf "${CYAN}${BOLD}==>${RESET} %s\n" "$*"; }
ok()    { printf "    ${GREEN}✓${RESET} %s\n"  "$*"; }
warn()  { printf "    ${YELLOW}!${RESET} %s\n" "$*"; }
fail()  { printf "    ${RED}✗${RESET} %s\n"   "$*"; exit 1; }

# ── Refuse root ─────────────────────────────────────────────────────────────
if [[ $EUID -eq 0 ]]; then
    fail "do not run this script as root — root bypasses the kernel hardening this vault depends on"
fi

# ── Toolchain checks ────────────────────────────────────────────────────────
say "Toolchain"

if ! command -v zig &> /dev/null; then
    if [[ -x /snap/bin/zig ]]; then
        ZIG=/snap/bin/zig
    else
        fail "zig not found. Install: snap install zig --classic --beta   or see https://ziglang.org/download"
    fi
else
    ZIG=$(command -v zig)
fi
ok "zig:   $($ZIG version)"

if ! command -v cargo &> /dev/null; then
    if [[ -f "$HOME/.cargo/env" ]]; then
        # shellcheck disable=SC1091
        . "$HOME/.cargo/env"
    fi
fi
if ! command -v cargo &> /dev/null; then
    fail "cargo not found. Install: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
fi
ok "cargo: $(cargo --version)"

# ── Build Zig hardening engine ──────────────────────────────────────────────
say "Building Zig hardening engine"
$ZIG build -Doptimize=ReleaseSafe 2>&1 | sed 's/^/    /'
ok "vault-armor → $PROJ/zig-out/bin/vault-armor"

# ── Build Rust TUI ──────────────────────────────────────────────────────────
say "Building Rust TUI (release — first build pulls Solana SDK, ~3-5 min)"
(
    cd "$PROJ/tui"
    cargo build --release 2>&1 | sed 's/^/    /'
)
TUI_BIN="$PROJ/tui/target/release/sovereign-vault"
[[ -x $TUI_BIN ]] || fail "build failed — sovereign-vault binary not found"
ok "sovereign-vault → $TUI_BIN"

# ── Capability: mlockall without sudo ───────────────────────────────────────
say "Configuring mlock capability"
NEEDS_CAP=true
if command -v getcap &> /dev/null; then
    if getcap "$TUI_BIN" 2>/dev/null | grep -q "cap_ipc_lock"; then
        ok "cap_ipc_lock already set"
        NEEDS_CAP=false
    fi
fi
if $NEEDS_CAP; then
    warn "Granting cap_ipc_lock so mlockall works without sudo each run"
    if sudo setcap cap_ipc_lock=ep "$TUI_BIN"; then
        ok "cap_ipc_lock granted"
    else
        warn "could not setcap — vault will fail to lock memory unless run with sudo"
        warn "manual fix: sudo setcap cap_ipc_lock=ep $TUI_BIN"
    fi
fi

# ── Launch ──────────────────────────────────────────────────────────────────
say "Launching"
echo ""
echo "    ${DIM}⚠ MAINNET ONLY — every signed transaction targets Solana mainnet-beta${RESET}"
echo "    ${DIM}Local keystore: \$XDG_DATA_HOME/sovereign-os-vault/${RESET}"
echo "    ${DIM}Signed transactions: ~/.local/share/sovereign-os-vault/signed/${RESET}"
echo ""

VAULT_ARMOR_PATH="$PROJ/zig-out/bin/vault-armor" exec "$TUI_BIN"
