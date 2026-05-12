#!/usr/bin/env bash
# Print test transactions for the inspector.
#
# Usage:
#   ./scripts/fixtures.sh <your-mpc-pubkey>
#   ./scripts/fixtures.sh                       # uses the daemon's pubkey if running
set -euo pipefail
PROJ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$PROJ/tui/target/release/tx-fixtures"

if [[ ! -x "$BIN" ]]; then
    echo "Building tx-fixtures..."
    ( cd "$PROJ/tui" && . ~/.cargo/env 2>/dev/null; cargo build --release --bin tx-fixtures )
fi

# If no pubkey given, try the running daemon.
if [[ $# -eq 0 ]]; then
    if command -v vultisig &>/dev/null && [[ -S /tmp/vultisig.sock ]]; then
        PUBKEY=$(vultisig address --network sol 2>/dev/null | grep -oE '[1-9A-HJ-NP-Za-km-z]{32,44}' | head -1)
        if [[ -n "${PUBKEY:-}" ]]; then
            echo "Using daemon's Solana pubkey: $PUBKEY"
            exec "$BIN" "$PUBKEY"
        fi
    fi
    echo "Usage: $0 <your-mpc-pubkey>" >&2
    echo "       (or start vultisig daemon and run with no args)" >&2
    exit 2
fi

exec "$BIN" "$@"
