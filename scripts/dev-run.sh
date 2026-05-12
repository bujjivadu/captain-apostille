#!/usr/bin/env bash
# Start captain-apostille (EST enrollment) and captain-mast (MQTT broker) for dev.
# Ctrl-C stops both.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APOSTILLE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MAST_ROOT="$(cd "$APOSTILLE_ROOT/../captain-mast" && pwd)"

LOCAL="$APOSTILLE_ROOT/.local"
CONFIG_DIR="$LOCAL/config"

APOSTILLE_BIN="$APOSTILLE_ROOT/target/debug/captain-apostille"
MAST_BIN="$MAST_ROOT/target/debug/captain-mast"

for bin in "$APOSTILLE_BIN" "$MAST_BIN"; do
  if [[ ! -x "$bin" ]]; then
    echo "ERROR: $bin not found – run scripts/dev-setup.sh first" >&2
    exit 1
  fi
done

cleanup() {
  echo ""
  echo "==> Shutting down..."
  kill "$MAST_PID" "$APOSTILLE_PID" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "==> Starting captain-mast (MQTT broker)..."
RUST_LOG="${RUST_LOG:-info}" "$MAST_BIN" --config "$CONFIG_DIR/mast.conf" &
MAST_PID=$!

echo "==> Starting captain-apostille (EST enrollment server)..."
RUST_LOG="${RUST_LOG:-info}" "$APOSTILLE_BIN" --config "$CONFIG_DIR/apostille.conf" serve &
APOSTILLE_PID=$!

echo ""
echo "captain-mast   : mqtt+tls://127.0.0.1:8883  (PID $MAST_PID)"
echo "captain-apostille: https://127.0.0.1:8443    (PID $APOSTILLE_PID)"
echo ""
echo "Ctrl-C to stop both."
wait
