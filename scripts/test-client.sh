#!/usr/bin/env bash
# test-client.sh — smoke-test a registered device end-to-end.
#
# Usage:
#   scripts/test-client.sh <device-id>
#
# What it does:
#   1. Reads artifacts from clients/<device-id>/
#   2. Generates an operational key + CSR (if not already present)
#   3. Enrolls with captain-apostille → receives operational.crt
#   4. Publishes a test message to captain-mast
#   5. Verifies the message was received via mosquitto_sub
#
# Prerequisites (on this Mac):
#   • openssl      — brew install openssl
#   • curl         — built-in (macOS)
#   • mosquitto    — brew install mosquitto
#   • python3      — built-in (macOS) or brew install python
#
# The device-id directory must already exist (run register-client.sh first).
set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

APOSTILLE_DOMAIN="${APOSTILLE_DOMAIN:-ca.mucalabs.io}"
MQTT_DOMAIN="${MQTT_DOMAIN:-mqtt.mucalabs.io}"

# ── Args ──────────────────────────────────────────────────────────────────────

DEVICE_ID="${1:-}"
if [[ -z "$DEVICE_ID" ]]; then
  echo "Usage: $0 <device-id>" >&2
  exit 1
fi

OUT_DIR="$REPO_ROOT/clients/$DEVICE_ID"
if [[ ! -d "$OUT_DIR" ]]; then
  echo "ERROR: No artifact directory for '$DEVICE_ID'. Run register-client.sh first." >&2
  exit 1
fi

for f in bootstrap.crt bootstrap.key ca-chain.crt connection.env; do
  if [[ ! -f "$OUT_DIR/$f" ]]; then
    echo "ERROR: Missing $f in $OUT_DIR — re-run register-client.sh." >&2
    exit 1
  fi
done

# ── Check prerequisites ───────────────────────────────────────────────────────

missing=()
for cmd in openssl curl python3 mosquitto_pub mosquitto_sub; do
  command -v "$cmd" &>/dev/null || missing+=("$cmd")
done
if [[ ${#missing[@]} -gt 0 ]]; then
  echo "ERROR: Missing required tools: ${missing[*]}" >&2
  echo "       Install with: brew install openssl mosquitto" >&2
  exit 1
fi

# Source credentials
# shellcheck disable=SC1090
source "$OUT_DIR/connection.env"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  captain-mast / captain-apostille connectivity test          ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Device   : $DEVICE_ID"
echo "║  Artifacts: $OUT_DIR/"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ── Step 1: Generate operational key (idempotent) ─────────────────────────────

if [[ -f "$OUT_DIR/operational.key" ]]; then
  echo "==> Operational key already exists — skipping keygen"
else
  echo "==> Generating operational key pair..."
  openssl genrsa -out "$OUT_DIR/operational.key" 2048 2>/dev/null
  chmod 600 "$OUT_DIR/operational.key"
  echo "    operational.key generated"
fi

# ── Step 2: Generate CSR ──────────────────────────────────────────────────────

echo "==> Building CSR for '$DEVICE_ID'..."
openssl req -new \
  -key "$OUT_DIR/operational.key" \
  -subj "/CN=$DEVICE_ID/O=MucaLabs" \
  -out "$OUT_DIR/device.csr" 2>/dev/null
echo "    CSR ready"

# ── Step 3: Enroll with captain-apostille ─────────────────────────────────────

echo "==> Enrolling with captain-apostille at $APOSTILLE_URL ..."

HTTP_STATUS=$(curl -s -w "%{http_code}" \
  --cacert  "$OUT_DIR/ca-chain.crt" \
  --cert    "$OUT_DIR/bootstrap.crt" \
  --key     "$OUT_DIR/bootstrap.key" \
  --data-binary @"$OUT_DIR/device.csr" \
  -H "Content-Type: application/pkcs10" \
  -o "$OUT_DIR/enroll.json" \
  "$APOSTILLE_URL/.well-known/est/simpleenroll")

if [[ "$HTTP_STATUS" != "200" ]]; then
  echo ""
  echo "ERROR: Enrollment failed (HTTP $HTTP_STATUS)." >&2
  if [[ -f "$OUT_DIR/enroll.json" ]]; then
    echo "       Server response:" >&2
    cat "$OUT_DIR/enroll.json" >&2
  fi
  echo ""
  echo "Possible causes:" >&2
  echo "  • Bootstrap cert expired (24h TTL) — re-run register-client.sh" >&2
  echo "  • captain-apostille not running — SSH to captain-club and check 'systemctl status captain-apostille'" >&2
  exit 1
fi

# Extract the PEM cert from the JSON response
python3 -c "
import json, sys
try:
    data = json.load(open('$OUT_DIR/enroll.json'))
    print(data['certificate'])
except Exception as e:
    print(f'ERROR parsing enroll.json: {e}', file=sys.stderr)
    sys.exit(1)
" > "$OUT_DIR/operational.crt"

echo "    Operational cert received and saved to operational.crt"

# Clean up bootstrap material and CSR
rm -f "$OUT_DIR/device.csr" "$OUT_DIR/enroll.json"
rm -f "$OUT_DIR/bootstrap.crt" "$OUT_DIR/bootstrap.key"
echo "    Bootstrap material removed"

# ── Step 4: Pub/sub loopback test ─────────────────────────────────────────────

TEST_TOPIC="devices/$DEVICE_ID/test"
TEST_MESSAGE="captain-mast-test-$(date -u +%s)"
SUB_LOG=$(mktemp)
SUB_PID=""

cleanup() {
  [[ -n "$SUB_PID" ]] && kill "$SUB_PID" 2>/dev/null || true
  rm -f "$SUB_LOG"
}
trap cleanup EXIT

echo ""
echo "==> Starting subscriber on topic '$TEST_TOPIC'..."
mosquitto_sub \
  -h "$MQTT_DOMAIN" -p 8883 \
  --cafile "$OUT_DIR/ca-chain.crt" \
  --cert   "$OUT_DIR/operational.crt" \
  --key    "$OUT_DIR/operational.key" \
  -u "$MQTT_USERNAME" -P "$MQTT_PASSWORD" \
  -t "$TEST_TOPIC" \
  -C 1 \
  > "$SUB_LOG" 2>&1 &
SUB_PID=$!

# Give the subscriber a moment to connect
sleep 2

echo "==> Publishing test message..."
mosquitto_pub \
  -h "$MQTT_DOMAIN" -p 8883 \
  --cafile "$OUT_DIR/ca-chain.crt" \
  --cert   "$OUT_DIR/operational.crt" \
  --key    "$OUT_DIR/operational.key" \
  -u "$MQTT_USERNAME" -P "$MQTT_PASSWORD" \
  -t "$TEST_TOPIC" \
  -m "$TEST_MESSAGE"

# Wait for the subscriber to receive the message (up to 10s)
for i in $(seq 1 10); do
  if grep -qF "$TEST_MESSAGE" "$SUB_LOG" 2>/dev/null; then
    break
  fi
  sleep 1
done

# ── Step 5: Result ────────────────────────────────────────────────────────────

echo ""
if grep -qF "$TEST_MESSAGE" "$SUB_LOG" 2>/dev/null; then
  RECEIVED=$(cat "$SUB_LOG")
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║  ✓  TEST PASSED                                              ║"
  echo "╠══════════════════════════════════════════════════════════════╣"
  echo "║  Topic   : $TEST_TOPIC"
  echo "║  Message : $RECEIVED"
  echo "║"
  echo "║  Device '$DEVICE_ID' is fully enrolled and connected."
  echo "╚══════════════════════════════════════════════════════════════╝"
else
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║  ✗  TEST FAILED — message not received                       ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo ""
  echo "Subscriber output:" >&2
  cat "$SUB_LOG" >&2
  echo ""
  echo "Troubleshooting:" >&2
  echo "  • Check captain-mast is running: ssh ubuntu@100.22.65.93 sudo systemctl status captain-mast" >&2
  echo "  • Check MQTT password in $OUT_DIR/connection.env" >&2
  echo "  • Check operational cert: openssl x509 -in $OUT_DIR/operational.crt -noout -text" >&2
  exit 1
fi

echo ""
echo "    Operational artifacts in: $OUT_DIR/"
echo "    Hand the following files to the device owner:"
echo "      • operational.crt  (device identity cert)"
echo "      • operational.key  (device private key — keep secret)"
echo "      • ca-chain.crt     (CA bundle — verify broker TLS)"
echo "      • connection.env   (broker URL + MQTT credentials)"
echo "      • README.txt       (setup and connection instructions)"
echo ""
