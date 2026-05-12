#!/usr/bin/env bash
# register-client.sh — provision a new device in captain-apostille and captain-mast.
#
# Usage:
#   scripts/register-client.sh <device-id> [mqtt-password]
#
# Outputs artifacts to clients/<device-id>/:
#   bootstrap.crt      — short-lived cert for one-time enrollment with apostille
#   bootstrap.key      — private key for the bootstrap cert
#   ca-chain.crt       — root + intermediate CA bundle (verify both services)
#   connection.env     — DEVICE_ID, MQTT_PASSWORD, endpoint URLs
#
# The device uses bootstrap.crt to enroll with captain-apostille and receive
# an operational cert.  It then connects to captain-mast with the operational
# cert + the password from connection.env.
set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

EC2_IP="${EC2_IP:-100.22.65.93}"
EC2_KEY="${EC2_KEY:-$HOME/.ssh/captain-key-pai.pem}"
APOSTILLE_DOMAIN="${APOSTILLE_DOMAIN:-ca.mucalabs.io}"
MQTT_DOMAIN="${MQTT_DOMAIN:-mqtt.mucalabs.io}"

# ── Args ──────────────────────────────────────────────────────────────────────

DEVICE_ID="${1:-}"
if [[ -z "$DEVICE_ID" ]]; then
  echo "Usage: $0 <device-id> [mqtt-password]" >&2
  exit 1
fi

# rumqttd requires an alphanumeric tenant ID (the cert's O field).
if [[ ! "$DEVICE_ID" =~ ^[A-Za-z0-9_-]+$ ]]; then
  echo "ERROR: device-id must be alphanumeric (hyphens and underscores OK): '$DEVICE_ID'" >&2
  exit 1
fi

# Auto-generate a password if not provided.
MQTT_PASSWORD="${2:-$(openssl rand -base64 18 | tr -d '+/=\n' | head -c 24)}"

OUT_DIR="$REPO_ROOT/clients/$DEVICE_ID"
mkdir -p "$OUT_DIR"

# ── Helpers ───────────────────────────────────────────────────────────────────

remote_sudo() {
  ssh -i "$EC2_KEY" -T -o StrictHostKeyChecking=accept-new "ubuntu@$EC2_IP" sudo "$@"
}
scp_from() {
  scp -i "$EC2_KEY" -o StrictHostKeyChecking=accept-new "ubuntu@$EC2_IP:$1" "$2"
}

# ── 1. Issue bootstrap cert on the server ────────────────────────────────────

echo "==> Issuing bootstrap cert for '$DEVICE_ID'..."
remote_sudo bash -s << REMOTE
set -euo pipefail
cd /tmp
captain-apostille --config /etc/captain-apostille/apostille.conf \
  ca bootstrap --device-id "$DEVICE_ID"
chmod 644 /tmp/bootstrap.crt /tmp/bootstrap.key /tmp/ca-chain.crt
REMOTE

scp_from /tmp/bootstrap.crt  "$OUT_DIR/bootstrap.crt"
scp_from /tmp/bootstrap.key  "$OUT_DIR/bootstrap.key"
scp_from /tmp/ca-chain.crt   "$OUT_DIR/ca-chain.crt"

# Clean up temp files on server
remote_sudo rm -f /tmp/bootstrap.crt /tmp/bootstrap.key /tmp/ca-chain.crt

chmod 600 "$OUT_DIR/bootstrap.key"

# ── 2. Register MQTT user in captain-mast ────────────────────────────────────

echo "==> Registering MQTT user '$DEVICE_ID'..."
remote_sudo -u captain-mast captain-mast \
  --config /etc/captain-mast/mast.conf passwd set "$DEVICE_ID" --password "$MQTT_PASSWORD"

# ── 3. Verify ca-chain.crt against the live endpoint ─────────────────────────

echo "==> Fetching CA chain from enrollment endpoint..."
curl -sf "https://$APOSTILLE_DOMAIN:8443/.well-known/est/cacerts" \
  -o "$OUT_DIR/ca-chain.crt"

# ── 4. Write connection manifest ──────────────────────────────────────────────

cat > "$OUT_DIR/connection.env" << EOF
DEVICE_ID=$DEVICE_ID
MQTT_USERNAME=$DEVICE_ID
MQTT_PASSWORD=$MQTT_PASSWORD
APOSTILLE_URL=https://$APOSTILLE_DOMAIN:8443
MQTT_URL=mqtts://$MQTT_DOMAIN:8883
EOF
chmod 600 "$OUT_DIR/connection.env"

# ── 5. Write enrollment instructions ─────────────────────────────────────────

cat > "$OUT_DIR/README.txt" << EOF
Device : $DEVICE_ID
Created: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 1 — FLASH THESE FILES ONTO THE DEVICE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Copy the following three files to the device filesystem before first boot.
Suggested paths (adjust to your platform):

  File            This dir         → Device path
  ────────────    ──────────────── ──────────────────────────────
  bootstrap.crt   bootstrap.crt   → /certs/bootstrap.crt
  bootstrap.key   bootstrap.key   → /certs/bootstrap.key
  ca-chain.crt    ca-chain.crt    → /certs/ca-chain.crt

  • Linux / Raspberry Pi : copy to any path, update the commands below.
  • ESP32 (SPIFFS/LittleFS): upload via idf.py or the Arduino filesystem uploader.
  • Embedded C / Rust     : embed as const byte arrays or read from flash.

  ⚠  bootstrap.crt expires in 24 hours — enroll before it lapses.
  ⚠  Never share bootstrap.key outside the device.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 2 — ENROLL (run once at first boot)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
The device calls captain-apostille to swap the bootstrap cert for a
long-lived operational cert signed by the same CA.

  # Generate the device's permanent key pair
  openssl genrsa -out /certs/operational.key 2048

  # Build a CSR  (O= must be alphanumeric — no spaces)
  openssl req -new -key /certs/operational.key \\
    -subj "/CN=$DEVICE_ID/O=MucaLabs" \\
    -out /tmp/device.csr

  # POST the CSR to captain-apostille using the bootstrap cert as auth
  curl https://$APOSTILLE_DOMAIN:8443/.well-known/est/simpleenroll \\
    --cacert /certs/ca-chain.crt \\
    --cert   /certs/bootstrap.crt \\
    --key    /certs/bootstrap.key \\
    --data-binary @/tmp/device.csr \\
    -H "Content-Type: application/pkcs10" \\
    -o /tmp/enroll.json

  # Extract and store the operational cert
  python3 -c "import json; print(json.load(open('/tmp/enroll.json'))['certificate'])" \\
    > /certs/operational.crt

  # Clean up — bootstrap material no longer needed
  rm /certs/bootstrap.crt /certs/bootstrap.key /tmp/device.csr /tmp/enroll.json

After enrollment the device holds:
  /certs/ca-chain.crt       ← keep forever (verify broker TLS)
  /certs/operational.crt    ← keep (renew annually via /simplereenroll)
  /certs/operational.key    ← keep secret

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 3 — CONNECT TO CAPTAIN-MAST (broker)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Authentication requires BOTH the operational cert (mTLS) AND the
MQTT username/password from connection.env.

  MQTT broker : $MQTT_DOMAIN:8883
  Username    : $DEVICE_ID
  Password    : (see connection.env — keep secret)

  mosquitto_pub -h $MQTT_DOMAIN -p 8883 \\
    --cafile /certs/ca-chain.crt \\
    --cert   /certs/operational.crt \\
    --key    /certs/operational.key \\
    -u "$DEVICE_ID" -P "<password from connection.env>" \\
    -t "devices/$DEVICE_ID/data" -m "hello"

  For embedded clients (Paho, esp-mqtt, rumqttc):
    ca_file        = /certs/ca-chain.crt
    client_cert    = /certs/operational.crt
    client_key     = /certs/operational.key
    mqtt_username  = $DEVICE_ID
    mqtt_password  = <from connection.env>
    host           = $MQTT_DOMAIN
    port           = 8883
    tls_version    = TLSv1.2 or TLSv1.3

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CERT RENEWAL (when operational.crt expires)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  openssl req -new -key /certs/operational.key \\
    -subj "/CN=$DEVICE_ID/O=MucaLabs" -out /tmp/renew.csr

  curl https://$APOSTILLE_DOMAIN:8443/.well-known/est/simplereenroll \\
    --cacert /certs/ca-chain.crt \\
    --cert   /certs/operational.crt \\
    --key    /certs/operational.key \\
    --data-binary @/tmp/renew.csr \\
    -H "Content-Type: application/pkcs10" \\
    -o /tmp/renew.json

  python3 -c "import json; print(json.load(open('/tmp/renew.json'))['certificate'])" \\
    > /certs/operational.crt
EOF

# ── Done ──────────────────────────────────────────────────────────────────────

echo ""
echo "==> Client '$DEVICE_ID' registered."
echo ""
echo "    Artifacts : $OUT_DIR/"
echo "    Bootstrap : valid 24 hours — load onto device and enroll promptly"
echo "    MQTT user : $DEVICE_ID"
echo "    Password  : $MQTT_PASSWORD"
echo ""
echo "    See $OUT_DIR/README.txt for enrollment steps."
