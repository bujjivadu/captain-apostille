#!/usr/bin/env bash
# One-time dev environment bootstrap.
# Idempotent: skips steps whose output files already exist.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APOSTILLE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MAST_ROOT="$(cd "$APOSTILLE_ROOT/../captain-mast" && pwd)"

LOCAL="$APOSTILLE_ROOT/.local"
CA_DIR="$LOCAL/ca"
CERTS_DIR="$LOCAL/certs"
CONFIG_DIR="$LOCAL/config"
DATA_DIR="$LOCAL/data"

APOSTILLE_BIN="$APOSTILLE_ROOT/target/debug/captain-apostille"
MAST_BIN="$MAST_ROOT/target/debug/captain-mast"

# ── Build ─────────────────────────────────────────────────────────────────────

echo "==> Building captain-apostille..."
(cd "$APOSTILLE_ROOT" && cargo build 2>&1)

echo "==> Building captain-mast..."
(cd "$MAST_ROOT" && cargo build 2>&1)

# ── Directory layout ──────────────────────────────────────────────────────────

mkdir -p \
  "$CA_DIR" \
  "$CERTS_DIR/broker" \
  "$CERTS_DIR/apostille" \
  "$CERTS_DIR/clients/test-client" \
  "$CONFIG_DIR" \
  "$DATA_DIR/mast"

# ── CA hierarchy ──────────────────────────────────────────────────────────────

if [[ -f "$CA_DIR/root.crt" ]]; then
  echo "==> CA already initialized – skipping."
else
  echo "==> Initializing CA hierarchy..."
  "$APOSTILLE_BIN" ca init \
    --out "$CA_DIR" \
    --cn  "Muca Dev Root CA" \
    --org "Muca Dev"
  echo "    root CA  : $CA_DIR/root.crt"
  echo "    inter CA : $CA_DIR/intermediate.crt"
fi

# CA bundle used as cafile in mast (root + intermediate so rustls can verify
# leaf certs signed by the intermediate without the client sending the chain).
cat "$CA_DIR/root.crt" "$CA_DIR/intermediate.crt" > "$CA_DIR/ca-bundle.crt"

# ── Apostille dev config (needed for the bootstrap subcommand) ────────────────

cat > "$CONFIG_DIR/apostille.conf" << CONF
ca_cert     $CA_DIR/intermediate.crt
ca_key      $CA_DIR/intermediate.key
ca_chain    $CA_DIR/root.crt

listen      127.0.0.1:8443
server_cert $CERTS_DIR/apostille/server.crt
server_key  $CERTS_DIR/apostille/server.key

# rumqttd extracts org_name as tenant ID and requires purely alphanumeric.
org_name                MucaDev
operational_ttl_days    365
bootstrap_ttl_hours     8760
CONF

# ── Broker TLS cert (signed by intermediate, SAN for localhost) ───────────────

if [[ -f "$CERTS_DIR/broker/broker.crt" ]]; then
  echo "==> Broker cert exists – skipping."
else
  echo "==> Generating broker certificate..."
  SAN_CNF=$(mktemp /tmp/broker-san.XXXXXX.cnf)
  # shellcheck disable=SC2064
  trap "rm -f '$SAN_CNF'" EXIT

  cat > "$SAN_CNF" << CNF
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
prompt = no
[req_distinguished_name]
CN = localhost
O  = Muca Dev
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
IP.1  = 127.0.0.1
CNF

  openssl genrsa -out "$CERTS_DIR/broker/broker.key" 2048 2>/dev/null
  openssl req -new \
    -key    "$CERTS_DIR/broker/broker.key" \
    -out    /tmp/broker.csr \
    -config "$SAN_CNF"
  openssl x509 -req \
    -in      /tmp/broker.csr \
    -CA      "$CA_DIR/intermediate.crt" \
    -CAkey   "$CA_DIR/intermediate.key" \
    -CAcreateserial \
    -out     "$CERTS_DIR/broker/broker.crt" \
    -days    365 \
    -extfile "$SAN_CNF" \
    -extensions v3_req 2>/dev/null
  rm -f /tmp/broker.csr "$CA_DIR/intermediate.srl"
  echo "    broker cert: $CERTS_DIR/broker/broker.crt"
fi

# ── Apostille server cert (for the EST serve endpoint) ───────────────────────

if [[ -f "$CERTS_DIR/apostille/server.crt" ]]; then
  echo "==> Apostille server cert exists – skipping."
else
  echo "==> Generating apostille server certificate..."
  SAN_CNF=$(mktemp /tmp/apostille-san.XXXXXX.cnf)
  cat > "$SAN_CNF" << CNF
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
prompt = no
[req_distinguished_name]
CN = localhost
O  = Muca Dev
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
IP.1  = 127.0.0.1
CNF

  openssl genrsa -out "$CERTS_DIR/apostille/server.key" 2048 2>/dev/null
  openssl req -new \
    -key    "$CERTS_DIR/apostille/server.key" \
    -out    /tmp/apostille.csr \
    -config "$SAN_CNF"
  openssl x509 -req \
    -in      /tmp/apostille.csr \
    -CA      "$CA_DIR/intermediate.crt" \
    -CAkey   "$CA_DIR/intermediate.key" \
    -CAcreateserial \
    -out     "$CERTS_DIR/apostille/server.crt" \
    -days    365 \
    -extfile "$SAN_CNF" \
    -extensions v3_req 2>/dev/null
  rm -f /tmp/apostille.csr "$CA_DIR/intermediate.srl"
  echo "    apostille cert: $CERTS_DIR/apostille/server.crt"
fi

# ── Test client cert (via captain-apostille bootstrap) ───────────────────────

CLIENT_DIR="$CERTS_DIR/clients/test-client"
if [[ -f "$CLIENT_DIR/bootstrap.crt" ]]; then
  echo "==> Test client cert exists – skipping."
else
  echo "==> Issuing test client certificate..."
  "$APOSTILLE_BIN" --config "$CONFIG_DIR/apostille.conf" ca bootstrap \
    --device-id test-client \
    --out       "$CLIENT_DIR" \
    --ttl-hours 8760
  echo "    client cert: $CLIENT_DIR/bootstrap.crt"
fi

# ── Captain-mast dev config ───────────────────────────────────────────────────

cat > "$CONFIG_DIR/mast.conf" << CONF
# captain-mast dev config – generated by scripts/dev-setup.sh

listener 8883
cafile              $CA_DIR/ca-bundle.crt
certfile            $CERTS_DIR/broker/broker.crt
keyfile             $CERTS_DIR/broker/broker.key
require_certificate true

# Dev: allow cert-only auth (no username/password required).
# Switch to false and add password_file for production-style testing.
allow_anonymous true

log_level info
log_dest  stdout

persistence true
persistence_location $DATA_DIR/mast/

max_connections -1
max_inflight_messages 20
max_queued_messages 1000

hf_enabled false
CONF

# ── Done ──────────────────────────────────────────────────────────────────────

echo ""
echo "==> Dev environment ready."
echo ""
echo "Run both services:"
echo "  scripts/dev-run.sh"
echo ""
echo "Or just the broker:"
echo "  RUST_LOG=info $MAST_BIN --config $CONFIG_DIR/mast.conf"
echo ""
echo "Test publish (in another terminal):"
echo "  mosquitto_pub -h localhost -p 8883 \\"
echo "    --cafile $CA_DIR/ca-bundle.crt \\"
echo "    --cert   $CLIENT_DIR/bootstrap.crt \\"
echo "    --key    $CLIENT_DIR/bootstrap.key \\"
echo "    -t test/hello -m world"
echo ""
echo "Test subscribe:"
echo "  mosquitto_sub -h localhost -p 8883 \\"
echo "    --cafile $CA_DIR/ca-bundle.crt \\"
echo "    --cert   $CLIENT_DIR/bootstrap.crt \\"
echo "    --key    $CLIENT_DIR/bootstrap.key \\"
echo "    -t test/#"
