#!/usr/bin/env bash
# Deploy captain-apostille and captain-mast to a fresh Ubuntu EC2 instance.
#
# Run from your LOCAL machine (not on the instance):
#   bash deploy/ec2-install.sh
#
# The script SSHes into the instance for you via the remote() helper.
# Prerequisites locally: SSH key for ubuntu@$EC2_IP, built binaries in
#   target/release/ for both captain-apostille and captain-mast.
# Prerequisites on the instance: nothing (script installs all deps).
set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────

EC2_IP="${EC2_IP:-100.22.65.93}"
EC2_KEY="${EC2_KEY:-$HOME/.ssh/captain-key-pai.pem}"
APOSTILLE_DOMAIN="${APOSTILLE_DOMAIN:-ca.mucalabs.io}"    # TLS endpoint for captain-apostille
MQTT_DOMAIN="${MQTT_DOMAIN:-mqtt.mucalabs.io}"            # SNI hostname for captain-mast broker

if [[ -z "$EC2_IP" ]]; then
  echo "ERROR: set EC2_IP=<instance-ip>" >&2
  exit 1
fi

if [[ ! -f "$EC2_KEY" ]]; then
  echo "ERROR: SSH key not found at $EC2_KEY (override with EC2_KEY=<path>)" >&2
  exit 1
fi

# ── Helpers ───────────────────────────────────────────────────────────────────

# Run a sudo bash heredoc on the remote host.
remote() { ssh -i "$EC2_KEY" -o StrictHostKeyChecking=accept-new "ubuntu@$EC2_IP" sudo "$@"; }

# Upload a file to /tmp on the remote host, then sudo mv it to its final path.
# Usage: scp_to <local-src> <remote-dest>
scp_to() {
  local src="$1" dest="$2" base
  base="$(basename "$src")"
  scp -i "$EC2_KEY" -o StrictHostKeyChecking=accept-new "$src" "ubuntu@$EC2_IP:/tmp/$base"
  remote mv "/tmp/$base" "$dest"
}

# ── 1. Install system dependencies ───────────────────────────────────────────

echo "==> Installing system dependencies..."
remote bash -s << 'REMOTE'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends \
  openssl curl ca-certificates mosquitto-clients \
  certbot python3-certbot-dns-route53
REMOTE

# ── 2. Create users and directories ──────────────────────────────────────────

echo "==> Creating users and directories..."
remote bash -s << 'REMOTE'
set -euo pipefail

for svc in captain-apostille captain-mast; do
  id "$svc" &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin "$svc"
done

install -d -o captain-apostille -g captain-apostille -m 750 \
  /etc/captain-apostille/ca \
  /var/lib/captain-apostille

install -d -o captain-mast -g captain-mast -m 750 \
  /etc/captain-mast/certs \
  /var/lib/captain-mast
REMOTE

# ── 3. Upload binaries ────────────────────────────────────────────────────────

echo "==> Uploading binaries..."
APOSTILLE_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MAST_ROOT="$(cd "$APOSTILLE_ROOT/../captain-mast" && pwd)"

scp_to "$APOSTILLE_ROOT/target/x86_64-unknown-linux-gnu/release/captain-apostille" /usr/local/bin/captain-apostille
scp_to "$MAST_ROOT/target/x86_64-unknown-linux-gnu/release/captain-mast"           /usr/local/bin/captain-mast

remote bash -s << 'REMOTE'
chmod 755 /usr/local/bin/captain-apostille /usr/local/bin/captain-mast
REMOTE

# ── 4. Upload production configs ──────────────────────────────────────────────

echo "==> Uploading configs..."
scp_to "$APOSTILLE_ROOT/deploy/config/apostille.conf" /etc/captain-apostille/apostille.conf
scp_to "$APOSTILLE_ROOT/deploy/config/mast.conf"      /etc/captain-mast/mast.conf

# ── 5. Upload CA certificates ─────────────────────────────────────────────────

echo "==> Uploading CA certificates..."
# Never upload root.key to the server — intermediate.key is enough to sign.
LOCAL="$APOSTILLE_ROOT/.local"

scp_to "$LOCAL/ca/intermediate.crt" /etc/captain-apostille/ca/intermediate.crt
scp_to "$LOCAL/ca/intermediate.key" /etc/captain-apostille/ca/intermediate.key
scp_to "$LOCAL/ca/root.crt"         /etc/captain-apostille/ca/root.crt
scp_to "$LOCAL/ca/ca-bundle.crt"    /etc/captain-apostille/ca/ca-bundle.crt

remote bash -s << 'REMOTE'
chown -R captain-apostille:captain-apostille /etc/captain-apostille
chmod 640 /etc/captain-apostille/ca/intermediate.key
# Let captain-mast read the CA bundle for mTLS verification.
# Copy ca-bundle into mast's certs dir (symlink won't work: /etc/captain-apostille/ca/ is 750)
cp /etc/captain-apostille/ca/ca-bundle.crt /etc/captain-mast/certs/ca-bundle.crt
chown -R captain-mast:captain-mast /etc/captain-mast
# Create empty passwd/acl files so captain-mast can start before any users are added.
touch /etc/captain-mast/passwd /etc/captain-mast/acl
chown captain-mast:captain-mast /etc/captain-mast/passwd /etc/captain-mast/acl
chmod 640 /etc/captain-mast/passwd
REMOTE

# ── 6. Generate broker cert on the server (SAN = mqtt.mucalabs.io) ───────────

echo "==> Generating broker cert..."
remote bash -s << REMOTE
set -euo pipefail
SAN_CNF=\$(mktemp)
cat > "\$SAN_CNF" << CNF
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
prompt = no
[req_distinguished_name]
CN = $MQTT_DOMAIN
O  = Muca Labs
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = $MQTT_DOMAIN
IP.1  = $EC2_IP
CNF

openssl genrsa -out /etc/captain-mast/certs/broker.key 2048 2>/dev/null
openssl req -new \
  -key    /etc/captain-mast/certs/broker.key \
  -out    /tmp/broker.csr \
  -config "\$SAN_CNF"
openssl x509 -req \
  -in      /tmp/broker.csr \
  -CA      /etc/captain-apostille/ca/intermediate.crt \
  -CAkey   /etc/captain-apostille/ca/intermediate.key \
  -CAcreateserial \
  -out     /etc/captain-mast/certs/broker.crt \
  -days    365 \
  -extfile "\$SAN_CNF" \
  -extensions v3_req 2>/dev/null

chmod 640 /etc/captain-mast/certs/broker.key
chown -R captain-mast:captain-mast /etc/captain-mast
rm -f "\$SAN_CNF" /tmp/broker.csr
REMOTE

# ── 7. Provision Let's Encrypt cert for captain-apostille ────────────────────
#
# Uses --standalone (certbot binds :80 directly). Port 80 must be reachable
# and nothing else should be listening on it.

echo "==> Provisioning Let's Encrypt cert for $APOSTILLE_DOMAIN..."
remote bash -s << REMOTE
set -euo pipefail
certbot certonly \
  --dns-route53 \
  --non-interactive \
  --agree-tos \
  --register-unsafely-without-email \
  -d $APOSTILLE_DOMAIN

# Symlink live LE certs into apostille config dir.
ln -sf /etc/letsencrypt/live/$APOSTILLE_DOMAIN/fullchain.pem \
       /etc/captain-apostille/server.crt
ln -sf /etc/letsencrypt/live/$APOSTILLE_DOMAIN/privkey.pem \
       /etc/captain-apostille/server.key
chown -h captain-apostille:captain-apostille \
  /etc/captain-apostille/server.crt \
  /etc/captain-apostille/server.key

# Grant captain-apostille read access to the LE cert dirs (live/ contains
# symlinks into archive/, so both need group read).
chgrp -R captain-apostille \
  /etc/letsencrypt/live/$APOSTILLE_DOMAIN \
  /etc/letsencrypt/archive/$APOSTILLE_DOMAIN
chmod -R g+rX \
  /etc/letsencrypt/live/$APOSTILLE_DOMAIN \
  /etc/letsencrypt/archive/$APOSTILLE_DOMAIN
# Allow traversal of the parent letsencrypt dirs (they default to 700).
chmod o+x /etc/letsencrypt/live /etc/letsencrypt/archive

# Restart apostille automatically on cert renewal.
cat > /etc/letsencrypt/renewal-hooks/deploy/restart-apostille.sh << 'HOOK'
#!/bin/bash
systemctl restart captain-apostille
HOOK
chmod +x /etc/letsencrypt/renewal-hooks/deploy/restart-apostille.sh
REMOTE

# ── 8. Install and start systemd units ───────────────────────────────────────

echo "==> Installing systemd units..."
scp_to "$APOSTILLE_ROOT/deploy/captain-apostille.service" /etc/systemd/system/captain-apostille.service
scp_to "$APOSTILLE_ROOT/deploy/captain-mast.service"      /etc/systemd/system/captain-mast.service

remote bash -s << 'REMOTE'
systemctl daemon-reload
systemctl enable captain-mast captain-apostille
systemctl restart captain-mast captain-apostille
sleep 2
systemctl status captain-mast --no-pager
systemctl status captain-apostille --no-pager
REMOTE

echo ""
echo "==> Deployment complete."
echo ""
echo "  ca endpoint  : https://$APOSTILLE_DOMAIN:8443"
echo "  mqtt broker  : mqtts://$MQTT_DOMAIN:8883"
echo ""
echo "Add an MQTT password:"
echo "  ssh -i $EC2_KEY ubuntu@$EC2_IP"
echo "  sudo -u captain-mast captain-mast --config /etc/captain-mast/mast.conf passwd set <USERNAME>"
