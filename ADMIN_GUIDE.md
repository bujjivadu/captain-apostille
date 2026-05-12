# Captain-Club Admin Guide

Operational runbook for provisioning IoT devices onto the **captain-apostille** (CA / enrollment) and **captain-mast** (MQTT broker) infrastructure.

---

## Infrastructure overview

| Service | Host | Port | Purpose |
|---|---|---|---|
| captain-apostille | ca.mucalabs.io | 8443 | Issues device certs via EST (RFC 7030) |
| captain-mast | mqtt.mucalabs.io | 8883 | MQTT broker; requires mTLS + password |
| captain-club (EC2) | 100.22.65.93 | — | Runs both services |

Devices authenticate with **two factors**:
1. An operational TLS client certificate issued by the captain-apostille CA
2. An MQTT username/password stored in the captain-mast password file

---

## Admin prerequisites

The admin workstation (your Mac) needs:

| Tool | Install |
|---|---|
| `openssl` | `brew install openssl` |
| `curl` | built-in |
| `mosquitto` (pub + sub) | `brew install mosquitto` |
| `python3` | built-in (macOS ≥ 12) or `brew install python` |
| SSH key for captain-club | `~/.ssh/captain-key-pai.pem` |
| AWS credentials (Route53 access) | `aws configure` or environment variables |

Verify SSH access before provisioning:

```bash
ssh -i ~/.ssh/captain-key-pai.pem ubuntu@100.22.65.93 sudo systemctl status captain-apostille captain-mast
```

Both services should show `active (running)`.

---

## Provisioning a new device

### Step 1 — Register (runs in ~10 seconds)

```bash
cd /path/to/captain-apostille
./scripts/register-client.sh <device-id>
```

`<device-id>` must be alphanumeric (hyphens and underscores OK, no spaces).  
Example: `sensor-floor3-01`, `gateway_building_b`, `cr-one-edge-01`

The script:
- Generates a bootstrap certificate on captain-club (24-hour TTL)
- Downloads the bootstrap cert + CA chain to `clients/<device-id>/`
- Creates an MQTT user with a randomly generated 24-character password
- Fetches the current CA chain directly from the enrollment endpoint
- Writes `connection.env` and `README.txt`

Output directory after registration:

```
clients/<device-id>/
├── bootstrap.crt    Short-lived cert for one-time enrollment (24h TTL)
├── bootstrap.key    Private key for bootstrap cert (mode 600)
├── ca-chain.crt     CA bundle — device needs this forever
├── connection.env   Broker URL, device ID, MQTT credentials (mode 600)
└── README.txt       Full instructions for the device owner
```

You can pass a custom MQTT password as a second argument:

```bash
./scripts/register-client.sh <device-id> MyCustomPassword42
```

---

### Step 2 — Test (runs enrollment + pub/sub, ~15 seconds)

```bash
./scripts/test-client.sh <device-id>
```

The script performs the **full enrollment flow on your Mac**, simulating what the device will do at first boot:

1. Generates `operational.key` (RSA 2048)
2. Builds a CSR with `/CN=<device-id>/O=MucaLabs`
3. POSTs to `https://ca.mucalabs.io:8443/.well-known/est/simpleenroll` using the bootstrap cert
4. Extracts `operational.crt` from the JSON response
5. Deletes the bootstrap material (bootstrap.crt, bootstrap.key)
6. Starts `mosquitto_sub` on `devices/<device-id>/test`
7. Publishes a timestamped message with `mosquitto_pub`
8. Verifies the message was received

**Passing output:**

```
╔══════════════════════════════════════════════════════════════╗
║  ✓  TEST PASSED                                              ║
╠══════════════════════════════════════════════════════════════╣
║  Topic   : devices/<device-id>/test
║  Message : captain-mast-test-1715371234
║
║  Device '<device-id>' is fully enrolled and connected.
╚══════════════════════════════════════════════════════════════╝
```

After a successful test, `clients/<device-id>/` contains the full set of operational artifacts ready to hand off:

```
clients/<device-id>/
├── operational.crt  Device identity cert (1-year TTL)
├── operational.key  Device private key (mode 600 — keep secret)
├── ca-chain.crt     CA bundle
├── connection.env   MQTT credentials
└── README.txt       Setup instructions for the device owner
```

The bootstrap files are removed automatically after enrollment.

> **Important:** Run `test-client.sh` within 24 hours of `register-client.sh`. After 24 hours the bootstrap cert expires and you must re-register.

---

### Step 3 — Hand off to device owner

Give the device owner the entire `clients/<device-id>/` directory (or the individual files listed above). The `README.txt` inside contains complete instructions for:

- Where to place each file on the device
- The one-time enrollment command (if they prefer to generate their own key on-device)
- How to connect to captain-mast (mosquitto + embedded client config)
- Annual cert renewal via `/simplereenroll`

---

## Quick-reference: common admin tasks

### List registered devices (MQTT users)

```bash
ssh -i ~/.ssh/captain-key-pai.pem ubuntu@100.22.65.93 \
  sudo captain-mast --config /etc/captain-mast/mast.conf passwd list
```

### Delete a device

Remove from MQTT:

```bash
ssh -i ~/.ssh/captain-key-pai.pem ubuntu@100.22.65.93 \
  sudo captain-mast --config /etc/captain-mast/mast.conf passwd delete <device-id>
```

Delete local artifacts:

```bash
rm -rf clients/<device-id>/
```

> Revocation: captain-apostille does not currently implement CRL/OCSP. To fully block a compromised device, delete it from the MQTT password file (above). Its operational cert will expire within 1 year.

### Check service health

```bash
EC2="ssh -i ~/.ssh/captain-key-pai.pem ubuntu@100.22.65.93"

# Service status
$EC2 sudo systemctl status captain-apostille captain-mast

# Apostille logs (last 50 lines)
$EC2 sudo journalctl -u captain-apostille -n 50

# Mast logs
$EC2 sudo journalctl -u captain-mast -n 50
```

### Restart a service

```bash
ssh -i ~/.ssh/captain-key-pai.pem ubuntu@100.22.65.93 \
  sudo systemctl restart captain-apostille
```

### Verify CA chain from enrollment endpoint

```bash
curl -sf https://ca.mucalabs.io:8443/.well-known/est/cacerts | openssl x509 -noout -text
```

### Inspect a device's operational cert

```bash
openssl x509 -in clients/<device-id>/operational.crt -noout -subject -issuer -dates
```

---

## Environment variable overrides

Both scripts respect the following environment variables so you can point them at a staging environment:

| Variable | Default |
|---|---|
| `EC2_IP` | `100.22.65.93` |
| `EC2_KEY` | `~/.ssh/captain-key-pai.pem` |
| `APOSTILLE_DOMAIN` | `ca.mucalabs.io` |
| `MQTT_DOMAIN` | `mqtt.mucalabs.io` |

Example (staging):

```bash
EC2_IP=10.0.1.5 APOSTILLE_DOMAIN=ca-staging.mucalabs.io \
  ./scripts/register-client.sh test-device-staging-01
```

---

## Troubleshooting

### `register-client.sh` — bootstrap cert not generated

```
ERROR: captain-apostille ca bootstrap failed
```

- Check `captain-apostille` is running: `sudo systemctl status captain-apostille`
- Check logs: `sudo journalctl -u captain-apostille -n 50`

### `test-client.sh` — enrollment returns HTTP 401 or 403

The bootstrap cert has expired (24-hour TTL). Re-run `register-client.sh` to get a fresh one, then re-run `test-client.sh`.

### `test-client.sh` — TEST FAILED (pub/sub)

1. Verify captain-mast is running: `sudo systemctl status captain-mast`
2. Check the MQTT password matches what's in the password file:
   ```bash
   cat clients/<device-id>/connection.env
   ssh -i ~/.ssh/captain-key-pai.pem ubuntu@100.22.65.93 \
     sudo captain-mast --config /etc/captain-mast/mast.conf passwd list
   ```
3. Verify the operational cert is valid:
   ```bash
   openssl x509 -in clients/<device-id>/operational.crt -noout -subject -dates
   ```
4. Test TCP connectivity:
   ```bash
   nc -zv mqtt.mucalabs.io 8883
   ```

### Device can't connect after receiving artifacts

Most common causes:
- Wrong file paths on device — see `README.txt` for correct placement
- `O=` field in device-generated CSR doesn't match `MucaLabs` — the cert's O field is used as the broker tenant ID and must be exactly `MucaLabs`
- Device clock is wrong — TLS cert validation requires accurate system time (within ~5 minutes)
- Device using TLS 1.0/1.1 — captain-mast requires TLS 1.2 or 1.3

---

## Workflow summary

```
Admin                           captain-club EC2
─────                           ───────────────
register-client.sh <id>   →     issues bootstrap cert
                          ←     bootstrap.crt, bootstrap.key, ca-chain.crt
                                creates MQTT user with password
                          →     
test-client.sh <id>       →     simpleenroll (bootstrap cert as auth)
                          ←     operational.crt
                          →     MQTT CONNECT (operational cert + password)
                          ←     CONNACK
                          →     PUBLISH devices/<id>/test
                          ←     message received by subscriber ✓

Hand off clients/<id>/ to device owner.
```
