Device : verify-device-01
Created: 2026-05-10T18:58:23Z

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
  openssl req -new -key /certs/operational.key \
    -subj "/CN=verify-device-01/O=MucaLabs" \
    -out /tmp/device.csr

  # POST the CSR to captain-apostille using the bootstrap cert as auth
  curl https://ca.mucalabs.io:8443/.well-known/est/simpleenroll \
    --cacert /certs/ca-chain.crt \
    --cert   /certs/bootstrap.crt \
    --key    /certs/bootstrap.key \
    --data-binary @/tmp/device.csr \
    -H "Content-Type: application/pkcs10" \
    -o /tmp/enroll.json

  # Extract and store the operational cert
  python3 -c "import json; print(json.load(open('/tmp/enroll.json'))['certificate'])" \
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

  MQTT broker : mqtt.mucalabs.io:8883
  Username    : verify-device-01
  Password    : (see connection.env — keep secret)

  mosquitto_pub -h mqtt.mucalabs.io -p 8883 \
    --cafile /certs/ca-chain.crt \
    --cert   /certs/operational.crt \
    --key    /certs/operational.key \
    -u "verify-device-01" -P "<password from connection.env>" \
    -t "devices/verify-device-01/data" -m "hello"

  For embedded clients (Paho, esp-mqtt, rumqttc):
    ca_file        = /certs/ca-chain.crt
    client_cert    = /certs/operational.crt
    client_key     = /certs/operational.key
    mqtt_username  = verify-device-01
    mqtt_password  = <from connection.env>
    host           = mqtt.mucalabs.io
    port           = 8883
    tls_version    = TLSv1.2 or TLSv1.3

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CERT RENEWAL (when operational.crt expires)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  openssl req -new -key /certs/operational.key \
    -subj "/CN=verify-device-01/O=MucaLabs" -out /tmp/renew.csr

  curl https://ca.mucalabs.io:8443/.well-known/est/simplereenroll \
    --cacert /certs/ca-chain.crt \
    --cert   /certs/operational.crt \
    --key    /certs/operational.key \
    --data-binary @/tmp/renew.csr \
    -H "Content-Type: application/pkcs10" \
    -o /tmp/renew.json

  python3 -c "import json; print(json.load(open('/tmp/renew.json'))['certificate'])" \
    > /certs/operational.crt
