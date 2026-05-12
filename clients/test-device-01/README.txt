Device: test-device-01
Generated: 2026-05-10T18:57:29Z

== Files ==
  bootstrap.crt   Short-lived cert for one-time enrollment (24h TTL)
  bootstrap.key   Private key for bootstrap cert
  ca-chain.crt    CA bundle — load onto device to verify both services
  connection.env  Endpoint URLs and MQTT credentials

== Enrollment (run once on the device) ==

  # 1. Generate a key pair
  openssl genrsa -out operational.key 2048

  # 2. Generate a CSR  (O must be alphanumeric — no spaces)
  openssl req -new -key operational.key \
    -subj "/CN=test-device-01/O=MucaLabs" \
    -out device.csr

  # 3. Enroll with captain-apostille to receive the operational cert
  curl https://ca.mucalabs.io:8443/.well-known/est/simpleenroll \
    --cert bootstrap.crt --key bootstrap.key \
    --data-binary @device.csr \
    -H "Content-Type: application/pkcs10" \
    -o enroll.json

  # 4. Extract the operational cert
  python3 -c "import json; print(json.load(open('enroll.json'))['certificate'])" \
    > operational.crt

== Connecting to captain-mast (after enrollment) ==

  source connection.env
  mosquitto_pub -h mqtt.mucalabs.io -p 8883 \
    --cafile ca-chain.crt \
    --cert operational.crt --key operational.key \
    -u "$MQTT_USERNAME" -P "$MQTT_PASSWORD" \
    -t "devices/test-device-01/data" -m "hello"
