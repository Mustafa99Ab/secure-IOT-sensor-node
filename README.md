
# Secure IoT Sensor Node with Encrypted Communication

## Overview
A practical IoT security demonstration using Wemos D1 (ESP8266) and DHT11 sensor with end-to-end encrypted communication, featuring AES-128 encryption, HMAC authentication, and TLS/MQTT secure channels.

---

## Objective

Design and implement a secure IoT system that demonstrates:
- **Confidentiality** - Prevent eavesdropping on sensor data
- **Integrity** - Detect data tampering and modification
- **Authentication** - Ensure data comes from legitimate devices
- **Anti-Replay Protection** - Prevent message replay attacks

The system uses encrypted sensor data transmission over a local Wi-Fi network with authentication mechanisms to create a production-grade IoT security example.

---

## Hardware Requirements

| Component | Purpose |
|-----------|---------|
| **Wemos D1 Mini (ESP8266)** | Wi-Fi enabled microcontroller with 80 MHz processor |
| **DHT11 Sensor** | Temperature & humidity readings (optional, can use dummy data) |
| **Computer/Raspberry Pi** | Local MQTT broker and decryption server |
| **Wi-Fi Router** | Network connectivity for device-to-server communication |

---

## Software Stack

### Device (ESP8266)
```
Arduino IDE with ESP8266 Board Support
├── ESP8266WiFi & WiFiClientSecure (TLS/SSL)
├── PubSubClient (MQTT)
├── ArduinoCrypto or similar (AES-128)
└── DHT sensor library
```

### Server
```
MQTT Broker: Mosquitto with TLS support
├── Port: 8883 (MQTT over TLS)
├── Self-signed SSL certificates
└── Username/Password authentication

Subscriber: Python Script
├── paho-mqtt client
├── cryptography library (AES + HMAC)
└── Data validation & logging
```

---

## Security Mechanisms

### 1. Data Encryption (Confidentiality)
- **Algorithm**: AES-128 in CBC mode
- **Key**: 128-bit pre-shared symmetric key
- **IV Generation**: Random Initialization Vector per message
- **Purpose**: Prevents eavesdroppers from reading plaintext sensor values
- **Implementation**: Ciphertext cannot be decrypted without the secret key

### 2. Secure Channel (TLS/SSL)
- **Protocol**: MQTT over TLS on port 8883
- **Certificate Verification**: ESP8266 verifies broker certificate
- **Server Authentication**: Prevents man-in-the-middle attacks
- **Transport Encryption**: Additional layer of protection during Wi-Fi transmission
- **Implementation**: WiFiClientSecure handles TLS handshake

### 3. Message Integrity & Authentication (HMAC)
- **Algorithm**: HMAC-SHA256 or HMAC-SHA1
- **Scope**: Computed over IV + encrypted data + headers
- **Purpose**: Tamper detection and source authentication
- **Validation**: Server recomputes HMAC and compares with received value
- **Defense**: Rejects modified or spoofed messages
- **Implementation**: Only device and server know the HMAC key

### 4. Device Authentication
- **TLS Certificates**: Broker certificate validation
- **Credentials**: MQTT username/password
- **Device ID**: Embedded in encrypted message
- **Key-based Auth**: Encryption/HMAC keys only known to authorized device and server
- **Purpose**: Prevents unauthorized devices from connecting

### 5. Anti-Replay Protection
- **Nonce/Timestamp**: Each message includes sequence counter or timestamp
- **Validation Methods**:
  - **Timestamp-based**: Server rejects messages outside time window
  - **Counter-based**: Server tracks last seen counter, rejects out-of-order
- **Random IV**: Combined with HMAC prevents replay of exact ciphertext
- **Defense**: Previously captured valid messages cannot be reused

---

## System Architecture

### Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. SENSOR DATA COLLECTION (Device Layer)                        │
│    Wemos D1 reads DHT11: Temperature 25°C, Humidity 60%          │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 2. LOCAL PROCESSING & SECURITY (Device)                         │
│    • Format message: {device_id, temp, humidity, timestamp}      │
│    • Generate random IV for AES encryption                       │
│    • Encrypt with AES-128-CBC using shared key                   │
│    • Compute HMAC-SHA256 over IV + ciphertext                    │
│    • Final payload: {IV, ciphertext, HMAC}                       │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 3. SECURE TRANSMISSION (Network Layer - TLS)                    │
│    • Establish TLS connection to MQTT broker                     │
│    • Verify broker certificate                                   │
│    • Publish encrypted message to secure topic                   │
│    • All traffic encrypted at transport layer                    │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 4. DATA RECEPTION (Server/Broker)                               │
│    • Mosquitto receives message over TLS                         │
│    • Validates TLS session and client credentials                │
│    • Forwards to subscribed Python client                        │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 5. DATA VERIFICATION (Server)                                   │
│    Step 1: Verify HMAC first (before decryption)                 │
│    Step 2: If HMAC valid, decrypt ciphertext with AES key        │
│    Step 3: Extract and validate timestamp/nonce                  │
│    Step 4: Check for replay attacks                              │
│    Step 5: Accept and process verified sensor data               │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 6. DATA UTILIZATION (Application Layer)                         │
│    • Display on dashboard                                        │
│    • Store in database                                           │
│    • Trigger alerts if needed                                    │
└─────────────────────────────────────────────────────────────────┘
```

---

## Implementation Timeline (3-4 Days)

### Day 1: Hardware & Basic IoT Foundation
- ✅ Connect DHT11 to Wemos D1 (Data→D4, Power→5V, GND)
- ✅ Setup Arduino IDE with ESP8266 board support
- ✅ Load cryptography libraries (WiFi, DHT, MQTT, Crypto)
- ✅ Write basic sketch to read DHT11 and print via serial
- ✅ Connect ESP8266 to Wi-Fi network
- ✅ Install Mosquitto MQTT broker (non-TLS initially)
- ✅ Implement basic MQTT publish (unencrypted)
- ✅ Verify end-to-end message flow: Device → Broker → Subscriber
- **Result**: Working IoT baseline without security

### Day 2: Secure Channel (TLS/SSL)
- ✅ Generate self-signed SSL certificates using OpenSSL
- ✅ Configure Mosquitto for TLS on port 8883
- ✅ Set MQTT username/password credentials
- ✅ Update ESP8266 to use WiFiClientSecure
- ✅ Load broker certificate/fingerprint in device code
- ✅ Test TLS connection and message publishing
- ✅ Verify with Wireshark: MQTT payload is encrypted
- ✅ Confirm unauthorized clients are rejected
- **Result**: Secure transport channel established

### Day 3: End-to-End Encryption & Integrity
- ✅ Implement AES-128-CBC encryption on ESP8266
- ✅ Define shared 128-bit encryption key
- ✅ Generate random IV for each message
- ✅ Implement HMAC-SHA256 computation
- ✅ Format final payload: `{IV, ciphertext, HMAC}`
- ✅ Develop server-side decryption script (Python)
- ✅ Verify HMAC before decryption
- ✅ Extract and validate nonce/timestamp
- ✅ Implement replay detection logic
- ✅ Test full encryption/decryption workflow
- ✅ Verify encrypted data matches original after decryption
- **Result**: Complete end-to-end encryption with integrity checks

### Day 4: Security Testing & Demonstration
- ✅ **Eavesdropping Test**: Capture with Wireshark, confirm data unreadable
- ✅ **Tampering Test**: Modify ciphertext, verify HMAC rejection
- ✅ **Spoofing Test**: Send fake message without keys, verify rejection
- ✅ **Replay Test**: Resend valid message, verify timestamp detection
- ✅ **Normal Operation**: Verify legitimate sensor data accepted
- ✅ Create architecture diagram
- ✅ Document configuration (keys, certificates, passwords)
- ✅ Write code comments and implementation guide
- **Result**: Fully tested secure IoT system with attack demonstrations

---

## Attack Simulations & Defenses

### Eavesdropping Attempt
**Attack**: Attacker sniffs Wi-Fi traffic
**Defense**: 
- TLS encrypts transport layer
- AES-128 encrypts payload
- Result: Traffic appears as random bytes, unreadable
**Outcome**: ✓ Confidentiality maintained

### Data Tampering
**Attack**: Attacker modifies bit in ciphertext
**Defense**:
- HMAC acts as tamper seal
- Server recomputes HMAC, compares with received
- Mismatch = tampered data rejected
**Outcome**: ✓ Integrity verified, tampering detected

### Device Spoofing
**Attack**: Unauthorized device publishes fake readings
**Defense**:
- Without encryption/HMAC keys, message is invalid
- HMAC verification fails
- Device ID check fails
**Outcome**: ✓ Authentication enforced, spoofed data rejected

### Replay Attack
**Attack**: Attacker captures valid message, resends it later
**Defense**:
- Timestamp in message checked
- Sequence counter verified
- Server rejects old timestamps or duplicate counters
- Random IV prevents exact ciphertext reuse
**Outcome**: ✓ Freshness verified, replay prevented

---

## Key Code Components

### ESP8266 (Device) - Pseudocode Structure
```cpp
// 1. Read Sensor
temp = dht.readTemperature();
humidity = dht.readHumidity();

// 2. Build Message
message = {
  "device_id": ESP.getChipId(),
  "temp": temp,
  "humidity": humidity,
  "timestamp": millis()
};

// 3. Encrypt
random_iv = generateRandomIV(16);
ciphertext = AES_encrypt(message, aes_key, random_iv);

// 4. Create HMAC
hmac = HMAC_SHA256(random_iv + ciphertext, hmac_key);

// 5. Send via MQTT+TLS
mqtt_client.publish("sensors/dht11", 
  "{\"iv\":\"" + toHex(random_iv) + 
  "\",\"data\":\"" + toBase64(ciphertext) + 
  "\",\"hmac\":\"" + toHex(hmac) + "\"}");
```

### Python Server - Pseudocode Structure
```python
def on_message(client, userdata, msg):
    # 1. Parse incoming message
    payload = json.loads(msg.payload)
    iv = fromHex(payload["iv"])
    ciphertext = fromBase64(payload["data"])
    received_hmac = fromHex(payload["hmac"])
    
    # 2. Verify HMAC first
    computed_hmac = HMAC_SHA256(iv + ciphertext, hmac_key)
    if computed_hmac != received_hmac:
        print("INTEGRITY CHECK FAILED - Data rejected")
        return
    
    # 3. Decrypt
    plaintext = AES_decrypt(ciphertext, aes_key, iv)
    data = json.loads(plaintext)
    
    # 4. Check timestamp (replay protection)
    if is_old_timestamp(data["timestamp"]) or is_duplicate(data["timestamp"]):
        print("REPLAY ATTACK DETECTED - Message rejected")
        return
    
    # 5. Process data
    print(f"Temperature: {data['temp']}°C, Humidity: {data['humidity']}%")
```

---

## Configuration Files

### Mosquitto (mosquitto.conf)
```
listener 1883
listener 8883
protocol mqtt
cafile /etc/mosquitto/ca.crt
certfile /etc/mosquitto/server.crt
keyfile /etc/mosquitto/server.key
allow_anonymous false
password_file /etc/mosquitto/passwd
```

### Device Configuration (.env)
```
WIFI_SSID=YourNetworkName
WIFI_PASSWORD=YourPassword
MQTT_BROKER=192.168.1.100
MQTT_PORT=8883
MQTT_USER=iot_device
MQTT_PASS=secure_password
AES_KEY=0123456789ABCDEF0123456789ABCDEF
HMAC_KEY=FEDCBA9876543210FEDCBA9876543210
DEVICE_ID=ESP8266_001
```

---

## Security Best Practices Demonstrated

1. **Encryption at Rest & in Transit**
   - TLS for network layer
   - AES-128 for application layer
   - Defense in depth approach

2. **Message Authentication**
   - HMAC prevents tampering
   - Device ID validation
   - Pre-shared key authentication

3. **Replay Prevention**
   - Timestamp validation
   - Sequence counters
   - Nonce-based verification

4. **Certificate Management**
   - Self-signed certificates for testing
   - Certificate pinning (fingerprint)
   - TLS handshake verification

5. **Secure Key Management**
   - Keys stored in device firmware
   - Keys not transmitted over network
   - Separate encryption and HMAC keys

---

## Learning Outcomes

By completing this project, you will understand:

✓ IoT security principles (CIA triad)
✓ Lightweight cryptography on microcontrollers
✓ TLS/MQTT secure communication
✓ Attack simulation and detection
✓ End-to-end encryption architecture
✓ Real-world IoT deployment challenges

---

## Performance Considerations

| Metric | Details |
|--------|---------|
| **Encryption Time** | ~10-50ms per message (AES-128) |
| **Memory Usage** | ~20KB for crypto libraries |
| **Message Size** | ~200 bytes (IV + encrypted data + HMAC) |
| **Power Draw** | ~80mA during encryption, ~40mA idle |
| **Network Throughput** | TLS handshake: ~2-3 seconds, MQTT publish: <100ms |

---

## References

- Hackaday: "Practical IoT Cryptography on the ESP8266"
- RandomNerdTutorials: "ESP8266 with HTTPS and SSL/TLS"
- Embedded Computing: "IoT RF Security Vulnerabilities"
- MQTT.org: "MQTT Protocol Specification"

---

## License

Educational project for IoT security demonstration

---

## Author Notes

This project demonstrates that even a $3 Wi-Fi board can implement enterprise-grade security measures. The layered approach (TLS + AES + HMAC) ensures data protection from multiple attack vectors. All code and configurations are fully documented for reproducibility and educational purposes.

**Key Takeaway**: IoT security is achievable and essential. With careful design, simple IoT devices can deliver data confidentially and reliably, preserving the trustworthiness of the entire IoT ecosystem.
