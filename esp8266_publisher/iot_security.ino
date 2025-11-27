#include <ESP8266WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <DHT.h>
#include <ArduinoJson.h>

#include <Crypto.h>
#include <AES.h>       // AES128 + encryptBlock()
#include <Hash.h>      // BearSSL HMAC (br_hmac_*)
#include <base64.h>    // base64::encode()

extern "C" {
  #include "user_interface.h"  // os_get_random() for IV
}

// ----------------- Hardware -----------------
#define DHTPIN  D4
#define DHTTYPE DHT11
DHT dht(DHTPIN, DHTTYPE);

// ----------------- WiFi/MQTT ----------------
const char* ssid         = "TestMQTT";
const char* password     = "12345678";
const char* mqtt_server  = "192.168.137.1";
const int   mqtt_port    = 8883;  // TLS
const char* mqtt_client_id = "ESP8266SecurePublisher";
const char* mqtt_topic   = "sensors/dht11_secure";  // <- your original topic

// ---- TLS SHA1 fingerprint pin (replace with your broker’s) ----
const char fingerprint[] PROGMEM =
  "57:25:19:AC:B6:C0:55:4D:7E:67:46:43:02:69:B7:3B:BE:58:44:14";

WiFiClientSecure tlsClient;
PubSubClient client(tlsClient);

// ----------------- Keys ---------------------
// AES-128 key (16 bytes). Replace before demo if needed.
const uint8_t AES_KEY[16] = {
  0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66 // "0123456789abcdef"
};
// HMAC-SHA256 key (32 bytes). Replace before demo if needed.
const uint8_t HMAC_KEY[32] = {
  0xa1,0xb2,0xc3,0xd4,0xe5,0xf6,0x10,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,
  0xbb,0xcc,0xdd,0xee,0xff,0x01,0x12,0x23,0x34,0x45,0x56,0x67,0x78,0x89,0x9a,0xab
};

const uint32_t MAX_TIME_WAIT_MS = 10000;

// -------------- Helpers --------------
void setup_wifi() {
  Serial.print("Connecting to "); Serial.println(ssid);
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) { delay(400); Serial.print("."); }
  Serial.println("\nWiFi connected ✅");
  Serial.print("IP: "); Serial.println(WiFi.localIP());
}

bool wait_for_time() {
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");
  uint32_t start = millis();
  time_t now = time(nullptr);
  while (now < 1700000000 && (millis() - start) < MAX_TIME_WAIT_MS) {
    delay(200);
    now = time(nullptr);
  }
  return now >= 1700000000;
}

void reconnect_mqtt() {
  while (!client.connected()) {
    Serial.print("MQTT connect... ");
    if (client.connect(mqtt_client_id)) {
      Serial.println("connected ✅");
    } else {
      Serial.printf("failed, rc=%d\n", client.state());
      delay(2000);
    }
  }
}

size_t pkcs7_pad(const uint8_t* in, size_t in_len, uint8_t* out, size_t out_cap) {
  size_t pad = 16 - (in_len % 16); if (pad == 0) pad = 16;
  size_t total = in_len + pad; if (total > out_cap) return 0;
  memcpy(out, in, in_len); for (size_t i=0;i<pad;i++) out[in_len+i] = (uint8_t)pad; return total;
}

bool aes128_cbc_encrypt(const uint8_t* key16, const uint8_t* iv16,
                        const uint8_t* in, size_t in_len, uint8_t* out) {
  AES128 aes; aes.setKey(key16, 16);
  uint8_t prev[16]; memcpy(prev, iv16, 16);
  for (size_t off=0; off<in_len; off+=16) {
    uint8_t block[16];
    for (int i=0;i<16;i++) block[i] = in[off+i] ^ prev[i];
    aes.encryptBlock(&out[off], block);
    memcpy(prev, &out[off], 16);
  }
  return true;
}

void compute_hmac_sha256(const char* ascii, size_t len, uint8_t* out32) {
  br_hmac_key_context kc; br_hmac_context ctx;
  br_hmac_key_init(&kc, &br_sha256_vtable, HMAC_KEY, sizeof(HMAC_KEY));
  br_hmac_init(&ctx, &kc, 0); br_hmac_update(&ctx, ascii, len); br_hmac_out(&ctx, out32);
}

String to_hex(const uint8_t* data, size_t len) {
  static const char* hex = "0123456789abcdef"; String s; s.reserve(len*2);
  for (size_t i=0;i<len;i++){ s += hex[(data[i]>>4)&0xF]; s += hex[data[i]&0xF]; }
  return s;
}

void random_iv(uint8_t iv[16]) { os_get_random(iv, 16); }

// -------------- Setup / Loop --------------
void setup() {
  Serial.begin(115200); delay(100);
  dht.begin();
  setup_wifi();

  // TLS certificate pinning (SHA1 fingerprint)
  if (!tlsClient.setFingerprint(fingerprint)) {
    Serial.println("Warning: failed to set fingerprint (check string format)");
  }

  client.setServer(mqtt_server, mqtt_port);

  Serial.print("Syncing time via NTP...");
  bool ok = wait_for_time();
  Serial.println(ok ? " OK" : " FAILED (ts may be 0)");
}

void loop() {
  if (!client.connected()) reconnect_mqtt();
  client.loop();

  float hum = dht.readHumidity();
  float temp = dht.readTemperature();
  if (isnan(hum) || isnan(temp)) { Serial.println("DHT read fail"); delay(3000); return; }

  time_t now = time(nullptr);

  // Build plaintext JSON to encrypt
  StaticJsonDocument<128> doc;
  doc["device_id"] = "esp8266-1";
  doc["ts"] = (uint32_t)now;   // optional inside-plaintext ts
  doc["temp"] = temp;
  doc["hum"]  = hum;

  char plain[160];
  size_t plain_len = serializeJson(doc, plain, sizeof(plain));
  Serial.print("Plaintext JSON: "); Serial.write((const uint8_t*)plain, plain_len); Serial.println();

  // Pad + encrypt
  uint8_t padded[208];
  size_t padded_len = pkcs7_pad((const uint8_t*)plain, plain_len, padded, sizeof(padded));
  if (!padded_len) { Serial.println("Pad buffer too small"); delay(3000); return; }

  uint8_t iv[16]; random_iv(iv);
  uint8_t ct[208]; aes128_cbc_encrypt(AES_KEY, iv, padded, padded_len, ct);

  // Base64
  String iv_b64 = base64::encode(iv, 16);
  String ct_b64 = base64::encode(ct, padded_len);

  // HMAC over "ts|iv_b64|ct_b64"
  char ts_buf[16]; snprintf(ts_buf, sizeof(ts_buf), "%u", (uint32_t)now);
  String mac_input; mac_input.reserve(16 + iv_b64.length() + ct_b64.length() + 2);
  mac_input += ts_buf; mac_input += '|'; mac_input += iv_b64; mac_input += '|'; mac_input += ct_b64;

  uint8_t mac[32]; compute_hmac_sha256(mac_input.c_str(), mac_input.length(), mac);

  // Outer JSON payload
  StaticJsonDocument<384> outer;
  outer["ts"] = (uint32_t)now;           // must match ts_buf above
  outer["iv"] = iv_b64;
  outer["ct"] = ct_b64;
  outer["hmac"] = to_hex(mac, sizeof(mac));

  char payload[512];
  size_t payload_len = serializeJson(outer, payload, sizeof(payload));
  Serial.print("Publishing payload: "); Serial.write((const uint8_t*)payload, payload_len); Serial.println();

  if (!client.publish(mqtt_topic, payload, true)) {
    Serial.println("Publish failed");
  }

  delay(5000);
}
