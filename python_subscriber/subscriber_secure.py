import base64, hmac, json, logging, os, sys, time
from hashlib import sha256
from binascii import unhexlify
from typing import Optional

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from dotenv import load_dotenv
import paho.mqtt.client as mqtt

# ---------- Config ----------
load_dotenv()

MQTT_HOST = os.getenv("MQTT_HOST", "localhost")
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
MQTT_TOPIC = os.getenv("MQTT_TOPIC", "sensors/dht11_secure")
CLIENT_ID  = os.getenv("CLIENT_ID", "secure-subscriber")

CLOCK_SKEW_SEC = int(os.getenv("CLOCK_SKEW_SEC", "120"))

def _get_key(env_name: str, expected_len_bytes: int) -> bytes:
    v = os.getenv(env_name, "").strip()
    if not v:
        logging.error(f"Missing {env_name}. Put it in .env as hex.")
        sys.exit(1)
    try:
        b = unhexlify(v)
    except Exception as e:
        logging.error(f"{env_name} must be hex: {e}")
        sys.exit(1)
    if len(b) != expected_len_bytes:
        logging.error(f"{env_name} must be {expected_len_bytes} bytes, got {len(b)}")
        sys.exit(1)
    return b

AES_KEY  = _get_key("AES_KEY_HEX", 16)   # AES-128
HMAC_KEY = _get_key("HMAC_KEY_HEX", 32)  # 256-bit HMAC key

# ---------- Logging ----------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

# ---------- Helpers ----------
def within_skew(ts: int) -> bool:
    now = int(time.time())
    return abs(now - ts) <= CLOCK_SKEW_SEC

def verify_hmac(ts_b: bytes, iv_b64: bytes, ct_b64: bytes, hmac_hex: str) -> bool:
    mac = hmac.new(HMAC_KEY, ts_b + b"|" + iv_b64 + b"|" + ct_b64, sha256).hexdigest()
    return hmac.compare_digest(mac, hmac_hex.lower())

def aes_decrypt_cbc(iv: bytes, ct: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    return unpad(pt, AES.block_size)

def parse_and_process(plaintext_bytes: bytes) -> None:
    try:
        obj = json.loads(plaintext_bytes.decode("utf-8"))
    except Exception:
        logging.warning("Decrypted payload is not valid JSON")
        logging.info(plaintext_bytes)
        return
    logging.info(f"[OK] {obj}")

# ---------- MQTT callbacks ----------
def on_connect(client, userdata, flags, reason_code, properties=None):
    if reason_code == 0:
        logging.info(f"Connected to MQTT {MQTT_HOST}:{MQTT_PORT}")
        client.subscribe(MQTT_TOPIC, qos=1)
        logging.info(f"Subscribed to '{MQTT_TOPIC}'")
    else:
        logging.error(f"Connection failed with code {reason_code}")

def on_message(client, userdata, msg):
    try:
        data = json.loads(msg.payload.decode("utf-8"))
        for k in ("ts","iv","ct","hmac"):
            if k not in data:
                raise ValueError(f"Missing field '{k}'")

        ts = int(data["ts"])
        iv_b64 = data["iv"].encode("ascii")
        ct_b64 = data["ct"].encode("ascii")
        hmac_hex = data["hmac"]

        if not within_skew(ts):
            raise ValueError("Stale/invalid timestamp")

        if not verify_hmac(str(ts).encode("ascii"), iv_b64, ct_b64, hmac_hex):
            raise ValueError("HMAC verification failed")

        iv = base64.b64decode(iv_b64, validate=True)
        ct = base64.b64decode(ct_b64, validate=True)
        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes")

        pt = aes_decrypt_cbc(iv, ct)
        parse_and_process(pt)

    except Exception as e:
        logging.warning(f"[DROP] reason={e}")

def main():
    client = mqtt.Client(client_id=CLIENT_ID, protocol=mqtt.MQTTv5)
    client.on_connect = on_connect
    client.on_message = on_message

    # Enable TLS for port 8883
    client.tls_set(ca_certs="C:/Users/zizou/Documents/mosquitto_certs/mosq_ca.crt")

    # If broker uses self-signed cert and hostname doesn’t match IP:
    client.tls_insecure_set(True)

    client.connect(MQTT_HOST, MQTT_PORT, keepalive=60)
    client.loop_forever()

if __name__ == "__main__":
    main()
