import json
import random
import sys
from pathlib import Path
from datetime import datetime, timedelta

OUTPUT_FILE = Path("data/training_logs.jsonl")

REQUEST_TYPES = ["HTTP", "SSH", "FTP", "SMTP", "DNS"]
COUNTRIES = ["US", "BG", "DE", "RU", "CN", "NL", "FR", "UK"]
CITIES = ["New York", "Sofia", "Berlin", "Moscow", "Beijing", "Amsterdam", "Paris", "London"]

MALICIOUS_PAYLOADS = [
    "' OR '1'='1'; --",
    "<script>alert('XSS')</script>",
    "../../etc/passwd",
    "admin' --",
    "DROP TABLE users; --",
    "<?php system($_GET['cmd']); ?>"
]

def generate_log(is_malicious=False):
    payload = random.choice(MALICIOUS_PAYLOADS) if is_malicious else "Normal request payload"
    timestamp = (datetime.utcnow() - timedelta(seconds=random.randint(0, 999999))).isoformat()

    return {
        "timestamp": timestamp,
        "source_ip": f"192.168.{random.randint(0,255)}.{random.randint(1,255)}",
        "source_port": random.randint(1024, 65535),
        "payload": payload,
        "request_type": random.choice(REQUEST_TYPES),
        "country": random.choice(COUNTRIES),
        "city": random.choice(CITIES)
    }

def main(count):
    existing = 0
    if OUTPUT_FILE.exists():
        existing = sum(1 for _ in open(OUTPUT_FILE, "r", encoding="utf-8"))

    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        for _ in range(count):
            is_malicious = random.random() < 0.25  # 25% malicious
            record = generate_log(is_malicious)
            f.write(json.dumps(record) + "\n")

    print(f"Existing: {existing}")
    print(f"Added {count} records → Total: {existing + count}")
    print(f"Wrote to {OUTPUT_FILE}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python generate_synthetic.py <count>")
        sys.exit(1)

    n = int(sys.argv[1])
    main(n)
