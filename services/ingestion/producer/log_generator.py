"""
Log Generator — CICIDS-style synthetic network traffic generator.
Produces realistic network flow records with benign, suspicious, and malicious patterns.
"""

import random
import uuid
import json
from datetime import datetime, timezone
from faker import Faker

fake = Faker()

# ── Known malicious IP ranges (simulated threat intelligence) ─────────────────
KNOWN_BAD_IPS = [
    "185.220.101.1", "192.42.116.14", "176.10.104.240",
    "94.102.49.190", "198.96.155.3", "171.25.193.20",
    "162.247.72.201", "185.100.87.202", "45.142.212.100",
    "91.108.4.0",
]

# ── Internal network ranges (source IPs for internal traffic) ─────────────────
INTERNAL_RANGES = [
    "10.0.{}.{}",
    "192.168.1.{}",
    "172.16.{}.{}",
]

# ── Common services / ports ───────────────────────────────────────────────────
COMMON_PORTS = {
    "HTTP": 80, "HTTPS": 443, "SSH": 22, "FTP": 21,
    "DNS": 53, "SMTP": 25, "RDP": 3389, "SMB": 445,
    "MySQL": 3306, "PostgreSQL": 5432, "Redis": 6379,
    "Elasticsearch": 9200, "MongoDB": 27017,
}

# ── Attack patterns ───────────────────────────────────────────────────────────
ATTACK_SIGNATURES = {
    "port_scan": {
        "packet_count_range": (50, 500),
        "payload_size_range": (0, 64),
        "duration_range": (0.001, 0.1),
        "flag": "SYN",
        "mitre": "T1046",
    },
    "brute_force": {
        "packet_count_range": (100, 1000),
        "payload_size_range": (200, 800),
        "duration_range": (0.1, 2.0),
        "flag": "PSH-ACK",
        "mitre": "T1110",
    },
    "ddos": {
        "packet_count_range": (1000, 50000),
        "payload_size_range": (64, 1500),
        "duration_range": (1.0, 60.0),
        "flag": "SYN",
        "mitre": "T1498",
    },
    "data_exfiltration": {
        "packet_count_range": (20, 200),
        "payload_size_range": (5000, 65000),
        "duration_range": (5.0, 120.0),
        "flag": "PSH-ACK",
        "mitre": "T1041",
    },
    "c2_communication": {
        "packet_count_range": (5, 50),
        "payload_size_range": (100, 2000),
        "duration_range": (0.5, 10.0),
        "flag": "PSH-ACK",
        "mitre": "T1071",
    },
    "exploitation": {
        "packet_count_range": (10, 100),
        "payload_size_range": (500, 8000),
        "duration_range": (0.1, 5.0),
        "flag": "PSH-ACK",
        "mitre": "T1190",
    },
}

PROTOCOLS = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"]

GEOLOCATIONS = [
    {"country": "US", "city": "New York", "lat": 40.7128, "lon": -74.0060},
    {"country": "CN", "city": "Beijing", "lat": 39.9042, "lon": 116.4074},
    {"country": "RU", "city": "Moscow", "lat": 55.7558, "lon": 37.6173},
    {"country": "DE", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821},
    {"country": "NL", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041},
    {"country": "GB", "city": "London", "lat": 51.5074, "lon": -0.1278},
    {"country": "IN", "city": "Mumbai", "lat": 19.0760, "lon": 72.8777},
    {"country": "BR", "city": "São Paulo", "lat": -23.5505, "lon": -46.6333},
    {"country": "JP", "city": "Tokyo", "lat": 35.6762, "lon": 139.6503},
    {"country": "KP", "city": "Pyongyang", "lat": 39.0194, "lon": 125.7381},
    {"country": "IR", "city": "Tehran", "lat": 35.6892, "lon": 51.3890},
    {"country": "UA", "city": "Kyiv", "lat": 50.4501, "lon": 30.5234},
]


def _random_internal_ip() -> str:
    template = random.choice(INTERNAL_RANGES)
    if template.count("{}") == 2:
        return template.format(random.randint(0, 255), random.randint(1, 254))
    return template.format(random.randint(1, 254))


def _random_external_ip() -> str:
    return f"{random.randint(1, 254)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def generate_benign_log() -> dict:
    """Generate a normal network traffic event."""
    service, port = random.choice(list(COMMON_PORTS.items()))
    src_ip = _random_internal_ip()
    dst_ip = _random_external_ip()
    geo = random.choice(GEOLOCATIONS[:6])  # Western countries for benign

    return {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": random.randint(1024, 65535),
        "dst_port": port,
        "protocol": random.choice(["TCP", "UDP"]),
        "service": service,
        "payload_size": random.randint(64, 4096),
        "duration": round(random.uniform(0.01, 5.0), 4),
        "packet_count": random.randint(1, 30),
        "flag": random.choice(["SYN-ACK", "PSH-ACK", "FIN-ACK"]),
        "bytes_fwd": random.randint(100, 50000),
        "bytes_bwd": random.randint(100, 50000),
        "ttl": random.choice([64, 128, 255]),
        "geo_country": geo["country"],
        "geo_city": geo["city"],
        "geo_lat": geo["lat"],
        "geo_lon": geo["lon"],
        "label": "benign",
        "attack_type": None,
        "mitre_technique": None,
        "is_known_bad_ip": False,
        "ip_reputation_score": round(random.uniform(0.0, 0.2), 3),
    }


def generate_suspicious_log() -> dict:
    """Generate a suspicious (borderline) network event."""
    log = generate_benign_log()
    log.update({
        "id": str(uuid.uuid4()),
        "packet_count": random.randint(30, 100),
        "payload_size": random.randint(2000, 10000),
        "duration": round(random.uniform(0.001, 0.5), 4),
        "flag": random.choice(["SYN", "RST", "FIN"]),
        "dst_port": random.randint(1, 1023),  # Privileged ports
        "ip_reputation_score": round(random.uniform(0.3, 0.6), 3),
        "label": "suspicious",
    })
    return log


def generate_malicious_log(attack_type: str = None) -> dict:
    """Generate a malicious network event based on known attack patterns."""
    if attack_type is None:
        attack_type = random.choice(list(ATTACK_SIGNATURES.keys()))

    sig = ATTACK_SIGNATURES[attack_type]
    geo = random.choice(GEOLOCATIONS[4:])  # Include adversarial geos

    # Mix known bad IPs with random
    use_bad_ip = random.random() < 0.4
    src_ip = random.choice(KNOWN_BAD_IPS) if use_bad_ip else _random_external_ip()
    dst_ip = _random_internal_ip()

    return {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice([22, 80, 443, 3389, 445, 8080, 4444, 31337]),
        "protocol": random.choice(PROTOCOLS),
        "service": attack_type.replace("_", " ").title(),
        "payload_size": random.randint(*sig["payload_size_range"]),
        "duration": round(random.uniform(*sig["duration_range"]), 4),
        "packet_count": random.randint(*sig["packet_count_range"]),
        "flag": sig["flag"],
        "bytes_fwd": random.randint(1000, 100000),
        "bytes_bwd": random.randint(100, 5000),
        "ttl": random.choice([1, 32, 64]),
        "geo_country": geo["country"],
        "geo_city": geo["city"],
        "geo_lat": geo["lat"],
        "geo_lon": geo["lon"],
        "label": "malicious",
        "attack_type": attack_type,
        "mitre_technique": sig["mitre"],
        "is_known_bad_ip": use_bad_ip,
        "ip_reputation_score": round(random.uniform(0.65, 1.0), 3),
    }


def generate_log(malicious_ratio: float = 0.15, suspicious_ratio: float = 0.10) -> dict:
    """
    Generate a single log event with configurable class distribution.
    Default: 75% benign, 10% suspicious, 15% malicious
    """
    rand = random.random()
    if rand < malicious_ratio:
        return generate_malicious_log()
    elif rand < malicious_ratio + suspicious_ratio:
        return generate_suspicious_log()
    else:
        return generate_benign_log()


def generate_batch(
    size: int = 100,
    malicious_ratio: float = 0.15,
    suspicious_ratio: float = 0.10
) -> list[dict]:
    """Generate a batch of log events."""
    return [generate_log(malicious_ratio, suspicious_ratio) for _ in range(size)]


if __name__ == "__main__":
    # Standalone test: print 5 sample logs
    print("=== BENIGN ===")
    print(json.dumps(generate_benign_log(), indent=2))
    print("\n=== SUSPICIOUS ===")
    print(json.dumps(generate_suspicious_log(), indent=2))
    print("\n=== MALICIOUS ===")
    print(json.dumps(generate_malicious_log(), indent=2))
