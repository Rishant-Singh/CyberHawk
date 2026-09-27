"""
Log Generator — CICIDS-style synthetic network traffic generator + authorized Lab Telemetry.
Produces normalized events with clear environment labels ('SIMULATED', 'LAB', 'OBSERVED').
"""

import os
import sys
import random
import uuid
import json
from datetime import datetime, timezone
from faker import Faker

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from telemetry_normalizer import normalize_event, PUBLIC_GEO_REGISTRY
from lab_telemetry_generator import generate_suricata_eve_event, generate_auth_log_event

fake = Faker()

# Known malicious external IPs
KNOWN_BAD_IPS = list(PUBLIC_GEO_REGISTRY.keys())

# Internal network ranges (source IPs for internal traffic)
INTERNAL_RANGES = [
    "10.0.{}.{}",
    "192.168.1.{}",
    "172.16.{}.{}",
]

COMMON_PORTS = {
    "HTTP": 80, "HTTPS": 443, "SSH": 22, "FTP": 21,
    "DNS": 53, "SMTP": 25, "RDP": 3389, "SMB": 445,
    "MySQL": 3306, "PostgreSQL": 5432, "Redis": 6379,
    "Elasticsearch": 9200, "MongoDB": 27017,
}

ATTACK_SIGNATURES = {
    "port_scan": {
        "packet_count_range": (50, 500),
        "payload_size_range": (0, 64),
        "duration_range": (0.001, 0.1),
        "flag": "SYN",
        "mitre": "T1046",
        "signature": "SYN Stealth Network Sweep",
        "severity": "MEDIUM",
    },
    "brute_force": {
        "packet_count_range": (100, 1000),
        "payload_size_range": (200, 800),
        "duration_range": (0.1, 2.0),
        "flag": "PSH-ACK",
        "mitre": "T1110",
        "signature": "Repeated Credential Guessing Pattern",
        "severity": "HIGH",
    },
    "ddos": {
        "packet_count_range": (1000, 50000),
        "payload_size_range": (64, 1500),
        "duration_range": (1.0, 60.0),
        "flag": "SYN",
        "mitre": "T1498",
        "signature": "Volumetric Denial of Service Flood",
        "severity": "CRITICAL",
    },
    "data_exfiltration": {
        "packet_count_range": (20, 200),
        "payload_size_range": (5000, 65000),
        "duration_range": (5.0, 120.0),
        "flag": "PSH-ACK",
        "mitre": "T1041",
        "signature": "Anomalous High-Volume Outbound Transfer",
        "severity": "CRITICAL",
    },
    "c2_communication": {
        "packet_count_range": (5, 50),
        "payload_size_range": (100, 2000),
        "duration_range": (0.5, 10.0),
        "flag": "PSH-ACK",
        "mitre": "T1071",
        "signature": "Periodic Encrypted Beacon to Untrusted Host",
        "severity": "CRITICAL",
    },
    "exploitation": {
        "packet_count_range": (10, 100),
        "payload_size_range": (500, 8000),
        "duration_range": (0.1, 5.0),
        "flag": "PSH-ACK",
        "mitre": "T1190",
        "signature": "Remote Code Execution Exploit Payload",
        "severity": "CRITICAL",
    },
}

PROTOCOLS = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"]


def _random_internal_ip() -> str:
    template = random.choice(INTERNAL_RANGES)
    if template.count("{}") == 2:
        return template.format(random.randint(0, 255), random.randint(1, 254))
    return template.format(random.randint(1, 254))


def _random_external_ip() -> str:
    return f"{random.randint(1, 254)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def generate_benign_log() -> dict:
    """Generate a simulated normal network flow event."""
    service, port = random.choice(list(COMMON_PORTS.items()))
    src_ip = _random_internal_ip()
    dst_ip = _random_external_ip()

    return normalize_event(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        detection_source="simulator",
        environment="SIMULATED",
        source_ip=src_ip,
        source_port=random.randint(1024, 65535),
        destination_ip=dst_ip,
        destination_port=port,
        protocol=random.choice(["TCP", "UDP"]),
        event_type="flow",
        severity="INFO",
        signature=f"Normal {service} Session",
        payload_size=random.randint(64, 4096),
        duration=round(random.uniform(0.01, 5.0), 4),
        packet_count=random.randint(1, 30),
        flag=random.choice(["SYN-ACK", "PSH-ACK", "FIN-ACK"]),
        bytes_fwd=random.randint(100, 50000),
        bytes_bwd=random.randint(100, 50000),
        ip_reputation_score=round(random.uniform(0.0, 0.2), 3),
        ground_truth_label="benign",
    )


def generate_suspicious_log() -> dict:
    """Generate a simulated suspicious network event."""
    service, port = random.choice(list(COMMON_PORTS.items()))
    src_ip = _random_external_ip()
    dst_ip = _random_internal_ip()

    return normalize_event(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        detection_source="simulator",
        environment="SIMULATED",
        source_ip=src_ip,
        source_port=random.randint(1024, 65535),
        destination_ip=dst_ip,
        destination_port=random.randint(1, 1023),
        protocol=random.choice(["TCP", "UDP"]),
        event_type="scan",
        severity="LOW",
        signature="Suspicious Privileged Port Access Attempt",
        payload_size=random.randint(2000, 10000),
        duration=round(random.uniform(0.001, 0.5), 4),
        packet_count=random.randint(30, 100),
        flag=random.choice(["SYN", "RST", "FIN"]),
        bytes_fwd=random.randint(500, 10000),
        bytes_bwd=random.randint(100, 5000),
        ip_reputation_score=round(random.uniform(0.3, 0.6), 3),
        ground_truth_label="suspicious",
    )


def generate_malicious_log(attack_type: str = None) -> dict:
    """Generate a simulated attack network event based on signature templates."""
    if attack_type is None:
        attack_type = random.choice(list(ATTACK_SIGNATURES.keys()))

    sig = ATTACK_SIGNATURES[attack_type]
    use_bad_ip = random.random() < 0.6
    src_ip = random.choice(KNOWN_BAD_IPS) if use_bad_ip else _random_external_ip()
    dst_ip = _random_internal_ip()

    return normalize_event(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        detection_source="simulator",
        environment="SIMULATED",
        source_ip=src_ip,
        source_port=random.randint(1024, 65535),
        destination_ip=dst_ip,
        destination_port=random.choice([22, 80, 443, 3389, 445, 8080, 4444, 31337]),
        protocol=random.choice(PROTOCOLS),
        event_type="intrusion",
        severity=sig["severity"],
        signature=sig["signature"],
        mitre_technique=sig["mitre"],
        attack_type=attack_type,
        payload_size=random.randint(*sig["payload_size_range"]),
        duration=round(random.uniform(*sig["duration_range"]), 4),
        packet_count=random.randint(*sig["packet_count_range"]),
        flag=sig["flag"],
        bytes_fwd=random.randint(1000, 100000),
        bytes_bwd=random.randint(100, 5000),
        ip_reputation_score=round(random.uniform(0.65, 1.0), 3) if use_bad_ip else round(random.uniform(0.5, 0.8), 3),
        ground_truth_label="malicious",
    )


def generate_log(malicious_ratio: float = 0.15, suspicious_ratio: float = 0.10) -> dict:
    """
    Generate a normalized security event.
    Distinguishes between LAB telemetry, OBSERVED telemetry, and SIMULATED traffic.
    """
    # 20% of generated stream represents authentic Lab / Observed Telemetry
    dice = random.random()
    if dice < 0.12:
        return generate_suricata_eve_event()  # LAB telemetry (Suricata EVE)
    elif dice < 0.18:
        return generate_auth_log_event()      # OBSERVED telemetry (Linux auth.log)

    # Remaining 80% represents synthetic flow traffic labeled SIMULATED
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
    """Generate a batch of normalized security log events."""
    return [generate_log(malicious_ratio, suspicious_ratio) for _ in range(size)]


if __name__ == "__main__":
    print("=== LAB SURICATA TELEMETRY ===")
    print(json.dumps(generate_suricata_eve_event(), indent=2))
    print("\n=== OBSERVED AUTH LOG ===")
    print(json.dumps(generate_auth_log_event(), indent=2))
    print("\n=== SIMULATED BENIGN FLOW ===")
    print(json.dumps(generate_benign_log(), indent=2))
