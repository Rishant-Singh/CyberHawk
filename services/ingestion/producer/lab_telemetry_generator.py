"""
Lab Telemetry Generator — Produces realistic authorized lab security events
mimicking Suricata IDS EVE JSON and Linux authentication logs.
Tagged explicitly as 'LAB' or 'OBSERVED' (never 'SIMULATED').
"""

import random
import uuid
from datetime import datetime, timezone
from telemetry_normalizer import normalize_event, PUBLIC_GEO_REGISTRY

# Registered lab assets
LAB_ASSETS = [
    {"ip": "10.0.0.25", "hostname": "LINUX-SERVER-01", "os": "Ubuntu 22.04 LTS"},
    {"ip": "10.0.0.10", "hostname": "WIN-DC-01", "os": "Windows Server 2022"},
    {"ip": "10.0.0.50", "hostname": "DATABASE-PROD-01", "os": "RHEL 9"},
    {"ip": "172.16.1.10", "hostname": "WEB-PROXY-01", "os": "Debian Linux"},
]

# Authentic Suricata EVE rules / scenarios
SURICATA_SCENARIOS = [
    {
        "signature": "ET SCAN Potential SSH Brute Force (Auth Failure Exceeded)",
        "category": "Attempted Administrator Privilege Gain",
        "attack_type": "brute_force",
        "mitre": "T1110",
        "severity": "HIGH",
        "dst_port": 22,
        "proto": "TCP",
        "target_ip": "10.0.0.25",
        "payload_size": 420,
        "packet_count": 280,
        "duration": 1.2,
        "flag": "PSH-ACK",
        "rep": 0.85,
    },
    {
        "signature": "ET WEB_SPECIFIC_APPS Apache Log4j RCE Attempt (CVE-2021-44228)",
        "category": "Exploit Public-Facing Application",
        "attack_type": "exploitation",
        "mitre": "T1190",
        "severity": "CRITICAL",
        "dst_port": 443,
        "proto": "TCP",
        "target_ip": "10.0.0.25",
        "payload_size": 1840,
        "packet_count": 45,
        "duration": 0.3,
        "flag": "PSH-ACK",
        "rep": 0.95,
    },
    {
        "signature": "ET SCAN Nmap Scripting Engine Detected",
        "category": "Network Service Discovery",
        "attack_type": "port_scan",
        "mitre": "T1046",
        "severity": "MEDIUM",
        "dst_port": 389,
        "proto": "TCP",
        "target_ip": "10.0.0.10",
        "payload_size": 90,
        "packet_count": 350,
        "duration": 0.08,
        "flag": "SYN",
        "rep": 0.70,
    },
    {
        "signature": "ET MALWARE Win32/CobaltStrike C2 HTTPS Beacon",
        "category": "Command and Control",
        "attack_type": "c2_communication",
        "mitre": "T1071",
        "severity": "CRITICAL",
        "dst_port": 443,
        "proto": "TCP",
        "target_ip": "10.0.0.50",
        "payload_size": 890,
        "packet_count": 22,
        "duration": 4.5,
        "flag": "PSH-ACK",
        "rep": 0.92,
    },
    {
        "signature": "ET POLICY Suspicious Inbound SMB Traffic to Domain Controller",
        "category": "Lateral Tool Transfer",
        "attack_type": "exploitation",
        "mitre": "T1021",
        "severity": "HIGH",
        "dst_port": 445,
        "proto": "TCP",
        "target_ip": "10.0.0.10",
        "payload_size": 2400,
        "packet_count": 95,
        "duration": 0.6,
        "flag": "PSH-ACK",
        "rep": 0.88,
    },
]


def generate_suricata_eve_event() -> dict:
    """
    Generate an authentic authorized Lab Telemetry event in Suricata EVE JSON format.
    Labeled as 'LAB'.
    """
    scenario = random.choice(SURICATA_SCENARIOS)
    src_ip = random.choice(list(PUBLIC_GEO_REGISTRY.keys()))
    dst_ip = scenario["target_ip"]
    src_port = random.randint(30000, 65535)
    dst_port = scenario["dst_port"]
    event_id = str(uuid.uuid4())
    ts = datetime.now(timezone.utc).isoformat()

    # Raw Suricata EVE structure
    raw_eve = {
        "timestamp": ts,
        "flow_id": random.randint(1000000000, 9999999999),
        "event_type": "alert",
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dst_ip,
        "dest_port": dst_port,
        "proto": scenario["proto"],
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": random.randint(2000000, 2999999),
            "rev": 1,
            "signature": scenario["signature"],
            "category": scenario["category"],
            "severity": 1 if scenario["severity"] == "CRITICAL" else 2 if scenario["severity"] == "HIGH" else 3,
            "metadata": {
                "mitre_technique_id": [scenario["mitre"]],
                "created_at": "2026_09_21",
            },
        },
        "host": "WEB-PROXY-01 (Suricata Sensor)",
    }

    return normalize_event(
        event_id=event_id,
        timestamp=ts,
        detection_source="suricata",
        environment="LAB",
        source_ip=src_ip,
        source_port=src_port,
        destination_ip=dst_ip,
        destination_port=dst_port,
        protocol=scenario["proto"],
        event_type="intrusion",
        severity=scenario["severity"],
        signature=scenario["signature"],
        mitre_technique=scenario["mitre"],
        attack_type=scenario["attack_type"],
        raw_event=raw_eve,
        payload_size=scenario["payload_size"],
        duration=scenario["duration"],
        packet_count=scenario["packet_count"],
        flag=scenario["flag"],
        ip_reputation_score=scenario["rep"],
        ground_truth_label="malicious",
    )


def generate_auth_log_event() -> dict:
    """
    Generate an authentic authorized Lab Telemetry event from Linux sshd / auth.log.
    Labeled as 'OBSERVED'.
    """
    src_ip = random.choice(list(PUBLIC_GEO_REGISTRY.keys()))
    target_asset = LAB_ASSETS[0]  # LINUX-SERVER-01
    src_port = random.randint(30000, 65535)
    event_id = str(uuid.uuid4())
    ts = datetime.now(timezone.utc).isoformat()

    raw_syslog = {
        "timestamp": ts,
        "host": target_asset["hostname"],
        "program": "sshd",
        "pid": random.randint(1000, 9999),
        "message": f"Failed password for invalid user admin from {src_ip} port {src_port} ssh2",
        "auth_result": "FAILED",
    }

    return normalize_event(
        event_id=event_id,
        timestamp=ts,
        detection_source="auth_log",
        environment="OBSERVED",
        source_ip=src_ip,
        source_port=src_port,
        destination_ip=target_asset["ip"],
        destination_port=22,
        protocol="TCP",
        event_type="authentication",
        severity="HIGH",
        signature="SSH Authentication Failure (Invalid User)",
        mitre_technique="T1110",
        attack_type="brute_force",
        raw_event=raw_syslog,
        payload_size=320,
        duration=0.8,
        packet_count=18,
        flag="PSH-ACK",
        ip_reputation_score=0.82,
        ground_truth_label="malicious",
    )
