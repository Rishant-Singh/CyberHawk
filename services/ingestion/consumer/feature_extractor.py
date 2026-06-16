"""
Feature Extractor — Transforms raw log events into ML-ready feature vectors.
Performs normalization, encoding, and feature engineering.
"""

import math
from typing import Any


# ── Known bad IP set (loaded from threat intel) ───────────────────────────────
KNOWN_BAD_IPS = {
    "185.220.101.1", "192.42.116.14", "176.10.104.240",
    "94.102.49.190", "198.96.155.3", "171.25.193.20",
    "162.247.72.201", "185.100.87.202", "45.142.212.100",
    "91.108.4.0",
}

HIGH_RISK_COUNTRIES = {"KP", "IR", "RU", "CN"}
HIGH_RISK_PORTS = {22, 23, 3389, 4444, 5900, 31337, 8080, 8443}

PROTOCOL_MAP = {"TCP": 0, "UDP": 1, "ICMP": 2, "HTTP": 3, "HTTPS": 4, "DNS": 5}
FLAG_MAP = {
    "SYN": 0, "SYN-ACK": 1, "PSH-ACK": 2, "FIN-ACK": 3,
    "FIN": 4, "RST": 5, "ACK": 6, "URG": 7,
}


def _is_private_ip(ip: str) -> bool:
    """Check if IP is in private ranges."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    first, second = int(parts[0]), int(parts[1])
    return (
        first == 10
        or (first == 172 and 16 <= second <= 31)
        or (first == 192 and second == 168)
    )


def extract_features(log: dict) -> dict[str, Any]:
    """
    Extract a rich feature set from a raw log event.
    Returns both raw features and the normalized vector for ML inference.
    """
    src_ip = log.get("src_ip", "0.0.0.0")
    dst_port = log.get("dst_port", 0)
    protocol = log.get("protocol", "TCP")
    flag = log.get("flag", "ACK")
    payload_size = log.get("payload_size", 0)
    duration = log.get("duration", 0.001)
    packet_count = log.get("packet_count", 1)
    bytes_fwd = log.get("bytes_fwd", 0)
    bytes_bwd = log.get("bytes_bwd", 0)
    geo_country = log.get("geo_country", "US")
    ip_rep_score = log.get("ip_reputation_score", 0.0)

    # ── Derived features ──────────────────────────────────────────────────────
    bytes_per_packet = (bytes_fwd + bytes_bwd) / max(packet_count, 1)
    flow_rate = packet_count / max(duration, 0.001)
    fwd_bwd_ratio = bytes_fwd / max(bytes_bwd, 1)

    # Normalize payload size (log scale)
    payload_log = math.log1p(payload_size) / math.log1p(65535)
    duration_log = math.log1p(duration) / math.log1p(3600)
    packet_log = math.log1p(packet_count) / math.log1p(100000)
    flow_rate_log = math.log1p(flow_rate) / math.log1p(100000)
    bytes_per_pkt_log = math.log1p(bytes_per_packet) / math.log1p(65535)

    # Boolean flags
    is_bad_ip = 1 if src_ip in KNOWN_BAD_IPS else 0
    is_private_src = 1 if _is_private_ip(src_ip) else 0
    is_high_risk_country = 1 if geo_country in HIGH_RISK_COUNTRIES else 0
    is_high_risk_port = 1 if dst_port in HIGH_RISK_PORTS else 0
    is_privileged_port = 1 if dst_port < 1024 else 0

    proto_encoded = PROTOCOL_MAP.get(protocol, 0) / len(PROTOCOL_MAP)
    flag_encoded = FLAG_MAP.get(flag, 0) / len(FLAG_MAP)
    port_normalized = min(dst_port / 65535, 1.0)

    return {
        # Metadata (not used for ML)
        "log_id": log.get("id"),
        "timestamp": log.get("timestamp"),
        "src_ip": src_ip,
        "dst_ip": log.get("dst_ip"),
        "src_port": log.get("src_port"),
        "dst_port": dst_port,
        "geo_country": geo_country,
        "geo_city": log.get("geo_city"),
        "geo_lat": log.get("geo_lat"),
        "geo_lon": log.get("geo_lon"),
        "protocol": protocol,
        "service": log.get("service"),
        "attack_type": log.get("attack_type"),
        "mitre_technique": log.get("mitre_technique"),
        "ground_truth_label": log.get("label", "unknown"),

        # Feature vector (used for ML inference)
        "features": [
            payload_log,          # 0: payload size (log-normalized)
            duration_log,         # 1: flow duration (log-normalized)
            packet_log,           # 2: packet count (log-normalized)
            flow_rate_log,        # 3: packets/second (log-normalized)
            bytes_per_pkt_log,    # 4: bytes per packet (log-normalized)
            fwd_bwd_ratio / 100,  # 5: fwd/bwd ratio (capped)
            proto_encoded,        # 6: protocol (encoded)
            flag_encoded,         # 7: TCP flag (encoded)
            port_normalized,      # 8: destination port (normalized)
            is_bad_ip,            # 9: known bad IP flag
            is_private_src,       # 10: private source IP flag
            is_high_risk_country, # 11: high-risk country flag
            is_high_risk_port,    # 12: high-risk port flag
            is_privileged_port,   # 13: privileged port flag
            ip_rep_score,         # 14: IP reputation score
        ],
        "feature_names": [
            "payload_size_log", "duration_log", "packet_count_log",
            "flow_rate_log", "bytes_per_pkt_log", "fwd_bwd_ratio",
            "protocol_encoded", "flag_encoded", "dst_port_normalized",
            "is_known_bad_ip", "is_private_src", "is_high_risk_country",
            "is_high_risk_port", "is_privileged_port", "ip_reputation_score",
        ],
    }
