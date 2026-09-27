"""
Telemetry Normalizer — Normalizes heterogeneous security logs (Suricata EVE, Auth logs, Synthetic)
into the standard CyberHawk Normalized Security Event format.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

# Known public threat IPs with approximate geolocation (public IPs only)
PUBLIC_GEO_REGISTRY = {
    "185.220.101.1": {"country": "DE", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821, "accuracy_radius_km": 25.0, "asn": "AS206238", "isp": "Tor Exit Node"},
    "192.42.116.14": {"country": "NL", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041, "accuracy_radius_km": 15.0, "asn": "AS1103", "isp": "SURFnet B.V."},
    "176.10.104.240": {"country": "CH", "city": "Zurich", "lat": 47.3769, "lon": 8.5417, "accuracy_radius_km": 20.0, "asn": "AS51852", "isp": "PrivateLayer AG"},
    "94.102.49.190": {"country": "NL", "city": "Rotterdam", "lat": 51.9244, "lon": 4.4777, "accuracy_radius_km": 30.0, "asn": "AS202425", "isp": "IP Volume Inc."},
    "198.96.155.3": {"country": "US", "city": "Seattle", "lat": 47.6062, "lon": -122.3321, "accuracy_radius_km": 40.0, "asn": "AS398324", "isp": "Tier 1 Provider"},
    "171.25.193.20": {"country": "SE", "city": "Stockholm", "lat": 59.3293, "lon": 18.0686, "accuracy_radius_km": 20.0, "asn": "AS42708", "isp": "Portlane AB"},
    "162.247.72.201": {"country": "US", "city": "New York", "lat": 40.7128, "lon": -74.0060, "accuracy_radius_km": 50.0, "asn": "AS397423", "isp": "TOR-EXIT"},
    "185.100.87.202": {"country": "RO", "city": "Bucharest", "lat": 44.4268, "lon": 26.1025, "accuracy_radius_km": 35.0, "asn": "AS60117", "isp": "HostSailor"},
    "45.142.212.100": {"country": "RU", "city": "Moscow", "lat": 55.7558, "lon": 37.6173, "accuracy_radius_km": 50.0, "asn": "AS200000", "isp": "Virtual Host LLC"},
    "91.108.4.0": {"country": "GB", "city": "London", "lat": 51.5074, "lon": -0.1278, "accuracy_radius_km": 30.0, "asn": "AS62041", "isp": "Telegram Messenger"},
}


def is_private_ip(ip: str) -> bool:
    """Check if an IPv4 address is an RFC1918 private / local address."""
    if not ip or not isinstance(ip, str):
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        first, second = int(parts[0]), int(parts[1])
        return (
            first == 10
            or first == 127
            or (first == 172 and 16 <= second <= 31)
            or (first == 192 and second == 168)
        )
    except ValueError:
        return False


def resolve_approx_geo(ip: str) -> dict:
    """
    Resolve approximate IP geolocation for public IPs.
    CRITICAL: Never invents coordinates for private internal IPs.
    """
    if is_private_ip(ip):
        return {
            "geo_country": None,
            "geo_city": None,
            "geo_lat": None,
            "geo_lon": None,
            "accuracy_radius_km": None,
            "is_private": True,
        }

    if ip in PUBLIC_GEO_REGISTRY:
        info = PUBLIC_GEO_REGISTRY[ip]
        return {
            "geo_country": info["country"],
            "geo_city": info["city"],
            "geo_lat": info["lat"],
            "geo_lon": info["lon"],
            "accuracy_radius_km": info["accuracy_radius_km"],
            "is_private": False,
        }

    # For unknown public IPs, do NOT fabricate exact cities/coordinates without GeoIP lookup
    return {
        "geo_country": "UNKNOWN",
        "geo_city": None,
        "geo_lat": None,
        "geo_lon": None,
        "accuracy_radius_km": None,
        "is_private": False,
    }


def normalize_event(
    event_id: Optional[str] = None,
    timestamp: Optional[str] = None,
    detection_source: str = "simulator",  # suricata | auth_log | zeek | simulator
    environment: str = "SIMULATED",       # SIMULATED | LAB | OBSERVED
    source_ip: str = "0.0.0.0",
    source_port: Optional[int] = None,
    destination_ip: str = "0.0.0.0",
    destination_port: Optional[int] = None,
    protocol: str = "TCP",
    event_type: str = "intrusion",        # intrusion | scan | authentication | flow | c2
    severity: str = "INFO",               # CRITICAL | HIGH | MEDIUM | LOW | INFO
    signature: Optional[str] = None,
    mitre_technique: Optional[str] = None,
    attack_type: Optional[str] = None,
    raw_event: Optional[dict] = None,
    # Network metrics for ML engine compatibility
    payload_size: int = 512,
    duration: float = 0.5,
    packet_count: int = 10,
    bytes_fwd: int = 2000,
    bytes_bwd: int = 1000,
    flag: str = "PSH-ACK",
    ip_reputation_score: float = 0.1,
    ground_truth_label: str = "benign",
) -> dict[str, Any]:
    """
    Produce a normalized security-event dictionary adhering strictly to the CyberHawk common schema.
    """
    eid = event_id or str(uuid.uuid4())
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    geo = resolve_approx_geo(source_ip)

    return {
        "id": eid,
        "event_id": eid,
        "timestamp": ts,
        "source": detection_source,
        "detection_source": detection_source,
        "environment": environment.upper(),
        "status": "NEW",

        # Network endpoints
        "src_ip": source_ip,
        "source_ip": source_ip,
        "src_port": source_port,
        "source_port": source_port,
        "dst_ip": destination_ip,
        "destination_ip": destination_ip,
        "dst_port": destination_port,
        "destination_port": destination_port,
        "protocol": protocol.upper(),

        # Threat classification
        "event_type": event_type,
        "severity": severity.upper(),
        "signature": signature,
        "mitre_technique": mitre_technique,
        "attack_type": attack_type,
        "service": signature or attack_type or f"{protocol}/{destination_port}",

        # Geolocation (approximate, public IPs only)
        "geo_country": geo["geo_country"],
        "geo_city": geo["geo_city"],
        "geo_lat": geo["geo_lat"],
        "geo_lon": geo["geo_lon"],
        "accuracy_radius_km": geo["accuracy_radius_km"],

        # Raw event envelope
        "raw_event": raw_event or {
            "source": detection_source,
            "environment": environment,
            "signature": signature,
            "src": f"{source_ip}:{source_port}",
            "dst": f"{destination_ip}:{destination_port}",
        },

        # Flow metrics for feature extraction / ML scoring
        "payload_size": payload_size,
        "duration": duration,
        "packet_count": packet_count,
        "bytes_fwd": bytes_fwd,
        "bytes_bwd": bytes_bwd,
        "flag": flag,
        "ip_reputation_score": ip_reputation_score,
        "label": ground_truth_label,
        "is_known_bad_ip": source_ip in PUBLIC_GEO_REGISTRY,
    }
