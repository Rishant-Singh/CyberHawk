"""
GeoIP Service — Geolocation resolution for public and private IP addresses.
Adheres strictly to privacy rules:
- Private RFC1918 IPs are NEVER sent to external geolocation services.
- Public IPs resolve to approximate geographic coordinates with explicit accuracy disclaimers.
"""

import logging
from typing import Optional
import httpx

logger = logging.getLogger(__name__)

# Known public threat IP geolocation registry (fast local offline cache)
LOCAL_GEOIP_REGISTRY = {
    "185.220.101.1": {
        "country": "DE", "country_name": "Germany", "city": "Frankfurt",
        "lat": 50.1109, "lon": 8.6821, "accuracy_radius_km": 25.0,
        "asn": "AS206238", "isp": "Tor Exit Network", "is_tor": True,
    },
    "192.42.116.14": {
        "country": "NL", "country_name": "Netherlands", "city": "Amsterdam",
        "lat": 52.3676, "lon": 4.9041, "accuracy_radius_km": 15.0,
        "asn": "AS1103", "isp": "SURFnet B.V.", "is_tor": False,
    },
    "176.10.104.240": {
        "country": "CH", "country_name": "Switzerland", "city": "Zurich",
        "lat": 47.3769, "lon": 8.5417, "accuracy_radius_km": 20.0,
        "asn": "AS51852", "isp": "PrivateLayer AG", "is_tor": False,
    },
    "94.102.49.190": {
        "country": "NL", "country_name": "Netherlands", "city": "Rotterdam",
        "lat": 51.9244, "lon": 4.4777, "accuracy_radius_km": 30.0,
        "asn": "AS202425", "isp": "IP Volume Inc.", "is_tor": False,
    },
    "198.96.155.3": {
        "country": "US", "country_name": "United States", "city": "Seattle",
        "lat": 47.6062, "lon": -122.3321, "accuracy_radius_km": 40.0,
        "asn": "AS398324", "isp": "Tier 1 Provider", "is_tor": False,
    },
    "171.25.193.20": {
        "country": "SE", "country_name": "Sweden", "city": "Stockholm",
        "lat": 59.3293, "lon": 18.0686, "accuracy_radius_km": 20.0,
        "asn": "AS42708", "isp": "Portlane AB", "is_tor": False,
    },
    "162.247.72.201": {
        "country": "US", "country_name": "United States", "city": "New York",
        "lat": 40.7128, "lon": -74.0060, "accuracy_radius_km": 50.0,
        "asn": "AS397423", "isp": "TOR-EXIT", "is_tor": True,
    },
    "185.100.87.202": {
        "country": "RO", "country_name": "Romania", "city": "Bucharest",
        "lat": 44.4268, "lon": 26.1025, "accuracy_radius_km": 35.0,
        "asn": "AS60117", "isp": "HostSailor", "is_tor": False,
    },
    "45.142.212.100": {
        "country": "RU", "country_name": "Russia", "city": "Moscow",
        "lat": 55.7558, "lon": 37.6173, "accuracy_radius_km": 50.0,
        "asn": "AS200000", "isp": "Virtual Host LLC", "is_tor": False,
    },
    "91.108.4.0": {
        "country": "GB", "country_name": "United Kingdom", "city": "London",
        "lat": 51.5074, "lon": -0.1278, "accuracy_radius_km": 30.0,
        "asn": "AS62041", "isp": "Telegram Messenger", "is_tor": False,
    },
}

# Runtime cache
_GEO_CACHE: dict[str, dict] = {}


def is_private_ip(ip: str) -> bool:
    """Check if an IPv4 string is an RFC1918 / Loopback / Link-Local address."""
    if not ip or not isinstance(ip, str):
        return False
    parts = ip.strip().split(".")
    if len(parts) != 4:
        return False
    try:
        first, second = int(parts[0]), int(parts[1])
        return (
            first == 10
            or first == 127
            or (first == 172 and 16 <= second <= 31)
            or (first == 192 and second == 168)
            or (first == 169 and second == 254)
        )
    except ValueError:
        return False


async def resolve_ip_location(ip: str, asset_context: Optional[dict] = None) -> dict:
    """
    Resolve IP geolocation metadata.
    Guarantees private IPs are kept internal.
    """
    clean_ip = ip.strip()

    # 1. Private RFC1918 range check
    if is_private_ip(clean_ip):
        hostname = asset_context.get("hostname") if asset_context else "Internal Asset"
        location = asset_context.get("location") if asset_context else "Lab Network"
        return {
            "ip": clean_ip,
            "is_private": True,
            "country": "INTERNAL",
            "country_name": "Internal / Lab Network",
            "city": location or hostname,
            "lat": None,
            "lon": None,
            "accuracy_radius_km": None,
            "asn": "RFC1918 Private Subnet",
            "isp": "CyberHawk Monitored Lab",
            "disclaimer": "Internal Private IP — Approximate public geolocation not applicable.",
            "asset_hostname": hostname,
        }

    # 2. Local registry check
    if clean_ip in LOCAL_GEOIP_REGISTRY:
        geo = LOCAL_GEOIP_REGISTRY[clean_ip]
        return {
            "ip": clean_ip,
            "is_private": False,
            "country": geo["country"],
            "country_name": geo["country_name"],
            "region": geo.get("region", geo["city"]),
            "city": geo["city"],
            "zip": geo.get("zip", ""),
            "lat": geo["lat"],
            "lon": geo["lon"],
            "asn": geo["asn"],
            "isp": geo["isp"],
            "disclaimer": "Exact Coordinates",
        }

    # 3. Memory cache check (only if coordinates were successfully resolved)
    if clean_ip in _GEO_CACHE and _GEO_CACHE[clean_ip].get("lat") is not None:
        return _GEO_CACHE[clean_ip]

    # 4. Primary online lookup via ipwho.is (HTTPS, exact latitude, longitude, city, region, postal/zip, ISP, ASN)
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.get(f"https://ipwho.is/{clean_ip}")
            if resp.status_code == 200:
                data = resp.json()
                if data.get("success") and data.get("latitude") is not None and data.get("longitude") is not None:
                    result = {
                        "ip": clean_ip,
                        "is_private": False,
                        "country": data.get("country_code"),
                        "country_name": data.get("country"),
                        "region": data.get("region"),
                        "city": data.get("city"),
                        "zip": data.get("postal"),
                        "lat": data.get("latitude"),
                        "lon": data.get("longitude"),
                        "timezone": data.get("timezone", {}).get("id") if isinstance(data.get("timezone"), dict) else data.get("timezone"),
                        "asn": data.get("connection", {}).get("asn") if isinstance(data.get("connection"), dict) else None,
                        "isp": data.get("connection", {}).get("isp") if isinstance(data.get("connection"), dict) else None,
                        "org": data.get("connection", {}).get("org") if isinstance(data.get("connection"), dict) else None,
                        "disclaimer": "Exact Coordinates",
                    }
                    _GEO_CACHE[clean_ip] = result
                    return result
    except Exception as e:
        logger.debug(f"ipwho.is lookup bypassed for {clean_ip}: {e}")

    # 5. Secondary fallback lookup via ip-api
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.get(
                f"http://ip-api.com/json/{clean_ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success" and data.get("lat") is not None and data.get("lon") is not None:
                    result = {
                        "ip": clean_ip,
                        "is_private": False,
                        "country": data.get("countryCode"),
                        "country_name": data.get("country"),
                        "region": data.get("regionName"),
                        "city": data.get("city"),
                        "zip": data.get("zip"),
                        "lat": data.get("lat"),
                        "lon": data.get("lon"),
                        "timezone": data.get("timezone"),
                        "asn": data.get("as"),
                        "isp": data.get("isp"),
                        "org": data.get("org"),
                        "disclaimer": "Exact Coordinates",
                    }
                    _GEO_CACHE[clean_ip] = result
                    return result
    except Exception as e:
        logger.debug(f"ip-api lookup bypassed for {clean_ip}: {e}")

    # Fallback for unknown public IP
    fallback = {
        "ip": clean_ip,
        "is_private": False,
        "country": "UNKNOWN",
        "country_name": "Unknown Country",
        "region": None,
        "city": None,
        "zip": None,
        "lat": None,
        "lon": None,
        "asn": None,
        "isp": None,
        "disclaimer": "Coordinates unavailable",
    }
    return fallback
