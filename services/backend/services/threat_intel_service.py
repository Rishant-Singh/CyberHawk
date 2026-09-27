"""
Threat Intelligence Enrichment Service — Optional AbuseIPDB and VirusTotal lookup.
Features:
- Reads API keys from environment (ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY).
- If keys are missing, degrades gracefully with 'Enrichment unavailable'.
- In-memory cache to prevent redundant API calls.
"""

import os
import logging
from typing import Optional
import httpx

logger = logging.getLogger(__name__)

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()

# Local in-memory enrichment cache
_INTEL_CACHE: dict[str, dict] = {}


async def enrich_ioc(ioc_value: str, ioc_type: str) -> dict:
    """
    Enrich an IOC with public threat intelligence feeds if configured.
    Guarantees no crashes on missing keys or network failures.
    """
    val = ioc_value.strip()

    if val in _INTEL_CACHE:
        return _INTEL_CACHE[val]

    result = {
        "ioc": val,
        "ioc_type": ioc_type,
        "is_enriched": False,
        "abuseipdb": None,
        "virustotal": None,
        "reputation_summary": "No external threat intel key configured.",
    }

    # 1. AbuseIPDB (for IP addresses)
    if ioc_type in ("ip", "ipv4", "ipv6") and ABUSEIPDB_API_KEY:
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
                resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers=headers,
                    params={"ipAddress": val, "maxAgeInDays": 30, "verbose": True},
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    result["abuseipdb"] = {
                        "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                        "total_reports": data.get("totalReports", 0),
                        "country_code": data.get("countryCode"),
                        "usage_type": data.get("usageType"),
                        "isp": data.get("isp"),
                        "domain": data.get("domain"),
                        "is_tor": data.get("isTor", False),
                        "last_reported_at": data.get("lastReportedAt"),
                    }
                    result["is_enriched"] = True
                    result["reputation_summary"] = (
                        f"AbuseIPDB Confidence: {data.get('abuseConfidenceScore', 0)}% "
                        f"across {data.get('totalReports', 0)} reports."
                    )
        except Exception as e:
            logger.debug(f"AbuseIPDB query failed: {e}")

    # 2. VirusTotal (for IP, domain, hash, URL)
    if VIRUSTOTAL_API_KEY:
        try:
            endpoint_type = "ip_addresses" if "ip" in ioc_type else "files" if "hash" in ioc_type else "domains"
            async with httpx.AsyncClient(timeout=4.0) as client:
                headers = {"x-apikey": VIRUSTOTAL_API_KEY}
                resp = await client.get(
                    f"https://www.virustotal.com/api/v3/{endpoint_type}/{val}",
                    headers=headers,
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    result["virustotal"] = {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                    }
                    result["is_enriched"] = True
        except Exception as e:
            logger.debug(f"VirusTotal query failed: {e}")

    # Cache positive or negative result
    _INTEL_CACHE[val] = result
    return result
