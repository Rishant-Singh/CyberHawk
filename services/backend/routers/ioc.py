"""
IOC Search Router — SOC-grade investigation engine for IPs, domains, hashes, URLs, and CVEs.
Enriches IOCs with:
- Related CyberHawk alerts and observations
- Related active incidents
- Affected internal assets
- GeoIP metadata with privacy shielding for RFC1918 internal IPs
- Optional external threat intelligence (AbuseIPDB, VirusTotal)
"""

import re
import logging
from typing import Optional
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query, HTTPException, Path
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, or_, func

from core.database import get_db
from core.security import get_current_user
from models.alert import Alert
from models.incident import Incident
from models.asset import Asset
from models.ioc import IOC
from services.geoip_service import resolve_ip_location, is_private_ip
from services.threat_intel_service import enrich_ioc

router = APIRouter()
logger = logging.getLogger(__name__)


def detect_ioc_type(value: str) -> str:
    """Accurately identify IOC format: IPv4, IPv6, Domain, URL, Hash (MD5/SHA1/SHA256), CVE."""
    val = value.strip().lower()
    
    # 1. CVE format (e.g. CVE-2021-44228)
    if re.match(r"^cve-\d{4}-\d{4,8}$", val):
        return "cve"
    
    # 2. IPv4
    parts = val.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return "ipv4"
    
    # 3. IPv6
    if ":" in val and len(val.split(":")) >= 3:
        return "ipv6"
    
    # 4. Hashes
    if re.match(r"^[a-f0-9]{32}$", val):
        return "hash_md5"
    if re.match(r"^[a-f0-9]{40}$", val):
        return "hash_sha1"
    if re.match(r"^[a-f0-9]{64}$", val):
        return "hash_sha256"
    
    # 5. URL
    if val.startswith("http://") or val.startswith("https://") or "/" in val:
        return "url"
    
    # 6. Domain or Hostname
    if "." in val and not val.endswith("."):
        return "domain"
    
    return "hostname"


@router.get("/search")
async def search_ioc(
    query: str = Query(..., min_length=1, description="IP address, domain, hash, URL, or CVE"),
    ioc_type: Optional[str] = Query(None, description="ipv4 | ipv6 | domain | url | hash | cve | auto"),
    days: int = Query(30, ge=1, le=365, description="Lookback window in days"),
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    """
    Search across alerts, incidents, assets, and threat intel for an IOC.
    """
    q = query.strip()
    detected_type = detect_ioc_type(q) if (not ioc_type or ioc_type == "auto") else ioc_type.lower()
    since = datetime.now(timezone.utc) - timedelta(days=days)

    # ── 1. Check dedicated IOC table ──────────────────────────────────────────
    ioc_record = (await db.execute(
        select(IOC).where(func.lower(IOC.ioc_value) == q.lower())
    )).scalars().first()

    # ── 2. Check Matching Alerts ──────────────────────────────────────────────
    if "ip" in detected_type:
        db_filter = or_(Alert.src_ip == q, Alert.dst_ip == q)
    elif "cve" in detected_type:
        db_filter = or_(Alert.explanation.ilike(f"%{q}%"), Alert.attack_type.ilike(f"%{q}%"))
    elif "hash" in detected_type or detected_type in ("domain", "url"):
        db_filter = or_(Alert.explanation.ilike(f"%{q}%"), Alert.service.ilike(f"%{q}%"))
    else:
        db_filter = or_(Alert.src_ip.ilike(f"%{q}%"), Alert.explanation.ilike(f"%{q}%"))

    result = await db.execute(
        select(Alert)
        .where(db_filter, Alert.timestamp >= since)
        .order_by(desc(Alert.timestamp))
        .limit(100)
    )
    alerts = result.scalars().all()
    total_hits = len(alerts)

    # ── 3. Check Related Assets ───────────────────────────────────────────────
    # If the IOC is an internal asset IP or matches a hostname
    related_assets = []
    asset_result = await db.execute(
        select(Asset).where(
            or_(Asset.ip_address == q, Asset.hostname.ilike(f"%{q}%"))
        )
    )
    direct_asset = asset_result.scalars().first()
    if direct_asset:
        related_assets.append(_serialize_asset(direct_asset))

    # Also check if this IOC targeted any internal assets as destination
    if "ip" in detected_type and alerts:
        target_ips = list({a.dst_ip for a in alerts if a.dst_ip and a.dst_ip != q})
        if target_ips:
            targeted_assets = (await db.execute(
                select(Asset).where(Asset.ip_address.in_(target_ips[:10]))
            )).scalars().all()
            for ta in targeted_assets:
                if ta.id not in [ra["id"] for ra in related_assets]:
                    related_assets.append(_serialize_asset(ta))

    # ── 4. Check Related Incidents ────────────────────────────────────────────
    incident_conditions = []
    if "ip" in detected_type:
        incident_conditions.append(or_(Incident.source_ip == q, Incident.destination_ip == q))
    incident_conditions.append(Incident.title.ilike(f"%{q}%"))
    incident_conditions.append(Incident.description.ilike(f"%{q}%"))

    incidents_result = await db.execute(
        select(Incident).where(or_(*incident_conditions)).limit(10)
    )
    incidents = incidents_result.scalars().all()

    # ── 5. Resolve Geolocation (with privacy rules) ───────────────────────────
    asset_ctx = {"hostname": direct_asset.hostname, "location": direct_asset.location} if direct_asset else None
    geo_data = await resolve_ip_location(q, asset_context=asset_ctx) if "ip" in detected_type else None

    # ── 6. Threat Intelligence Enrichment ─────────────────────────────────────
    intel_data = await enrich_ioc(q, detected_type)

    # Calculate reputation & scores
    threat_scores = [a.threat_score for a in alerts]
    max_score = max(threat_scores) if threat_scores else (ioc_record.risk_score if ioc_record else 0)
    avg_score = (sum(threat_scores) / len(threat_scores)) if threat_scores else max_score

    if max_score >= 80 or (ioc_record and ioc_record.threat_level == "CRITICAL"):
        reputation = "malicious"
    elif max_score >= 60 or (ioc_record and ioc_record.threat_level == "HIGH"):
        reputation = "suspicious"
    elif max_score >= 30:
        reputation = "potentially_unwanted"
    elif alerts or ioc_record:
        reputation = "clean"
    elif intel_data and (intel_data.get("abuseipdb") or {}).get("abuse_confidence_score", 0) > 20:
        score = intel_data["abuseipdb"]["abuse_confidence_score"]
        reputation = "malicious" if score >= 80 else "suspicious"
        max_score = score
        avg_score = score
    else:
        reputation = "clean"

    first_seen = alerts[-1].timestamp.isoformat() if alerts else (ioc_record.first_seen.isoformat() if ioc_record else None)
    last_seen = alerts[0].timestamp.isoformat() if alerts else (ioc_record.last_seen.isoformat() if ioc_record else None)
    attack_types = list({a.attack_type for a in alerts if a.attack_type})
    mitre_techniques = list({a.mitre_technique for a in alerts if a.mitre_technique})

    # Group timeline by day
    timeline_dict: dict = {}
    for a in alerts:
        day = a.timestamp.strftime("%Y-%m-%d")
        timeline_dict[day] = timeline_dict.get(day, 0) + 1

    has_geo = bool(geo_data and geo_data.get("lat") is not None and geo_data.get("lon") is not None)

    return {
        "query": q,
        "ioc": q,
        "ioc_type": detected_type,
        "found": bool(alerts or ioc_record or direct_asset or incidents or has_geo),
        "total_hits": total_hits or (ioc_record.hit_count if ioc_record else 0),
        "reputation": reputation,
        "risk_score": round(avg_score, 1),
        "max_score": max_score,
        "threat_level": "CRITICAL" if max_score >= 80 else "HIGH" if max_score >= 60 else "MEDIUM" if max_score >= 30 else "LOW",
        
        # Geolocation & ISP
        "geo": geo_data,
        "can_view_map": has_geo,
        "is_private_ip": is_private_ip(q) if "ip" in detected_type else False,

        # Activity Tracking
        "first_seen": first_seen,
        "last_seen": last_seen,
        "occurrences": total_hits or (ioc_record.hit_count if ioc_record else 0),
        
        # Threat Context
        "attack_types": attack_types,
        "mitre_techniques": mitre_techniques,
        "threat_intelligence": intel_data,

        # Connected SOC Entities
        "related_incidents": [
            {
                "id": inc.id,
                "title": inc.title,
                "severity": inc.severity,
                "status": inc.status,
                "created_at": inc.created_at.isoformat() if inc.created_at else None,
            }
            for inc in incidents
        ],
        "related_assets": related_assets,

        # Timeline
        "timeline": [{"date": k, "count": v} for k, v in sorted(timeline_dict.items())],

        # Recent Alert History
        "alerts": [
            {
                "id": a.id,
                "timestamp": a.timestamp.isoformat(),
                "src_ip": a.src_ip,
                "dst_ip": a.dst_ip,
                "threat_level": a.threat_level,
                "threat_score": a.threat_score,
                "classification": a.classification,
                "attack_type": a.attack_type,
                "mitre_technique": a.mitre_technique,
                "environment": a.environment,
                "detection_source": a.detection_source,
                "explanation": a.explanation,
            }
            for a in alerts[:50]
        ],
    }


@router.get("/recent")
async def get_recent_iocs(
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    """Get the most recently seen threat IOCs with reputation and geo."""
    # First attempt from dedicated IOC table
    result = await db.execute(
        select(IOC).order_by(desc(IOC.last_seen)).limit(limit)
    )
    iocs = result.scalars().all()
    if iocs:
        return [
            {
                "ip": i.ioc_value,
                "ioc_value": i.ioc_value,
                "ioc_type": i.ioc_type,
                "max_score": i.risk_score,
                "threat_level": i.threat_level,
                "reputation": i.reputation,
                "hit_count": i.hit_count,
                "last_seen": i.last_seen.isoformat() if i.last_seen else None,
                "country": i.geo_country,
                "city": i.geo_city,
                "tags": i.tags or [],
            }
            for i in iocs
        ]

    # Fallback to alerts aggregation
    alt_result = await db.execute(
        select(
            Alert.src_ip,
            func.max(Alert.threat_score).label("max_score"),
            func.max(Alert.threat_level).label("threat_level"),
            func.count(Alert.id).label("hit_count"),
            func.max(Alert.timestamp).label("last_seen"),
            func.max(Alert.geo_country).label("country"),
        )
        .where(Alert.threat_level.in_(["CRITICAL", "HIGH", "MEDIUM"]))
        .group_by(Alert.src_ip)
        .order_by(desc("max_score"))
        .limit(limit)
    )
    rows = alt_result.all()
    return [
        {
            "ip": r[0],
            "ioc_value": r[0],
            "ioc_type": "ipv4",
            "max_score": r[1],
            "threat_level": r[2],
            "reputation": "malicious" if r[1] >= 80 else "suspicious",
            "hit_count": r[3],
            "last_seen": r[4].isoformat() if r[4] else None,
            "country": r[5],
        }
        for r in rows
    ]


@router.get("/{value}")
async def get_single_ioc(
    value: str = Path(..., description="IOC string value"),
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    """Direct lookup of a single IOC by value."""
    return await search_ioc(query=value, ioc_type=None, days=30, db=db, _=user)


def _serialize_asset(a: Asset) -> dict:
    return {
        "id": a.id,
        "hostname": a.hostname,
        "ip_address": a.ip_address,
        "asset_type": a.asset_type,
        "criticality": a.criticality,
        "owner": a.owner,
        "department": a.department,
        "environment": a.environment,
        "location": a.location,
    }
