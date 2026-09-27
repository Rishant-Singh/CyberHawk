"""Threats router — real-time threat data, recent events, stats."""

from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func

from core.database import get_db
from core.security import get_current_user
from models.alert import Alert

router = APIRouter()


@router.get("/recent")
async def get_recent_threats(
    limit: int = Query(50, ge=1, le=200),
    threat_level: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    """Get the most recent threat events."""
    q = select(Alert).order_by(desc(Alert.timestamp)).limit(limit)
    if threat_level:
        q = q.where(Alert.threat_level == threat_level.upper())
    result = await db.execute(q)
    alerts = result.scalars().all()

    return [
        {
            "id": a.id,
            "timestamp": a.timestamp.isoformat(),
            "src_ip": a.src_ip,
            "dst_ip": a.dst_ip,
            "threat_score": a.threat_score,
            "threat_level": a.threat_level,
            "classification": a.classification,
            "anomaly_score": a.anomaly_score,
            "mitre_technique": a.mitre_technique,
            "attack_type": a.attack_type,
            "geo_country": a.geo_country,
            "geo_lat": a.geo_lat,
            "geo_lon": a.geo_lon,
            "explanation": a.explanation,
        }
        for a in alerts
    ]


@router.get("/timeline")
async def get_threat_timeline(
    hours: int = Query(24, ge=1, le=168),
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    """Get threat event counts grouped by hour for timeline chart."""
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import extract

    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    result = await db.execute(
        select(
            func.date_trunc("hour", Alert.timestamp).label("hour"),
            Alert.threat_level,
            func.count(Alert.id).label("count")
        )
        .where(Alert.timestamp >= since)
        .group_by("hour", Alert.threat_level)
        .order_by("hour")
    )
    rows = result.all()

    timeline = {}
    for row in rows:
        hour_str = row[0].isoformat() if row[0] else "unknown"
        if hour_str not in timeline:
            timeline[hour_str] = {"hour": hour_str, "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        timeline[hour_str][row[1]] = row[2]

    return sorted(timeline.values(), key=lambda x: x["hour"])


@router.get("/network-graph")
async def get_network_graph(
    limit: int = Query(100, ge=10, le=500),
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    """Get network connection graph data for D3 force visualization."""
    result = await db.execute(
        select(Alert.src_ip, Alert.dst_ip, Alert.threat_level, Alert.threat_score,
               Alert.classification, Alert.attack_type)
        .where(Alert.dst_ip.is_not(None))
        .order_by(desc(Alert.timestamp))
        .limit(limit)
    )
    rows = result.all()

    nodes = {}
    edges = []

    for row in rows:
        src, dst = row[0], row[1]
        level, score, cls = row[2], row[3], row[4]

        if src not in nodes:
            nodes[src] = {"id": src, "type": "source", "threat_level": level,
                         "threat_score": score, "connections": 0}
        if dst not in nodes:
            nodes[dst] = {"id": dst, "type": "target", "threat_level": "INFO",
                         "threat_score": 0, "connections": 0}

        nodes[src]["connections"] += 1
        nodes[src]["threat_score"] = max(nodes[src]["threat_score"], score)
        nodes[src]["threat_level"] = level if score > nodes[src].get("max_score", 0) else nodes[src]["threat_level"]

        edges.append({
            "source": src,
            "target": dst,
            "threat_level": level,
            "threat_score": score,
            "classification": cls,
            "attack_type": row[5],
        })

    return {
        "nodes": list(nodes.values()),
        "edges": edges[:200],  # Limit edges for performance
    }


@router.get("/map-events")
async def get_map_events(
    threat_level: Optional[str] = Query(None, description="CRITICAL | HIGH | MEDIUM | LOW"),
    environment: Optional[str] = Query(None, description="OBSERVED | LAB | SIMULATED | ALL"),
    hours: int = Query(24, ge=1, le=720),
    limit: int = Query(150, ge=10, le=500),
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    """
    Get geographic threat events with valid coordinates for the Global Threat Map.
    Supports severity and environment filtering.
    """
    from datetime import datetime, timedelta, timezone
    from models.asset import Asset
    from services.geoip_service import is_private_ip

    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    q = (
        select(Alert)
        .where(
            Alert.timestamp >= since,
            Alert.geo_lat.is_not(None),
            Alert.geo_lon.is_not(None),
        )
        .order_by(desc(Alert.timestamp))
        .limit(limit)
    )

    if threat_level and threat_level.upper() != "ALL":
        q = q.where(Alert.threat_level == threat_level.upper())

    if environment and environment.upper() != "ALL":
        q = q.where(Alert.environment == environment.upper())

    result = await db.execute(q)
    alerts = result.scalars().all()

    # Asset lookup cache for target names
    all_assets = (await db.execute(select(Asset))).scalars().all()
    asset_map = {a.ip_address: a for a in all_assets}

    events = []
    for a in alerts:
        target_asset = asset_map.get(a.dst_ip) if a.dst_ip else None
        events.append({
            "id": a.id,
            "timestamp": a.timestamp.isoformat(),
            "src_ip": a.src_ip,
            "dst_ip": a.dst_ip,
            "threat_level": a.threat_level,
            "threat_score": a.threat_score,
            "classification": a.classification,
            "attack_type": a.attack_type,
            "mitre_technique": a.mitre_technique,
            "geo_country": a.geo_country,
            "geo_city": a.geo_city,
            "geo_lat": a.geo_lat,
            "geo_lon": a.geo_lon,
            "accuracy_radius_km": a.accuracy_radius_km,
            "environment": a.environment,
            "detection_source": a.detection_source,
            "explanation": a.explanation,
            "target_asset_name": target_asset.hostname if target_asset else None,
            "target_asset_criticality": target_asset.criticality if target_asset else None,
            "target_asset_location": target_asset.location if target_asset else ("Internal Lab" if is_private_ip(a.dst_ip) else None),
        })

    return events


@router.get("/geolocation/{ip}")
async def get_ip_geolocation(
    ip: str,
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    """
    Resolve IP geolocation metadata.
    RFC1918 private IPs are shielded and resolved against internal asset inventory.
    """
    from services.geoip_service import resolve_ip_location
    from models.asset import Asset

    direct_asset = (await db.execute(
        select(Asset).where(Asset.ip_address == ip.strip())
    )).scalars().first()

    asset_ctx = {"hostname": direct_asset.hostname, "location": direct_asset.location} if direct_asset else None
    return await resolve_ip_location(ip, asset_context=asset_ctx)

