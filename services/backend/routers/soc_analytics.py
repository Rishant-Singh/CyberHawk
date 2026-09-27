"""SOC Analytics router — KPIs, trends, heatmaps, and top attacker data."""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, extract

from core.database import get_db
from core.security import get_current_user
from models.alert import Alert
from models.incident import Incident

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/overview")
async def get_overview(
    hours: int = Query(24, ge=1, le=720, description="Lookback window in hours"),
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    """
    Key SOC metrics: total alerts, by-severity counts, detection rate,
    MTTD/MTTR estimates, and active incident count.
    """
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    # Alert counts by level
    level_result = await db.execute(
        select(Alert.threat_level, func.count(Alert.id))
        .where(Alert.timestamp >= since)
        .group_by(Alert.threat_level)
    )
    level_map = {r[0]: r[1] for r in level_result}

    total = sum(level_map.values())
    malicious = level_map.get("CRITICAL", 0) + level_map.get("HIGH", 0)
    detection_rate = round((malicious / total * 100), 1) if total > 0 else 0.0

    # Acknowledged alerts (proxy for "responded" — MTTR)
    acked_result = await db.execute(
        select(func.count(Alert.id))
        .where(Alert.is_acknowledged == True, Alert.timestamp >= since)
    )
    acknowledged = acked_result.scalar_one()

    # Avg threat score
    avg_score_result = await db.execute(
        select(func.avg(Alert.threat_score)).where(Alert.timestamp >= since)
    )
    avg_score = round(float(avg_score_result.scalar_one() or 0), 1)

    # Incident counts
    open_incidents = (await db.execute(
        select(func.count(Incident.id)).where(Incident.status == "open")
    )).scalar_one()
    investigating = (await db.execute(
        select(func.count(Incident.id)).where(Incident.status == "investigating")
    )).scalar_one()

    # Top attack type this window
    top_attack = await db.execute(
        select(Alert.attack_type, func.count(Alert.id).label("cnt"))
        .where(Alert.timestamp >= since, Alert.attack_type.is_not(None))
        .group_by(Alert.attack_type)
        .order_by(desc("cnt"))
        .limit(1)
    )
    top_row = top_attack.first()

    return {
        "window_hours": hours,
        "total_alerts": total,
        "critical": level_map.get("CRITICAL", 0),
        "high": level_map.get("HIGH", 0),
        "medium": level_map.get("MEDIUM", 0),
        "low": level_map.get("LOW", 0),
        "info": level_map.get("INFO", 0),
        "acknowledged": acknowledged,
        "detection_rate": detection_rate,
        "avg_threat_score": avg_score,
        "open_incidents": open_incidents,
        "investigating_incidents": investigating,
        "top_attack_type": top_row[0] if top_row else None,
    }


@router.get("/trend")
async def get_trend(
    days: int = Query(7, ge=1, le=90),
    metric: str = Query("count", description="count | avg_score | critical_count"),
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    """Daily trend data for the selected metric over the past N days."""
    since = datetime.now(timezone.utc) - timedelta(days=days)

    if metric == "avg_score":
        agg = func.avg(Alert.threat_score).label("value")
    elif metric == "critical_count":
        # We'll post-filter
        agg = func.count(Alert.id).label("value")
    else:
        agg = func.count(Alert.id).label("value")

    q = (
        select(
            func.date_trunc("day", Alert.timestamp).label("day"),
            agg,
        )
        .where(Alert.timestamp >= since)
        .group_by("day")
        .order_by("day")
    )

    if metric == "critical_count":
        q = (
            select(
                func.date_trunc("day", Alert.timestamp).label("day"),
                func.count(Alert.id).label("value"),
            )
            .where(Alert.timestamp >= since, Alert.threat_level == "CRITICAL")
            .group_by("day")
            .order_by("day")
        )

    result = await db.execute(q)
    rows = result.all()

    return {
        "metric": metric,
        "days": days,
        "data": [
            {"date": r[0].strftime("%Y-%m-%d") if r[0] else None, "value": round(float(r[1] or 0), 2)}
            for r in rows
        ],
    }


@router.get("/top-attackers")
async def get_top_attackers(
    limit: int = Query(15, ge=5, le=50),
    hours: int = Query(168, ge=1, le=720),
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    """Top attacking IPs ranked by max threat score."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    result = await db.execute(
        select(
            Alert.src_ip,
            func.max(Alert.threat_score).label("max_score"),
            func.count(Alert.id).label("total_alerts"),
            func.max(Alert.threat_level).label("max_level"),
            func.max(Alert.geo_country).label("country"),
            func.max(Alert.geo_city).label("city"),
            func.max(Alert.attack_type).label("primary_attack"),
        )
        .where(Alert.timestamp >= since)
        .group_by(Alert.src_ip)
        .order_by(desc("max_score"))
        .limit(limit)
    )
    rows = result.all()

    return [
        {
            "ip": r[0],
            "max_score": r[1],
            "total_alerts": r[2],
            "max_level": r[3],
            "country": r[4],
            "city": r[5],
            "primary_attack": r[6],
        }
        for r in rows
    ]


@router.get("/attack-heatmap")
async def get_attack_heatmap(
    days: int = Query(30, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    """
    Returns hourly-by-weekday heatmap data (7 days × 24 hours grid).
    Useful for identifying peak attack times.
    """
    since = datetime.now(timezone.utc) - timedelta(days=days)

    result = await db.execute(
        select(
            extract("dow", Alert.timestamp).label("weekday"),   # 0=Sun, 6=Sat
            extract("hour", Alert.timestamp).label("hour"),
            func.count(Alert.id).label("count"),
        )
        .where(Alert.timestamp >= since)
        .group_by("weekday", "hour")
        .order_by("weekday", "hour")
    )
    rows = result.all()

    return {
        "days": days,
        "data": [
            {"weekday": int(r[0]), "hour": int(r[1]), "count": r[2]}
            for r in rows
        ],
    }


@router.get("/attack-types")
async def get_attack_type_distribution(
    hours: int = Query(168, ge=1, le=720),
    limit: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    """Attack type distribution for donut/bar charts."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    result = await db.execute(
        select(Alert.attack_type, func.count(Alert.id).label("count"))
        .where(Alert.timestamp >= since, Alert.attack_type.is_not(None))
        .group_by(Alert.attack_type)
        .order_by(desc("count"))
        .limit(limit)
    )
    rows = result.all()
    return [{"type": r[0], "count": r[1]} for r in rows]


@router.get("/geo-distribution")
async def get_geo_distribution(
    hours: int = Query(168, ge=1, le=720),
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    """Attack counts by country for choropleth / pie chart."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    result = await db.execute(
        select(Alert.geo_country, func.count(Alert.id).label("count"))
        .where(Alert.timestamp >= since, Alert.geo_country.is_not(None))
        .group_by(Alert.geo_country)
        .order_by(desc("count"))
        .limit(30)
    )
    rows = result.all()
    return [{"country": r[0], "count": r[1]} for r in rows]
