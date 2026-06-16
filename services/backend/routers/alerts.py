"""Alerts router — CRUD, filtering, stats, acknowledgment."""

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, and_

from core.database import get_db
from core.security import get_current_user, require_role
from models.alert import Alert
from schemas.alert import AlertResponse, AlertFilter, AlertStats

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/", response_model=dict)
async def list_alerts(
    src_ip: Optional[str] = Query(None),
    threat_level: Optional[str] = Query(None),
    classification: Optional[str] = Query(None),
    mitre_technique: Optional[str] = Query(None),
    min_score: Optional[int] = Query(None, ge=0, le=100),
    start_time: Optional[datetime] = Query(None),
    end_time: Optional[datetime] = Query(None),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    """List alerts with optional filters and pagination."""
    filters = []

    if src_ip:
        filters.append(Alert.src_ip == src_ip)
    if threat_level:
        filters.append(Alert.threat_level == threat_level.upper())
    if classification:
        filters.append(Alert.classification == classification.lower())
    if mitre_technique:
        filters.append(Alert.mitre_technique == mitre_technique)
    if min_score is not None:
        filters.append(Alert.threat_score >= min_score)
    if start_time:
        filters.append(Alert.timestamp >= start_time)
    if end_time:
        filters.append(Alert.timestamp <= end_time)

    # Count query
    count_q = select(func.count(Alert.id)).where(and_(*filters))
    total = (await db.execute(count_q)).scalar_one()

    # Data query
    data_q = (
        select(Alert)
        .where(and_(*filters))
        .order_by(desc(Alert.timestamp))
        .offset((page - 1) * size)
        .limit(size)
    )
    result = await db.execute(data_q)
    alerts = result.scalars().all()

    return {
        "total": total,
        "page": page,
        "size": size,
        "pages": (total + size - 1) // size,
        "items": [AlertResponse.model_validate(a).model_dump() for a in alerts],
    }


@router.get("/stats", response_model=AlertStats)
async def get_alert_stats(
    hours: int = Query(24, ge=1, le=168),
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    """Get alert statistics for the dashboard."""
    from sqlalchemy import case

    # Counts by level
    level_counts = await db.execute(
        select(Alert.threat_level, func.count(Alert.id))
        .group_by(Alert.threat_level)
    )
    level_map = {row[0]: row[1] for row in level_counts}

    total = sum(level_map.values())
    acked = (await db.execute(
        select(func.count(Alert.id)).where(Alert.is_acknowledged == True)
    )).scalar_one()

    # Top attack types
    attack_counts = await db.execute(
        select(Alert.attack_type, func.count(Alert.id).label("count"))
        .where(Alert.attack_type.is_not(None))
        .group_by(Alert.attack_type)
        .order_by(desc("count"))
        .limit(5)
    )
    top_attacks = [{"type": row[0], "count": row[1]} for row in attack_counts]

    # Top source IPs
    ip_counts = await db.execute(
        select(Alert.src_ip, func.count(Alert.id).label("count"))
        .group_by(Alert.src_ip)
        .order_by(desc("count"))
        .limit(10)
    )
    top_ips = [{"ip": row[0], "count": row[1]} for row in ip_counts]

    return AlertStats(
        total=total,
        critical=level_map.get("CRITICAL", 0),
        high=level_map.get("HIGH", 0),
        medium=level_map.get("MEDIUM", 0),
        low=level_map.get("LOW", 0),
        info=level_map.get("INFO", 0),
        acknowledged=acked,
        by_hour=[],
        top_attack_types=top_attacks,
        top_src_ips=top_ips,
    )


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    """Get a single alert by ID."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalars().first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return AlertResponse.model_validate(alert)


@router.post("/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Mark an alert as acknowledged."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalars().first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.is_acknowledged = True
    alert.acknowledged_by = current_user["user_id"]
    alert.acknowledged_at = datetime.now(timezone.utc)
    await db.commit()

    return {"message": "Alert acknowledged", "alert_id": alert_id}


@router.delete("/{alert_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    _=Depends(require_role("admin")),
):
    """Delete an alert (admin only)."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalars().first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    await db.delete(alert)
    await db.commit()
