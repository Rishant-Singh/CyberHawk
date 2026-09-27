"""Asset Inventory router — auto-discover and manage network assets."""

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func

from core.database import get_db
from core.security import get_current_user
from models.asset import Asset
from models.alert import Alert

router = APIRouter()
logger = logging.getLogger(__name__)


# ── Discovery ──────────────────────────────────────────────────────────────────

@router.post("/discover", status_code=status.HTTP_200_OK)
async def discover_assets(
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    """
    Auto-discover assets from existing alert traffic.
    Scans src_ip/dst_ip fields in alerts and upserts Asset records.
    """
    result = await db.execute(
        select(
            Alert.src_ip,
            func.max(Alert.threat_score).label("max_score"),
            func.count(Alert.id).label("alert_count"),
            func.min(Alert.timestamp).label("first_seen"),
            func.max(Alert.timestamp).label("last_seen"),
            func.max(Alert.geo_country).label("country"),
            func.max(Alert.geo_city).label("city"),
        )
        .group_by(Alert.src_ip)
    )
    rows = result.all()

    created = 0
    updated = 0

    for row in rows:
        ip = row[0]
        if not ip:
            continue

        existing = (await db.execute(
            select(Asset).where(Asset.ip_address == ip)
        )).scalars().first()

        if existing:
            existing.threat_score = float(row[1] or 0)
            existing.total_alerts = row[2] or 0
            existing.last_seen = row[4] or datetime.now(timezone.utc)
            existing.geo_country = row[5]
            existing.geo_city = row[6]
            existing.is_compromised = (row[1] or 0) >= 80
            updated += 1
        else:
            asset = Asset(
                ip_address=ip,
                threat_score=float(row[1] or 0),
                total_alerts=row[2] or 0,
                first_seen=row[3] or datetime.now(timezone.utc),
                last_seen=row[4] or datetime.now(timezone.utc),
                geo_country=row[5],
                geo_city=row[6],
                is_compromised=(row[1] or 0) >= 80,
            )
            db.add(asset)
            created += 1

    await db.commit()
    return {"discovered": created + updated, "created": created, "updated": updated}


# ── List / Create ──────────────────────────────────────────────────────────────

@router.get("/")
async def list_assets(
    criticality: Optional[str] = Query(None),
    asset_type: Optional[str] = Query(None),
    department: Optional[str] = Query(None),
    is_compromised: Optional[bool] = Query(None),
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    """List assets with optional filters."""
    from sqlalchemy import and_

    filters = []
    if criticality:
        filters.append(Asset.criticality == criticality.lower())
    if asset_type:
        filters.append(Asset.asset_type == asset_type.lower())
    if department:
        filters.append(Asset.department == department)
    if is_compromised is not None:
        filters.append(Asset.is_compromised == is_compromised)
    if search:
        from sqlalchemy import or_
        filters.append(or_(
            Asset.ip_address.ilike(f"%{search}%"),
            Asset.hostname.ilike(f"%{search}%"),
            Asset.owner.ilike(f"%{search}%"),
        ))

    count_q = select(func.count(Asset.id)).where(and_(*filters))
    total = (await db.execute(count_q)).scalar_one()

    data_q = (
        select(Asset)
        .where(and_(*filters))
        .order_by(desc(Asset.threat_score))
        .offset((page - 1) * size)
        .limit(size)
    )
    result = await db.execute(data_q)
    assets = result.scalars().all()

    return {
        "total": total,
        "page": page,
        "size": size,
        "pages": (total + size - 1) // size,
        "items": [_serialize(a) for a in assets],
    }


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_asset(
    payload: dict,
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    """Manually register an asset."""
    # Check for duplicate IP
    existing = (await db.execute(
        select(Asset).where(Asset.ip_address == payload.get("ip_address"))
    )).scalars().first()
    if existing:
        raise HTTPException(status_code=409, detail="Asset with this IP already exists")

    asset = Asset(
        ip_address=payload["ip_address"],
        hostname=payload.get("hostname"),
        mac_address=payload.get("mac_address"),
        asset_type=payload.get("asset_type", "unknown"),
        criticality=payload.get("criticality", "medium"),
        owner=payload.get("owner"),
        department=payload.get("department"),
        os=payload.get("os"),
        services=payload.get("services", []),
        tags=payload.get("tags", []),
    )
    db.add(asset)
    await db.commit()
    await db.refresh(asset)
    return _serialize(asset)


# ── Single Asset ───────────────────────────────────────────────────────────────

@router.get("/{asset_id}")
async def get_asset(
    asset_id: str,
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    asset = await _get_or_404(asset_id, db)
    return _serialize(asset)


@router.put("/{asset_id}")
async def update_asset(
    asset_id: str,
    payload: dict,
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    """Update asset metadata."""
    asset = await _get_or_404(asset_id, db)
    updatable = ["hostname", "mac_address", "asset_type", "criticality",
                 "owner", "department", "os", "services", "tags", "is_active"]
    for field in updatable:
        if field in payload:
            setattr(asset, field, payload[field])
    await db.commit()
    await db.refresh(asset)
    return _serialize(asset)


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset(
    asset_id: str,
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    asset = await _get_or_404(asset_id, db)
    await db.delete(asset)
    await db.commit()


# ── Asset Threats ──────────────────────────────────────────────────────────────

@router.get("/{asset_id}/threats")
async def get_asset_threats(
    asset_id: str,
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    """Get all alerts where this asset was involved (as src or dst)."""
    asset = await _get_or_404(asset_id, db)
    from sqlalchemy import or_
    result = await db.execute(
        select(Alert)
        .where(or_(Alert.src_ip == asset.ip_address, Alert.dst_ip == asset.ip_address))
        .order_by(desc(Alert.timestamp))
        .limit(limit)
    )
    alerts = result.scalars().all()
    return [
        {
            "id": a.id,
            "timestamp": a.timestamp.isoformat(),
            "src_ip": a.src_ip,
            "dst_ip": a.dst_ip,
            "threat_level": a.threat_level,
            "threat_score": a.threat_score,
            "attack_type": a.attack_type,
            "mitre_technique": a.mitre_technique,
            "classification": a.classification,
        }
        for a in alerts
    ]


# ── Stats ──────────────────────────────────────────────────────────────────────

@router.get("/stats/summary")
async def asset_stats(
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    by_type = await db.execute(
        select(Asset.asset_type, func.count(Asset.id)).group_by(Asset.asset_type)
    )
    by_criticality = await db.execute(
        select(Asset.criticality, func.count(Asset.id)).group_by(Asset.criticality)
    )
    compromised = (await db.execute(
        select(func.count(Asset.id)).where(Asset.is_compromised == True)
    )).scalar_one()
    total = (await db.execute(select(func.count(Asset.id)))).scalar_one()

    return {
        "total": total,
        "compromised": compromised,
        "by_type": {r[0]: r[1] for r in by_type},
        "by_criticality": {r[0]: r[1] for r in by_criticality},
    }


# ── Helpers ────────────────────────────────────────────────────────────────────

async def _get_or_404(asset_id: str, db: AsyncSession) -> Asset:
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalars().first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


def _serialize(a: Asset) -> dict:
    return {
        "id": a.id,
        "ip_address": a.ip_address,
        "hostname": a.hostname,
        "mac_address": a.mac_address,
        "asset_type": a.asset_type,
        "criticality": a.criticality,
        "owner": a.owner,
        "department": a.department,
        "os": a.os,
        "services": a.services or [],
        "tags": a.tags or [],
        "geo_country": a.geo_country,
        "geo_city": a.geo_city,
        "first_seen": a.first_seen.isoformat() if a.first_seen else None,
        "last_seen": a.last_seen.isoformat() if a.last_seen else None,
        "is_active": a.is_active,
        "threat_score": a.threat_score,
        "total_alerts": a.total_alerts,
        "is_compromised": a.is_compromised,
    }
