"""Incidents router — full CRUD for security incidents with alert linking and timelines."""

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func

from core.database import get_db
from core.security import get_current_user
from models.incident import Incident
from models.alert import Alert

router = APIRouter()
logger = logging.getLogger(__name__)


# ── List / Create ──────────────────────────────────────────────────────────────

@router.get("/")
async def list_incidents(
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = Query(None),
    assigned_to: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    """List incidents with optional filters."""
    filters = []
    if status_filter:
        filters.append(Incident.status == status_filter.lower())
    if severity:
        filters.append(Incident.severity == severity.upper())
    if assigned_to:
        filters.append(Incident.assigned_to == assigned_to)

    from sqlalchemy import and_
    count_q = select(func.count(Incident.id)).where(and_(*filters))
    total = (await db.execute(count_q)).scalar_one()

    data_q = (
        select(Incident)
        .where(and_(*filters))
        .order_by(desc(Incident.created_at))
        .offset((page - 1) * size)
        .limit(size)
    )
    result = await db.execute(data_q)
    incidents = result.scalars().all()

    return {
        "total": total,
        "page": page,
        "size": size,
        "pages": (total + size - 1) // size,
        "items": [_serialize(i) for i in incidents],
    }


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_incident(
    payload: dict,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Create a new incident."""
    incident = Incident(
        title=payload.get("title", "Untitled Incident"),
        description=payload.get("description"),
        severity=payload.get("severity", "MEDIUM").upper(),
        status="open",
        created_by=current_user.get("user_id"),
        assigned_to=payload.get("assigned_to"),
        alert_ids=payload.get("alert_ids", []),
        mitre_techniques=payload.get("mitre_techniques", []),
        tags=payload.get("tags", []),
        notes=payload.get("notes", []),
        ioc_list=payload.get("ioc_list", []),
    )
    db.add(incident)
    await db.commit()
    await db.refresh(incident)
    return _serialize(incident)


# ── Single Incident ────────────────────────────────────────────────────────────

@router.get("/{incident_id}")
async def get_incident(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    """Get a single incident by ID."""
    incident = await _get_or_404(incident_id, db)
    return _serialize(incident)


@router.put("/{incident_id}")
async def update_incident(
    incident_id: str,
    payload: dict,
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    """Update an incident (title, description, severity, status, assignment, tags)."""
    incident = await _get_or_404(incident_id, db)

    updatable = ["title", "description", "severity", "status", "assigned_to",
                 "alert_ids", "mitre_techniques", "tags", "notes", "ioc_list"]
    for field in updatable:
        if field in payload:
            value = payload[field]
            if field == "severity":
                value = value.upper()
            elif field == "status":
                value = value.lower()
            setattr(incident, field, value)

    incident.updated_at = datetime.now(timezone.utc)

    # Auto-set resolved_at when closed
    if incident.status in ("resolved", "closed") and not incident.resolved_at:
        incident.resolved_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(incident)
    return _serialize(incident)


@router.delete("/{incident_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_incident(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    """Delete an incident."""
    incident = await _get_or_404(incident_id, db)
    await db.delete(incident)
    await db.commit()


# ── Alert Linking ──────────────────────────────────────────────────────────────

@router.post("/{incident_id}/alerts")
async def link_alerts(
    incident_id: str,
    payload: dict,
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    """Link one or more alert IDs to an incident."""
    incident = await _get_or_404(incident_id, db)
    new_ids = payload.get("alert_ids", [])
    existing = list(incident.alert_ids or [])
    merged = list(set(existing + new_ids))
    incident.alert_ids = merged
    incident.updated_at = datetime.now(timezone.utc)
    await db.commit()
    return {"incident_id": incident_id, "alert_ids": merged}


# ── Timeline ───────────────────────────────────────────────────────────────────

@router.get("/{incident_id}/timeline")
async def get_incident_timeline(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    """Get all linked alerts sorted chronologically (incident timeline)."""
    incident = await _get_or_404(incident_id, db)
    alert_ids = incident.alert_ids or []

    events = []
    if alert_ids:
        from sqlalchemy import or_
        result = await db.execute(
            select(Alert)
            .where(Alert.id.in_(alert_ids))
            .order_by(Alert.timestamp)
        )
        alerts = result.scalars().all()
        for a in alerts:
            events.append({
                "type": "alert",
                "id": a.id,
                "timestamp": a.timestamp.isoformat(),
                "title": f"{a.threat_level} — {a.attack_type or a.classification}",
                "src_ip": a.src_ip,
                "dst_ip": a.dst_ip,
                "threat_score": a.threat_score,
                "mitre_technique": a.mitre_technique,
                "explanation": a.explanation,
            })

    # Include notes as timeline events
    for note in (incident.notes or []):
        events.append({
            "type": "note",
            "timestamp": note.get("created_at"),
            "title": "Analyst Note",
            "content": note.get("text"),
            "author": note.get("author"),
        })

    events.sort(key=lambda e: e.get("timestamp") or "")
    return {
        "incident_id": incident_id,
        "title": incident.title,
        "status": incident.status,
        "timeline": events,
    }


# ── Stats ──────────────────────────────────────────────────────────────────────

@router.get("/stats/summary")
async def incident_stats(
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    """Return incident count by status and severity."""
    by_status = await db.execute(
        select(Incident.status, func.count(Incident.id)).group_by(Incident.status)
    )
    by_severity = await db.execute(
        select(Incident.severity, func.count(Incident.id)).group_by(Incident.severity)
    )
    return {
        "by_status": {r[0]: r[1] for r in by_status},
        "by_severity": {r[0]: r[1] for r in by_severity},
        "total": (await db.execute(select(func.count(Incident.id)))).scalar_one(),
    }


# ── Helpers ────────────────────────────────────────────────────────────────────

async def _get_or_404(incident_id: str, db: AsyncSession) -> Incident:
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalars().first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


def _serialize(i: Incident) -> dict:
    return {
        "id": i.id,
        "title": i.title,
        "description": i.description,
        "severity": i.severity,
        "status": i.status,
        "created_by": i.created_by,
        "assigned_to": i.assigned_to,
        "created_at": i.created_at.isoformat() if i.created_at else None,
        "updated_at": i.updated_at.isoformat() if i.updated_at else None,
        "resolved_at": i.resolved_at.isoformat() if i.resolved_at else None,
        "alert_ids": i.alert_ids or [],
        "mitre_techniques": i.mitre_techniques or [],
        "tags": i.tags or [],
        "notes": i.notes or [],
        "ioc_list": i.ioc_list or [],
        "alert_count": len(i.alert_ids or []),
    }
