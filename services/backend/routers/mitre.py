"""MITRE ATT&CK router — technique lookup and alert mapping."""

import json
import os
from typing import Optional

from fastapi import APIRouter, Depends, Query, HTTPException

from core.security import get_current_user

router = APIRouter()

# Load MITRE data once at import time
_MITRE_DATA = None

def _load_mitre() -> dict:
    global _MITRE_DATA
    if _MITRE_DATA is None:
        mitre_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "../../../../data/mitre_attack_patterns.json"
        )
        if os.path.exists(mitre_path):
            with open(mitre_path, "r") as f:
                _MITRE_DATA = json.load(f)
        else:
            _MITRE_DATA = {"techniques": [], "tactics": []}
    return _MITRE_DATA


@router.get("/techniques")
async def list_techniques(
    tactic: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    _=Depends(get_current_user),
):
    """List all MITRE ATT&CK techniques with optional filters."""
    data = _load_mitre()
    techniques = data.get("techniques", [])

    if tactic:
        techniques = [t for t in techniques if tactic.lower() in t.get("tactic", "").lower()]
    if severity:
        techniques = [t for t in techniques if t.get("severity", "").upper() == severity.upper()]

    return {
        "total": len(techniques),
        "techniques": techniques,
        "tactics": data.get("tactics", []),
    }


@router.get("/techniques/{technique_id}")
async def get_technique(
    technique_id: str,
    _=Depends(get_current_user),
):
    """Get a specific MITRE technique by ID (e.g., T1190)."""
    data = _load_mitre()
    for tech in data.get("techniques", []):
        if tech.get("id", "").upper() == technique_id.upper():
            return tech
    raise HTTPException(status_code=404, detail=f"Technique {technique_id} not found")


@router.get("/map")
async def map_techniques(
    techniques: str = Query(..., description="Comma-separated technique IDs"),
    _=Depends(get_current_user),
):
    """Map a list of technique IDs to full technique objects."""
    ids = [t.strip().upper() for t in techniques.split(",")]
    data = _load_mitre()
    result = {}
    for tech in data.get("techniques", []):
        if tech.get("id", "").upper() in ids:
            result[tech["id"]] = tech
    return result


@router.get("/tactics")
async def list_tactics(_=Depends(get_current_user)):
    """List all MITRE ATT&CK tactics."""
    data = _load_mitre()
    return {"tactics": data.get("tactics", [])}


@router.get("/heatmap")
async def get_mitre_heatmap(
    hours: int = 168,
    _=Depends(get_current_user),
):
    """
    Return technique usage frequency from the alerts DB.
    Used to color the interactive MITRE ATT&CK matrix.
    """
    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    from core.database import AsyncSessionLocal
    from models.alert import Alert
    from sqlalchemy import select, func, desc
    from datetime import datetime, timedelta, timezone

    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Alert.mitre_technique, func.count(Alert.id).label("count"))
            .where(Alert.timestamp >= since, Alert.mitre_technique.is_not(None))
            .group_by(Alert.mitre_technique)
            .order_by(desc("count"))
        )
        rows = result.all()

    return {
        "hours": hours,
        "heatmap": {r[0]: r[1] for r in rows},
    }
