"""Logs router — Elasticsearch full-text search and filtering."""

from typing import Optional
from datetime import datetime

from fastapi import APIRouter, Depends, Query

from core.security import get_current_user
from services.elasticsearch_service import search_logs, get_threat_heatmap

router = APIRouter()


@router.get("/search")
async def search(
    q: Optional[str] = Query(None, description="Full-text search query"),
    src_ip: Optional[str] = Query(None),
    threat_level: Optional[str] = Query(None),
    min_score: Optional[int] = Query(None, ge=0, le=100),
    start_time: Optional[datetime] = Query(None),
    end_time: Optional[datetime] = Query(None),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    _=Depends(get_current_user),
):
    """Full-text search across logs using Elasticsearch."""
    return await search_logs(
        query=q,
        src_ip=src_ip,
        threat_level=threat_level,
        start_time=start_time,
        end_time=end_time,
        min_score=min_score,
        page=page,
        size=size,
    )


@router.get("/heatmap")
async def heatmap(
    hours: int = Query(24, ge=1, le=168),
    _=Depends(get_current_user),
):
    """Get hourly anomaly heatmap data."""
    return await get_threat_heatmap(hours=hours)
