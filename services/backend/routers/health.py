"""Health router — system health monitoring."""

import psutil
import asyncio
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from elasticsearch import AsyncElasticsearch

from core.config import settings
from core.security import get_current_user
from services.elasticsearch_service import get_es
from services.websocket_manager import manager

router = APIRouter()


@router.get("/ping")
async def ping():
    """Simple liveness probe."""
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@router.get("/system")
async def system_health(_=Depends(get_current_user)):
    """Comprehensive system health metrics."""
    cpu_percent = psutil.cpu_percent(interval=0.1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage("/")

    # Check Elasticsearch
    es_status = "unknown"
    es_docs = 0
    try:
        es = get_es()
        health = await es.cluster.health(timeout="2s")
        es_status = health.get("status", "unknown")
        stats = await es.indices.stats(index=["cti_threats", "cti_logs"])
        es_docs = stats["_all"]["primaries"]["docs"]["count"]
    except Exception:
        es_status = "unavailable"

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "system": {
            "cpu_percent": cpu_percent,
            "memory_percent": memory.percent,
            "memory_used_gb": round(memory.used / 1e9, 2),
            "memory_total_gb": round(memory.total / 1e9, 2),
            "disk_percent": disk.percent,
            "disk_used_gb": round(disk.used / 1e9, 2),
            "disk_total_gb": round(disk.total / 1e9, 2),
        },
        "services": {
            "api": "healthy",
            "elasticsearch": es_status,
            "elasticsearch_docs": es_docs,
        },
        "websocket": {
            "connected_clients": manager.connection_count,
        },
    }
