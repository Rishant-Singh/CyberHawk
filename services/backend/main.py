"""
CTI Platform — FastAPI Application Entry Point
"""

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from core.config import settings
from core.database import init_db
from routers import auth, logs, alerts, threats, health, mitre
from websocket.ws_router import ws_router
from services.websocket_manager import manager
from services.kafka_consumer_service import start_kafka_consumer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle: startup → serve → shutdown."""
    logger.info("Starting CTI Platform API...")

    # Initialize database (create tables, seed admin user)
    await init_db()

    # Start Kafka consumer for scored threats → WebSocket broadcast
    consumer_task = asyncio.create_task(start_kafka_consumer())

    logger.info(f"CTI API ready on port {settings.BACKEND_PORT}")
    yield

    # Shutdown
    consumer_task.cancel()
    try:
        await consumer_task
    except asyncio.CancelledError:
        pass
    logger.info("CTI API shut down cleanly.")


app = FastAPI(
    title="Cyber Threat Intelligence Platform API",
    description="Real-time threat detection, anomaly analysis, and MITRE ATT&CK mapping",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── Middleware ────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(auth.router,    prefix="/api/auth",    tags=["Authentication"])
app.include_router(logs.router,    prefix="/api/logs",    tags=["Logs"])
app.include_router(alerts.router,  prefix="/api/alerts",  tags=["Alerts"])
app.include_router(threats.router, prefix="/api/threats", tags=["Threats"])
app.include_router(health.router,  prefix="/api/health",  tags=["Health"])
app.include_router(mitre.router,   prefix="/api/mitre",   tags=["MITRE ATT&CK"])
app.include_router(ws_router)  # WebSocket at /ws/live


@app.get("/", tags=["Root"])
async def root():
    return {
        "service": "CTI Platform API",
        "version": "1.0.0",
        "status": "operational",
        "docs": "/docs",
    }
