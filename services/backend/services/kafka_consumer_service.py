"""
Kafka consumer service that runs in background,
reads scored threats and broadcasts via WebSocket.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone

from confluent_kafka import Consumer, KafkaError
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.database import AsyncSessionLocal
from models.alert import Alert
from services.websocket_manager import manager

logger = logging.getLogger(__name__)


async def start_kafka_consumer():
    """
    Background task: consumes scored threats from Kafka,
    persists critical/high/medium alerts to PostgreSQL,
    and broadcasts all threats via WebSocket.
    """
    conf = {
        "bootstrap.servers": settings.KAFKA_BOOTSTRAP_SERVERS,
        "group.id": settings.KAFKA_GROUP_ID,
        "auto.offset.reset": "latest",
        "enable.auto.commit": True,
    }

    consumer = None
    for attempt in range(20):
        try:
            consumer = Consumer(conf)
            consumer.subscribe([settings.KAFKA_SCORED_TOPIC])
            logger.info(f"Backend Kafka consumer subscribed to '{settings.KAFKA_SCORED_TOPIC}'")
            break
        except Exception as e:
            logger.warning(f"Kafka consumer init failed (attempt {attempt+1}/20): {e}")
            await asyncio.sleep(5)
    
    if consumer is None:
        logger.error("Could not initialize Kafka consumer. WebSocket live feed disabled.")
        return

    loop = asyncio.get_event_loop()

    try:
        while True:
            # Poll in executor to avoid blocking event loop
            msg = await loop.run_in_executor(None, lambda: consumer.poll(timeout=0.5))

            if msg is None:
                continue
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    logger.error(f"Kafka error: {msg.error()}")
                continue

            try:
                threat = json.loads(msg.value().decode("utf-8"))

                # Broadcast to WebSocket clients
                await manager.broadcast_threat(threat)

                # Persist to PostgreSQL if significant
                if threat.get("threat_level") in ("CRITICAL", "HIGH", "MEDIUM"):
                    await _persist_alert(threat)

            except (json.JSONDecodeError, Exception) as e:
                logger.error(f"Error processing Kafka message: {e}")

    except asyncio.CancelledError:
        logger.info("Kafka consumer task cancelled.")
    finally:
        consumer.close()


async def _persist_alert(threat: dict):
    """Persist a scored threat as an Alert record."""
    try:
        async with AsyncSessionLocal() as session:
            alert = Alert(
                id=str(uuid.uuid4()),
                log_id=threat.get("log_id"),
                timestamp=datetime.fromisoformat(
                    threat.get("timestamp", datetime.now(timezone.utc).isoformat())
                ),
                src_ip=threat.get("src_ip", "0.0.0.0"),
                dst_ip=threat.get("dst_ip"),
                src_port=threat.get("src_port"),
                dst_port=threat.get("dst_port"),
                protocol=threat.get("protocol"),
                service=threat.get("service"),
                geo_country=threat.get("geo_country"),
                geo_city=threat.get("geo_city"),
                geo_lat=threat.get("geo_lat"),
                geo_lon=threat.get("geo_lon"),
                threat_score=threat.get("threat_score", 0),
                threat_level=threat.get("threat_level", "INFO"),
                anomaly_score=threat.get("anomaly_score", 0.0),
                classification=threat.get("classification", "unknown"),
                classification_confidence=threat.get("classification_confidence", 0.0),
                attack_type=threat.get("attack_type"),
                mitre_technique=threat.get("mitre_technique"),
                explanation=threat.get("explanation"),
                recommendations=threat.get("recommendations"),
                top_features=threat.get("top_features"),
            )
            session.add(alert)
            await session.commit()
    except Exception as e:
        logger.error(f"Failed to persist alert: {e}")
