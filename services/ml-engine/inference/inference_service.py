"""
ML Inference Service — FastAPI server that:
1. Receives batches of feature-extracted events from the Kafka consumer
2. Runs anomaly detection + malware classification
3. Computes threat scores
4. Writes results to Elasticsearch and PostgreSQL
5. Publishes scored threats to the scored-threats Kafka topic
"""

import os
import sys
import json
import logging
import asyncio
from datetime import datetime, timezone
from typing import Any

import httpx
from contextlib import asynccontextmanager
from fastapi import FastAPI
from pydantic import BaseModel
from confluent_kafka import Producer
from elasticsearch import AsyncElasticsearch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from models.anomaly_detector import get_detector
from models.malware_classifier import get_classifier
from models.threat_scorer import compute_threat_score, generate_explanation

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] INFERENCE: %(message)s",
)
logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:29092")
KAFKA_SCORED_TOPIC = os.getenv("KAFKA_SCORED_TOPIC", "scored-threats")
ES_URL = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch:9200")
POSTGRES_URL = os.getenv("POSTGRES_URL", "postgresql://cti_user:cti_secure_pass@postgres:5432/cti_db")

@asynccontextmanager
async def lifespan(app: FastAPI):
    global es, kafka_producer

    # Load ML models
    logger.info("Loading ML models...")
    for attempt in range(10):
        if detector.load() and classifier.load():
            break
        logger.warning(f"Models not ready (attempt {attempt + 1}/10), retrying...")
        await asyncio.sleep(5)

    # Connect to Elasticsearch
    logger.info("Connecting to Elasticsearch...")
    es = AsyncElasticsearch([ES_URL], request_timeout=30)
    for attempt in range(20):
        try:
            if await es.ping():
                await _ensure_es_indices()
                break
        except Exception:
            pass
        logger.info(f"Waiting for Elasticsearch (attempt {attempt+1}/20)...")
        await asyncio.sleep(5)

    # Connect to Kafka producer
    kafka_producer = Producer({
        "bootstrap.servers": KAFKA_BOOTSTRAP,
        "acks": "1",
        "linger.ms": 10,
    })
    logger.info("Inference service ready.")

    yield

    if es:
        await es.close()
    if kafka_producer:
        kafka_producer.flush(timeout=5)


app = FastAPI(title="CTI ML Inference Service", version="1.0.0", lifespan=lifespan)

# ── Global resources ──────────────────────────────────────────────────────────
es: AsyncElasticsearch = None
kafka_producer: Producer = None
detector = get_detector()
classifier = get_classifier()


class InferenceRequest(BaseModel):
    events: list[dict[str, Any]]


class InferenceResponse(BaseModel):
    processed: int
    threats_detected: int
    results: list[dict[str, Any]]





async def _ensure_es_indices():
    """Create Elasticsearch indices with mappings if they don't exist."""
    log_mapping = {
        "mappings": {
            "properties": {
                "timestamp": {"type": "date"},
                "src_ip": {"type": "ip"},
                "dst_ip": {"type": "ip"},
                "threat_score": {"type": "integer"},
                "threat_level": {"type": "keyword"},
                "classification": {"type": "keyword"},
                "anomaly_score": {"type": "float"},
                "mitre_technique": {"type": "keyword"},
                "geo_location": {"type": "geo_point"},
                "attack_type": {"type": "keyword"},
            }
        }
    }
    for index in ["cti_logs", "cti_threats"]:
        if not await es.indices.exists(index=index):
            await es.indices.create(index=index, mappings=log_mapping["mappings"])
            logger.info(f"Created index: {index}")


@app.post("/infer", response_model=InferenceResponse)
async def infer(request: InferenceRequest):
    """Process a batch of events through the ML pipeline."""
    results = []
    threats_detected = 0

    for event in request.events:
        try:
            result = await process_single_event(event)
            results.append(result)
            if result.get("threat_level") in ("CRITICAL", "HIGH", "MEDIUM"):
                threats_detected += 1
        except Exception as e:
            logger.error(f"Error processing event {event.get('log_id')}: {e}")

    return InferenceResponse(
        processed=len(results),
        threats_detected=threats_detected,
        results=results,
    )


async def process_single_event(event: dict) -> dict:
    features = event.get("features", [])
    feature_names = event.get("feature_names", [])

    # ── Anomaly detection ──────────────────────────────────────────────────
    anomaly_result = detector.predict(features)
    top_features = detector.explain(features, feature_names)

    # ── Malware classification ─────────────────────────────────────────────
    classification_result = classifier.predict(features)

    # ── Threat scoring ─────────────────────────────────────────────────────
    ip_rep = features[14] if len(features) > 14 else 0.0
    is_bad_ip = bool(features[9] > 0.5) if len(features) > 9 else False

    threat_score = compute_threat_score(
        anomaly_score=anomaly_result["anomaly_score"],
        classification=classification_result["classification"],
        classification_confidence=classification_result["confidence"],
        ip_reputation_score=ip_rep,
        mitre_technique=event.get("mitre_technique"),
        is_known_bad_ip=is_bad_ip,
        attack_type=event.get("attack_type"),
    )

    # ── Explanation ────────────────────────────────────────────────────────
    explanation = generate_explanation(
        top_features, anomaly_result, classification_result, threat_score,
        event.get("attack_type")
    )

    result = {
        "log_id": event.get("log_id"),
        "timestamp": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "src_ip": event.get("src_ip"),
        "dst_ip": event.get("dst_ip"),
        "src_port": event.get("src_port"),
        "dst_port": event.get("dst_port"),
        "protocol": event.get("protocol"),
        "service": event.get("service"),
        "geo_country": event.get("geo_country"),
        "geo_city": event.get("geo_city"),
        "geo_lat": event.get("geo_lat"),
        "geo_lon": event.get("geo_lon"),
        "anomaly_score": anomaly_result["anomaly_score"],
        "is_anomaly": anomaly_result["is_anomaly"],
        "classification": classification_result["classification"],
        "classification_confidence": classification_result["confidence"],
        "class_probabilities": classification_result["probabilities"],
        "threat_score": threat_score.final_score,
        "threat_level": threat_score.threat_level,
        "mitre_technique": event.get("mitre_technique"),
        "attack_type": event.get("attack_type"),
        "explanation": explanation,
        "recommendations": threat_score.recommendations,
        "top_features": top_features,
    }

    # Async persistence tasks
    asyncio.create_task(_persist_to_elasticsearch(result))
    if result["threat_level"] in ("CRITICAL", "HIGH", "MEDIUM"):
        asyncio.create_task(_publish_to_kafka(result))

    return result


async def _persist_to_elasticsearch(result: dict):
    if not es:
        return
    try:
        doc = {**result}
        if result.get("geo_lat") and result.get("geo_lon"):
            doc["geo_location"] = {
                "lat": result["geo_lat"],
                "lon": result["geo_lon"],
            }
        index = "cti_threats" if result["threat_level"] not in ("INFO", "LOW") else "cti_logs"
        await es.index(index=index, document=doc)
    except Exception as e:
        logger.error(f"ES persistence failed: {e}")


async def _publish_to_kafka(result: dict):
    if not kafka_producer:
        return
    try:
        kafka_producer.produce(
            topic=KAFKA_SCORED_TOPIC,
            key=result.get("src_ip", "unknown").encode(),
            value=json.dumps(result).encode("utf-8"),
        )
        kafka_producer.poll(0)
    except Exception as e:
        logger.error(f"Kafka publish failed: {e}")


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "models_loaded": detector.is_loaded and classifier.is_loaded,
        "es_connected": await es.ping() if es else False,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001, log_level="info")
