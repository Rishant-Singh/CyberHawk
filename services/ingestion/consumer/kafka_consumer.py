"""
Kafka Consumer — Reads raw logs from Kafka, extracts features,
and forwards to the ML Engine inference endpoint for scoring.
"""

import json
import os
import sys
import time
import logging
import requests
from confluent_kafka import Consumer, KafkaError
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from feature_extractor import extract_features

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] CONSUMER: %(message)s",
)
logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
KAFKA_TOPIC = os.getenv("KAFKA_RAW_TOPIC", "raw-logs")
KAFKA_GROUP_ID = os.getenv("KAFKA_GROUP_ID", "cti-consumer-group")
ML_ENGINE_URL = os.getenv("ML_ENGINE_URL", "http://ml-engine:8001/infer")
BATCH_SIZE = int(os.getenv("CONSUMER_BATCH_SIZE", "10"))


def create_consumer() -> Consumer:
    conf = {
        "bootstrap.servers": KAFKA_BOOTSTRAP,
        "group.id": KAFKA_GROUP_ID,
        "auto.offset.reset": "latest",
        "enable.auto.commit": True,
        "auto.commit.interval.ms": 5000,
        "session.timeout.ms": 30000,
        "max.poll.interval.ms": 300000,
        "fetch.min.bytes": 1,
        "fetch.wait.max.ms": 100,
    }
    return Consumer(conf)


def forward_to_ml(batch: list[dict]) -> None:
    """Send a batch of feature-extracted events to the ML engine."""
    try:
        response = requests.post(
            ML_ENGINE_URL,
            json={"events": batch},
            timeout=10,
        )
        if response.status_code != 200:
            logger.error(f"ML engine returned {response.status_code}: {response.text[:200]}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to forward to ML engine: {e}")


def main():
    consumer = None
    for attempt in range(30):
        try:
            consumer = create_consumer()
            consumer.subscribe([KAFKA_TOPIC])
            logger.info(f"Subscribed to {KAFKA_TOPIC}")
            break
        except Exception as e:
            logger.warning(f"Consumer init failed (attempt {attempt + 1}/30): {e}")
            time.sleep(5)
    else:
        logger.critical("Could not initialize Kafka consumer. Exiting.")
        return

    logger.info(f"Consumer running. Batch size: {BATCH_SIZE}")
    batch = []
    msg_count = 0

    try:
        while True:
            msg = consumer.poll(timeout=1.0)

            if msg is None:
                if batch:
                    forward_to_ml(batch)
                    batch = []
                continue

            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                logger.error(f"Kafka error: {msg.error()}")
                continue

            try:
                raw_log = json.loads(msg.value().decode("utf-8"))
                enriched = extract_features(raw_log)
                batch.append(enriched)
                msg_count += 1

                if len(batch) >= BATCH_SIZE:
                    forward_to_ml(batch)
                    if msg_count % 100 == 0:
                        logger.info(f"Processed {msg_count} messages")
                    batch = []

            except (json.JSONDecodeError, KeyError) as e:
                logger.warning(f"Malformed message skipped: {e}")

    except KeyboardInterrupt:
        logger.info("Shutting down consumer...")
    finally:
        if batch:
            forward_to_ml(batch)
        consumer.close()
        logger.info(f"Consumer closed. Total processed: {msg_count}")


if __name__ == "__main__":
    main()
