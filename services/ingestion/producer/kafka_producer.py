"""
Kafka Producer — Streams generated logs to the raw-logs topic.
Runs continuously, producing events at the configured rate.
"""

import json
import os
import time
import signal
import logging
from confluent_kafka import Producer
from log_generator import generate_log

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] PRODUCER: %(message)s",
)
logger = logging.getLogger(__name__)

# ── Config from environment ───────────────────────────────────────────────────
KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
KAFKA_TOPIC = os.getenv("KAFKA_RAW_TOPIC", "raw-logs")
LOG_RATE = float(os.getenv("LOG_RATE_PER_SECOND", "5"))
MALICIOUS_RATIO = float(os.getenv("MALICIOUS_RATIO", "0.15"))
SUSPICIOUS_RATIO = float(os.getenv("SUSPICIOUS_RATIO", "0.10"))

# ── Global state ──────────────────────────────────────────────────────────────
running = True
total_produced = 0


def delivery_report(err, msg):
    """Callback fired when a message is acknowledged by the broker."""
    global total_produced
    if err is not None:
        logger.error(f"Delivery failed for topic={msg.topic()}: {err}")
    else:
        total_produced += 1


def create_producer() -> Producer:
    """Create a configured Kafka producer with retry logic."""
    conf = {
        "bootstrap.servers": KAFKA_BOOTSTRAP,
        "client.id": "cti-log-producer",
        "acks": "1",                  # Leader ack only for low latency
        "compression.type": "snappy",
        "linger.ms": 20,              # Batch small messages
        "batch.size": 65536,
        "retries": 5,
        "retry.backoff.ms": 500,
    }
    return Producer(conf)


def signal_handler(sig, frame):
    global running
    logger.info("Received shutdown signal, stopping producer...")
    running = False


def main():
    global running

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    # Wait for Kafka to be ready
    logger.info(f"Connecting to Kafka at {KAFKA_BOOTSTRAP}...")
    producer = None
    for attempt in range(30):
        try:
            producer = create_producer()
            # Test connectivity with metadata request
            producer.list_topics(timeout=5)
            logger.info(f"Connected to Kafka. Topic: {KAFKA_TOPIC}")
            break
        except Exception as e:
            logger.warning(f"Kafka not ready (attempt {attempt + 1}/30): {e}")
            time.sleep(5)
    else:
        logger.critical("Failed to connect to Kafka after 30 attempts. Exiting.")
        return

    interval = 1.0 / LOG_RATE
    logger.info(f"Starting log stream: {LOG_RATE} logs/sec | malicious={MALICIOUS_RATIO:.0%}")

    stats_interval = 60  # Log stats every 60 seconds
    stats_timer = time.time()

    while running:
        start = time.time()

        try:
            log = generate_log(MALICIOUS_RATIO, SUSPICIOUS_RATIO)
            payload = json.dumps(log).encode("utf-8")

            producer.produce(
                topic=KAFKA_TOPIC,
                key=log["src_ip"].encode("utf-8"),
                value=payload,
                callback=delivery_report,
            )
            producer.poll(0)  # Trigger delivery callbacks

        except BufferError:
            logger.warning("Producer queue full, flushing...")
            producer.flush(timeout=5)
        except Exception as e:
            logger.error(f"Error producing message: {e}")

        # Stats logging
        if time.time() - stats_timer >= stats_interval:
            logger.info(f"Stats: {total_produced} messages produced total")
            stats_timer = time.time()

        # Rate limiting
        elapsed = time.time() - start
        sleep_time = max(0, interval - elapsed)
        time.sleep(sleep_time)

    # Graceful shutdown
    logger.info(f"Flushing remaining messages ({total_produced} total produced)...")
    producer.flush(timeout=30)
    logger.info("Producer shutdown complete.")


if __name__ == "__main__":
    main()
