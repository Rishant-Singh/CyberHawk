# Cyber Threat Intelligence Platform

A **production-grade, end-to-end CTI platform** that ingests real-time network/system logs, detects anomalies using ML, classifies threats, assigns dynamic threat scores, and renders insights on a military-grade Cyber Command Center dashboard.

---

## System Architecture

```
[Log Generator] → [Kafka] → [Kafka Consumer] → [ML Engine (Anomaly + Classifier + Scorer)]
                                                       ↓
                                            [Elasticsearch] + [PostgreSQL]
                                                       ↓
                                              [FastAPI Backend] → [WebSocket]
                                                       ↓
                                           [React Frontend — Command Center]
```

## Technology Stack

| Layer | Technology |
|---|---|
| Message Broker | Apache Kafka + Zookeeper |
| Processing | Python 3.11, confluent-kafka |
| ML | scikit-learn, XGBoost, PyTorch (autoencoder) |
| Backend API | FastAPI, Pydantic, SQLAlchemy, asyncpg |
| Auth | JWT (python-jose), bcrypt |
| Storage | Elasticsearch 8.x, PostgreSQL 15 |
| Frontend | React 18, Vite, D3.js v7 |
| Styling | Tailwind CSS v3 |
| Containerization | Docker + docker-compose |

---

## Quick Start

### Prerequisites
- Docker Desktop (v24+)
- Docker Compose v2
- 8 GB RAM minimum (Kafka + Elasticsearch are memory-hungry)

### 1. Configure environment
```bash
cp .env.example .env
# Edit .env and set strong passwords for JWT_SECRET_KEY, POSTGRES_PASSWORD, etc.
```

### 2. Start all services
```bash
docker-compose up -d
```

### 3. Wait for services to initialize (~60s)
```bash
docker-compose ps          # All should be "healthy"
docker-compose logs -f backend  # Watch for "CTI API ready on port 8000"
```

### 4. Access the platform
| Service | URL |
|---|---|
| **Frontend Dashboard** | http://localhost:3000 |
| **Backend API Docs** | http://localhost:8000/docs |
| **Elasticsearch** | http://localhost:9200 |
| **Kafka UI** (if enabled) | http://localhost:8080 |

### 5. Login
Default admin credentials (change immediately after first login):
- **Username:** `admin`
- **Password:** See `ADMIN_DEFAULT_PASSWORD` in your `.env`

---

## Services Overview

### `services/ingestion/`
- **`producer/log_generator.py`** — Generates realistic CICIDS-style network logs (IP pairs, protocols, ports, geo, labels)
- **`producer/kafka_producer.py`** — Streams logs to Kafka topic `raw-logs` at configurable rate
- **`consumer/kafka_consumer.py`** — Reads from `raw-logs`, extracts features, sends to ML engine
- **`consumer/feature_extractor.py`** — Feature engineering: flow stats, byte ratios, entropy, geo lookup

### `services/ml-engine/`
- **`models/anomaly_detector.py`** — Isolation Forest + Autoencoder ensemble
- **`models/malware_classifier.py`** — XGBoost multi-class classifier (benign/suspicious/malicious + attack type)
- **`models/threat_scorer.py`** — Weighted threat scoring (0–100): anomaly × 30 + severity × 25 + IP rep × 25 + pattern × 20
- **`train/`** — Training scripts using CICIDS-style synthetic data
- **`inference/inference_service.py`** — REST inference server

### `services/backend/`
FastAPI application with:
- `POST /api/auth/login` — JWT authentication
- `GET /api/alerts` — Paginated, filterable alert list
- `GET /api/threats` — Real-time threat data
- `GET /api/logs` — Elasticsearch full-text log search
- `GET /api/mitre` — MITRE ATT&CK technique lookup
- `GET /api/health` — System health metrics
- `WS /ws/live` — Real-time WebSocket threat stream

### `services/frontend/`
React 18 Command Center with:
- **Threat Map** — D3 force-directed graph of active connections
- **Radar Sweep** — SVG animated radar with threat blips
- **Threat Gauge** — D3 arc meter (0–100)
- **Anomaly Heatmap** — Calendar heatmap (15 weeks)
- **Attack Timeline** — Live scrolling event feed
- **Alert Drill-Down** — Full threat details + MITRE technique + ML explanation
- **MITRE Panel** — Searchable ATT&CK matrix with hit counts
- **System Health** — CPU/RAM/Disk/Kafka/service status

---

## Development

### Run frontend locally
```bash
cd services/frontend
npm install
npm run dev   # http://localhost:3000
```
> Make sure the backend is running at `http://localhost:8000`

### Run backend locally
```bash
cd services/backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### Train ML models
```bash
cd services/ml-engine
pip install -r requirements.txt
python train/train_anomaly.py
python train/train_classifier.py
```

---

## Environment Variables

See [`.env.example`](.env.example) for all required variables. Key ones:

| Variable | Description |
|---|---|
| `JWT_SECRET_KEY` | Random secret for JWT signing (min 32 chars) |
| `POSTGRES_PASSWORD` | PostgreSQL password |
| `ADMIN_DEFAULT_PASSWORD` | Initial admin password |
| `KAFKA_BOOTSTRAP_SERVERS` | Kafka broker address |
| `ELASTICSEARCH_URL` | Elasticsearch endpoint |

---

## Security Notes

- Change `JWT_SECRET_KEY` and `ADMIN_DEFAULT_PASSWORD` before deploying
- Elasticsearch and PostgreSQL ports are **not exposed** externally in production mode
- JWT tokens expire after 24 hours by default
- All API endpoints require authentication except `/` and `/docs`

---

## Project Structure

```
cyber-threat-intelligence/
├── docker-compose.yml           # Full stack orchestration
├── .env.example                 # Environment template
├── data/
│   └── mitre_attack_patterns.json
├── services/
│   ├── ingestion/               # Log producer + Kafka consumer
│   ├── ml-engine/               # Anomaly detection + classification
│   ├── backend/                 # FastAPI REST + WebSocket
│   └── frontend/                # React command center dashboard
└── README.md
```

---

## License

MIT
