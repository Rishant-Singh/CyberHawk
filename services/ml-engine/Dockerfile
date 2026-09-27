FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ librdkafka-dev curl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir \
    --extra-index-url https://download.pytorch.org/whl/cpu \
    -r requirements.txt

COPY . .

# Create models directory
RUN mkdir -p /app/models/saved

# Train models on first startup, then run inference service
CMD ["sh", "-c", "python train/train_anomaly.py && python train/train_classifier.py && uvicorn inference.inference_service:app --host 0.0.0.0 --port 8001 --log-level info"]
