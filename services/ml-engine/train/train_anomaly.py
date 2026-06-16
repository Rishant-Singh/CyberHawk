"""
Train Anomaly Detector — Trains Isolation Forest + Autoencoder on synthetic normal traffic.
Run once before starting the ML inference service.
"""

import os
import sys
import logging
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from models.anomaly_detector import AnomalyDetector, NetworkAutoencoder, N_FEATURES

logging.basicConfig(level=logging.INFO, format="%(asctime)s [TRAIN] %(message)s")
logger = logging.getLogger(__name__)

MODELS_DIR = os.getenv("MODELS_DIR", "/app/models/saved")
N_SAMPLES = 10000  # Normal traffic samples for training


def generate_normal_traffic(n: int) -> np.ndarray:
    """Generate synthetic normal traffic feature vectors."""
    rng = np.random.default_rng(42)
    data = np.zeros((n, N_FEATURES), dtype=np.float32)

    # Feature definitions match feature_extractor.py:
    # 0: payload_size_log (normal traffic: small-medium)
    data[:, 0] = rng.uniform(0.05, 0.6, n)  # Normal payload sizes
    # 1: duration_log (normal: short to medium)
    data[:, 1] = rng.uniform(0.01, 0.5, n)
    # 2: packet_count_log (normal: few packets)
    data[:, 2] = rng.uniform(0.01, 0.3, n)
    # 3: flow_rate_log (normal: moderate rate)
    data[:, 3] = rng.uniform(0.1, 0.5, n)
    # 4: bytes_per_pkt_log (normal: reasonable)
    data[:, 4] = rng.uniform(0.05, 0.5, n)
    # 5: fwd_bwd_ratio (normal: close to 1)
    data[:, 5] = rng.uniform(0.0, 0.1, n)
    # 6: protocol_encoded (mostly TCP/UDP)
    data[:, 6] = rng.choice([0.0, 0.2], n)
    # 7: flag_encoded (normal: SYN-ACK, PSH-ACK, FIN-ACK)
    data[:, 7] = rng.choice([0.14, 0.28, 0.43], n)
    # 8: dst_port_normalized (normal services)
    data[:, 8] = rng.choice([80/65535, 443/65535, 22/65535, 53/65535], n)
    # 9: is_known_bad_ip (normal: 0)
    data[:, 9] = rng.choice([0, 0, 0, 0, 1], n) * 0.1  # Rarely bad
    # 10: is_private_src (normal: mostly private)
    data[:, 10] = rng.choice([0, 1, 1, 1], n).astype(float)
    # 11: is_high_risk_country (normal: mostly safe)
    data[:, 11] = rng.choice([0, 0, 0, 1], n).astype(float) * 0.1
    # 12: is_high_risk_port (normal: 0)
    data[:, 12] = rng.choice([0, 0, 0, 1], n).astype(float) * 0.05
    # 13: is_privileged_port (normal: sometimes)
    data[:, 13] = rng.choice([0, 1], n).astype(float)
    # 14: ip_reputation_score (normal: low)
    data[:, 14] = rng.uniform(0.0, 0.2, n)

    return np.clip(data, 0, 1)


def train_isolation_forest(X: np.ndarray, scaler: StandardScaler) -> IsolationForest:
    logger.info("Training Isolation Forest...")
    X_scaled = scaler.fit_transform(X)

    iso_forest = IsolationForest(
        n_estimators=200,
        contamination=0.1,  # Assume ~10% anomalies in production
        max_samples="auto",
        random_state=42,
        n_jobs=-1,
    )
    iso_forest.fit(X_scaled)
    logger.info("Isolation Forest trained.")
    return iso_forest


def train_autoencoder(X: np.ndarray, scaler: StandardScaler) -> tuple[NetworkAutoencoder, float]:
    logger.info("Training Autoencoder...")
    X_scaled = scaler.transform(X).astype(np.float32)
    X_tensor = torch.tensor(X_scaled)

    dataset = TensorDataset(X_tensor, X_tensor)
    loader = DataLoader(dataset, batch_size=256, shuffle=True, num_workers=0)

    model = NetworkAutoencoder(N_FEATURES)
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3, weight_decay=1e-5)
    criterion = nn.MSELoss()
    scheduler = torch.optim.lr_scheduler.StepLR(optimizer, step_size=10, gamma=0.5)

    model.train()
    for epoch in range(30):
        epoch_loss = 0.0
        for batch_x, batch_y in loader:
            optimizer.zero_grad()
            output = model(batch_x)
            loss = criterion(output, batch_y)
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item()
        scheduler.step()
        if (epoch + 1) % 10 == 0:
            avg = epoch_loss / len(loader)
            logger.info(f"  Epoch {epoch+1}/30 — Loss: {avg:.6f}")

    # Compute threshold as 95th percentile of reconstruction errors on training data
    model.eval()
    with torch.no_grad():
        errors = model.reconstruction_error(X_tensor).numpy()
    ae_threshold = float(np.percentile(errors, 95))
    logger.info(f"Autoencoder AE threshold (95th pctile): {ae_threshold:.6f}")
    return model, ae_threshold


def main():
    os.makedirs(MODELS_DIR, exist_ok=True)

    # Check if models already exist
    iso_path = os.path.join(MODELS_DIR, "isolation_forest.joblib")
    ae_path = os.path.join(MODELS_DIR, "autoencoder.pt")
    if os.path.exists(iso_path) and os.path.exists(ae_path):
        logger.info("Anomaly models already exist — skipping training.")
        return

    logger.info(f"Generating {N_SAMPLES} normal traffic samples...")
    X_normal = generate_normal_traffic(N_SAMPLES)

    scaler = StandardScaler()

    iso_forest = train_isolation_forest(X_normal, scaler)
    autoencoder, ae_threshold = train_autoencoder(X_normal, scaler)

    detector = AnomalyDetector()
    detector.save(iso_forest, autoencoder, scaler, ae_threshold)
    logger.info("✓ Anomaly models saved successfully.")


if __name__ == "__main__":
    main()
