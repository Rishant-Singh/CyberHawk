"""
Anomaly Detector — Dual-model approach:
1. Isolation Forest: tree-based outlier detection (fast, production-ready)
2. Autoencoder (PyTorch): learns normal patterns, flags high reconstruction error

Both models produce an anomaly score in [0, 1]. Ensemble combines them.
"""

import os
import logging
import numpy as np
import joblib
import torch
import torch.nn as nn
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

MODELS_DIR = os.getenv("MODELS_DIR", "/app/models/saved")
ANOMALY_THRESHOLD = float(os.getenv("ANOMALY_THRESHOLD", "0.65"))
N_FEATURES = 15


# ─────────────────────────────────────────────────────────────────────────────
# AUTOENCODER ARCHITECTURE
# ─────────────────────────────────────────────────────────────────────────────

class NetworkAutoencoder(nn.Module):
    """
    Autoencoder for network traffic anomaly detection.
    Learns a compressed representation of normal traffic.
    High reconstruction error → anomalous.
    """

    def __init__(self, input_dim: int = N_FEATURES):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 32),
            nn.LeakyReLU(0.2),
            nn.Dropout(0.1),
            nn.Linear(32, 16),
            nn.LeakyReLU(0.2),
            nn.Linear(16, 8),
            nn.LeakyReLU(0.2),
        )
        self.decoder = nn.Sequential(
            nn.Linear(8, 16),
            nn.LeakyReLU(0.2),
            nn.Linear(16, 32),
            nn.LeakyReLU(0.2),
            nn.Dropout(0.1),
            nn.Linear(32, input_dim),
            nn.Sigmoid(),  # Features are normalized to [0, 1]
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))

    def reconstruction_error(self, x: torch.Tensor) -> torch.Tensor:
        with torch.no_grad():
            recon = self.forward(x)
            return torch.mean((x - recon) ** 2, dim=1)


# ─────────────────────────────────────────────────────────────────────────────
# ANOMALY DETECTOR CLASS
# ─────────────────────────────────────────────────────────────────────────────

class AnomalyDetector:
    """
    Ensemble anomaly detector combining Isolation Forest and Autoencoder.
    """

    def __init__(self):
        self.iso_forest: IsolationForest | None = None
        self.autoencoder: NetworkAutoencoder | None = None
        self.scaler: StandardScaler | None = None
        self.ae_threshold: float = 0.05  # Reconstruction error threshold
        self.iso_weight = 0.5
        self.ae_weight = 0.5
        self.is_loaded = False

    def load(self) -> bool:
        """Load trained models from disk."""
        iso_path = os.path.join(MODELS_DIR, "isolation_forest.joblib")
        ae_path = os.path.join(MODELS_DIR, "autoencoder.pt")
        scaler_path = os.path.join(MODELS_DIR, "anomaly_scaler.joblib")

        if not all(os.path.exists(p) for p in [iso_path, ae_path, scaler_path]):
            logger.warning("Anomaly model files not found — need training first.")
            return False

        self.iso_forest = joblib.load(iso_path)
        self.scaler = joblib.load(scaler_path)
        self.autoencoder = NetworkAutoencoder(N_FEATURES)
        self.autoencoder.load_state_dict(torch.load(ae_path, map_location="cpu", weights_only=True))
        self.autoencoder.eval()
        self.is_loaded = True
        logger.info("Anomaly detector loaded successfully.")
        return True

    def save(self, iso_forest: IsolationForest, autoencoder: NetworkAutoencoder,
             scaler: StandardScaler, ae_threshold: float) -> None:
        """Persist models to disk."""
        os.makedirs(MODELS_DIR, exist_ok=True)
        joblib.dump(iso_forest, os.path.join(MODELS_DIR, "isolation_forest.joblib"))
        joblib.dump(scaler, os.path.join(MODELS_DIR, "anomaly_scaler.joblib"))
        torch.save(autoencoder.state_dict(), os.path.join(MODELS_DIR, "autoencoder.pt"))
        joblib.dump(ae_threshold, os.path.join(MODELS_DIR, "ae_threshold.joblib"))

        self.iso_forest = iso_forest
        self.autoencoder = autoencoder
        self.scaler = scaler
        self.ae_threshold = ae_threshold
        self.is_loaded = True
        logger.info("Anomaly detector saved.")

    def predict(self, features: list[float]) -> dict:
        """
        Run anomaly detection on a feature vector.
        Returns score in [0, 1] and a boolean flag.
        """
        if not self.is_loaded:
            return {"anomaly_score": 0.0, "is_anomaly": False, "method": "unavailable"}

        x = np.array(features, dtype=np.float32).reshape(1, -1)
        x_scaled = self.scaler.transform(x)

        # Isolation Forest score: -1 (anomaly) or 1 (normal)
        iso_raw = self.iso_forest.decision_function(x_scaled)[0]
        # Normalize to [0, 1]: lower score → more anomalous
        iso_score = 1.0 - (iso_raw - self.iso_forest.offset_) / (
            abs(self.iso_forest.offset_) + 1e-8
        )
        iso_score = float(np.clip(iso_score, 0, 1))

        # Autoencoder reconstruction error
        x_tensor = torch.tensor(x_scaled, dtype=torch.float32)
        ae_error = float(self.autoencoder.reconstruction_error(x_tensor)[0])
        ae_score = float(np.clip(ae_error / (self.ae_threshold * 3), 0, 1))

        # Weighted ensemble
        final_score = self.iso_weight * iso_score + self.ae_weight * ae_score
        final_score = float(np.clip(final_score, 0, 1))

        return {
            "anomaly_score": round(final_score, 4),
            "isolation_forest_score": round(iso_score, 4),
            "autoencoder_score": round(ae_score, 4),
            "is_anomaly": final_score >= ANOMALY_THRESHOLD,
            "method": "ensemble",
        }

    def explain(self, features: list[float], feature_names: list[str]) -> list[dict]:
        """
        Generate human-readable explanation of why an event was flagged.
        Returns top contributing features sorted by impact.
        """
        if not self.is_loaded or not features:
            return []

        x = np.array(features, dtype=np.float32)
        baseline = np.zeros_like(x)
        contributions = []

        for i, (val, name) in enumerate(zip(x, feature_names)):
            # Simple perturbation-based importance
            impact = abs(val - baseline[i])
            contributions.append({
                "feature": name,
                "value": round(float(val), 4),
                "impact": round(float(impact), 4),
            })

        return sorted(contributions, key=lambda c: c["impact"], reverse=True)[:5]


# Singleton instance
_detector = AnomalyDetector()


def get_detector() -> AnomalyDetector:
    return _detector
