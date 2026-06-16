"""
Train Malware Classifier — XGBoost multi-class classifier.
Generates synthetic labeled training data and trains/saves the model.
"""

import os
import sys
import logging
import numpy as np
import joblib
from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from models.malware_classifier import MalwareClassifier, REVERSE_LABEL_MAP

logging.basicConfig(level=logging.INFO, format="%(asctime)s [TRAIN] %(message)s")
logger = logging.getLogger(__name__)

MODELS_DIR = os.getenv("MODELS_DIR", "/app/models/saved")
N_FEATURES = 15


def generate_labeled_data(n_per_class: int = 5000) -> tuple[np.ndarray, np.ndarray]:
    """Generate synthetic labeled training data for each class."""
    rng = np.random.default_rng(42)
    all_X, all_y = [], []

    # ── BENIGN (class 0) ──────────────────────────────────────────────────────
    n = n_per_class
    X_b = np.column_stack([
        rng.uniform(0.05, 0.6, n),    # payload_size_log
        rng.uniform(0.01, 0.5, n),    # duration_log
        rng.uniform(0.01, 0.3, n),    # packet_count_log
        rng.uniform(0.1, 0.5, n),     # flow_rate_log
        rng.uniform(0.05, 0.5, n),    # bytes_per_pkt_log
        rng.uniform(0.0, 0.05, n),    # fwd_bwd_ratio
        rng.choice([0.0, 0.2], n),    # protocol_encoded
        rng.choice([0.14, 0.28, 0.43], n),  # flag_encoded
        rng.choice([80/65535, 443/65535], n),  # dst_port_normalized
        np.zeros(n),                  # is_known_bad_ip
        np.ones(n),                   # is_private_src
        np.zeros(n),                  # is_high_risk_country
        np.zeros(n),                  # is_high_risk_port
        rng.choice([0, 1], n).astype(float),  # is_privileged_port
        rng.uniform(0.0, 0.15, n),    # ip_reputation_score
    ])
    all_X.append(X_b)
    all_y.extend([0] * n)

    # ── SUSPICIOUS (class 1) ──────────────────────────────────────────────────
    n = n_per_class
    X_s = np.column_stack([
        rng.uniform(0.3, 0.8, n),     # Slightly larger payloads
        rng.uniform(0.001, 0.2, n),   # Shorter durations
        rng.uniform(0.2, 0.6, n),     # More packets
        rng.uniform(0.4, 0.8, n),     # Higher flow rate
        rng.uniform(0.1, 0.6, n),     # bytes_per_pkt_log
        rng.uniform(0.05, 0.3, n),    # fwd_bwd_ratio
        rng.choice([0.0, 0.2, 0.4], n),  # protocol_encoded
        rng.choice([0.0, 0.71, 0.86], n),  # SYN/RST flags
        rng.choice([22/65535, 3389/65535, 445/65535], n),  # High-risk ports
        rng.choice([0, 0, 1], n).astype(float) * 0.3,  # Sometimes bad IP
        rng.choice([0, 1], n).astype(float),
        rng.choice([0, 1], n).astype(float),
        rng.choice([0, 1], n).astype(float),
        np.ones(n),                   # Privileged ports
        rng.uniform(0.3, 0.6, n),     # ip_reputation_score
    ])
    all_X.append(X_s)
    all_y.extend([1] * n)

    # ── MALICIOUS (class 2) ───────────────────────────────────────────────────
    n = n_per_class
    X_m = np.column_stack([
        rng.uniform(0.6, 1.0, n),     # Large payloads
        rng.uniform(0.001, 0.05, n),  # Very short or very long
        rng.uniform(0.5, 1.0, n),     # High packet counts
        rng.uniform(0.7, 1.0, n),     # Very high flow rates
        rng.uniform(0.3, 1.0, n),     # bytes_per_pkt_log
        rng.uniform(0.2, 1.0, n),     # fwd_bwd_ratio
        rng.choice([0.0, 0.4, 0.8], n),  # Various protocols
        rng.choice([0.0, 0.71], n),   # SYN/RST flags
        rng.choice([22/65535, 4444/65535, 31337/65535], n),  # Malicious ports
        rng.choice([0, 1, 1], n).astype(float),  # Often bad IP
        np.zeros(n),                  # External source
        rng.choice([0, 1, 1], n).astype(float),  # High-risk country
        np.ones(n),                   # High-risk port
        np.ones(n),                   # Privileged port
        rng.uniform(0.65, 1.0, n),    # High reputation score
    ])
    all_X.append(X_m)
    all_y.extend([2] * n)

    X = np.vstack(all_X).astype(np.float32)
    y = np.array(all_y, dtype=np.int32)
    return X, y


def main():
    os.makedirs(MODELS_DIR, exist_ok=True)

    clf_path = os.path.join(MODELS_DIR, "malware_classifier.joblib")
    if os.path.exists(clf_path):
        logger.info("Malware classifier already exists — skipping training.")
        return

    logger.info("Generating labeled training data (15,000 samples)...")
    X, y = generate_labeled_data(n_per_class=5000)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    logger.info("Training XGBoost classifier...")
    model = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric="mlogloss",
        random_state=42,
        n_jobs=-1,
        objective="multi:softprob",
        num_class=3,
    )
    model.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        verbose=50,
    )

    # Evaluation
    y_pred = model.predict(X_test)
    report = classification_report(
        y_test, y_pred,
        target_names=["benign", "suspicious", "malicious"]
    )
    logger.info(f"\nClassification Report:\n{report}")

    le = LabelEncoder()
    le.fit([0, 1, 2])

    classifier = MalwareClassifier()
    classifier.save(model, le)
    logger.info("✓ Malware classifier saved successfully.")


if __name__ == "__main__":
    main()
