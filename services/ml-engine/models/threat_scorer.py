"""
Threat Scorer — Weighted multi-factor scoring engine.
Produces a threat score in [0, 100] based on:
  - Anomaly score (ML-derived)           weight=30
  - Malware classification confidence    weight=25
  - IP reputation score                  weight=25
  - Pattern similarity to known attacks  weight=20

Also generates threat level, recommended actions, and alert priority.
"""

from dataclasses import dataclass


# ── Weights must sum to 100 ───────────────────────────────────────────────────
WEIGHTS = {
    "anomaly": 30,
    "classification": 25,
    "ip_reputation": 25,
    "pattern": 20,
}

# ── Threat level thresholds ───────────────────────────────────────────────────
THRESHOLDS = {
    "CRITICAL": 90,
    "HIGH": 75,
    "MEDIUM": 50,
    "LOW": 25,
    "INFO": 0,
}

# ── MITRE technique severity boost ───────────────────────────────────────────
MITRE_SEVERITY_BOOST = {
    "T1486": 15,  # Ransomware
    "T1003": 12,  # Credential dumping
    "T1041": 10,  # Data exfiltration
    "T1055": 10,  # Process injection
    "T1110": 8,   # Brute force
    "T1190": 8,   # Exploit public-facing app
    "T1078": 6,   # Valid accounts
    "T1059": 5,   # Command and scripting
}

RECOMMENDATIONS = {
    "CRITICAL": [
        "Immediately isolate affected systems from the network",
        "Trigger incident response playbook",
        "Preserve forensic evidence (memory dump, disk image)",
        "Notify security leadership and CISO",
        "Block source IP at perimeter firewall",
    ],
    "HIGH": [
        "Block source IP address at firewall",
        "Investigate affected system for IOCs",
        "Enable enhanced logging on target system",
        "Review related alerts in last 24 hours",
        "Check lateral movement indicators",
    ],
    "MEDIUM": [
        "Monitor source IP for continued suspicious activity",
        "Review recent activity from this IP/user",
        "Update detection rules if new pattern confirmed",
        "Increase log verbosity on affected service",
    ],
    "LOW": [
        "Log and monitor for recurring patterns",
        "Add to watchlist for correlation",
        "Review baseline if pattern persists",
    ],
    "INFO": [
        "Normal activity — no action required",
        "Retained for baseline analytics",
    ],
}


@dataclass
class ThreatScore:
    raw_score: float
    final_score: int
    threat_level: str
    anomaly_contribution: float
    classification_contribution: float
    ip_reputation_contribution: float
    pattern_contribution: float
    mitre_boost: int
    recommendations: list[str]


def compute_threat_score(
    anomaly_score: float,
    classification: str,
    classification_confidence: float,
    ip_reputation_score: float,
    mitre_technique: str | None = None,
    is_known_bad_ip: bool = False,
    attack_type: str | None = None,
) -> ThreatScore:
    """
    Compute a composite threat score (0-100) using weighted factors.

    Args:
        anomaly_score: ML anomaly score in [0, 1]
        classification: 'benign' | 'suspicious' | 'malicious'
        classification_confidence: confidence in [0, 1]
        ip_reputation_score: threat intel score in [0, 1]
        mitre_technique: MITRE ATT&CK technique ID (optional)
        is_known_bad_ip: whether IP is in known bad list
        attack_type: detected attack pattern name
    """
    # ── Component 1: Anomaly contribution ──────────────────────────────────
    anomaly_contrib = anomaly_score * WEIGHTS["anomaly"]

    # ── Component 2: Classification contribution ───────────────────────────
    class_multiplier = {"benign": 0.0, "suspicious": 0.5, "malicious": 1.0}.get(
        classification, 0.0
    )
    class_contrib = class_multiplier * classification_confidence * WEIGHTS["classification"]

    # ── Component 3: IP reputation contribution ────────────────────────────
    effective_rep = ip_reputation_score
    if is_known_bad_ip:
        effective_rep = max(effective_rep, 0.85)
    ip_contrib = effective_rep * WEIGHTS["ip_reputation"]

    # ── Component 4: Pattern similarity contribution ───────────────────────
    pattern_score = 0.0
    if attack_type is not None:
        pattern_score = 0.8  # Known attack pattern matched
    elif mitre_technique is not None:
        pattern_score = 0.5  # MITRE technique mapped
    pattern_contrib = pattern_score * WEIGHTS["pattern"]

    # ── Raw combined score ─────────────────────────────────────────────────
    raw_score = anomaly_contrib + class_contrib + ip_contrib + pattern_contrib

    # ── MITRE severity boost ───────────────────────────────────────────────
    mitre_boost = MITRE_SEVERITY_BOOST.get(mitre_technique or "", 0)
    raw_score = min(100.0, raw_score + mitre_boost)

    final_score = int(round(raw_score))

    # ── Threat level determination ─────────────────────────────────────────
    threat_level = "INFO"
    for level, threshold in THRESHOLDS.items():
        if final_score >= threshold:
            threat_level = level
            break

    return ThreatScore(
        raw_score=round(raw_score, 2),
        final_score=final_score,
        threat_level=threat_level,
        anomaly_contribution=round(anomaly_contrib, 2),
        classification_contribution=round(class_contrib, 2),
        ip_reputation_contribution=round(ip_contrib, 2),
        pattern_contribution=round(pattern_contrib, 2),
        mitre_boost=mitre_boost,
        recommendations=RECOMMENDATIONS[threat_level],
    )


def generate_explanation(
    features: list[dict],
    anomaly_result: dict,
    classification_result: dict,
    threat_score: ThreatScore,
    attack_type: str | None,
) -> str:
    """Generate a human-readable explanation for why an event was flagged."""
    parts = []

    if threat_score.threat_level in ("CRITICAL", "HIGH"):
        parts.append(f"⚠️ {threat_score.threat_level} threat detected (score: {threat_score.final_score}/100).")

    if anomaly_result.get("is_anomaly"):
        parts.append(
            f"Anomaly detection flagged this event (score: {anomaly_result['anomaly_score']:.2f}) "
            f"using ensemble of Isolation Forest and Autoencoder."
        )

    if classification_result.get("classification") != "benign":
        parts.append(
            f"Traffic classified as {classification_result['classification'].upper()} "
            f"with {classification_result['confidence']:.1%} confidence."
        )

    if attack_type:
        parts.append(f"Pattern matches known attack signature: {attack_type.replace('_', ' ').title()}.")

    # Top contributing features
    if features:
        top = features[:3]
        feature_desc = ", ".join(
            f"{f['feature'].replace('_', ' ')} ({f['value']:.3f})" for f in top
        )
        parts.append(f"Key contributing factors: {feature_desc}.")

    return " ".join(parts) if parts else "Routine traffic — no anomalies detected."
