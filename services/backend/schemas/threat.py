"""Pydantic schemas for threat events."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class ThreatSummary(BaseModel):
    total_events: int
    threats_by_level: dict[str, int]
    avg_threat_score: float
    top_mitre_techniques: list[dict]
    top_attack_types: list[dict]
    timeline: list[dict]


class LiveThreat(BaseModel):
    """Schema for real-time WebSocket threat broadcast."""
    id: str
    timestamp: str
    src_ip: str
    dst_ip: Optional[str]
    threat_score: int
    threat_level: str
    classification: str
    anomaly_score: float
    mitre_technique: Optional[str]
    attack_type: Optional[str]
    geo_country: Optional[str]
    geo_lat: Optional[float]
    geo_lon: Optional[float]
    explanation: Optional[str]
    recommendations: Optional[list]
