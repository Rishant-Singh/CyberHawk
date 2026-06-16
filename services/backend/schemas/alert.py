"""Pydantic schemas for alerts."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class AlertBase(BaseModel):
    src_ip: str
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    threat_score: int = Field(ge=0, le=100)
    threat_level: str
    classification: str
    anomaly_score: float
    mitre_technique: Optional[str] = None
    attack_type: Optional[str] = None
    explanation: Optional[str] = None


class AlertCreate(AlertBase):
    log_id: Optional[str] = None
    geo_country: Optional[str] = None
    geo_lat: Optional[float] = None
    geo_lon: Optional[float] = None
    recommendations: Optional[list] = None
    top_features: Optional[list] = None


class AlertResponse(AlertBase):
    id: str
    timestamp: datetime
    geo_country: Optional[str] = None
    geo_city: Optional[str] = None
    geo_lat: Optional[float] = None
    geo_lon: Optional[float] = None
    recommendations: Optional[list] = None
    top_features: Optional[list] = None
    classification_confidence: float = 0.0
    is_acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class AlertFilter(BaseModel):
    src_ip: Optional[str] = None
    threat_level: Optional[str] = None
    classification: Optional[str] = None
    mitre_technique: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    min_score: Optional[int] = None
    page: int = Field(default=1, ge=1)
    size: int = Field(default=50, ge=1, le=200)


class AlertStats(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    acknowledged: int
    by_hour: list[dict]
    top_attack_types: list[dict]
    top_src_ips: list[dict]
