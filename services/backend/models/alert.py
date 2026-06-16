"""SQLAlchemy ORM model for security alerts."""

import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Integer, Float, Boolean, DateTime, Text, Enum, JSON
from sqlalchemy.orm import Mapped, mapped_column
from core.database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    log_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )

    # Network info
    src_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    dst_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(20), nullable=True)
    service: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Geo
    geo_country: Mapped[str | None] = mapped_column(String(10), nullable=True)
    geo_city: Mapped[str | None] = mapped_column(String(100), nullable=True)
    geo_lat: Mapped[float | None] = mapped_column(Float, nullable=True)
    geo_lon: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Threat info
    threat_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False, index=True)
    threat_level: Mapped[str] = mapped_column(
        Enum("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", name="threat_level_enum"),
        default="INFO", nullable=False, index=True
    )
    anomaly_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    classification: Mapped[str] = mapped_column(
        Enum("benign", "suspicious", "malicious", "unknown", name="classification_enum"),
        default="unknown", nullable=False
    )
    classification_confidence: Mapped[float] = mapped_column(Float, default=0.0)
    attack_type: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    mitre_technique: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)

    # Details
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendations: Mapped[list | None] = mapped_column(JSON, nullable=True)
    top_features: Mapped[list | None] = mapped_column(JSON, nullable=True)

    # Status
    is_acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    acknowledged_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return f"<Alert {self.id[:8]} level={self.threat_level} score={self.threat_score}>"
