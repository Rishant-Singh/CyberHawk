"""SQLAlchemy ORM model for raw threat events (time-series)."""

import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Integer, Float, DateTime, JSON
from sqlalchemy.orm import Mapped, mapped_column
from core.database import Base


class ThreatEvent(Base):
    __tablename__ = "threat_events"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    log_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    src_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    dst_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    threat_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    threat_level: Mapped[str] = mapped_column(String(20), default="INFO", index=True)
    anomaly_score: Mapped[float] = mapped_column(Float, default=0.0)
    classification: Mapped[str] = mapped_column(String(20), default="unknown")
    mitre_technique: Mapped[str | None] = mapped_column(String(20), nullable=True)
    attack_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    geo_country: Mapped[str | None] = mapped_column(String(10), nullable=True)
    geo_lat: Mapped[float | None] = mapped_column(Float, nullable=True)
    geo_lon: Mapped[float | None] = mapped_column(Float, nullable=True)
    raw_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)
