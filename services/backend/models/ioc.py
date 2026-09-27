"""SQLAlchemy ORM model for Indicators of Compromise (IOCs)."""

import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Integer, Float, DateTime, JSON, Text
from sqlalchemy.orm import Mapped, mapped_column
from core.database import Base


class IOC(Base):
    __tablename__ = "iocs"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    ioc_value: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    ioc_type: Mapped[str] = mapped_column(
        String(20), nullable=False, index=True
    )  # ipv4, ipv6, domain, url, hash_md5, hash_sha256, cve

    threat_level: Mapped[str] = mapped_column(String(20), default="UNKNOWN", index=True)
    reputation: Mapped[str] = mapped_column(String(30), default="unknown")  # clean, suspicious, malicious, unknown
    risk_score: Mapped[int] = mapped_column(Integer, default=0, index=True)

    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    hit_count: Mapped[int] = mapped_column(Integer, default=1)

    # Geolocation metadata (for public IP IOCs)
    geo_country: Mapped[str | None] = mapped_column(String(10), nullable=True)
    geo_city: Mapped[str | None] = mapped_column(String(100), nullable=True)
    geo_lat: Mapped[float | None] = mapped_column(Float, nullable=True)
    geo_lon: Mapped[float | None] = mapped_column(Float, nullable=True)
    accuracy_radius_km: Mapped[float | None] = mapped_column(Float, nullable=True)
    asn: Mapped[str | None] = mapped_column(String(50), nullable=True)
    isp: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Threat Intelligence & MITRE
    threat_intel: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    related_mitre: Mapped[list | None] = mapped_column(JSON, default=list, nullable=True)
    tags: Mapped[list | None] = mapped_column(JSON, default=list, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"<IOC {self.ioc_value} type={self.ioc_type} rep={self.reputation}>"
