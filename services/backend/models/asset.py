"""SQLAlchemy ORM model for network assets."""

import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Integer, Float, Boolean, DateTime, Enum, JSON
from sqlalchemy.orm import Mapped, mapped_column
from core.database import Base


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )

    # Identity
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, unique=True, index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    mac_address: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # Classification
    asset_type: Mapped[str] = mapped_column(
        Enum("server", "workstation", "router", "firewall", "iot", "cloud", "unknown",
             name="asset_type_enum"),
        default="unknown", nullable=False
    )
    criticality: Mapped[str] = mapped_column(
        Enum("critical", "high", "medium", "low", name="asset_criticality_enum"),
        default="medium", nullable=False, index=True
    )

    # Ownership
    owner: Mapped[str | None] = mapped_column(String(100), nullable=True)
    department: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Technical
    os: Mapped[str | None] = mapped_column(String(100), nullable=True)
    services: Mapped[list | None] = mapped_column(JSON, default=list, nullable=True)
    tags: Mapped[list | None] = mapped_column(JSON, default=list, nullable=True)

    # Network & Environment
    subnet: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    environment: Mapped[str] = mapped_column(
        String(20), default="LAB", nullable=False, index=True
    )  # LAB | INTERNAL | DMZ | OBSERVED
    location: Mapped[str | None] = mapped_column(String(100), default="Lab Network", nullable=True)

    # Geo
    geo_country: Mapped[str | None] = mapped_column(String(10), nullable=True)
    geo_city: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Activity tracking
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    # Risk
    threat_score: Mapped[float] = mapped_column(Float, default=0.0)
    total_alerts: Mapped[int] = mapped_column(Integer, default=0)
    is_compromised: Mapped[bool] = mapped_column(Boolean, default=False)

    def __repr__(self) -> str:
        return f"<Asset {self.ip_address} type={self.asset_type} criticality={self.criticality}>"
