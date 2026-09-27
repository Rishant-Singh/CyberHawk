"""SQLAlchemy ORM model for security incidents."""

import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Text, Enum, JSON
from sqlalchemy.orm import Mapped, mapped_column
from core.database import Base


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    severity: Mapped[str] = mapped_column(
        Enum("CRITICAL", "HIGH", "MEDIUM", "LOW", name="incident_severity_enum"),
        default="MEDIUM", nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(
        String(30),
        default="NEW", nullable=False, index=True
    )  # NEW, OPEN, INVESTIGATING, CONTAINED, RESOLVED, CLOSED
    environment: Mapped[str] = mapped_column(
        String(20), default="LAB", nullable=False, index=True
    )  # SIMULATED | LAB | OBSERVED

    # Connected entities
    asset_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)

    created_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    assigned_to: Mapped[str | None] = mapped_column(String(100), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Linked data (stored as JSON arrays)
    alert_ids: Mapped[list | None] = mapped_column(JSON, default=list, nullable=True)
    mitre_techniques: Mapped[list | None] = mapped_column(JSON, default=list, nullable=True)
    tags: Mapped[list | None] = mapped_column(JSON, default=list, nullable=True)
    notes: Mapped[list | None] = mapped_column(JSON, default=list, nullable=True)
    ioc_list: Mapped[list | None] = mapped_column(JSON, default=list, nullable=True)
    timeline: Mapped[list | None] = mapped_column(JSON, default=list, nullable=True)
    evidence: Mapped[list | None] = mapped_column(JSON, default=list, nullable=True)

    def __repr__(self) -> str:
        return f"<Incident {self.id[:8]} status={self.status} severity={self.severity} env={self.environment}>"
