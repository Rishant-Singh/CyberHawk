"""
Database — SQLAlchemy async engine, session factory, and table initialization.
"""

import logging
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

from core.config import settings
from core.security import hash_password

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


engine = create_async_engine(
    settings.POSTGRES_URL,
    echo=False,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


async def get_db() -> AsyncSession:
    """FastAPI dependency that provides a database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    """Create all tables, apply incremental migrations, and seed initial data."""
    from models.user import User
    from models.alert import Alert
    from models.threat import ThreatEvent
    from models.incident import Incident
    from models.asset import Asset
    from models.ioc import IOC
    from sqlalchemy import text

    import asyncio
    import time

    # Wait for PostgreSQL to be ready
    for attempt in range(30):
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("Database tables created/verified.")
            break
        except Exception as e:
            logger.warning(f"DB not ready (attempt {attempt+1}/30): {e}")
            await asyncio.sleep(3)
    else:
        logger.critical("Failed to initialize database after 30 attempts.")
        return

    # Incremental safe migrations for existing tables
    await _apply_migrations()

    # Seed admin user & initial lab assets
    await _seed_admin()
    await _seed_lab_assets()


async def _apply_migrations():
    """Ensure newly added columns exist in previously created PostgreSQL tables."""
    from sqlalchemy import text
    migrations = [
        # Alerts table
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS environment VARCHAR(20) DEFAULT 'SIMULATED';",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS detection_source VARCHAR(50) DEFAULT 'simulator';",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS event_id VARCHAR(64);",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS event_type VARCHAR(50) DEFAULT 'intrusion';",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS accuracy_radius_km DOUBLE PRECISION;",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS raw_event JSON;",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'NEW';",
        
        # Incidents table
        "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS environment VARCHAR(20) DEFAULT 'LAB';",
        "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS asset_id VARCHAR(36);",
        "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS source_ip VARCHAR(45);",
        "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS destination_ip VARCHAR(45);",
        "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS timeline JSON;",
        "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS evidence JSON;",

        # Assets table
        "ALTER TABLE assets ADD COLUMN IF NOT EXISTS subnet VARCHAR(50);",
        "ALTER TABLE assets ADD COLUMN IF NOT EXISTS environment VARCHAR(20) DEFAULT 'LAB';",
        "ALTER TABLE assets ADD COLUMN IF NOT EXISTS location VARCHAR(100) DEFAULT 'Lab Network';",
    ]

    async with engine.begin() as conn:
        for stmt in migrations:
            try:
                await conn.execute(text(stmt))
            except Exception as e:
                logger.debug(f"Migration note: {e}")

        # Ensure incidents.status is converted from enum to VARCHAR for case-insensitive flexible statuses
        try:
            await conn.execute(text("""
                DO $$
                BEGIN
                    IF EXISTS (
                        SELECT 1 FROM information_schema.columns 
                        WHERE table_name = 'incidents' AND column_name = 'status' AND udt_name = 'incident_status_enum'
                    ) THEN
                        ALTER TABLE incidents ALTER COLUMN status TYPE VARCHAR(30);
                    END IF;
                END $$;
            """))
        except Exception as e:
            logger.debug(f"Status column conversion: {e}")

    logger.info("Database migrations applied successfully.")


async def _seed_lab_assets():
    """Seed initial realistic lab assets if asset inventory is empty."""
    from models.asset import Asset
    from sqlalchemy import select

    initial_assets = [
        {
            "ip_address": "10.0.0.25",
            "hostname": "LINUX-SERVER-01",
            "asset_type": "server",
            "criticality": "high",
            "owner": "SOC Lab Team",
            "department": "Security Operations",
            "os": "Ubuntu Linux 22.04 LTS",
            "services": ["SSH:22", "HTTP:80", "HTTPS:443"],
            "tags": ["lab", "dmz", "monitored", "linux"],
            "subnet": "10.0.0.0/24",
            "environment": "LAB",
            "location": "Lab Network - DMZ",
        },
        {
            "ip_address": "10.0.0.10",
            "hostname": "WIN-DC-01",
            "asset_type": "server",
            "criticality": "critical",
            "owner": "Domain Admins",
            "department": "IT Infrastructure",
            "os": "Windows Server 2022 Datacenter",
            "services": ["LDAP:389", "Kerberos:88", "DNS:53", "SMB:445", "RDP:3389"],
            "tags": ["lab", "domain-controller", "crown-jewel"],
            "subnet": "10.0.0.0/24",
            "environment": "LAB",
            "location": "Lab Network - Core",
        },
        {
            "ip_address": "10.0.0.50",
            "hostname": "DATABASE-PROD-01",
            "asset_type": "server",
            "criticality": "critical",
            "owner": "DBA Team",
            "department": "Engineering",
            "os": "Red Hat Enterprise Linux 9",
            "services": ["PostgreSQL:5432", "SSH:22"],
            "tags": ["lab", "database", "pci-scope"],
            "subnet": "10.0.0.0/24",
            "environment": "LAB",
            "location": "Lab Network - Internal",
        },
        {
            "ip_address": "172.16.1.10",
            "hostname": "WEB-PROXY-01",
            "asset_type": "firewall",
            "criticality": "medium",
            "owner": "NetOps",
            "department": "Network Engineering",
            "os": "Debian Linux (Suricata Sensor)",
            "services": ["Suricata IDS:EVE", "Squid:3128"],
            "tags": ["sensor", "suricata", "perimeter"],
            "subnet": "172.16.1.0/24",
            "environment": "LAB",
            "location": "Perimeter Sensor Gateway",
        },
    ]

    async with AsyncSessionLocal() as session:
        for a in initial_assets:
            existing = (await session.execute(
                select(Asset).where(Asset.ip_address == a["ip_address"])
            )).scalars().first()
            if not existing:
                asset = Asset(
                    ip_address=a["ip_address"],
                    hostname=a["hostname"],
                    asset_type=a["asset_type"],
                    criticality=a["criticality"],
                    owner=a["owner"],
                    department=a["department"],
                    os=a["os"],
                    services=a["services"],
                    tags=a["tags"],
                    subnet=a["subnet"],
                    environment=a["environment"],
                    location=a["location"],
                )
                session.add(asset)
        await session.commit()
    logger.info("Lab asset inventory verified.")


async def _seed_admin():
    """Create initial admin user if none exists."""
    from models.user import User
    from sqlalchemy import select

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.role == "admin"))
        if result.scalars().first():
            return  # Admin already exists

        admin = User(
            username=settings.ADMIN_USERNAME,
            email=settings.ADMIN_EMAIL,
            hashed_password=hash_password(settings.ADMIN_PASSWORD),
            role="admin",
            is_active=True,
        )
        session.add(admin)
        await session.commit()
        logger.info(f"Admin user seeded: {settings.ADMIN_EMAIL}")
