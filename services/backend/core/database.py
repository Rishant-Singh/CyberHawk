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
    """Create all tables and seed initial admin user."""
    from models.user import User
    from models.alert import Alert
    from models.threat import ThreatEvent

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

    # Seed admin user
    await _seed_admin()


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
