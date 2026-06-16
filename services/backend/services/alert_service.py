"""
Alert service — higher-level alert management logic (bulk ops, enrichment, dedup).
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, delete

from models.alert import Alert

logger = logging.getLogger(__name__)


async def get_alert_count_by_level(
    db: AsyncSession,
    hours: int = 24,
) -> Dict[str, int]:
    """Count alerts by threat level in the last N hours."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    rows = await db.execute(
        select(Alert.threat_level, func.count(Alert.id))
        .where(Alert.timestamp >= since)
        .group_by(Alert.threat_level)
    )
    return {row[0]: row[1] for row in rows}


async def deduplicate_alert(
    db: AsyncSession,
    src_ip: str,
    attack_type: Optional[str],
    window_seconds: int = 60,
) -> bool:
    """
    Returns True if a similar alert was already created within the dedup window.
    Prevents alert storms from the same source/type pair.
    """
    since = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
    filters = [Alert.src_ip == src_ip, Alert.timestamp >= since]
    if attack_type:
        filters.append(Alert.attack_type == attack_type)

    existing = (await db.execute(
        select(func.count(Alert.id)).where(and_(*filters))
    )).scalar_one()

    return existing > 0


async def bulk_acknowledge(
    db: AsyncSession,
    alert_ids: List[str],
    user_id: str,
) -> int:
    """Acknowledge multiple alerts at once. Returns number of updated rows."""
    now = datetime.now(timezone.utc)
    count = 0
    for aid in alert_ids:
        result = await db.execute(select(Alert).where(Alert.id == aid))
        alert = result.scalars().first()
        if alert and not alert.is_acknowledged:
            alert.is_acknowledged = True
            alert.acknowledged_by = user_id
            alert.acknowledged_at = now
            count += 1
    await db.commit()
    return count


async def purge_old_alerts(
    db: AsyncSession,
    days: int = 30,
) -> int:
    """Delete acknowledged alerts older than N days. Returns number deleted."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    result = await db.execute(
        delete(Alert)
        .where(
            and_(
                Alert.is_acknowledged.is_(True),
                Alert.timestamp < cutoff,
            )
        )
        .execution_options(synchronize_session=False)
    )
    await db.commit()
    deleted = result.rowcount or 0
    logger.info(f"Purged {deleted} old acknowledged alerts (older than {days} days)")
    return deleted
