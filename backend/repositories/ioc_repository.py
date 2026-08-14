"""
SentinelX AI — IOC Repository
================================
Data access layer for IOCEntity model.

Responsibilities:
  - Bulk upsert IOCs from the pipeline (upsert = insert or increment count)
  - Query IOCs with type filtering, value search, and pagination
  - Aggregate statistics across the platform (top IOC types, frequent values)

Upsert strategy:
  The IOCEntity table has a UNIQUE constraint on (log_id, ioc_type, value).
  On conflict, we increment occurrence_count and update last_seen.
  This is implemented with SQLAlchemy's insert().on_conflict_do_update()
  using PostgreSQL dialect.

Performance:
  - Bulk upserts are batched in a single statement where possible
  - Value search uses ILIKE for case-insensitive matching
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from backend.models.ioc_entity import IOCEntity, IOCType
from backend.nlp.extractor.ioc_extractor import ExtractedIOC

logger = logging.getLogger(__name__)


class IOCRepository:
    """Repository for IOCEntity upsert and query operations."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    # ── Bulk upsert ───────────────────────────────────────────────────────────

    async def bulk_upsert_from_extracted(
        self,
        log_id: int,
        iocs: list[ExtractedIOC],
        event_id: int | None = None,
    ) -> int:
        """
        Upsert a list of ExtractedIOC objects into the ioc_entities table.

        On conflict (same log_id + ioc_type + value):
          - Increments occurrence_count by 1
          - Updates last_seen to NOW()

        Args:
            log_id:   Parent SecurityLog primary key.
            iocs:     Deduplicated IOC list from IOCExtractor.
            event_id: Optional: first ParsedEvent this IOC appeared in.

        Returns:
            Number of IOC records upserted.
        """
        if not iocs:
            return 0

        now = datetime.now(timezone.utc)
        rows = [
            {
                "log_id":           log_id,
                "event_id":         event_id,
                "ioc_type":         ioc.ioc_type.value,
                "value":            ioc.value[:2048],
                "context":          ioc.context[:500] if ioc.context else None,
                "occurrence_count": 1,
                "first_seen":       now,
                "last_seen":        now,
                "created_at":       now,
            }
            for ioc in iocs
        ]

        stmt = pg_insert(IOCEntity).values(rows)
        stmt = stmt.on_conflict_do_update(
            constraint="uq_ioc_log_type_value",
            set_={
                "occurrence_count": IOCEntity.occurrence_count + 1,
                "last_seen":        now,
            },
        )

        await self._db.execute(stmt)
        await self._db.flush()
        logger.info("Upserted %d IOCs for log_id=%d", len(iocs), log_id)
        return len(iocs)

    # ── Read ──────────────────────────────────────────────────────────────────

    async def get_by_id(self, ioc_id: int) -> IOCEntity | None:
        """Fetch a single IOC record by primary key."""
        result = await self._db.execute(
            select(IOCEntity).where(IOCEntity.id == ioc_id)
        )
        return result.scalar_one_or_none()

    async def list_by_log(
        self,
        log_id: int,
        *,
        ioc_type: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[IOCEntity], int]:
        """
        Paginated IOC list for a given log, optionally filtered by type.

        Returns:
            (items, total_count)
        """
        query = select(IOCEntity).where(IOCEntity.log_id == log_id)
        if ioc_type:
            query = query.where(IOCEntity.ioc_type == ioc_type)

        count_result = await self._db.execute(
            select(func.count()).select_from(query.subquery())
        )
        total = count_result.scalar_one()

        offset = (page - 1) * page_size
        query = (
            query
            .order_by(IOCEntity.occurrence_count.desc(), IOCEntity.id.asc())
            .offset(offset)
            .limit(page_size)
        )
        result = await self._db.execute(query)
        return list(result.scalars().all()), total

    async def search_by_value(
        self,
        value: str,
        *,
        ioc_type: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[IOCEntity], int]:
        """
        Case-insensitive search for IOCs by value substring.

        Useful for threat hunting (e.g. search all records for "185.24.18").
        """
        query = select(IOCEntity).where(IOCEntity.value.ilike(f"%{value}%"))
        if ioc_type:
            query = query.where(IOCEntity.ioc_type == ioc_type)

        count_result = await self._db.execute(
            select(func.count()).select_from(query.subquery())
        )
        total = count_result.scalar_one()

        offset = (page - 1) * page_size
        query = query.order_by(IOCEntity.last_seen.desc()).offset(offset).limit(page_size)
        result = await self._db.execute(query)
        return list(result.scalars().all()), total

    async def list_all(
        self,
        *,
        ioc_type: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[IOCEntity], int]:
        """Return all IOCs paginated, optionally filtered by type."""
        query = select(IOCEntity)
        if ioc_type:
            query = query.where(IOCEntity.ioc_type == ioc_type)

        count_result = await self._db.execute(
            select(func.count()).select_from(query.subquery())
        )
        total = count_result.scalar_one()

        offset = (page - 1) * page_size
        query = query.order_by(IOCEntity.last_seen.desc()).offset(offset).limit(page_size)
        result = await self._db.execute(query)
        return list(result.scalars().all()), total


    async def get_by_value_and_type(
        self, value: str, ioc_type: IOCType, log_id: int
    ) -> IOCEntity | None:
        """Look up a specific IOC within a specific log."""
        result = await self._db.execute(
            select(IOCEntity).where(
                IOCEntity.log_id == log_id,
                IOCEntity.ioc_type == ioc_type.value,
                IOCEntity.value == value,
            )
        )
        return result.scalar_one_or_none()

    # ── Aggregations ──────────────────────────────────────────────────────────

    async def ioc_type_summary(self) -> list[dict[str, Any]]:
        """Return total IOC counts grouped by type across the entire platform."""
        result = await self._db.execute(
            select(IOCEntity.ioc_type, func.count(IOCEntity.id).label("count"))
            .group_by(IOCEntity.ioc_type)
            .order_by(func.count(IOCEntity.id).desc())
        )
        return [{"ioc_type": row[0], "count": row[1]} for row in result.all()]

    async def top_ioc_values(
        self,
        ioc_type: str,
        *,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """
        Return the most frequently seen IOC values of a specific type.

        For example: top 10 attacker IPs across all logs.
        """
        result = await self._db.execute(
            select(IOCEntity.value, func.sum(IOCEntity.occurrence_count).label("total"))
            .where(IOCEntity.ioc_type == ioc_type)
            .group_by(IOCEntity.value)
            .order_by(func.sum(IOCEntity.occurrence_count).desc())
            .limit(limit)
        )
        return [{"value": row[0], "total_occurrences": row[1]} for row in result.all()]

    async def total_ioc_count(self) -> int:
        """Total number of IOCEntity records in the database."""
        result = await self._db.execute(select(func.count(IOCEntity.id)))
        return result.scalar_one()

    async def unique_ioc_value_count(self) -> int:
        """Count of distinct IOC values (deduplicated across all logs)."""
        result = await self._db.execute(
            select(func.count(func.distinct(IOCEntity.value)))
        )
        return result.scalar_one()
