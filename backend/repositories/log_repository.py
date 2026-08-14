"""
SentinelX AI — Log Repository
================================
Data access layer for SecurityLog model.
All database interactions for log records go through this class.

Responsibilities:
  - Create new SecurityLog records (on file upload)
  - Update status, counters, and timestamps during pipeline processing
  - Query logs with filtering, pagination, and sorting
  - Soft-delete (status = failed) rather than physical deletion

Follows Phase 1 conventions:
  - __init__(self, db: AsyncSession)
  - All methods are async
  - Uses SQLAlchemy Core select() — no ORM lazy loading
  - Commits are explicit — no autocommit
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from backend.models.security_log import LogStatus, LogType, SecurityLog

logger = logging.getLogger(__name__)


class LogRepository:
    """Repository for SecurityLog CRUD operations."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    # ── Create ────────────────────────────────────────────────────────────────

    async def create(
        self,
        *,
        filename: str,
        log_type: LogType,
        raw_content: str,
        file_size_bytes: int,
        line_count: int,
        uploaded_by: int | None = None,
    ) -> SecurityLog:
        """
        Persist a new SecurityLog record.

        The log is created in PENDING status. The pipeline service
        transitions it to PROCESSING → COMPLETED or FAILED.
        """
        log = SecurityLog(
            filename=filename,
            log_type=log_type.value,
            raw_content=raw_content,
            file_size_bytes=file_size_bytes,
            line_count=line_count,
            status=LogStatus.PENDING.value,
            uploaded_by=uploaded_by,
        )
        self._db.add(log)
        await self._db.commit()
        await self._db.refresh(log)
        logger.info("Created SecurityLog id=%d filename=%s type=%s", log.id, filename, log_type.value)
        return log

    # ── Read ──────────────────────────────────────────────────────────────────

    async def get_by_id(self, log_id: int) -> SecurityLog | None:
        """Fetch a log record by primary key."""
        result = await self._db.execute(
            select(SecurityLog).where(SecurityLog.id == log_id)
        )
        return result.scalar_one_or_none()

    async def list_logs(
        self,
        *,
        page: int = 1,
        page_size: int = 20,
        status: str | None = None,
        log_type: str | None = None,
        uploaded_by: int | None = None,
    ) -> tuple[list[SecurityLog], int]:
        """
        Paginated list of logs with optional filtering.

        Returns:
            (items, total_count)
        """
        query = select(SecurityLog)
        if status:
            query = query.where(SecurityLog.status == status)
        if log_type:
            query = query.where(SecurityLog.log_type == log_type)
        if uploaded_by is not None:
            query = query.where(SecurityLog.uploaded_by == uploaded_by)

        # Total count
        count_result = await self._db.execute(
            select(func.count()).select_from(query.subquery())
        )
        total = count_result.scalar_one()

        # Paginated results — newest first
        offset = (page - 1) * page_size
        query = query.order_by(SecurityLog.created_at.desc()).offset(offset).limit(page_size)
        result = await self._db.execute(query)
        items = list(result.scalars().all())

        return items, total

    # ── Status transitions ────────────────────────────────────────────────────

    async def mark_processing(self, log_id: int) -> None:
        """Transition log to PROCESSING and stamp processing_started_at."""
        await self._db.execute(
            update(SecurityLog)
            .where(SecurityLog.id == log_id)
            .values(
                status=LogStatus.PROCESSING.value,
                processing_started_at=datetime.now(timezone.utc),
            )
        )
        await self._db.commit()
        logger.info("SecurityLog id=%d → PROCESSING", log_id)

    async def mark_completed(
        self,
        log_id: int,
        *,
        log_type: str,
        parsed_event_count: int,
        ioc_count: int,
        line_count: int | None = None,
    ) -> None:
        """
        Transition log to COMPLETED and update all counters.

        Called by the pipeline service after successful processing.
        """
        values: dict[str, Any] = {
            "status":                    LogStatus.COMPLETED.value,
            "log_type":                  log_type,
            "parsed_event_count":        parsed_event_count,
            "ioc_count":                 ioc_count,
            "processing_completed_at":   datetime.now(timezone.utc),
        }
        if line_count is not None:
            values["line_count"] = line_count

        await self._db.execute(
            update(SecurityLog)
            .where(SecurityLog.id == log_id)
            .values(**values)
        )
        await self._db.commit()
        logger.info(
            "SecurityLog id=%d → COMPLETED events=%d iocs=%d",
            log_id, parsed_event_count, ioc_count,
        )

    async def mark_failed(self, log_id: int, *, error: str) -> None:
        """Transition log to FAILED and record the error message."""
        await self._db.execute(
            update(SecurityLog)
            .where(SecurityLog.id == log_id)
            .values(
                status=LogStatus.FAILED.value,
                parse_error=error[:2000],   # Truncate to fit column
                processing_completed_at=datetime.now(timezone.utc),
            )
        )
        await self._db.commit()
        logger.error("SecurityLog id=%d → FAILED: %s", log_id, error[:200])

    # ── Statistics ────────────────────────────────────────────────────────────

    async def count_by_status(self) -> dict[str, int]:
        """Return counts grouped by status for the dashboard."""
        result = await self._db.execute(
            select(SecurityLog.status, func.count(SecurityLog.id))
            .group_by(SecurityLog.status)
        )
        return {row[0]: row[1] for row in result.all()}
