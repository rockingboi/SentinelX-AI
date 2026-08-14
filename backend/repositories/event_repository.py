"""
SentinelX AI — Event Repository
==================================
Data access layer for ParsedEvent model.

Responsibilities:
  - Bulk-insert NormalizedEvents from the pipeline into parsed_events table
  - Query events with multi-field filtering and pagination
  - Aggregate statistics (severity breakdown, top event types, top source IPs)
  - Look up individual events for API responses

Performance notes:
  - Bulk inserts use add_all() + flush() to avoid N+1 round-trips
  - All heavy read queries use indexed columns (log_id, severity, event_type,
    source_ip, event_timestamp) — see ParsedEvent model definition
"""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.models.parsed_event import ParsedEvent
from backend.schemas.logs import NormalizedEvent

logger = logging.getLogger(__name__)


class EventRepository:
    """Repository for ParsedEvent CRUD and aggregation operations."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    # ── Bulk insert ───────────────────────────────────────────────────────────

    async def bulk_create_from_normalized(
        self,
        log_id: int,
        events: list[NormalizedEvent],
    ) -> list[ParsedEvent]:
        """
        Persist all NormalizedEvents from a pipeline run.

        Maps NormalizedEvent Pydantic fields → ParsedEvent ORM columns.
        Uses add_all() + flush() for a single round-trip per batch.

        Args:
            log_id: Parent SecurityLog primary key.
            events: Output of NLPPipeline.process().processed_events[*].event

        Returns:
            List of persisted ParsedEvent ORM objects (with IDs assigned).
        """
        if not events:
            return []

        orm_events: list[ParsedEvent] = []
        for ev in events:
            orm_ev = ParsedEvent(
                log_id=log_id,
                event_type=ev.event_type,
                log_type=ev.log_type,
                username=ev.username,
                source_ip=ev.source_ip,
                dest_ip=ev.dest_ip,
                source_port=ev.source_port,
                dest_port=ev.dest_port,
                protocol=ev.protocol,
                service=ev.service,
                hostname=ev.hostname,
                process_name=ev.process_name,
                process_id=ev.process_id,
                command_line=ev.command_line,
                file_path=ev.file_path,
                url=ev.url,
                http_method=ev.http_method,
                http_status_code=ev.http_status_code,
                user_agent=ev.user_agent,
                timestamp_raw=ev.timestamp_raw,
                event_timestamp=ev.event_timestamp,
                severity=ev.severity,
                severity_score=ev.severity_score,
                mitre_technique_id=ev.mitre_technique_id,
                mitre_technique_name=ev.mitre_technique_name,
                mitre_tactic=ev.mitre_tactic,
                mitre_tactic_id=ev.mitre_tactic_id,
                raw_line=ev.raw_line[:4096] if ev.raw_line else None,   # Guard column width
                normalized_data=ev.normalized_data or {},
                line_number=ev.line_number,
            )
            orm_events.append(orm_ev)

        self._db.add_all(orm_events)
        await self._db.flush()   # Assigns IDs without committing the transaction
        logger.info("Flushed %d ParsedEvents for log_id=%d", len(orm_events), log_id)
        return orm_events

    # ── Read ──────────────────────────────────────────────────────────────────

    async def get_by_id(self, event_id: int) -> ParsedEvent | None:
        """Fetch a single event by primary key."""
        result = await self._db.execute(
            select(ParsedEvent).where(ParsedEvent.id == event_id)
        )
        return result.scalar_one_or_none()

    async def list_by_log(
        self,
        log_id: int,
        *,
        page: int = 1,
        page_size: int = 50,
        severity: str | None = None,
        event_type: str | None = None,
        source_ip: str | None = None,
        mitre_technique_id: str | None = None,
    ) -> tuple[list[ParsedEvent], int]:
        """
        Paginated list of events for a given log, with optional filters.

        Returns:
            (items, total_count)
        """
        query = select(ParsedEvent).where(ParsedEvent.log_id == log_id)

        if severity:
            query = query.where(ParsedEvent.severity == severity)
        if event_type:
            query = query.where(ParsedEvent.event_type == event_type)
        if source_ip:
            query = query.where(ParsedEvent.source_ip == source_ip)
        if mitre_technique_id:
            query = query.where(ParsedEvent.mitre_technique_id == mitre_technique_id)

        # Count
        count_result = await self._db.execute(
            select(func.count()).select_from(query.subquery())
        )
        total = count_result.scalar_one()

        # Paginate — ordered by line number for deterministic output
        offset = (page - 1) * page_size
        query = query.order_by(ParsedEvent.line_number.asc()).offset(offset).limit(page_size)
        result = await self._db.execute(query)
        return list(result.scalars().all()), total

    async def list_threats(
        self,
        log_id: int,
        *,
        min_severity_score: int = 50,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[ParsedEvent], int]:
        """Return only threat-level events (severity_score >= threshold)."""
        query = (
            select(ParsedEvent)
            .where(ParsedEvent.log_id == log_id)
            .where(ParsedEvent.severity_score >= min_severity_score)
        )
        count_result = await self._db.execute(
            select(func.count()).select_from(query.subquery())
        )
        total = count_result.scalar_one()
        offset = (page - 1) * page_size
        query = query.order_by(ParsedEvent.severity_score.desc()).offset(offset).limit(page_size)
        result = await self._db.execute(query)
        return list(result.scalars().all()), total

    # ── Aggregations ──────────────────────────────────────────────────────────

    async def severity_breakdown(self, log_id: int) -> dict[str, int]:
        """Return event counts grouped by severity for a given log."""
        result = await self._db.execute(
            select(ParsedEvent.severity, func.count(ParsedEvent.id))
            .where(ParsedEvent.log_id == log_id)
            .where(ParsedEvent.severity.is_not(None))
            .group_by(ParsedEvent.severity)
        )
        return {row[0]: row[1] for row in result.all()}

    async def top_event_types(
        self, log_id: int, *, limit: int = 10
    ) -> list[dict[str, Any]]:
        """Return the most frequent event types in a log."""
        result = await self._db.execute(
            select(ParsedEvent.event_type, func.count(ParsedEvent.id).label("count"))
            .where(ParsedEvent.log_id == log_id)
            .where(ParsedEvent.event_type.is_not(None))
            .group_by(ParsedEvent.event_type)
            .order_by(func.count(ParsedEvent.id).desc())
            .limit(limit)
        )
        return [{"event_type": row[0], "count": row[1]} for row in result.all()]

    async def top_source_ips(
        self, log_id: int, *, limit: int = 10
    ) -> list[dict[str, Any]]:
        """Return the most frequent source IPs across events in a log."""
        result = await self._db.execute(
            select(ParsedEvent.source_ip, func.count(ParsedEvent.id).label("count"))
            .where(ParsedEvent.log_id == log_id)
            .where(ParsedEvent.source_ip.is_not(None))
            .group_by(ParsedEvent.source_ip)
            .order_by(func.count(ParsedEvent.id).desc())
            .limit(limit)
        )
        return [{"ip": row[0], "count": row[1]} for row in result.all()]

    async def top_mitre_techniques(
        self, log_id: int, *, limit: int = 10
    ) -> list[dict[str, Any]]:
        """Return the most hit MITRE techniques across events in a log."""
        result = await self._db.execute(
            select(
                ParsedEvent.mitre_technique_id,
                ParsedEvent.mitre_technique_name,
                ParsedEvent.mitre_tactic,
                func.count(ParsedEvent.id).label("count"),
            )
            .where(ParsedEvent.log_id == log_id)
            .where(ParsedEvent.mitre_technique_id.is_not(None))
            .group_by(
                ParsedEvent.mitre_technique_id,
                ParsedEvent.mitre_technique_name,
                ParsedEvent.mitre_tactic,
            )
            .order_by(func.count(ParsedEvent.id).desc())
            .limit(limit)
        )
        return [
            {
                "technique_id":   row[0],
                "technique_name": row[1],
                "tactic":         row[2],
                "count":          row[3],
            }
            for row in result.all()
        ]

    async def global_severity_breakdown(self) -> dict[str, int]:
        """Return event counts grouped by severity across ALL logs."""
        result = await self._db.execute(
            select(ParsedEvent.severity, func.count(ParsedEvent.id))
            .where(ParsedEvent.severity.is_not(None))
            .group_by(ParsedEvent.severity)
        )
        return {row[0]: row[1] for row in result.all()}

    async def total_event_count(self) -> int:
        """Total number of ParsedEvent records in the database."""
        result = await self._db.execute(select(func.count(ParsedEvent.id)))
        return result.scalar_one()
