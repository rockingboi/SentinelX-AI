"""
SentinelX AI — Incident Repository
=====================================
Data access layer for IncidentEvent model.

Responsibilities:
  - Auto-create incidents from high-severity pipeline output
  - CRUD for analyst-managed incidents
  - Query and filter by severity, status, MITRE, source IPs
  - Aggregate counts for the dashboard

Incident auto-generation strategy:
  - The pipeline service calls create_from_pipeline_result() after processing
  - One incident is generated per unique (event_type, source_ip) pairing
    when severity >= HIGH (score >= 7)
  - Analysts can merge, close, or escalate incidents via the API
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from backend.models.incident_event import IncidentEvent
from backend.nlp.pipeline import PipelineResult

logger = logging.getLogger(__name__)

# Minimum severity score to trigger automatic incident creation
_AUTO_INCIDENT_MIN_SCORE = 7


class IncidentRepository:
    """Repository for IncidentEvent CRUD and auto-creation operations."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    # ── Auto-create from pipeline ─────────────────────────────────────────────

    async def create_from_pipeline_result(
        self,
        log_id: int,
        result: PipelineResult,
    ) -> list[IncidentEvent]:
        """
        Auto-generate incidents from a completed pipeline run.

        Groups threat events by (event_type, primary_source_ip) and
        creates one IncidentEvent per group that meets the severity threshold.

        Args:
            log_id: The SecurityLog this run belongs to.
            result: Completed PipelineResult from NLPPipeline.

        Returns:
            List of created IncidentEvent ORM objects.
        """
        # Only consider threats at HIGH severity or above
        threat_events = [
            pe for pe in result.processed_events
            if pe.severity_score >= _AUTO_INCIDENT_MIN_SCORE
        ]

        if not threat_events:
            return []

        # Group by (event_type, source_ip) to avoid duplicate incidents
        groups: dict[tuple[str, str], list] = {}
        for pe in threat_events:
            key = (
                pe.event.event_type or "Unknown Event",
                pe.event.source_ip or "unknown",
            )
            groups.setdefault(key, []).append(pe)

        created: list[IncidentEvent] = []
        for (event_type, source_ip), group in groups.items():
            # Take the highest severity event in the group
            primary = max(group, key=lambda p: p.severity_score)
            ev = primary.event

            # Collect unique MITRE techniques and tactics from the group
            techniques = list({pe.event.mitre_technique_id for pe in group if pe.event.mitre_technique_id})
            tactics    = list({pe.event.mitre_tactic for pe in group if pe.event.mitre_tactic})
            source_ips = list({pe.event.source_ip for pe in group if pe.event.source_ip})
            hosts      = list({pe.event.hostname for pe in group if pe.event.hostname})

            title = self._build_title(event_type, source_ip, primary.classification.threat_category)

            incident = IncidentEvent(
                title=title,
                description=(
                    f"Auto-detected: {len(group)} event(s) of type '{event_type}' "
                    f"from {source_ip}. "
                    f"MITRE: {', '.join(techniques) or 'N/A'}. "
                    f"Pipeline run on log_id={log_id}."
                ),
                severity=primary.classification.severity.value,
                status="open",
                event_type=event_type,
                log_ids=[log_id],
                event_count=len(group),
                ioc_count=sum(len(pe.iocs) for pe in group),
                mitre_techniques=techniques or None,
                mitre_tactics=tactics or None,
                source_ips=source_ips or None,
                affected_hosts=hosts or None,
                source_log_id=log_id,
            )
            created.append(incident)

        if created:
            self._db.add_all(created)
            await self._db.flush()
            logger.info(
                "Auto-created %d incidents for log_id=%d",
                len(created), log_id,
            )

        return created

    # ── Manual CRUD ───────────────────────────────────────────────────────────

    async def create(
        self,
        *,
        title: str,
        severity: str,
        event_type: str | None = None,
        description: str | None = None,
        log_ids: list[int] | None = None,
        mitre_techniques: list[str] | None = None,
        mitre_tactics: list[str] | None = None,
        source_ips: list[str] | None = None,
        affected_hosts: list[str] | None = None,
        source_log_id: int | None = None,
        assigned_to: int | None = None,
    ) -> IncidentEvent:
        """Manually create a new incident record."""
        incident = IncidentEvent(
            title=title,
            description=description,
            severity=severity,
            status="open",
            event_type=event_type,
            log_ids=log_ids,
            event_count=0,
            ioc_count=0,
            mitre_techniques=mitre_techniques,
            mitre_tactics=mitre_tactics,
            source_ips=source_ips,
            affected_hosts=affected_hosts,
            source_log_id=source_log_id,
            assigned_to=assigned_to,
        )
        self._db.add(incident)
        await self._db.commit()
        await self._db.refresh(incident)
        logger.info("Created IncidentEvent id=%d title=%s", incident.id, title)
        return incident

    async def get_by_id(self, incident_id: int) -> IncidentEvent | None:
        """Fetch a single incident by primary key."""
        result = await self._db.execute(
            select(IncidentEvent).where(IncidentEvent.id == incident_id)
        )
        return result.scalar_one_or_none()

    async def list_incidents(
        self,
        *,
        page: int = 1,
        page_size: int = 20,
        status: str | None = None,
        severity: str | None = None,
        assigned_to: int | None = None,
    ) -> tuple[list[IncidentEvent], int]:
        """
        Paginated list of incidents with optional filters.

        Returns:
            (items, total_count)
        """
        query = select(IncidentEvent)
        if status:
            query = query.where(IncidentEvent.status == status)
        if severity:
            query = query.where(IncidentEvent.severity == severity)
        if assigned_to is not None:
            query = query.where(IncidentEvent.assigned_to == assigned_to)

        count_result = await self._db.execute(
            select(func.count()).select_from(query.subquery())
        )
        total = count_result.scalar_one()

        offset = (page - 1) * page_size
        query = query.order_by(IncidentEvent.created_at.desc()).offset(offset).limit(page_size)
        result = await self._db.execute(query)
        return list(result.scalars().all()), total

    # ── Status updates ────────────────────────────────────────────────────────

    async def update_status(
        self,
        incident_id: int,
        *,
        status: str,
        closed_at: datetime | None = None,
    ) -> bool:
        """
        Update the status of an incident (open → investigating → closed, etc.).

        Returns:
            True if the record was found and updated, False otherwise.
        """
        values: dict[str, Any] = {"status": status}
        if status == "closed" and closed_at is None:
            values["closed_at"] = datetime.now(timezone.utc)
        elif closed_at:
            values["closed_at"] = closed_at

        result = await self._db.execute(
            update(IncidentEvent)
            .where(IncidentEvent.id == incident_id)
            .values(**values)
        )
        await self._db.commit()
        updated = result.rowcount > 0
        if updated:
            logger.info("IncidentEvent id=%d → status=%s", incident_id, status)
        return updated

    async def assign_to(self, incident_id: int, *, user_id: int) -> bool:
        """Assign an incident to a specific analyst user."""
        result = await self._db.execute(
            update(IncidentEvent)
            .where(IncidentEvent.id == incident_id)
            .values(assigned_to=user_id)
        )
        await self._db.commit()
        return result.rowcount > 0

    # ── Aggregations ──────────────────────────────────────────────────────────

    async def count_by_status(self) -> dict[str, int]:
        """Return incident counts grouped by status."""
        result = await self._db.execute(
            select(IncidentEvent.status, func.count(IncidentEvent.id))
            .group_by(IncidentEvent.status)
        )
        return {row[0]: row[1] for row in result.all()}

    async def count_by_severity(self) -> dict[str, int]:
        """Return incident counts grouped by severity."""
        result = await self._db.execute(
            select(IncidentEvent.severity, func.count(IncidentEvent.id))
            .group_by(IncidentEvent.severity)
        )
        return {row[0]: row[1] for row in result.all()}

    async def total_incident_count(self) -> int:
        """Total number of IncidentEvent records."""
        result = await self._db.execute(select(func.count(IncidentEvent.id)))
        return result.scalar_one()

    # ── Private helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _build_title(event_type: str, source_ip: str, threat_category: str) -> str:
        """Build a descriptive incident title."""
        if source_ip and source_ip != "unknown":
            return f"{threat_category} — {event_type} — {source_ip}"
        return f"{threat_category} — {event_type}"
