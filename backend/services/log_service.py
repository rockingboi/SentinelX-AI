"""
SentinelX AI — Log Service
=============================
Business logic and orchestration layer for log upload and processing.

This is the single entry point for all log-related operations.
Route handlers stay thin — all business logic lives here.

Orchestration flow for process_log():
  ┌─────────────────────────────────────────────────────────┐
  │ 1. Validate log exists and is in PENDING status         │
  │ 2. Mark log as PROCESSING                               │
  │ 3. Fetch raw_content from SecurityLog record            │
  │ 4. Run NLPPipeline.process_async()                      │
  │    ├─ Detect log type                                   │
  │    ├─ Parse all lines → NormalizedEvent[]               │
  │    ├─ Extract IOCs per event                            │
  │    └─ Classify events (MITRE + severity)                │
  │ 5. Bulk-insert ParsedEvents (flush, not commit yet)     │
  │ 6. Bulk-upsert IOCEntities (flush)                      │
  │ 7. Auto-create IncidentEvents (flush)                   │
  │ 8. Mark log as COMPLETED with final counters            │
  │ 9. COMMIT entire transaction                            │
  └─────────────────────────────────────────────────────────┘
  On any failure: ROLLBACK + mark log as FAILED

Design:
  - All DB work is inside ONE transaction (atomicity guarantee)
  - The NLP pipeline runs BEFORE the transaction begins (CPU-bound)
  - Service methods return Pydantic schemas — never raw ORM objects
  - Follows Phase 1 conventions: __init__(db), async methods, schema returns
"""
from __future__ import annotations

import logging
import math
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.exceptions import NotFoundError, ValidationError
from backend.models.security_log import LogStatus, LogType
from backend.nlp.pipeline import NLPPipeline, nlp_pipeline
from backend.repositories.event_repository import EventRepository
from backend.repositories.incident_repository import IncidentRepository
from backend.repositories.ioc_repository import IOCRepository
from backend.repositories.log_repository import LogRepository
from backend.schemas.logs import (
    IOCEntityListResponse,
    IOCEntityResponse,
    IncidentEventListResponse,
    IncidentEventResponse,
    LogParseResponse,
    LogUploadResponse,
    ParsedEventListResponse,
    ParsedEventResponse,
    SecurityLogListResponse,
    SecurityLogResponse,
    StatisticsResponse,
    SeverityBreakdown,
    IOCTypeSummary,
    MitreHit,
    TopSourceIP,
)

logger = logging.getLogger(__name__)

# Supported file extensions for validation
_ALLOWED_EXTENSIONS = frozenset({
    ".log", ".txt", ".csv", ".evtx", ".xml", ".json",
    ".gz", ".zip",   # Compressed — handled by caller
})


class LogService:
    """
    Orchestration service for security log upload, processing, and querying.

    Usage:
        service = LogService(db)
        upload   = await service.upload_log(filename, raw_content, user_id)
        result   = await service.process_log(upload.log_id)
    """

    def __init__(self, db: AsyncSession, pipeline: NLPPipeline | None = None) -> None:
        self._db       = db
        self._pipeline = pipeline or nlp_pipeline   # DI-friendly; default = singleton
        self._logs     = LogRepository(db)
        self._events   = EventRepository(db)
        self._iocs     = IOCRepository(db)
        self._incidents = IncidentRepository(db)

    # ── Upload ────────────────────────────────────────────────────────────────

    async def upload_log(
        self,
        filename: str,
        raw_content: str | bytes,
        uploaded_by: int | None = None,
        force_log_type: str | None = None,
    ) -> LogUploadResponse:
        """
        Store a raw log file and return a LogUploadResponse.

        Performs lightweight validation only — no NLP processing here.
        The caller must separately call process_log() to run the pipeline.

        Args:
            filename:       Original filename (used for display only).
            raw_content:    Raw log content as str or bytes.
            uploaded_by:    User ID of the uploader (optional).
            force_log_type: Override auto-detection (optional).

        Returns:
            LogUploadResponse with the assigned log_id and status=pending.

        Raises:
            ValidationError: If the file is empty or too large (>100MB).
        """
        # Decode bytes if needed
        if isinstance(raw_content, bytes):
            raw_content = self._decode(raw_content)

        # Validation guards
        if not raw_content or not raw_content.strip():
            raise ValidationError("Log file is empty.")

        max_bytes = 100 * 1024 * 1024
        if len(raw_content.encode("utf-8", errors="replace")) > max_bytes:
            raise ValidationError("Log file exceeds 100MB limit.")

        # Count lines before storage
        line_count = raw_content.count("\n") + (
            1 if raw_content and not raw_content.endswith("\n") else 0
        )
        file_size_bytes = len(raw_content.encode("utf-8", errors="replace"))

        # Determine initial log_type (quick heuristic — refined during processing)
        if force_log_type:
            try:
                log_type = LogType(force_log_type)
            except ValueError:
                raise ValidationError(
                    f"Invalid log type '{force_log_type}'. "
                    f"Valid: {[t.value for t in LogType]}"
                )
        else:
            log_type = LogType.UNKNOWN

        log = await self._logs.create(
            filename=filename,
            log_type=log_type,
            raw_content=raw_content,
            file_size_bytes=file_size_bytes,
            line_count=line_count,
            uploaded_by=uploaded_by,
        )

        logger.info(
            "Log uploaded: id=%d filename=%s size=%d lines=%d user=%s",
            log.id, filename, file_size_bytes, line_count, uploaded_by,
        )

        return LogUploadResponse(
            log_id=log.id,
            filename=log.filename,
            log_type=log.log_type,
            line_count=log.line_count,
            file_size_bytes=log.file_size_bytes,
            status=log.status,
            message=f"Log uploaded successfully. Use POST /logs/{log.id}/parse to process.",
        )

    # ── Process (NLP pipeline + persist) ─────────────────────────────────────

    async def process_log(
        self,
        log_id: int,
        force_log_type: str | None = None,
    ) -> LogParseResponse:
        """
        Run the full NLP pipeline on a stored log and persist all results.

        This method:
          1. Fetches the SecurityLog record (must be in PENDING status)
          2. Runs the NLP pipeline (async, non-blocking)
          3. Persists all results in a single atomic transaction
          4. Returns a summary response

        Args:
            log_id:         The SecurityLog primary key.
            force_log_type: Override auto-detected log type.

        Returns:
            LogParseResponse with event and IOC counts.

        Raises:
            NotFoundError:   If log_id doesn't exist.
            ValidationError: If log is not in PENDING status.
        """
        # ── Fetch and validate log ────────────────────────────────────────────
        log = await self._logs.get_by_id(log_id)
        if log is None:
            raise NotFoundError(f"Log with id={log_id} not found.")

        if log.status == LogStatus.PROCESSING.value:
            raise ValidationError(f"Log id={log_id} is already being processed.")
        if log.status == LogStatus.COMPLETED.value:
            raise ValidationError(f"Log id={log_id} was already processed successfully.")

        # ── Mark as processing ────────────────────────────────────────────────
        await self._logs.mark_processing(log_id)

        # ── Resolve force_log_type ────────────────────────────────────────────
        pipeline_force_type: LogType | None = None
        if force_log_type:
            try:
                pipeline_force_type = LogType(force_log_type)
            except ValueError:
                await self._logs.mark_failed(
                    log_id, error=f"Invalid log type override: {force_log_type}"
                )
                raise ValidationError(f"Invalid log type: {force_log_type}")

        # ── Run NLP pipeline (outside DB transaction — CPU-bound) ─────────────
        try:
            result = await self._pipeline.process_async(
                log.raw_content,
                force_log_type=pipeline_force_type,
            )
        except Exception as exc:
            error_msg = f"Pipeline error: {exc}"
            logger.exception("Pipeline failed for log_id=%d", log_id)
            await self._logs.mark_failed(log_id, error=error_msg)
            raise

        # ── Persist results in ONE atomic transaction ──────────────────────────
        try:
            # 1. Bulk-insert ParsedEvents (flush only — part of same tx)
            normalized_events = [pe.event for pe in result.processed_events]
            orm_events = await self._events.bulk_create_from_normalized(
                log_id, normalized_events
            )

            # 2. Bulk-upsert IOCEntities (flush)
            ioc_count = await self._iocs.bulk_upsert_from_extracted(
                log_id,
                result.all_iocs,
                event_id=orm_events[0].id if orm_events else None,
            )

            # 3. Auto-create incidents for HIGH+ severity events (flush)
            await self._incidents.create_from_pipeline_result(log_id, result)

            # 4. Mark log as COMPLETED with final counters
            await self._logs.mark_completed(
                log_id,
                log_type=result.log_type.value,
                parsed_event_count=result.stats.parsed_events,
                ioc_count=result.stats.unique_iocs,
                line_count=result.stats.total_lines,
            )

            # 5. Single COMMIT — everything or nothing
            await self._db.commit()

            logger.info(
                "Log id=%d processed: events=%d iocs=%d time=%.0fms",
                log_id, result.stats.parsed_events,
                result.stats.unique_iocs, result.stats.processing_time_ms,
            )

        except Exception as exc:
            await self._db.rollback()
            error_msg = f"Persistence error: {exc}"
            logger.exception("Persistence failed for log_id=%d", log_id)
            await self._logs.mark_failed(log_id, error=error_msg)
            raise

        return LogParseResponse(
            log_id=log_id,
            log_type=result.log_type.value,
            status="completed",
            parsed_event_count=result.stats.parsed_events,
            ioc_count=result.stats.unique_iocs,
            processing_time_ms=int(result.stats.processing_time_ms),
            message=(
                f"Log processed successfully. "
                f"{result.stats.parsed_events} events and "
                f"{result.stats.unique_iocs} unique IOCs extracted. "
                f"{result.stats.threats_detected} threat-level events found."
            ),
        )

    # ── Query: Logs ───────────────────────────────────────────────────────────

    async def get_log(self, log_id: int) -> SecurityLogResponse:
        """
        Fetch a single log record by ID.

        Raises:
            NotFoundError: If the log doesn't exist.
        """
        log = await self._logs.get_by_id(log_id)
        if log is None:
            raise NotFoundError(f"Log with id={log_id} not found.")
        return SecurityLogResponse.model_validate(log)

    async def list_logs(
        self,
        *,
        page: int = 1,
        page_size: int = 20,
        status: str | None = None,
        log_type: str | None = None,
        uploaded_by: int | None = None,
    ) -> SecurityLogListResponse:
        """Paginated list of log records with optional filtering."""
        page_size = min(page_size, 100)   # Hard cap
        items, total = await self._logs.list_logs(
            page=page,
            page_size=page_size,
            status=status,
            log_type=log_type,
            uploaded_by=uploaded_by,
        )
        return SecurityLogListResponse(
            items=[SecurityLogResponse.model_validate(log) for log in items],
            total=total,
            page=page,
            page_size=page_size,
            total_pages=math.ceil(total / page_size) if total else 1,
        )

    # ── Query: Events ─────────────────────────────────────────────────────────

    async def get_log_events(
        self,
        log_id: int,
        *,
        page: int = 1,
        page_size: int = 50,
        severity: str | None = None,
        event_type: str | None = None,
        source_ip: str | None = None,
        mitre_technique_id: str | None = None,
    ) -> ParsedEventListResponse:
        """
        Paginated list of ParsedEvents for a given log.

        Raises:
            NotFoundError: If the log doesn't exist.
        """
        await self._assert_log_exists(log_id)
        page_size = min(page_size, 200)
        items, total = await self._events.list_by_log(
            log_id,
            page=page,
            page_size=page_size,
            severity=severity,
            event_type=event_type,
            source_ip=source_ip,
            mitre_technique_id=mitre_technique_id,
        )
        return ParsedEventListResponse(
            items=[ParsedEventResponse.model_validate(ev) for ev in items],
            total=total,
            page=page,
            page_size=page_size,
            total_pages=math.ceil(total / page_size) if total else 1,
        )

    # ── Query: IOCs ───────────────────────────────────────────────────────────

    async def get_log_iocs(
        self,
        log_id: int,
        *,
        ioc_type: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> IOCEntityListResponse:
        """
        Paginated list of IOCEntities for a given log.

        Raises:
            NotFoundError: If the log doesn't exist.
        """
        await self._assert_log_exists(log_id)
        page_size = min(page_size, 200)
        items, total = await self._iocs.list_by_log(
            log_id,
            ioc_type=ioc_type,
            page=page,
            page_size=page_size,
        )
        return IOCEntityListResponse(
            items=[IOCEntityResponse.model_validate(ioc) for ioc in items],
            total=total,
            page=page,
            page_size=page_size,
            total_pages=math.ceil(total / page_size) if total else 1,
            ioc_type_filter=ioc_type,
        )

    async def search_iocs(
        self,
        value: str | None,
        *,
        ioc_type: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> IOCEntityListResponse:
        """Global IOC search. If value is None, returns all IOCs paginated."""
        if value is not None and len(value) < 2:
            raise ValidationError("Search value must be at least 2 characters.")
        page_size = min(page_size, 200)
        if value:
            items, total = await self._iocs.search_by_value(
                value,
                ioc_type=ioc_type,
                page=page,
                page_size=page_size,
            )
        else:
            # No search term — list all IOCs (optionally filtered by type)
            items, total = await self._iocs.list_all(
                ioc_type=ioc_type,
                page=page,
                page_size=page_size,
            )
        return IOCEntityListResponse(
            items=[IOCEntityResponse.model_validate(ioc) for ioc in items],
            total=total,
            page=page,
            page_size=page_size,
            total_pages=math.ceil(total / page_size) if total else 1,
            ioc_type_filter=ioc_type,
        )

    # ── Query: Incidents ──────────────────────────────────────────────────────

    async def get_incidents(
        self,
        *,
        page: int = 1,
        page_size: int = 20,
        status: str | None = None,
        severity: str | None = None,
    ) -> IncidentEventListResponse:
        """Paginated list of incidents with optional filters."""
        page_size = min(page_size, 100)
        items, total = await self._incidents.list_incidents(
            page=page,
            page_size=page_size,
            status=status,
            severity=severity,
        )
        return IncidentEventListResponse(
            items=[IncidentEventResponse.model_validate(i) for i in items],
            total=total,
            page=page,
            page_size=page_size,
            total_pages=math.ceil(total / page_size) if total else 1,
        )

    async def update_incident_status(
        self, incident_id: int, *, status: str
    ) -> IncidentEventResponse:
        """
        Update an incident's status (open → investigating → contained → closed).

        Raises:
            NotFoundError:   If incident doesn't exist.
            ValidationError: If status is invalid.
        """
        valid_statuses = {"open", "investigating", "contained", "closed", "false_positive"}
        if status not in valid_statuses:
            raise ValidationError(f"Invalid status '{status}'. Valid: {valid_statuses}")

        updated = await self._incidents.update_status(incident_id, status=status)
        if not updated:
            raise NotFoundError(f"Incident with id={incident_id} not found.")

        incident = await self._incidents.get_by_id(incident_id)
        return IncidentEventResponse.model_validate(incident)

    # ── Statistics ────────────────────────────────────────────────────────────

    async def get_statistics(self) -> StatisticsResponse:
        """
        Aggregate statistics for the dashboard.

        Queries:
          - Log counts by status
          - Total event count + severity breakdown
          - Total IOC count + type summary
          - Incident counts by status and severity
          - Top attacker IPs and MITRE techniques

        Returns:
            StatisticsResponse (Pydantic schema, API-ready).
        """
        # ── Log stats ─────────────────────────────────────────────────────────
        log_status_counts = await self._logs.count_by_status()
        _, total_logs = await self._logs.list_logs(page=1, page_size=1)

        # ── Event stats ───────────────────────────────────────────────────────
        total_events = await self._events.total_event_count()
        global_severity = await self._events.global_severity_breakdown()

        severity_bd = SeverityBreakdown(
            critical=global_severity.get("critical", 0),
            high=global_severity.get("high", 0),
            medium=global_severity.get("medium", 0),
            low=global_severity.get("low", 0),
            informational=global_severity.get("info", 0),
        )

        # ── IOC stats ─────────────────────────────────────────────────────────
        total_iocs = await self._iocs.total_ioc_count()
        unique_ioc_vals = await self._iocs.unique_ioc_value_count()
        ioc_type_rows = await self._iocs.ioc_type_summary()
        ioc_type_summary = [
            IOCTypeSummary(ioc_type=row["ioc_type"], count=row["count"])
            for row in ioc_type_rows
        ]

        # ── Incident stats ────────────────────────────────────────────────────
        incident_status_counts  = await self._incidents.count_by_status()
        incident_severity_counts = await self._incidents.count_by_severity()
        total_incidents = await self._incidents.total_incident_count()

        # ── Top attacker IPs (global — sample from first 10 logs) ─────────────
        # Full cross-log aggregation deferred to Phase 3 (graph queries)
        top_ips_raw = await self._iocs.top_ioc_values("ipv4", limit=10)
        top_source_ips = [
            TopSourceIP(ip=row["value"], count=row["total_occurrences"])
            for row in top_ips_raw
        ]

        # ── Top MITRE techniques ──────────────────────────────────────────────
        # Aggregate across all logs (simplified via IOC approach)
        top_mitre_raw: list[dict] = []   # Full implementation in Phase 3
        top_mitre = [
            MitreHit(
                technique_id=row["technique_id"],
                technique_name=row["technique_name"],
                tactic=row["tactic"],
                count=row["count"],
            )
            for row in top_mitre_raw
        ]

        return StatisticsResponse(
            total_logs=total_logs,
            logs_pending=log_status_counts.get("pending", 0),
            logs_processing=log_status_counts.get("processing", 0),
            logs_completed=log_status_counts.get("completed", 0),
            logs_failed=log_status_counts.get("failed", 0),
            total_events=total_events,
            severity_breakdown=severity_bd,
            total_iocs=total_iocs,
            unique_ioc_values=unique_ioc_vals,
            ioc_type_summary=ioc_type_summary,
            total_incidents=total_incidents,
            open_incidents=incident_status_counts.get("open", 0),
            critical_incidents=incident_severity_counts.get("critical", 0),
            high_incidents=incident_severity_counts.get("high", 0),
            top_source_ips=top_source_ips,
            top_mitre_techniques=top_mitre,
            top_event_types=[],   # Populated in Phase 3 via graph aggregation
        )

    # ── Private helpers ───────────────────────────────────────────────────────

    async def _assert_log_exists(self, log_id: int) -> None:
        """Raise NotFoundError if the log_id doesn't exist in the database."""
        log = await self._logs.get_by_id(log_id)
        if log is None:
            raise NotFoundError(f"Log with id={log_id} not found.")

    @staticmethod
    def _decode(raw: bytes) -> str:
        """Decode bytes with fallback encoding chain."""
        for enc in ("utf-8", "utf-8-sig", "latin-1", "cp1252"):
            try:
                return raw.decode(enc)
            except (UnicodeDecodeError, LookupError):
                continue
        return raw.decode("utf-8", errors="replace")
