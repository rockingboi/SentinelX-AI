"""
SentinelX AI — Log & Incident Routes
========================================
All REST endpoints for Phase 2: Security Log Processing & NLP Engine.

Endpoint map:
  ── Logs ──────────────────────────────────────────────────────
  POST   /api/v1/logs/upload               Upload a raw log file
  POST   /api/v1/logs/{log_id}/parse       Trigger NLP pipeline
  GET    /api/v1/logs/                     Paginated log list
  GET    /api/v1/logs/{log_id}             Single log detail
  GET    /api/v1/logs/{log_id}/events      Parsed events for a log
  GET    /api/v1/logs/{log_id}/iocs        IOCs extracted from a log

  ── IOC Search ────────────────────────────────────────────────
  GET    /api/v1/iocs/search               Global IOC value search

  ── Incidents ─────────────────────────────────────────────────
  GET    /api/v1/incidents/                Paginated incident list
  PATCH  /api/v1/incidents/{id}/status     Update incident status

  ── Statistics ────────────────────────────────────────────────
  GET    /api/v1/statistics                Dashboard aggregate stats

Auth:
  - Upload / Parse: analyst or admin only
  - Read endpoints: any authenticated user
  - Status update: analyst or admin only
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Query, UploadFile, File, Form, status
from fastapi.responses import JSONResponse

from backend.dependencies import (
    AnalystOrAdmin,
    CurrentUser,
    DBSession,
)
from backend.schemas.common import APIResponse
from backend.schemas.logs import (
    IOCEntityListResponse,
    IncidentEventListResponse,
    LogParseRequest,
    LogParseResponse,
    LogUploadResponse,
    ParsedEventListResponse,
    SecurityLogListResponse,
    SecurityLogResponse,
    StatisticsResponse,
)
from backend.services.log_service import LogService

logger = logging.getLogger(__name__)

# ── Routers ────────────────────────────────────────────────────────────────────
logs_router      = APIRouter()
ioc_router       = APIRouter()
incident_router  = APIRouter()
stats_router     = APIRouter()


# =============================================================================
# LOGS
# =============================================================================

@logs_router.post(
    "/upload",
    summary="Upload a security log file",
    status_code=status.HTTP_201_CREATED,
    response_model=APIResponse[LogUploadResponse],
    dependencies=[AnalystOrAdmin],
)
async def upload_log(
    db:             DBSession,
    current_user:   CurrentUser,
    file:           UploadFile = File(..., description="Raw log file (txt, log, xml, evtx, csv)"),
    force_log_type: str | None = Form(
        default=None,
        description="Override auto-detection: linux_syslog | windows_event | apache_access | nginx_access | sysmon",
    ),
) -> JSONResponse:
    """
    Upload a raw security log file.

    - Stores the raw content and returns a `log_id`
    - Does **not** run analysis — call `POST /logs/{log_id}/parse` separately
    - File size limit: 100 MB
    - Supported formats: `.log`, `.txt`, `.xml`, `.evtx`, `.csv`
    """
    raw_bytes = await file.read()
    svc = LogService(db)
    result = await svc.upload_log(
        filename=file.filename or "upload.log",
        raw_content=raw_bytes,
        uploaded_by=getattr(current_user, "id", None),
        force_log_type=force_log_type,
    )
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={
            "success": True,
            "message": result.message,
            "data":    result.model_dump(mode="json"),
        },
    )


@logs_router.post(
    "/{log_id}/parse",
    summary="Run NLP pipeline on an uploaded log",
    response_model=APIResponse[LogParseResponse],
    dependencies=[AnalystOrAdmin],
)
async def parse_log(
    log_id:  int,
    db:      DBSession,
    payload: LogParseRequest = LogParseRequest(),
) -> JSONResponse:
    """
    Trigger the full NLP processing pipeline on a stored log.

    Pipeline stages:
    1. **Detect** — identify log format automatically
    2. **Parse** — extract structured `NormalizedEvent` objects
    3. **Extract IOCs** — pull IPs, domains, hashes, URLs, usernames
    4. **Classify** — map to MITRE ATT&CK tactics and techniques
    5. **Persist** — store all results atomically in PostgreSQL

    Returns event counts, IOC counts, and processing time.
    """
    svc = LogService(db)
    result = await svc.process_log(
        log_id=log_id,
        force_log_type=payload.force_log_type,
    )
    return JSONResponse(
        content={
            "success": True,
            "message": result.message,
            "data":    result.model_dump(mode="json"),
        }
    )


@logs_router.get(
    "/",
    summary="List all security logs",
    response_model=APIResponse[SecurityLogListResponse],
)
async def list_logs(
    db:          DBSession,
    _:           CurrentUser,
    page:        int        = Query(default=1,    ge=1,           description="Page number"),
    page_size:   int        = Query(default=20,   ge=1,  le=100,  description="Items per page"),
    status:      str | None = Query(default=None, description="Filter by status: pending | processing | completed | failed"),
    log_type:    str | None = Query(default=None, description="Filter by log type"),
    uploaded_by: int | None = Query(default=None, description="Filter by uploader user ID"),
) -> JSONResponse:
    """
    Return a paginated list of security logs.

    Optionally filter by `status`, `log_type`, or `uploaded_by`.
    Results are ordered newest-first.
    """
    svc = LogService(db)
    result = await svc.list_logs(
        page=page,
        page_size=page_size,
        status=status,
        log_type=log_type,
        uploaded_by=uploaded_by,
    )
    return JSONResponse(
        content={
            "success": True,
            "message": f"Found {result.total} log(s).",
            "data":    result.model_dump(mode="json"),
        }
    )


@logs_router.get(
    "/{log_id}",
    summary="Get a single log record",
    response_model=APIResponse[SecurityLogResponse],
)
async def get_log(
    log_id: int,
    db:     DBSession,
    _:      CurrentUser,
) -> JSONResponse:
    """Fetch the details of a specific security log by ID."""
    svc = LogService(db)
    result = await svc.get_log(log_id)
    return JSONResponse(
        content={
            "success": True,
            "message": "OK",
            "data":    result.model_dump(mode="json"),
        }
    )


@logs_router.get(
    "/{log_id}/events",
    summary="Get parsed events for a log",
    response_model=APIResponse[ParsedEventListResponse],
)
async def get_log_events(
    log_id:             int,
    db:                 DBSession,
    _:                  CurrentUser,
    page:               int        = Query(default=1,    ge=1),
    page_size:          int        = Query(default=50,   ge=1, le=200),
    severity:           str | None = Query(default=None, description="critical | high | medium | low | info"),
    event_type:         str | None = Query(default=None, description="Filter by event type (e.g. 'Failed Login')"),
    source_ip:          str | None = Query(default=None, description="Filter by source IP address"),
    mitre_technique_id: str | None = Query(default=None, description="Filter by MITRE technique (e.g. T1110)"),
) -> JSONResponse:
    """
    Return structured events extracted from a processed log.

    Supports filtering by severity, event type, source IP, and MITRE technique.
    """
    svc = LogService(db)
    result = await svc.get_log_events(
        log_id,
        page=page,
        page_size=page_size,
        severity=severity,
        event_type=event_type,
        source_ip=source_ip,
        mitre_technique_id=mitre_technique_id,
    )
    return JSONResponse(
        content={
            "success": True,
            "message": f"Found {result.total} event(s).",
            "data":    result.model_dump(mode="json"),
        }
    )


@logs_router.get(
    "/{log_id}/iocs",
    summary="Get IOCs extracted from a log",
    response_model=APIResponse[IOCEntityListResponse],
)
async def get_log_iocs(
    log_id:   int,
    db:       DBSession,
    _:        CurrentUser,
    ioc_type: str | None = Query(default=None, description="Filter by type: ipv4 | domain | url | md5 | sha256 | ..."),
    page:     int        = Query(default=1,    ge=1),
    page_size:int        = Query(default=50,   ge=1, le=200),
) -> JSONResponse:
    """
    Return Indicators of Compromise (IOCs) extracted from a processed log.

    IOC types include: `ipv4`, `ipv6`, `domain`, `url`, `email`, `md5`,
    `sha1`, `sha256`, `cve`, `hostname`, `username`, `port`,
    `process_name`, `command_line`, `filename`, `file_path`.
    """
    svc = LogService(db)
    result = await svc.get_log_iocs(
        log_id,
        ioc_type=ioc_type,
        page=page,
        page_size=page_size,
    )
    return JSONResponse(
        content={
            "success": True,
            "message": f"Found {result.total} IOC(s).",
            "data":    result.model_dump(mode="json"),
        }
    )


# =============================================================================
# IOC SEARCH
# =============================================================================

@ioc_router.get(
    "/search",
    summary="Search IOCs by value across all logs",
    response_model=APIResponse[IOCEntityListResponse],
)
async def search_iocs(
    db:       DBSession,
    _:        CurrentUser,
    q:        str | None = Query(default=None, min_length=2, description="Value substring to search (e.g. '185.24', 'mimikatz'). Omit to list all IOCs."),
    ioc_type: str | None = Query(default=None,      description="Restrict search to a specific IOC type"),
    page:     int        = Query(default=1,  ge=1),
    page_size:int        = Query(default=50, ge=1, le=200),
) -> JSONResponse:
    """
    **Threat hunting endpoint** — search for an IOC value across all logs.

    - Omit `q` to list all IOCs (paginated, ordered by last_seen desc).
    - `?q=185.24.18` — find all events from a suspicious IP range
    - `?q=mimikatz` — find all command-line or filename IOCs mentioning mimikatz
    - `?q=T1059&ioc_type=command_line` — filter by type
    """
    svc = LogService(db)
    result = await svc.search_iocs(
        value=q,
        ioc_type=ioc_type,
        page=page,
        page_size=page_size,
    )
    msg = f"Found {result.total} IOC match(es) for '{q}'." if q else f"{result.total} IOC(s) total."
    return JSONResponse(
        content={
            "success": True,
            "message": msg,
            "data":    result.model_dump(mode="json"),
        }
    )


# =============================================================================
# INCIDENTS
# =============================================================================

@incident_router.get(
    "/",
    summary="List security incidents",
    response_model=APIResponse[IncidentEventListResponse],
)
async def list_incidents(
    db:        DBSession,
    _:         CurrentUser,
    page:      int        = Query(default=1,    ge=1),
    page_size: int        = Query(default=20,   ge=1, le=100),
    status:    str | None = Query(default=None, description="open | investigating | contained | closed | false_positive"),
    severity:  str | None = Query(default=None, description="critical | high | medium | low"),
) -> JSONResponse:
    """
    Return a paginated list of security incidents.

    Incidents are auto-created when the NLP pipeline detects HIGH+ severity events.
    Analysts can also create and manage incidents manually.
    """
    svc = LogService(db)
    result = await svc.get_incidents(
        page=page,
        page_size=page_size,
        status=status,
        severity=severity,
    )
    return JSONResponse(
        content={
            "success": True,
            "message": f"Found {result.total} incident(s).",
            "data":    result.model_dump(mode="json"),
        }
    )


@incident_router.patch(
    "/{incident_id}/status",
    summary="Update incident status",
    dependencies=[AnalystOrAdmin],
    response_model=APIResponse[dict],
)
async def update_incident_status(
    incident_id: int,
    db:          DBSession,
    status:      str = Query(..., description="New status: open | investigating | contained | closed | false_positive"),
) -> JSONResponse:
    """
    Update the investigation status of an incident.

    Valid transitions:
    `open` → `investigating` → `contained` → `closed`
    Any status may be set to `false_positive` to dismiss it.
    Closing an incident automatically stamps `closed_at`.
    """
    svc = LogService(db)
    result = await svc.update_incident_status(incident_id, status=status)
    return JSONResponse(
        content={
            "success": True,
            "message": f"Incident {incident_id} status updated to '{status}'.",
            "data":    result.model_dump(mode="json"),
        }
    )


# =============================================================================
# STATISTICS
# =============================================================================

@stats_router.get(
    "/",
    summary="Get platform-wide statistics",
    response_model=APIResponse[StatisticsResponse],
)
async def get_statistics(
    db: DBSession,
    _:  CurrentUser,
) -> JSONResponse:
    """
    Return aggregate statistics for the SentinelX dashboard.

    Includes:
    - Log counts by status (pending / processing / completed / failed)
    - Event counts with severity breakdown (critical → info)
    - IOC counts and type distribution
    - Incident counts by status and severity
    - Top attacker IPs
    - Top MITRE ATT&CK techniques
    """
    svc = LogService(db)
    result = await svc.get_statistics()
    return JSONResponse(
        content={
            "success": True,
            "message": "OK",
            "data":    result.model_dump(mode="json"),
        }
    )
