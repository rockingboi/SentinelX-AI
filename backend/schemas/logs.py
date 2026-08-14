"""
SentinelX AI — Phase 2 Log & NLP Schemas
==========================================
All Pydantic v2 request/response schemas for the log processing pipeline.

Follows the same conventions as Phase 1:
- from_attributes = True for ORM ↔ schema conversion
- model_config with json_schema_extra for OpenAPI examples
- Strict typing throughout
- APIResponse[T] envelope used at the route layer
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator


# =============================================================================
# Enumerations (string literals mirroring model enums for Pydantic validation)
# =============================================================================

class LogTypeEnum(str):
    WINDOWS_EVENT   = "windows_event"
    LINUX_SYSLOG    = "linux_syslog"
    APACHE_ACCESS   = "apache_access"
    NGINX_ACCESS    = "nginx_access"
    SYSMON          = "sysmon"
    UNKNOWN         = "unknown"


class LogStatusEnum(str):
    PENDING     = "pending"
    PROCESSING  = "processing"
    COMPLETED   = "completed"
    FAILED      = "failed"


class SeverityEnum(str):
    CRITICAL        = "critical"
    HIGH            = "high"
    MEDIUM          = "medium"
    LOW             = "low"
    INFORMATIONAL   = "informational"


class IncidentStatusEnum(str):
    OPEN            = "open"
    INVESTIGATING   = "investigating"
    CONTAINED       = "contained"
    CLOSED          = "closed"
    FALSE_POSITIVE  = "false_positive"


class IOCTypeEnum(str):
    IPV4            = "ipv4"
    IPV6            = "ipv6"
    URL             = "url"
    DOMAIN          = "domain"
    EMAIL           = "email"
    FILENAME        = "filename"
    FILE_PATH       = "file_path"
    MD5             = "md5"
    SHA1            = "sha1"
    SHA256          = "sha256"
    CVE             = "cve"
    HOSTNAME        = "hostname"
    USERNAME        = "username"
    PORT            = "port"
    PROCESS_NAME    = "process_name"
    COMMAND_LINE    = "command_line"


# =============================================================================
# Security Log Schemas
# =============================================================================

class SecurityLogResponse(BaseModel):
    """Public representation of an uploaded SecurityLog record."""

    id: int
    filename: str
    log_type: str
    file_size_bytes: int
    line_count: int
    status: str
    parse_error: str | None
    parsed_event_count: int
    ioc_count: int
    uploaded_by: int | None
    created_at: datetime
    updated_at: datetime
    processing_started_at: datetime | None
    processing_completed_at: datetime | None

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "example": {
                "id": 1,
                "filename": "auth.log",
                "log_type": "linux_syslog",
                "file_size_bytes": 24576,
                "line_count": 320,
                "status": "completed",
                "parse_error": None,
                "parsed_event_count": 47,
                "ioc_count": 12,
                "uploaded_by": 1,
                "created_at": "2025-01-01T10:00:00Z",
                "updated_at": "2025-01-01T10:00:35Z",
                "processing_started_at": "2025-01-01T10:00:01Z",
                "processing_completed_at": "2025-01-01T10:00:35Z",
            }
        },
    }


class SecurityLogListResponse(BaseModel):
    """Paginated list of SecurityLog records."""

    items: list[SecurityLogResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class LogUploadResponse(BaseModel):
    """Response after a successful log file upload."""

    log_id: int
    filename: str
    log_type: str
    line_count: int
    file_size_bytes: int
    status: str
    message: str

    model_config = {
        "json_schema_extra": {
            "example": {
                "log_id": 42,
                "filename": "windows_security.evtx.txt",
                "log_type": "windows_event",
                "line_count": 1024,
                "file_size_bytes": 98304,
                "status": "pending",
                "message": "Log uploaded successfully. Use POST /logs/42/parse to process.",
            }
        }
    }


class LogParseRequest(BaseModel):
    """Optional configuration for triggering a parse job."""

    force_log_type: str | None = Field(
        default=None,
        description="Override auto-detected log type. One of: windows_event, linux_syslog, apache_access, nginx_access, sysmon",
    )

    @field_validator("force_log_type")
    @classmethod
    def validate_log_type(cls, v: str | None) -> str | None:
        if v is None:
            return v
        valid = {"windows_event", "linux_syslog", "apache_access", "nginx_access", "sysmon"}
        if v not in valid:
            raise ValueError(f"Invalid log type. Must be one of: {valid}")
        return v


class LogParseResponse(BaseModel):
    """Response after triggering the NLP pipeline on a log."""

    log_id: int
    log_type: str
    status: str
    parsed_event_count: int
    ioc_count: int
    processing_time_ms: int
    message: str

    model_config = {
        "json_schema_extra": {
            "example": {
                "log_id": 42,
                "log_type": "linux_syslog",
                "status": "completed",
                "parsed_event_count": 47,
                "ioc_count": 12,
                "processing_time_ms": 234,
                "message": "Log parsed successfully.",
            }
        }
    }


# =============================================================================
# Parsed Event Schemas
# =============================================================================

class ParsedEventResponse(BaseModel):
    """Public representation of a structured ParsedEvent record."""

    id: int
    log_id: int
    event_type: str | None
    log_type: str
    username: str | None
    source_ip: str | None
    dest_ip: str | None
    source_port: int | None
    dest_port: int | None
    protocol: str | None
    service: str | None
    hostname: str | None
    process_name: str | None
    process_id: int | None
    command_line: str | None
    file_path: str | None
    url: str | None
    http_method: str | None
    http_status_code: int | None
    user_agent: str | None
    timestamp_raw: str | None
    event_timestamp: datetime | None
    severity: str | None
    severity_score: int | None
    mitre_technique_id: str | None
    mitre_technique_name: str | None
    mitre_tactic: str | None
    mitre_tactic_id: str | None
    raw_line: str | None
    normalized_data: dict[str, Any] | None
    line_number: int | None
    created_at: datetime

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "example": {
                "id": 1,
                "log_id": 42,
                "event_type": "Failed Login",
                "log_type": "linux_syslog",
                "username": "root",
                "source_ip": "185.24.18.15",
                "service": "SSH",
                "severity": "high",
                "severity_score": 75,
                "mitre_technique_id": "T1110",
                "mitre_technique_name": "Brute Force",
                "mitre_tactic": "Credential Access",
                "mitre_tactic_id": "TA0006",
                "raw_line": "Jul  1 10:23:11 server sshd[1234]: Failed password for root from 185.24.18.15 port 52431 ssh2",
                "created_at": "2025-07-01T10:23:11Z",
            }
        },
    }


class ParsedEventListResponse(BaseModel):
    """Paginated list of ParsedEvent records."""

    items: list[ParsedEventResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


# =============================================================================
# IOC Entity Schemas
# =============================================================================

class IOCEntityResponse(BaseModel):
    """Public representation of an IOCEntity record."""

    id: int
    log_id: int
    event_id: int | None
    ioc_type: str
    value: str
    context: str | None
    occurrence_count: int
    first_seen: datetime
    last_seen: datetime
    created_at: datetime

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "example": {
                "id": 1,
                "log_id": 42,
                "event_id": 7,
                "ioc_type": "ipv4",
                "value": "185.24.18.15",
                "context": "Failed password for root from 185.24.18.15",
                "occurrence_count": 14,
                "first_seen": "2025-07-01T10:00:00Z",
                "last_seen": "2025-07-01T10:23:11Z",
                "created_at": "2025-07-01T10:00:01Z",
            }
        },
    }


class IOCEntityListResponse(BaseModel):
    """Paginated list of IOCEntity records, optionally filtered by type."""

    items: list[IOCEntityResponse]
    total: int
    page: int
    page_size: int
    total_pages: int
    ioc_type_filter: str | None = None


# =============================================================================
# Incident Event Schemas
# =============================================================================

class IncidentEventResponse(BaseModel):
    """Public representation of an IncidentEvent record."""

    id: int
    title: str
    description: str | None
    severity: str
    status: str
    event_type: str | None
    log_ids: list[int] | None
    event_count: int
    ioc_count: int
    mitre_techniques: list[str] | None
    mitre_tactics: list[str] | None
    source_ips: list[str] | None
    affected_hosts: list[str] | None
    assigned_to: int | None
    source_log_id: int | None
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "example": {
                "id": 1,
                "title": "Brute Force Attack — SSH — 185.24.18.15",
                "severity": "high",
                "status": "open",
                "event_type": "Brute Force",
                "event_count": 14,
                "ioc_count": 3,
                "mitre_techniques": ["T1110"],
                "mitre_tactics": ["Credential Access"],
                "source_ips": ["185.24.18.15"],
                "created_at": "2025-07-01T10:00:01Z",
                "updated_at": "2025-07-01T10:00:01Z",
                "closed_at": None,
            }
        },
    }


class IncidentEventListResponse(BaseModel):
    """Paginated list of IncidentEvent records."""

    items: list[IncidentEventResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


# =============================================================================
# Statistics Schema
# =============================================================================

class SeverityBreakdown(BaseModel):
    """Event counts grouped by severity level."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0


class MitreHit(BaseModel):
    """A single MITRE technique and its occurrence count."""

    technique_id: str
    technique_name: str
    tactic: str
    count: int


class TopSourceIP(BaseModel):
    """A source IP and its associated event count."""

    ip: str
    count: int


class IOCTypeSummary(BaseModel):
    """IOC type counts across all logs."""

    ioc_type: str
    count: int


class StatisticsResponse(BaseModel):
    """Aggregate platform statistics for the statistics dashboard page."""

    # Log overview
    total_logs: int
    logs_pending: int
    logs_processing: int
    logs_completed: int
    logs_failed: int

    # Event overview
    total_events: int
    severity_breakdown: SeverityBreakdown

    # IOC overview
    total_iocs: int
    unique_ioc_values: int
    ioc_type_summary: list[IOCTypeSummary]

    # Incident overview
    total_incidents: int
    open_incidents: int
    critical_incidents: int
    high_incidents: int

    # Top attacker intelligence
    top_source_ips: list[TopSourceIP]
    top_mitre_techniques: list[MitreHit]
    top_event_types: list[dict[str, Any]]

    model_config = {
        "json_schema_extra": {
            "example": {
                "total_logs": 47,
                "logs_completed": 43,
                "total_events": 8192,
                "severity_breakdown": {
                    "critical": 12,
                    "high": 234,
                    "medium": 891,
                    "low": 2048,
                    "informational": 5007,
                },
                "total_iocs": 1247,
                "top_source_ips": [
                    {"ip": "185.24.18.15", "count": 142},
                    {"ip": "10.0.0.55", "count": 87},
                ],
            }
        }
    }


# =============================================================================
# Pipeline Internal Schema (used by NLP engine, not exposed in API)
# =============================================================================

class NormalizedEvent(BaseModel):
    """
    The unified intermediate schema that all parsers must produce.
    This is the contract between the parser layer and the
    classifier/severity/MITRE layers downstream.

    Not exposed in the API — used internally by the pipeline.
    """

    # Source identification
    log_type: str
    raw_line: str
    line_number: int | None = None

    # Standard fields
    event_type: str | None = None
    username: str | None = None
    source_ip: str | None = None
    dest_ip: str | None = None
    source_port: int | None = None
    dest_port: int | None = None
    protocol: str | None = None
    service: str | None = None
    hostname: str | None = None
    process_name: str | None = None
    process_id: int | None = None
    command_line: str | None = None
    file_path: str | None = None
    url: str | None = None
    http_method: str | None = None
    http_status_code: int | None = None
    user_agent: str | None = None

    # Timestamps
    timestamp_raw: str | None = None
    event_timestamp: datetime | None = None

    # Severity (filled by SeverityEngine)
    severity: str | None = None
    severity_score: int | None = None

    # MITRE (filled by MITREMapper)
    mitre_technique_id: str | None = None
    mitre_technique_name: str | None = None
    mitre_tactic: str | None = None
    mitre_tactic_id: str | None = None

    # Extra parser-specific fields stored as JSONB
    normalized_data: dict[str, Any] = Field(default_factory=dict)

    # IOCs extracted (filled by IOCExtractor)
    iocs: list[dict[str, Any]] = Field(default_factory=list)

    model_config = {"arbitrary_types_allowed": True}
