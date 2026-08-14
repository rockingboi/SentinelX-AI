"""
SentinelX AI — IncidentEvent ORM Model
=========================================
Represents a correlated security incident — a higher-level grouping
of related ParsedEvents that together constitute a security incident.

Design:
- PostgreSQL ARRAY columns for log_ids, mitre_techniques, source_ips
  — efficient storage for multi-value metadata without join tables
- Status lifecycle: open → investigating → closed
- Assigned analyst enables SOC workflow integration
- Designed for Phase 3 AI agent correlation; Phase 2 creates stubs only
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum as PyEnum
from typing import TYPE_CHECKING

from sqlalchemy import (
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from databases.postgres import Base

if TYPE_CHECKING:
    from backend.models.user import User


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class IncidentStatus(str, PyEnum):
    """SOC workflow lifecycle for incidents."""
    OPEN            = "open"
    INVESTIGATING   = "investigating"
    CONTAINED       = "contained"
    CLOSED          = "closed"
    FALSE_POSITIVE  = "false_positive"


class IncidentSeverity(str, PyEnum):
    """Incident severity aligned with NIST SP 800-61."""
    CRITICAL        = "critical"
    HIGH            = "high"
    MEDIUM          = "medium"
    LOW             = "low"
    INFORMATIONAL   = "informational"


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

class IncidentEvent(Base):
    """
    Security incident entity — a correlated grouping of ParsedEvents.

    Phase 2: created automatically when critical/high severity events
    are detected during log parsing.

    Phase 3: AI agents will enrich, correlate, and investigate these.
    """

    __tablename__ = "incident_events"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, index=True, autoincrement=True
    )

    # ── Incident identification ──────────────────────────────────────────────
    title: Mapped[str] = mapped_column(
        String(500), nullable=False,
        comment="Human-readable incident title"
    )
    description: Mapped[str | None] = mapped_column(
        Text, nullable=True,
        comment="Detailed description of the incident"
    )

    # ── Classification ───────────────────────────────────────────────────────
    severity: Mapped[str] = mapped_column(
        Enum(IncidentSeverity, name="incident_severity_enum"),
        nullable=False, default=IncidentSeverity.MEDIUM, index=True,
        comment="Overall incident severity level"
    )
    status: Mapped[str] = mapped_column(
        Enum(IncidentStatus, name="incident_status_enum"),
        nullable=False, default=IncidentStatus.OPEN, index=True,
        comment="Current SOC workflow status"
    )
    event_type: Mapped[str | None] = mapped_column(
        String(100), nullable=True, index=True,
        comment="Primary event type that triggered this incident"
    )

    # ── Source data references ───────────────────────────────────────────────
    log_ids: Mapped[list[int] | None] = mapped_column(
        ARRAY(Integer), nullable=True,
        comment="Array of SecurityLog IDs contributing to this incident"
    )
    event_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0,
        comment="Total number of ParsedEvents in this incident"
    )
    ioc_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0,
        comment="Total number of unique IOCs in this incident"
    )

    # ── MITRE ATT&CK ─────────────────────────────────────────────────────────
    mitre_techniques: Mapped[list[str] | None] = mapped_column(
        ARRAY(String), nullable=True,
        comment="Array of MITRE technique IDs observed (e.g. ['T1110', 'T1059'])"
    )
    mitre_tactics: Mapped[list[str] | None] = mapped_column(
        ARRAY(String), nullable=True,
        comment="Array of MITRE tactic names observed"
    )

    # ── Network intelligence ─────────────────────────────────────────────────
    source_ips: Mapped[list[str] | None] = mapped_column(
        ARRAY(String), nullable=True,
        comment="Array of unique source IP addresses in this incident"
    )
    affected_hosts: Mapped[list[str] | None] = mapped_column(
        ARRAY(String), nullable=True,
        comment="Array of hostnames/systems affected"
    )

    # ── SOC workflow ─────────────────────────────────────────────────────────
    assigned_to: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True, index=True,
        comment="Analyst assigned to investigate this incident"
    )

    # ── Source log that auto-created this incident ───────────────────────────
    source_log_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("security_logs.id", ondelete="SET NULL"),
        nullable=True, index=True,
        comment="Primary SecurityLog that triggered incident creation"
    )

    # ── Timestamps ───────────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    closed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
        comment="Timestamp when incident was closed"
    )

    # ── Relationships ─────────────────────────────────────────────────────────
    assignee: Mapped["User | None"] = relationship(
        "User", foreign_keys=[assigned_to], lazy="selectin"
    )

    def __repr__(self) -> str:
        return (
            f"<IncidentEvent id={self.id} severity={self.severity!r} "
            f"status={self.status!r} title={self.title[:40]!r}>"
        )
