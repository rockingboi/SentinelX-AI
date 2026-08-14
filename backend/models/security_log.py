"""
SentinelX AI — SecurityLog ORM Model
=======================================
Represents a raw security log file uploaded to the platform.
Stores both the metadata and full text content for pipeline processing.

Design:
- content stored as TEXT (not filesystem) for statelesness + replayability
- status field tracks the pipeline processing lifecycle
- supports all log types defined in LogType enum
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum as PyEnum
from typing import TYPE_CHECKING

from sqlalchemy import (
    BigInteger,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from databases.postgres import Base

if TYPE_CHECKING:
    from backend.models.user import User
    from backend.models.parsed_event import ParsedEvent
    from backend.models.ioc_entity import IOCEntity


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class LogType(str, PyEnum):
    """Supported security log format types."""
    WINDOWS_EVENT   = "windows_event"
    LINUX_SYSLOG    = "linux_syslog"
    APACHE_ACCESS   = "apache_access"
    NGINX_ACCESS    = "nginx_access"
    SYSMON          = "sysmon"
    UNKNOWN         = "unknown"


class LogStatus(str, PyEnum):
    """Pipeline processing lifecycle states."""
    PENDING     = "pending"       # Uploaded, not yet parsed
    PROCESSING  = "processing"    # Pipeline currently running
    COMPLETED   = "completed"     # Successfully parsed
    FAILED      = "failed"        # Pipeline error


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

class SecurityLog(Base):
    """
    Raw security log entity.

    Lifecycle: PENDING → PROCESSING → COMPLETED | FAILED

    A SecurityLog is the entry point for the NLP pipeline.
    Once processing is complete, ParsedEvent and IOCEntity records
    are created as children of this record.
    """

    __tablename__ = "security_logs"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, index=True, autoincrement=True
    )

    # ── File metadata ────────────────────────────────────────────────────────
    filename: Mapped[str] = mapped_column(
        String(500), nullable=False, comment="Original uploaded filename"
    )
    log_type: Mapped[str] = mapped_column(
        Enum(LogType, name="log_type_enum"), nullable=False, index=True,
        default=LogType.UNKNOWN, comment="Detected or declared log format"
    )
    file_size_bytes: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0,
        comment="Raw content size in bytes"
    )
    line_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0,
        comment="Number of lines in the log file"
    )

    # ── Content ──────────────────────────────────────────────────────────────
    raw_content: Mapped[str] = mapped_column(
        Text, nullable=False,
        comment="Full raw log file content stored as text"
    )

    # ── Pipeline status ──────────────────────────────────────────────────────
    status: Mapped[str] = mapped_column(
        Enum(LogStatus, name="log_status_enum"), nullable=False,
        default=LogStatus.PENDING, index=True,
        comment="Pipeline processing lifecycle state"
    )
    parse_error: Mapped[str | None] = mapped_column(
        Text, nullable=True,
        comment="Error message if processing failed"
    )
    parsed_event_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0,
        comment="Number of events extracted by the pipeline"
    )
    ioc_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0,
        comment="Number of IOCs extracted by the pipeline"
    )

    # ── Ownership ────────────────────────────────────────────────────────────
    uploaded_by: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True, index=True,
        comment="User who uploaded this log file"
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
    processing_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
        comment="When pipeline processing began"
    )
    processing_completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
        comment="When pipeline processing finished"
    )

    # ── Relationships ─────────────────────────────────────────────────────────
    uploader: Mapped["User | None"] = relationship(
        "User", foreign_keys=[uploaded_by], lazy="selectin"
    )
    parsed_events: Mapped[list["ParsedEvent"]] = relationship(
        "ParsedEvent", back_populates="security_log", lazy="noload",
        cascade="all, delete-orphan"
    )
    ioc_entities: Mapped[list["IOCEntity"]] = relationship(
        "IOCEntity", back_populates="security_log", lazy="noload",
        cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return (
            f"<SecurityLog id={self.id} filename={self.filename!r} "
            f"type={self.log_type!r} status={self.status!r}>"
        )
