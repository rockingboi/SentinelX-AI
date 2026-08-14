"""
SentinelX AI — IOCEntity ORM Model
=====================================
Represents a single Indicator of Compromise (IOC) extracted from a log.

Design:
- Unique constraint on (log_id, ioc_type, value) prevents duplicates per log
- occurrence_count tracks how many times an IOC appeared in the same log
- Supports 15 IOC types covering the full spectrum of cyber indicators
- first_seen / last_seen enable temporal analysis in future phases
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
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from databases.postgres import Base

if TYPE_CHECKING:
    from backend.models.security_log import SecurityLog
    from backend.models.parsed_event import ParsedEvent


# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------

class IOCType(str, PyEnum):
    """All supported Indicator of Compromise types."""
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


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

class IOCEntity(Base):
    """
    Indicator of Compromise extracted by the NLP pipeline.

    Each unique (log_id, ioc_type, value) triple is stored once.
    Multiple occurrences within the same log increment occurrence_count.
    """

    __tablename__ = "ioc_entities"
    __table_args__ = (
        UniqueConstraint(
            "log_id", "ioc_type", "value",
            name="uq_ioc_log_type_value",
        ),
    )

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, index=True, autoincrement=True
    )

    # ── Parent references ────────────────────────────────────────────────────
    log_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("security_logs.id", ondelete="CASCADE"),
        nullable=False, index=True,
        comment="Parent SecurityLog this IOC was found in"
    )
    event_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("parsed_events.id", ondelete="SET NULL"),
        nullable=True, index=True,
        comment="ParsedEvent this IOC was first found in (nullable)"
    )

    # ── IOC data ─────────────────────────────────────────────────────────────
    ioc_type: Mapped[str] = mapped_column(
        Enum(IOCType, name="ioc_type_enum"), nullable=False, index=True,
        comment="The category of indicator (ipv4, sha256, domain, etc.)"
    )
    value: Mapped[str] = mapped_column(
        String(2048), nullable=False, index=True,
        comment="The actual IOC value (e.g. '185.24.18.15' or 'evil.com')"
    )
    context: Mapped[str | None] = mapped_column(
        Text, nullable=True,
        comment="Surrounding log context where this IOC was found"
    )

    # ── Frequency / temporal ─────────────────────────────────────────────────
    occurrence_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1,
        comment="Number of times this IOC appeared in the parent log"
    )
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        comment="Timestamp when this IOC was first observed"
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
        comment="Timestamp when this IOC was most recently observed"
    )

    # ── Timestamps ───────────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # ── Relationships ─────────────────────────────────────────────────────────
    security_log: Mapped["SecurityLog"] = relationship(
        "SecurityLog", back_populates="ioc_entities", lazy="noload"
    )
    parsed_event: Mapped["ParsedEvent | None"] = relationship(
        "ParsedEvent", foreign_keys=[event_id], lazy="noload"
    )

    def __repr__(self) -> str:
        return (
            f"<IOCEntity id={self.id} type={self.ioc_type!r} "
            f"value={self.value!r} count={self.occurrence_count}>"
        )
