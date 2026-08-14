"""
SentinelX AI — ParsedEvent ORM Model
=======================================
Represents a single structured security event extracted from a raw log line.

Design:
- One SecurityLog → many ParsedEvents (one per parsed log line/entry)
- normalized_data (JSONB) stores parser-specific extra fields without migrations
- All standard security fields are first-class columns for query efficiency
- mitre_* fields are nullable — not every event maps to a technique
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from databases.postgres import Base

if TYPE_CHECKING:
    from backend.models.security_log import SecurityLog


class ParsedEvent(Base):
    """
    Structured security event produced by the NLP pipeline.

    Each row corresponds to exactly one log line/entry that was
    successfully parsed. Fields map to the unified event schema
    that all parsers must produce.
    """

    __tablename__ = "parsed_events"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, index=True, autoincrement=True
    )

    # ── Parent log reference ─────────────────────────────────────────────────
    log_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("security_logs.id", ondelete="CASCADE"),
        nullable=False, index=True,
        comment="Parent SecurityLog this event was extracted from"
    )

    # ── Event classification ─────────────────────────────────────────────────
    event_type: Mapped[str | None] = mapped_column(
        String(100), nullable=True, index=True,
        comment="e.g. Failed Login, Privilege Escalation, Port Scan"
    )
    log_type: Mapped[str] = mapped_column(
        String(50), nullable=False,
        comment="Source log format (mirrors SecurityLog.log_type)"
    )

    # ── Standard security fields (normalized) ────────────────────────────────
    username: Mapped[str | None] = mapped_column(
        String(255), nullable=True, index=True
    )
    source_ip: Mapped[str | None] = mapped_column(
        String(45), nullable=True, index=True,
        comment="IPv4 or IPv6 source address"
    )
    dest_ip: Mapped[str | None] = mapped_column(
        String(45), nullable=True,
        comment="IPv4 or IPv6 destination address"
    )
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dest_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(20), nullable=True)
    service: Mapped[str | None] = mapped_column(
        String(100), nullable=True,
        comment="e.g. SSH, HTTP, RDP, SMB"
    )
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    process_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    process_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    command_line: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    http_method: Mapped[str | None] = mapped_column(String(10), nullable=True)
    http_status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── Event time ───────────────────────────────────────────────────────────
    timestamp_raw: Mapped[str | None] = mapped_column(
        Text, nullable=True,
        comment="Raw timestamp string as it appeared in the log"
    )
    event_timestamp: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True,
        comment="Parsed UTC timestamp of the event"
    )

    # ── Severity ─────────────────────────────────────────────────────────────
    severity: Mapped[str | None] = mapped_column(
        String(20), nullable=True, index=True,
        comment="critical | high | medium | low | informational"
    )
    severity_score: Mapped[int | None] = mapped_column(
        Integer, nullable=True,
        comment="Numeric severity score 0–100"
    )

    # ── MITRE ATT&CK ─────────────────────────────────────────────────────────
    mitre_technique_id: Mapped[str | None] = mapped_column(
        String(20), nullable=True, index=True,
        comment="e.g. T1110, T1059.001"
    )
    mitre_technique_name: Mapped[str | None] = mapped_column(
        String(200), nullable=True,
        comment="e.g. Brute Force, PowerShell"
    )
    mitre_tactic: Mapped[str | None] = mapped_column(
        String(100), nullable=True,
        comment="e.g. Credential Access, Execution, Persistence"
    )
    mitre_tactic_id: Mapped[str | None] = mapped_column(
        String(20), nullable=True,
        comment="e.g. TA0006"
    )

    # ── Raw + extra data ─────────────────────────────────────────────────────
    raw_line: Mapped[str | None] = mapped_column(
        Text, nullable=True,
        comment="The original unparsed log line"
    )
    normalized_data: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True,
        comment="Parser-specific extra fields (flexible schema)"
    )

    # ── Line reference ───────────────────────────────────────────────────────
    line_number: Mapped[int | None] = mapped_column(
        Integer, nullable=True,
        comment="Line number within the original file"
    )

    # ── Timestamps ───────────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    # ── Relationships ─────────────────────────────────────────────────────────
    security_log: Mapped["SecurityLog"] = relationship(
        "SecurityLog", back_populates="parsed_events", lazy="noload"
    )

    def __repr__(self) -> str:
        return (
            f"<ParsedEvent id={self.id} log_id={self.log_id} "
            f"type={self.event_type!r} severity={self.severity!r}>"
        )
