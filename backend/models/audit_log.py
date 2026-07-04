"""
SentinelX AI — Audit Log ORM Model
=====================================
Immutable audit trail for all security-relevant user actions.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from databases.postgres import Base

if TYPE_CHECKING:
    from backend.models.user import User


class AuditLog(Base):
    """
    Audit log entry — records security-sensitive events.
    Records are NEVER updated or deleted (append-only).
    """

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)

    # Who
    user_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    username: Mapped[str | None] = mapped_column(
        String(100), nullable=True, comment="Snapshot of username at time of action"
    )

    # What
    action: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True,
        comment="e.g. USER_LOGIN, USER_REGISTER, INVESTIGATION_CREATED"
    )
    resource: Mapped[str | None] = mapped_column(
        String(200), nullable=True, comment="Affected resource path or name"
    )
    resource_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    detail: Mapped[str | None] = mapped_column(
        Text, nullable=True, comment="JSON-encoded additional context"
    )
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="success",
        comment="success | failure | error"
    )

    # Where
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)

    # When
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    # Relationships
    user: Mapped["User | None"] = relationship("User", back_populates="audit_logs", lazy="noload")

    def __repr__(self) -> str:
        return f"<AuditLog id={self.id} action={self.action!r} user_id={self.user_id}>"
