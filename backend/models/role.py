"""
SentinelX AI — Role ORM Model
================================
Defines user roles and their associated permissions.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from databases.postgres import Base

if TYPE_CHECKING:
    from backend.models.user import User


class Role(Base):
    """
    Role entity — defines access tiers in the platform.
    Default roles: admin, analyst, viewer.
    """

    __tablename__ = "roles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    permissions: Mapped[str | None] = mapped_column(
        Text, nullable=True, comment="JSON-encoded permission list"
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    users: Mapped[list["User"]] = relationship("User", back_populates="role_obj", lazy="selectin")

    def __repr__(self) -> str:
        return f"<Role id={self.id} name={self.name!r}>"
