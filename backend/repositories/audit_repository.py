"""
SentinelX AI — Audit Log Repository
=======================================
Append-only data access layer for AuditLog.
All security events flow through this repository.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.models.audit_log import AuditLog

logger = logging.getLogger(__name__)


class AuditRepository:
    """Repository for writing and querying audit log entries."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def log(
        self,
        *,
        action: str,
        user_id: int | None = None,
        username: str | None = None,
        resource: str | None = None,
        resource_id: str | None = None,
        detail: dict[str, Any] | None = None,
        status: str = "success",
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> AuditLog:
        """
        Persist an audit log entry. Always commits immediately.
        Never raises — failures are logged and swallowed to avoid
        breaking the main request flow.
        """
        try:
            entry = AuditLog(
                action=action,
                user_id=user_id,
                username=username,
                resource=resource,
                resource_id=str(resource_id) if resource_id else None,
                detail=json.dumps(detail, default=str) if detail else None,
                status=status,
                ip_address=ip_address,
                user_agent=user_agent,
                timestamp=datetime.now(timezone.utc),
            )
            self._db.add(entry)
            await self._db.commit()
            await self._db.refresh(entry)
            logger.debug("Audit: action=%s user_id=%s status=%s", action, user_id, status)
            return entry
        except Exception as exc:
            logger.error("Failed to write audit log: %s", exc, exc_info=True)
            await self._db.rollback()
            raise

    async def get_user_activity(
        self, user_id: int, limit: int = 50
    ) -> list[AuditLog]:
        """Return the most recent audit entries for a user."""
        result = await self._db.execute(
            select(AuditLog)
            .where(AuditLog.user_id == user_id)
            .order_by(AuditLog.timestamp.desc())
            .limit(limit)
        )
        return list(result.scalars().all())
