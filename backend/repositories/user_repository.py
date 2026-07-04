"""
SentinelX AI — User Repository
=================================
Data access layer for User model.
Follows the Repository Pattern — all DB access goes through here.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.models.user import User

logger = logging.getLogger(__name__)


class UserRepository:
    """
    Repository for User entity CRUD operations.
    Injected into services via dependency injection.
    """

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def get_by_id(self, user_id: int) -> User | None:
        """Fetch a user by primary key."""
        result = await self._db.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()

    async def get_by_email(self, email: str) -> User | None:
        """Fetch a user by email (case-insensitive)."""
        result = await self._db.execute(
            select(User).where(User.email == email.lower().strip())
        )
        return result.scalar_one_or_none()

    async def get_by_username(self, username: str) -> User | None:
        """Fetch a user by username."""
        result = await self._db.execute(
            select(User).where(User.username == username.strip())
        )
        return result.scalar_one_or_none()

    async def email_exists(self, email: str) -> bool:
        """Return True if a user with this email already exists."""
        result = await self._db.execute(
            select(User.id).where(User.email == email.lower().strip())
        )
        return result.scalar_one_or_none() is not None

    async def username_exists(self, username: str) -> bool:
        """Return True if a user with this username already exists."""
        result = await self._db.execute(
            select(User.id).where(User.username == username.strip())
        )
        return result.scalar_one_or_none() is not None

    async def create(
        self,
        *,
        email: str,
        username: str,
        hashed_password: str,
        full_name: str | None = None,
        role: str = "viewer",
    ) -> User:
        """Persist a new User record and return it."""
        user = User(
            email=email.lower().strip(),
            username=username.strip(),
            hashed_password=hashed_password,
            full_name=full_name,
            role=role,
        )
        self._db.add(user)
        await self._db.commit()
        await self._db.refresh(user)
        logger.info("Created user id=%d email=%s", user.id, user.email)
        return user

    async def update_last_login(self, user_id: int) -> None:
        """Stamp the last_login_at timestamp."""
        user = await self.get_by_id(user_id)
        if user is not None:
            user.last_login_at = datetime.now(timezone.utc)
            await self._db.commit()

    async def deactivate(self, user_id: int) -> bool:
        """Soft-delete by deactivating the account. Returns True if updated."""
        user = await self.get_by_id(user_id)
        if user is None:
            return False
        user.is_active = False
        await self._db.commit()
        return True
