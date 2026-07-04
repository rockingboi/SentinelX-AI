"""
SentinelX AI — Dependency Injection
======================================
FastAPI dependencies for:
- Database sessions (PostgreSQL async)
- Redis client
- Current authenticated user extraction
- Role-based access control guards
"""
from __future__ import annotations

import logging
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config import settings
from backend.core.security import decode_token

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# HTTP Bearer scheme — extracts Authorization: Bearer <token>
# ---------------------------------------------------------------------------
_bearer_scheme = HTTPBearer(auto_error=False)


# ---------------------------------------------------------------------------
# Database Session
# ---------------------------------------------------------------------------

async def get_db() -> AsyncSession:  # type: ignore[return]
    """
    Yield an async SQLAlchemy session.
    Automatically rolls back on exception; closes after request completes.
    """
    from databases.postgres import AsyncSessionLocal

    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


DBSession = Annotated[AsyncSession, Depends(get_db)]


# ---------------------------------------------------------------------------
# Redis Client
# ---------------------------------------------------------------------------

async def get_redis():  # type: ignore[return]
    """Yield the shared Redis client from the connection pool."""
    from databases.redis import get_redis_client
    return get_redis_client()


RedisClient = Annotated[object, Depends(get_redis)]


# ---------------------------------------------------------------------------
# Current User Extraction
# ---------------------------------------------------------------------------

async def get_current_user(
    db: DBSession,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> "UserModel":  # type: ignore[name-defined]  # noqa: F821
    """
    Validate the Bearer JWT and return the authenticated User model.

    Raises:
        HTTP 401 — missing or invalid token
        HTTP 401 — user not found or inactive
    """
    from backend.repositories.user_repository import UserRepository

    auth_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if credentials is None:
        raise auth_error

    try:
        payload = decode_token(credentials.credentials)
        user_id: str | None = payload.get("sub")
        token_type: str | None = payload.get("type")

        if user_id is None or token_type != "access":
            raise auth_error

    except JWTError:
        raise auth_error

    repo = UserRepository(db)
    user = await repo.get_by_id(int(user_id))

    if user is None:
        raise auth_error

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated",
        )

    return user


CurrentUser = Annotated[object, Depends(get_current_user)]


# ---------------------------------------------------------------------------
# Role Guards
# ---------------------------------------------------------------------------

def require_role(*roles: str):
    """
    Factory that returns a dependency enforcing role membership.

    Usage:
        @router.get("/admin", dependencies=[Depends(require_role("admin"))])
    """
    async def _guard(current_user: CurrentUser) -> None:
        user_role = getattr(current_user, "role", None)
        if user_role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required role(s): {roles}. Your role: {user_role}",
            )

    return _guard


AdminOnly = Depends(require_role("admin"))
AnalystOrAdmin = Depends(require_role("admin", "analyst"))
