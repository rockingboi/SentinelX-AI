"""
SentinelX AI — Authentication Service
========================================
Business logic for user registration, login, and token lifecycle.
Orchestrates UserRepository, AuditRepository, and security utilities.
"""
from __future__ import annotations

import logging
from datetime import timedelta

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config import settings
from backend.core.exceptions import AuthenticationError, ConflictError
from backend.core.security import (
    create_access_token,
    create_refresh_token,
    hash_password,
    verify_password,
)
from backend.models.user import User
from backend.repositories.audit_repository import AuditRepository
from backend.repositories.user_repository import UserRepository
from backend.schemas.user import TokenResponse, UserRegisterRequest, UserResponse

logger = logging.getLogger(__name__)


class AuthService:
    """
    Service layer for all authentication operations.
    Keeps route handlers thin — all business logic lives here.
    """

    def __init__(self, db: AsyncSession) -> None:
        self._db = db
        self._users = UserRepository(db)
        self._audit = AuditRepository(db)

    async def register(
        self,
        payload: UserRegisterRequest,
        request: Request | None = None,
    ) -> UserResponse:
        """
        Register a new user account.

        Raises:
            ConflictError: If email or username already exists.
        """
        if await self._users.email_exists(payload.email):
            raise ConflictError(f"Email '{payload.email}' is already registered.")

        if await self._users.username_exists(payload.username):
            raise ConflictError(f"Username '{payload.username}' is already taken.")

        hashed = hash_password(payload.password)
        user = await self._users.create(
            email=payload.email,
            username=payload.username,
            hashed_password=hashed,
            full_name=payload.full_name,
            role="viewer",  # Default role on registration
        )

        await self._audit.log(
            action="USER_REGISTER",
            user_id=user.id,
            username=user.username,
            resource="auth",
            status="success",
            ip_address=_extract_ip(request),
            user_agent=_extract_ua(request),
        )

        logger.info("New user registered: id=%d email=%s", user.id, user.email)
        return UserResponse.model_validate(user)

    async def login(
        self,
        email: str,
        password: str,
        request: Request | None = None,
    ) -> TokenResponse:
        """
        Authenticate a user and return JWT tokens.

        Raises:
            AuthenticationError: If credentials are invalid or account is inactive.
        """
        user = await self._users.get_by_email(email)

        if user is None or not verify_password(password, user.hashed_password):
            # Audit failed attempt (user_id may be None if user not found)
            await self._audit.log(
                action="USER_LOGIN",
                user_id=user.id if user else None,
                username=email,
                resource="auth",
                status="failure",
                detail={"reason": "invalid_credentials"},
                ip_address=_extract_ip(request),
                user_agent=_extract_ua(request),
            )
            raise AuthenticationError("Invalid email or password.")

        if not user.is_active:
            raise AuthenticationError("Account is deactivated. Contact an administrator.")

        # Issue tokens
        access_token = create_access_token(
            subject=user.id,
            additional_claims={"role": user.role, "email": user.email},
        )
        refresh_token = create_refresh_token(subject=user.id)

        # Update last login timestamp
        await self._users.update_last_login(user.id)

        await self._audit.log(
            action="USER_LOGIN",
            user_id=user.id,
            username=user.username,
            resource="auth",
            status="success",
            ip_address=_extract_ip(request),
            user_agent=_extract_ua(request),
        )

        logger.info("User logged in: id=%d email=%s", user.id, user.email)

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            user=UserResponse.model_validate(user),
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_ip(request: Request | None) -> str | None:
    if request is None:
        return None
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else None


def _extract_ua(request: Request | None) -> str | None:
    if request is None:
        return None
    return request.headers.get("User-Agent")
