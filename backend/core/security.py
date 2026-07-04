"""
SentinelX AI — Security Utilities
===================================
JWT token operations + Password hashing via passlib/bcrypt.
All cryptographic operations centralised here.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from jose import JWTError, jwt
from passlib.context import CryptContext

from backend.config import settings

logger = logging.getLogger(__name__)

# =============================================================================
# Password Hashing
# =============================================================================

_pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=settings.BCRYPT_ROUNDS,
)


def hash_password(plain_password: str) -> str:
    """Hash a plain-text password using bcrypt."""
    return _pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain-text password against its bcrypt hash."""
    return _pwd_context.verify(plain_password, hashed_password)


# =============================================================================
# JWT Token Operations
# =============================================================================

def create_access_token(
    subject: str | int,
    additional_claims: dict[str, Any] | None = None,
    expires_delta: timedelta | None = None,
) -> str:
    """
    Create a signed JWT access token.

    Args:
        subject:           User identifier (e.g., user ID or email).
        additional_claims: Extra claims to embed in the payload.
        expires_delta:     Custom expiry. Defaults to ACCESS_TOKEN_EXPIRE_MINUTES.

    Returns:
        Signed JWT string.
    """
    now = datetime.now(tz=timezone.utc)
    expire = now + (
        expires_delta
        if expires_delta is not None
        else timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    payload: dict[str, Any] = {
        "sub": str(subject),
        "iat": now,
        "exp": expire,
        "type": "access",
    }

    if additional_claims:
        payload.update(additional_claims)

    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(subject: str | int) -> str:
    """Create a long-lived refresh token."""
    return create_access_token(
        subject=subject,
        additional_claims={"type": "refresh"},
        expires_delta=timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )


def decode_token(token: str) -> dict[str, Any]:
    """
    Decode and validate a JWT token.

    Raises:
        JWTError: If the token is invalid or expired.
    """
    return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])


def extract_subject(token: str) -> str:
    """
    Extract the 'sub' claim from a token without full validation.
    Use decode_token() for authenticated routes.
    """
    try:
        payload = decode_token(token)
        return payload["sub"]
    except (JWTError, KeyError) as exc:
        logger.debug("Failed to extract subject from token: %s", exc)
        raise
