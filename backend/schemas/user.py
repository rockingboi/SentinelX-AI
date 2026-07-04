"""
SentinelX AI — User & Auth Schemas
=====================================
Pydantic v2 schemas for user registration, login, and JWT token responses.
"""
from __future__ import annotations

import re
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator


# =============================================================================
# Validators
# =============================================================================

_PASSWORD_PATTERN = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&_\-#])[A-Za-z\d@$!%*?&_\-#]{8,128}$"
)


def _validate_password(value: str) -> str:
    if not _PASSWORD_PATTERN.match(value):
        raise ValueError(
            "Password must be 8–128 characters and include uppercase, "
            "lowercase, a digit, and a special character (@$!%*?&_-#)."
        )
    return value


# =============================================================================
# Request Schemas
# =============================================================================

class UserRegisterRequest(BaseModel):
    """Schema for user registration."""

    email: EmailStr = Field(..., examples=["analyst@sentinelx.ai"])
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_\-]+$")
    password: str = Field(..., min_length=8, max_length=128)
    full_name: str | None = Field(default=None, max_length=200)

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        return _validate_password(v)

    model_config = {
        "json_schema_extra": {
            "example": {
                "email": "analyst@sentinelx.ai",
                "username": "jdoe_analyst",
                "password": "SentinelX@2025!",
                "full_name": "John Doe",
            }
        }
    }


class UserLoginRequest(BaseModel):
    """Schema for user login."""

    email: EmailStr = Field(..., examples=["analyst@sentinelx.ai"])
    password: str = Field(..., min_length=1, max_length=128)

    model_config = {
        "json_schema_extra": {
            "example": {
                "email": "admin@sentinelx.ai",
                "password": "SentinelX@2025!",
            }
        }
    }


# =============================================================================
# Response Schemas
# =============================================================================

class UserResponse(BaseModel):
    """Public user representation — never exposes hashed_password."""

    id: int
    email: str
    username: str
    full_name: str | None
    role: str
    is_active: bool
    is_verified: bool
    created_at: datetime
    last_login_at: datetime | None

    model_config = {"from_attributes": True}


class TokenResponse(BaseModel):
    """JWT token pair returned after successful login."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = Field(description="Access token TTL in seconds")
    user: UserResponse


class TokenData(BaseModel):
    """Decoded JWT payload (internal use only)."""

    sub: str
    type: str
    exp: int
    iat: int
