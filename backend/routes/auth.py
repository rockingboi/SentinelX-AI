"""
SentinelX AI — Authentication Routes
========================================
POST /api/v1/auth/register  — Create new account
POST /api/v1/auth/login     — Authenticate and receive JWT tokens
GET  /api/v1/auth/me        — Get current authenticated user
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse

from backend.dependencies import DBSession, CurrentUser
from backend.schemas.common import APIResponse
from backend.schemas.user import (
    TokenResponse,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
)
from backend.services.auth_service import AuthService

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post(
    "/register",
    summary="Register new user",
    status_code=status.HTTP_201_CREATED,
    response_model=APIResponse[UserResponse],
)
async def register(
    payload: UserRegisterRequest,
    request: Request,
    db: DBSession,
) -> JSONResponse:
    """
    Creates a new user account with the 'viewer' role.

    - Email and username must be unique
    - Password must be 8+ chars with uppercase, lowercase, digit, and special char
    """
    svc = AuthService(db)
    user = await svc.register(payload, request=request)

    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={
            "success": True,
            "message": "Account created successfully. You can now log in.",
            "data": user.model_dump(mode="json"),
        },
    )


@router.post(
    "/login",
    summary="Login and receive JWT tokens",
    status_code=status.HTTP_200_OK,
    response_model=APIResponse[TokenResponse],
)
async def login(
    payload: UserLoginRequest,
    request: Request,
    db: DBSession,
) -> JSONResponse:
    """
    Authenticates the user and returns:
    - `access_token` — short-lived (30 min) JWT for API access
    - `refresh_token` — long-lived (7 days) JWT for token renewal
    """
    svc = AuthService(db)
    token_response = await svc.login(
        email=payload.email,
        password=payload.password,
        request=request,
    )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "success": True,
            "message": "Login successful.",
            "data": token_response.model_dump(mode="json"),
        },
    )


@router.get(
    "/me",
    summary="Get current user profile",
    response_model=APIResponse[UserResponse],
)
async def get_me(current_user: CurrentUser) -> JSONResponse:
    """
    Returns the authenticated user's profile.
    Requires a valid Bearer token in the Authorization header.
    """
    user_data = UserResponse.model_validate(current_user)
    return JSONResponse(
        content={
            "success": True,
            "message": "OK",
            "data": user_data.model_dump(mode="json"),
        }
    )
