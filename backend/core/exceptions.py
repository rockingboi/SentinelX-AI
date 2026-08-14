"""
SentinelX AI — Custom Exception Hierarchy & Global Handlers
=============================================================
Clean exception model following RFC 7807 Problem Details standard.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)


# =============================================================================
# Exception Hierarchy
# =============================================================================

class SentinelXBaseException(Exception):
    """Base exception for all SentinelX custom errors."""

    def __init__(
        self,
        message: str,
        detail: Any = None,
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
    ) -> None:
        self.message = message
        self.detail = detail
        self.status_code = status_code
        super().__init__(self.message)


class NotFoundError(SentinelXBaseException):
    def __init__(self, resource: str, identifier: Any = None) -> None:
        detail = f"{resource} not found"
        if identifier is not None:
            detail = f"{resource} with id '{identifier}' not found"
        super().__init__(message=detail, detail=detail, status_code=status.HTTP_404_NOT_FOUND)


class ConflictError(SentinelXBaseException):
    def __init__(self, message: str) -> None:
        super().__init__(message=message, detail=message, status_code=status.HTTP_409_CONFLICT)


class AuthenticationError(SentinelXBaseException):
    def __init__(self, message: str = "Authentication failed") -> None:
        super().__init__(message=message, detail=message, status_code=status.HTTP_401_UNAUTHORIZED)


class AuthorizationError(SentinelXBaseException):
    def __init__(self, message: str = "Insufficient permissions") -> None:
        super().__init__(message=message, detail=message, status_code=status.HTTP_403_FORBIDDEN)


class ValidationError(SentinelXBaseException):
    def __init__(self, message: str, detail: Any = None) -> None:
        super().__init__(message=message, detail=detail, status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)


class DatabaseError(SentinelXBaseException):
    def __init__(self, message: str = "Database operation failed") -> None:
        super().__init__(message=message, status_code=status.HTTP_503_SERVICE_UNAVAILABLE)


class ServiceUnavailableError(SentinelXBaseException):
    def __init__(self, service: str) -> None:
        super().__init__(
            message=f"Service '{service}' is currently unavailable",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )


# =============================================================================
# Response Builders
# =============================================================================

def _error_response(
    status_code: int,
    error_type: str,
    message: str,
    detail: Any = None,
) -> JSONResponse:
    content: dict[str, Any] = {
        "success": False,
        "error": {
            "type": error_type,
            "message": message,
        },
    }
    if detail is not None:
        content["error"]["detail"] = detail
    return JSONResponse(status_code=status_code, content=content)


# =============================================================================
# Exception Handlers
# =============================================================================

async def sentinelx_exception_handler(
    request: Request, exc: SentinelXBaseException
) -> JSONResponse:
    logger.warning(
        "SentinelX exception",
        extra={
            "error_type": type(exc).__name__,
            "err_message": exc.message,
            "path": request.url.path,
            "method": request.method,
        },
    )
    return _error_response(
        status_code=exc.status_code,
        error_type=type(exc).__name__,
        message=exc.message,
        detail=exc.detail,
    )


async def http_exception_handler(
    request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    logger.warning(
        "HTTP exception",
        extra={
            "status_code": exc.status_code,
            "detail": exc.detail,
            "path": request.url.path,
        },
    )
    return _error_response(
        status_code=exc.status_code,
        error_type="HTTPException",
        message=str(exc.detail),
    )


async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    errors = exc.errors()
    logger.warning(
        "Request validation failed",
        extra={"path": request.url.path, "errors": errors},
    )
    return _error_response(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        error_type="ValidationError",
        message="Request validation failed",
        detail=errors,
    )


async def unhandled_exception_handler(
    request: Request, exc: Exception
) -> JSONResponse:
    logger.exception(
        "Unhandled exception",
        extra={"path": request.url.path, "method": request.method},
    )
    return _error_response(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        error_type="InternalServerError",
        message="An unexpected error occurred. Please try again later.",
    )


# =============================================================================
# Registration Helper
# =============================================================================

def register_exception_handlers(app: FastAPI) -> None:
    """Register all exception handlers on the FastAPI application."""
    app.add_exception_handler(SentinelXBaseException, sentinelx_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(RequestValidationError, validation_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(Exception, unhandled_exception_handler)  # type: ignore[arg-type]
