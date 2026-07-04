"""
SentinelX AI — Common Response Schemas
========================================
Shared Pydantic schemas used across the entire API surface.
"""
from __future__ import annotations

from typing import Any, Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class APIResponse(BaseModel, Generic[T]):
    """Generic success envelope for all API responses."""

    success: bool = True
    message: str = "OK"
    data: T | None = None


class ErrorDetail(BaseModel):
    type: str
    message: str
    detail: Any = None


class ErrorResponse(BaseModel):
    """Standardised error envelope."""

    success: bool = False
    error: ErrorDetail


class ServiceStatus(BaseModel):
    """Health status of a single downstream service."""

    status: str = Field(description="healthy | unhealthy | unavailable")
    message: str
    version: str | None = None


class HealthResponse(BaseModel):
    """Full platform health check response."""

    status: str = Field(description="healthy | degraded | unhealthy")
    version: str
    environment: str
    services: dict[str, ServiceStatus]

    model_config = {"json_schema_extra": {
        "example": {
            "status": "healthy",
            "version": "1.0.0",
            "environment": "development",
            "services": {
                "postgres": {"status": "healthy", "message": "Connected", "version": "16.1"},
                "redis": {"status": "healthy", "message": "Connected", "version": "7.2.3"},
                "neo4j": {"status": "healthy", "message": "Connected", "version": "5.24.0"},
                "qdrant": {"status": "healthy", "message": "Connected", "collection_count": 0},
            },
        }
    }}


class PaginationMeta(BaseModel):
    """Pagination metadata for list endpoints."""

    page: int
    page_size: int
    total: int
    total_pages: int
