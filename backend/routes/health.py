"""
SentinelX AI — Health & Root Routes
======================================
GET /         — API root info
GET /health   — Full platform health check (all 4 DBs)
"""
from __future__ import annotations

import logging

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from backend.config import settings
from backend.schemas.common import HealthResponse

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/", summary="API Root", include_in_schema=True)
async def root() -> JSONResponse:
    """Returns basic API identification info."""
    return JSONResponse(
        content={
            "name": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "status": "running",
            "docs": "/docs",
            "health": "/health",
        }
    )


@router.get(
    "/health",
    summary="Platform Health Check",
    response_model=HealthResponse,
    response_description="Health status of all platform services",
)
async def health_check() -> JSONResponse:
    """
    Performs live connectivity checks against all downstream services:
    PostgreSQL, Redis, Neo4j, and Qdrant.

    Returns 200 if all services are healthy, 207 if degraded, 503 if unhealthy.
    """
    from backend.services.dashboard_service import DashboardService

    svc = DashboardService()
    payload = await svc.get_system_status()

    status_map = {
        "healthy": 200,
        "degraded": 207,
        "unhealthy": 503,
    }
    http_code = status_map.get(payload["status"], 503)

    return JSONResponse(content=payload, status_code=http_code)
