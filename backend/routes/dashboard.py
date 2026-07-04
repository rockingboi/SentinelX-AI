"""
SentinelX AI — Dashboard Routes
==================================
GET /api/v1/dashboard  — System status (protected)
"""
from __future__ import annotations

import logging

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from backend.dependencies import CurrentUser
from backend.services.dashboard_service import DashboardService

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get(
    "",
    summary="System Dashboard",
    description=(
        "Returns real-time health of all platform services plus system metrics. "
        "Requires authentication."
    ),
)
async def get_dashboard(current_user: CurrentUser) -> JSONResponse:
    """
    Protected endpoint returning:
    - Live health status of PostgreSQL, Redis, Neo4j, Qdrant
    - System metrics (Phase 1: placeholder values)
    - Current user context
    """
    svc = DashboardService()
    payload = await svc.get_system_status()

    # Inject current user context into dashboard payload
    payload["user"] = {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role,
    }

    return JSONResponse(
        content={
            "success": True,
            "message": "Dashboard loaded successfully.",
            "data": payload,
        }
    )
