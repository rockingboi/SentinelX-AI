"""
SentinelX AI — Dashboard Service
====================================
Aggregates health information from all platform services
and returns a unified dashboard payload.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from backend.config import settings

logger = logging.getLogger(__name__)


class DashboardService:
    """
    Service for aggregating platform health and system metrics.
    In Phase 1 this uses real DB health checks + dummy stats.
    Later phases will plug in real telemetry data.
    """

    async def get_system_status(self) -> dict:
        """
        Gather health status from all downstream services.
        Returns a structured payload for the dashboard API.
        """
        from databases.postgres import check_postgres_health
        from databases.redis import check_redis_health
        from graph_db.neo4j import check_neo4j_health
        from vector_db.qdrant_client import check_qdrant_health

        # Run health checks concurrently
        import asyncio

        postgres_health, redis_health, neo4j_health, qdrant_health = await asyncio.gather(
            check_postgres_health(),
            check_redis_health(),
            check_neo4j_health(),
            check_qdrant_health(),
            return_exceptions=True,
        )

        # Normalise exception results
        def _safe(result: dict | Exception) -> dict:
            if isinstance(result, Exception):
                return {"status": "unhealthy", "message": str(result)}
            return result

        services = {
            "postgres": _safe(postgres_health),
            "redis": _safe(redis_health),
            "neo4j": _safe(neo4j_health),
            "qdrant": _safe(qdrant_health),
        }

        # Compute overall status
        statuses = [s.get("status", "unhealthy") for s in services.values()]
        if all(s == "healthy" for s in statuses):
            overall = "healthy"
        elif any(s == "healthy" for s in statuses):
            overall = "degraded"
        else:
            overall = "unhealthy"

        return {
            "status": overall,
            "version": settings.APP_VERSION,
            "environment": settings.APP_ENV,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "services": services,
            "metrics": self._get_dummy_metrics(),
        }

    def _get_dummy_metrics(self) -> dict:
        """
        Placeholder metrics for Phase 1 UI.
        Will be replaced with real data in Phase 3 (agents online).
        """
        return {
            "investigations": {
                "total": 0,
                "active": 0,
                "completed": 0,
                "critical": 0,
            },
            "threats": {
                "detected": 0,
                "mitigated": 0,
                "pending": 0,
            },
            "agents": {
                "total": 0,
                "online": 0,
                "tasks_processed": 0,
            },
            "system": {
                "uptime_hours": 0,
                "api_requests_today": 0,
                "avg_response_ms": 0,
            },
        }
