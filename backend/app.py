"""
SentinelX AI — FastAPI Application Factory
============================================
Creates and configures the FastAPI application instance.
Follows the Application Factory pattern for testability.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.openapi.utils import get_openapi

from backend.config import settings
from backend.core.exceptions import register_exception_handlers
from backend.core.logging import setup_logging
from backend.middleware.logging_middleware import RequestLoggingMiddleware

logger = logging.getLogger(__name__)


# =============================================================================
# Lifespan — startup / shutdown events
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Manages application lifecycle:
    - Startup: verify DB connectivity, run migrations, seed admin
    - Shutdown: close connection pools gracefully
    """
    logger.info("🚀 SentinelX AI starting up — env=%s", settings.APP_ENV)

    # ── Import here to avoid circular imports ──────────────────────────────
    from databases.postgres import init_db, close_db
    from databases.redis import init_redis, close_redis
    from graph_db.neo4j import init_neo4j, close_neo4j
    from vector_db.qdrant_client import init_qdrant, close_qdrant

    await init_db()
    await init_redis()
    await init_neo4j()
    await init_qdrant()

    logger.info("✅ All services initialised. API is ready.")

    yield

    # ── Shutdown ────────────────────────────────────────────────────────────
    logger.info("🛑 SentinelX AI shutting down…")
    await close_db()
    await close_redis()
    await close_neo4j()
    await close_qdrant()
    logger.info("👋 Shutdown complete.")


# =============================================================================
# Application Factory
# =============================================================================

def create_app() -> FastAPI:
    """
    Construct and return a fully configured FastAPI instance.
    Called once at module level; can also be called in tests with overrides.
    """
    # ── Setup logging first ─────────────────────────────────────────────────
    setup_logging(log_level=settings.LOG_LEVEL, app_env=settings.APP_ENV)

    # ── FastAPI instance ────────────────────────────────────────────────────
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description=(
            "SentinelX AI — Autonomous Cyber Investigation Officer\n\n"
            "An enterprise-grade platform for automated cybersecurity "
            "incident investigation powered by Multi-Agent AI, RAG, and GraphRAG."
        ),
        docs_url="/docs" if not settings.is_production else None,
        redoc_url="/redoc" if not settings.is_production else None,
        openapi_url="/openapi.json" if not settings.is_production else None,
        lifespan=lifespan,
    )

    # ── CORS ────────────────────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID", "X-Process-Time-Ms"],
    )

    # ── GZip compression ────────────────────────────────────────────────────
    app.add_middleware(GZipMiddleware, minimum_size=1000)

    # ── Request logging ─────────────────────────────────────────────────────
    app.add_middleware(RequestLoggingMiddleware)

    # ── Exception handlers ──────────────────────────────────────────────────
    register_exception_handlers(app)

    # ── Routers ─────────────────────────────────────────────────────────────
    _register_routers(app)

    # ── Custom OpenAPI schema ────────────────────────────────────────────────
    _configure_openapi(app)

    return app


def _register_routers(app: FastAPI) -> None:
    """Attach all route modules to the application."""
    from backend.routes.health import router as health_router
    from backend.routes.auth import router as auth_router
    from backend.routes.dashboard import router as dashboard_router

    # Root + health (no version prefix)
    app.include_router(health_router, tags=["System"])

    # Versioned API routes
    v1_prefix = settings.API_V1_PREFIX
    app.include_router(auth_router, prefix=f"{v1_prefix}/auth", tags=["Authentication"])
    app.include_router(dashboard_router, prefix=f"{v1_prefix}/dashboard", tags=["Dashboard"])


def _configure_openapi(app: FastAPI) -> None:
    """Customise the generated OpenAPI schema with security definitions."""

    def custom_openapi() -> dict:
        if app.openapi_schema:
            return app.openapi_schema

        schema = get_openapi(
            title=app.title,
            version=app.version,
            description=app.description,
            routes=app.routes,
        )

        # Add JWT Bearer security scheme
        schema.setdefault("components", {})
        schema["components"]["securitySchemes"] = {
            "BearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
            }
        }

        app.openapi_schema = schema
        return schema

    app.openapi = custom_openapi  # type: ignore[method-assign]


# =============================================================================
# Application singleton
# =============================================================================
app: FastAPI = create_app()
