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

    # Seed default admin user on first boot
    await _seed_admin()

    # ── Phase 3 — Knowledge Intelligence Layer ──────────────────────────────
    await _init_knowledge_layer()

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
# Admin User Seeder
# =============================================================================

async def _seed_admin() -> None:
    """
    Idempotently ensure the default admin user exists.
    Safe to call on every startup — does nothing if the user already exists.
    """
    from databases.postgres import AsyncSessionLocal
    from backend.repositories.user_repository import UserRepository
    from backend.core.security import hash_password

    async with AsyncSessionLocal() as session:
        try:
            repo = UserRepository(session)
            existing = await repo.get_by_email("admin@sentinelx.ai")
            if existing:
                if existing.role != "admin":
                    existing.role = "admin"
                    await session.commit()
                    logger.info("👑 Admin role promoted for admin@sentinelx.ai")
                else:
                    logger.info("👑 Admin user already exists — skipping seed")
                return

            await repo.create(
                email="admin@sentinelx.ai",
                username="admin",
                hashed_password=hash_password("SentinelX@2025!"),
                full_name="SentinelX Admin",
                role="admin",
            )
            await session.commit()
            logger.info("👑 Default admin user seeded: admin@sentinelx.ai / SentinelX@2025!")
        except Exception as exc:  # noqa: BLE001
            logger.warning("Admin seed skipped: %s", exc)



# =============================================================================
# Phase 3 — Knowledge Layer Initialisation
# =============================================================================

async def _init_knowledge_layer() -> None:
    """
    Initialise Phase 3 Knowledge Intelligence Layer at startup:
    1. Ensure the Qdrant knowledge collection exists (idempotent)
    2. Build the in-memory BM25 index from all currently indexed chunks

    Both steps are best-effort: a failure logs a warning but does NOT abort
    startup — the API remains available and retries can be triggered via
    POST /api/v1/knowledge/index/rebuild.
    """
    try:
        from vector_db.collections import ensure_knowledge_collection
        await ensure_knowledge_collection()
        logger.info("✅ Qdrant knowledge collection verified")
    except Exception as exc:
        logger.warning("⚠️  Knowledge collection setup failed: %s", exc)

    try:
        from rag.retrieval.bm25_index import get_bm25_index
        bm25 = get_bm25_index()
        count = await bm25.build()
        logger.info("✅ BM25 index built with %d chunks", count)
    except Exception as exc:
        logger.warning("⚠️  BM25 index build failed: %s", exc)


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

    # Phase 2 — Security Log Processing & NLP Engine
    from backend.routes.logs import (
        logs_router,
        ioc_router,
        incident_router,
        stats_router,
    )

    # Phase 3 — Knowledge Intelligence Layer
    from backend.routes.knowledge import router as knowledge_router

    # Root + health (no version prefix)
    app.include_router(health_router, tags=["System"])

    # Versioned API routes — Phase 1
    v1_prefix = settings.API_V1_PREFIX
    app.include_router(auth_router,      prefix=f"{v1_prefix}/auth",      tags=["Authentication"])
    app.include_router(dashboard_router, prefix=f"{v1_prefix}/dashboard", tags=["Dashboard"])

    # Versioned API routes — Phase 2
    app.include_router(logs_router,     prefix=f"{v1_prefix}/logs",       tags=["Security Logs"])
    app.include_router(ioc_router,      prefix=f"{v1_prefix}/iocs",       tags=["IOC Intelligence"])
    app.include_router(incident_router, prefix=f"{v1_prefix}/incidents",  tags=["Incidents"])
    app.include_router(stats_router,    prefix=f"{v1_prefix}/statistics", tags=["Statistics"])

    # Versioned API routes — Phase 3
    app.include_router(knowledge_router, prefix=f"{v1_prefix}/knowledge", tags=["Knowledge Intelligence"])


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
