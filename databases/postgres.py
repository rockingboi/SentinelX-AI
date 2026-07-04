"""
SentinelX AI — PostgreSQL Database Layer
==========================================
SQLAlchemy 2.0 async engine + session factory.
Includes health check and Alembic-compatible Base.
"""
from __future__ import annotations

import logging

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from backend.config import settings

logger = logging.getLogger(__name__)

# =============================================================================
# Declarative Base — all models inherit from this
# =============================================================================

class Base(DeclarativeBase):
    """SQLAlchemy declarative base with metadata for all ORM models."""
    pass


# =============================================================================
# Engine & Session Factory (module-level singletons)
# =============================================================================

_engine: AsyncEngine | None = None
AsyncSessionLocal: async_sessionmaker[AsyncSession] | None = None  # type: ignore[assignment]


def _create_engine() -> AsyncEngine:
    return create_async_engine(
        settings.DATABASE_URL,
        echo=settings.DEBUG,          # Log SQL statements in dev
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,           # Verify connections before use
        pool_recycle=3600,            # Recycle connections every hour
        connect_args={
            "server_settings": {
                "application_name": "sentinelx_backend",
            }
        },
    )


# =============================================================================
# Lifecycle
# =============================================================================

@retry(
    stop=stop_after_attempt(10),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type(Exception),
    reraise=True,
)
async def init_db() -> None:
    """
    Initialise the async engine and session factory.
    Verifies connectivity and runs table creation (dev only).
    Called at application startup via lifespan.
    """
    global _engine, AsyncSessionLocal

    logger.info("Initialising PostgreSQL connection…")

    _engine = _create_engine()
    AsyncSessionLocal = async_sessionmaker(
        bind=_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
    )

    # Verify connectivity
    async with _engine.connect() as conn:
        await conn.execute(text("SELECT 1"))

    logger.info("✅ PostgreSQL connected — pool_size=10, max_overflow=20")

    # Auto-create tables in development (use Alembic in production)
    if settings.is_development:
        await _create_tables()


async def _create_tables() -> None:
    """Create all tables defined in models (dev only). Production uses Alembic."""
    # Import models so Base.metadata knows about them
    import backend.models.user  # noqa: F401
    import backend.models.role  # noqa: F401
    import backend.models.audit_log  # noqa: F401

    assert _engine is not None
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("📋 Database tables created (dev mode)")


async def close_db() -> None:
    """Dispose the engine and close all connections."""
    global _engine
    if _engine is not None:
        await _engine.dispose()
        logger.info("PostgreSQL connection pool closed.")


# =============================================================================
# Health Check
# =============================================================================

async def check_postgres_health() -> dict:
    """
    Ping PostgreSQL and return status dict.
    Safe to call at any time — returns error status if unavailable.
    """
    if _engine is None:
        return {"status": "unavailable", "message": "Engine not initialised"}

    try:
        async with _engine.connect() as conn:
            result = await conn.execute(text("SELECT version()"))
            version = result.scalar()
        return {
            "status": "healthy",
            "message": "Connected",
            "version": str(version).split(" ")[1] if version else "unknown",
        }
    except Exception as exc:
        logger.warning("PostgreSQL health check failed: %s", exc)
        return {"status": "unhealthy", "message": str(exc)}
