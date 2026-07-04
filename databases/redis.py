"""
SentinelX AI — Redis Connection Manager
=========================================
Async Redis client using redis-py with hiredis parser.
Connection pool, health check, and typed helpers.
"""
from __future__ import annotations

import logging

import redis.asyncio as aioredis
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from backend.config import settings

logger = logging.getLogger(__name__)

# Module-level singleton
_redis_client: aioredis.Redis | None = None  # type: ignore[type-arg]


# =============================================================================
# Lifecycle
# =============================================================================

@retry(
    stop=stop_after_attempt(10),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type(Exception),
    reraise=True,
)
async def init_redis() -> None:
    """
    Create the Redis connection pool and verify connectivity.
    Called at application startup via lifespan.
    """
    global _redis_client

    logger.info("Initialising Redis connection…")

    _redis_client = aioredis.from_url(
        settings.REDIS_URL,
        encoding="utf-8",
        decode_responses=True,
        max_connections=20,
        socket_connect_timeout=5,
        socket_timeout=5,
        retry_on_timeout=True,
        health_check_interval=30,
    )

    # Verify connectivity
    await _redis_client.ping()
    logger.info("✅ Redis connected — url=%s", settings.REDIS_URL)


async def close_redis() -> None:
    """Close the Redis connection pool."""
    global _redis_client
    if _redis_client is not None:
        await _redis_client.aclose()
        logger.info("Redis connection pool closed.")


def get_redis_client() -> aioredis.Redis:  # type: ignore[type-arg]
    """Return the shared Redis client. Raises if not initialised."""
    if _redis_client is None:
        raise RuntimeError("Redis client not initialised. Call init_redis() first.")
    return _redis_client


# =============================================================================
# Health Check
# =============================================================================

async def check_redis_health() -> dict:
    """Ping Redis and return a status dict."""
    if _redis_client is None:
        return {"status": "unavailable", "message": "Client not initialised"}

    try:
        await _redis_client.ping()
        info = await _redis_client.info("server")
        return {
            "status": "healthy",
            "message": "Connected",
            "version": info.get("redis_version", "unknown"),
        }
    except Exception as exc:
        logger.warning("Redis health check failed: %s", exc)
        return {"status": "unhealthy", "message": str(exc)}


# =============================================================================
# Typed Helpers
# =============================================================================

async def redis_set(key: str, value: str, expire_seconds: int | None = None) -> None:
    """Set a key/value pair with optional TTL."""
    client = get_redis_client()
    await client.set(key, value, ex=expire_seconds)


async def redis_get(key: str) -> str | None:
    """Get a value by key. Returns None if not found."""
    client = get_redis_client()
    return await client.get(key)


async def redis_delete(key: str) -> None:
    """Delete a key."""
    client = get_redis_client()
    await client.delete(key)
