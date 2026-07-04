"""
SentinelX AI — Neo4j Graph Database Connection Manager
========================================================
Async Neo4j driver with session factory and health check.
Used for attack-path analysis, entity relationships, and GraphRAG.
"""
from __future__ import annotations

import logging

from neo4j import AsyncDriver, AsyncGraphDatabase
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from backend.config import settings

logger = logging.getLogger(__name__)

_driver: AsyncDriver | None = None


# =============================================================================
# Lifecycle
# =============================================================================

@retry(
    stop=stop_after_attempt(10),
    wait=wait_exponential(multiplier=1, min=3, max=15),
    retry=retry_if_exception_type(Exception),
    reraise=True,
)
async def init_neo4j() -> None:
    """
    Create the Neo4j async driver and verify connectivity.
    Called at application startup via lifespan.
    """
    global _driver

    logger.info("Initialising Neo4j connection…")

    _driver = AsyncGraphDatabase.driver(
        settings.NEO4J_URI,
        auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD),
        max_connection_lifetime=3600,
        max_connection_pool_size=50,
        connection_acquisition_timeout=30,
    )

    # Verify connectivity
    await _driver.verify_connectivity()
    logger.info("✅ Neo4j connected — uri=%s", settings.NEO4J_URI)


async def close_neo4j() -> None:
    """Close the Neo4j driver."""
    global _driver
    if _driver is not None:
        await _driver.close()
        logger.info("Neo4j driver closed.")


def get_neo4j_driver() -> AsyncDriver:
    """Return the shared Neo4j async driver."""
    if _driver is None:
        raise RuntimeError("Neo4j driver not initialised. Call init_neo4j() first.")
    return _driver


# =============================================================================
# Health Check
# =============================================================================

async def check_neo4j_health() -> dict:
    """Run a simple Cypher query and return status dict."""
    if _driver is None:
        return {"status": "unavailable", "message": "Driver not initialised"}

    try:
        async with _driver.session(database=settings.NEO4J_DATABASE) as session:
            result = await session.run("CALL dbms.components() YIELD name, versions RETURN name, versions")
            record = await result.single()
            version = record["versions"][0] if record else "unknown"

        return {
            "status": "healthy",
            "message": "Connected",
            "version": version,
        }
    except Exception as exc:
        logger.warning("Neo4j health check failed: %s", exc)
        return {"status": "unhealthy", "message": str(exc)}
