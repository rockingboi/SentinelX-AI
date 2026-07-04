"""
SentinelX AI — Qdrant Vector Database Connection Manager
==========================================================
Async Qdrant client with collection management and health check.
Used for semantic search, RAG retrieval, and threat intelligence embeddings.
"""
from __future__ import annotations

import logging

from qdrant_client import AsyncQdrantClient
from qdrant_client.http.exceptions import UnexpectedResponse
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from backend.config import settings

logger = logging.getLogger(__name__)

_client: AsyncQdrantClient | None = None


# =============================================================================
# Lifecycle
# =============================================================================

@retry(
    stop=stop_after_attempt(10),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type(Exception),
    reraise=True,
)
async def init_qdrant() -> None:
    """
    Create the Qdrant async client and verify connectivity.
    Called at application startup via lifespan.
    """
    global _client

    logger.info("Initialising Qdrant connection…")

    _client = AsyncQdrantClient(
        url=settings.QDRANT_URL,
        api_key=settings.QDRANT_API_KEY if settings.QDRANT_API_KEY else None,
        timeout=30,
        prefer_grpc=False,
    )

    # Verify connectivity
    await _client.get_collections()
    logger.info("✅ Qdrant connected — url=%s", settings.QDRANT_URL)


async def close_qdrant() -> None:
    """Close the Qdrant async client."""
    global _client
    if _client is not None:
        await _client.close()
        logger.info("Qdrant client closed.")


def get_qdrant_client() -> AsyncQdrantClient:
    """Return the shared Qdrant async client."""
    if _client is None:
        raise RuntimeError("Qdrant client not initialised. Call init_qdrant() first.")
    return _client


# =============================================================================
# Health Check
# =============================================================================

async def check_qdrant_health() -> dict:
    """List collections and return status dict."""
    if _client is None:
        return {"status": "unavailable", "message": "Client not initialised"}

    try:
        collections_response = await _client.get_collections()
        collection_names = [c.name for c in collections_response.collections]

        return {
            "status": "healthy",
            "message": "Connected",
            "collections": collection_names,
            "collection_count": len(collection_names),
        }
    except UnexpectedResponse as exc:
        logger.warning("Qdrant health check failed: %s", exc)
        return {"status": "unhealthy", "message": str(exc)}
    except Exception as exc:
        logger.warning("Qdrant health check failed: %s", exc)
        return {"status": "unhealthy", "message": str(exc)}
