"""
SentinelX AI — Qdrant Collection Manager
==========================================
Creates and verifies the knowledge collection in Qdrant at startup.

Design rules:
  - IDEMPOTENT: safe to call on every startup; does nothing if the collection
    already exists (preserves existing data — never auto-drops/recreates).
  - FAIL-CLEAR: if the collection cannot be created, the error propagates
    and startup is aborted. The application must not run without a valid
    vector store.
  - Collection name is read from settings.QDRANT_KNOWLEDGE_COLLECTION (env var:
    QDRANT_KNOWLEDGE_COLLECTION). It is NEVER hardcoded elsewhere.
  - Payload fields used for filtering are indexed at collection creation time:
      • doc_hash     — deduplication checks (keyword index)
      • source_type  — filter by knowledge source (keyword index)
      • technique_id — MITRE technique filtering (keyword index)
      • cve_id       — CVE filtering (keyword index)
      • severity     — severity filtering (keyword index)
  - Vector distance: Cosine (compatible with L2-normalised BGE embeddings)
  - HNSW index is used (Qdrant default); quantisation is disabled for accuracy.
"""
from __future__ import annotations

import logging

from qdrant_client import AsyncQdrantClient
from qdrant_client.http.exceptions import UnexpectedResponse
from qdrant_client.http.models import (
    Distance,
    HnswConfigDiff,
    PayloadSchemaType,
    VectorParams,
)

from backend.config import settings

logger = logging.getLogger(__name__)


# =============================================================================
# Collection lifecycle
# =============================================================================

async def ensure_knowledge_collection(client: AsyncQdrantClient | None = None) -> None:
    """
    Ensure the knowledge collection exists in Qdrant.

    Creates the collection with the correct vector configuration and payload
    indexes if it does not already exist. If it already exists, verifies that
    it is accessible and logs its current point count.

    This function is IDEMPOTENT — it will never delete or recreate an
    existing collection. Existing data is always preserved.

    Args:
        client: AsyncQdrantClient to use. If None, uses the shared singleton
                from vector_db.qdrant_client.

    Raises:
        RuntimeError: If the collection cannot be created or accessed.
    """
    if client is None:
        from vector_db.qdrant_client import get_qdrant_client
        client = get_qdrant_client()

    collection_name = settings.QDRANT_KNOWLEDGE_COLLECTION
    vector_dim = settings.EMBEDDING_DIM

    # ── Check if collection already exists ───────────────────────────────────
    try:
        existing = await client.get_collections()
        existing_names = {c.name for c in existing.collections}
    except Exception as exc:
        raise RuntimeError(f"Cannot query Qdrant collections: {exc}") from exc

    if collection_name in existing_names:
        # Collection exists — verify accessibility and log point count
        try:
            info = await client.get_collection(collection_name)
            point_count = info.points_count or 0
            logger.info(
                "✅ Qdrant collection '%s' already exists — %d points indexed",
                collection_name,
                point_count,
            )
        except Exception as exc:
            raise RuntimeError(
                f"Qdrant collection '{collection_name}' exists but is not accessible: {exc}"
            ) from exc
        return

    # ── Create the collection ─────────────────────────────────────────────────
    logger.info(
        "Creating Qdrant collection '%s' (dim=%d, distance=Cosine)…",
        collection_name,
        vector_dim,
    )

    try:
        await client.create_collection(
            collection_name=collection_name,
            vectors_config=VectorParams(
                size=vector_dim,
                distance=Distance.COSINE,
                # HNSW index parameters — defaults are good for most workloads
                hnsw_config=HnswConfigDiff(
                    m=16,                # Number of edges per node (higher = better recall, more RAM)
                    ef_construct=100,    # Construction beam width (higher = better recall, slower index)
                    full_scan_threshold=10_000,  # Below this point count, use exact search
                ),
            ),
        )
        logger.info("✅ Qdrant collection '%s' created", collection_name)
    except UnexpectedResponse as exc:
        if "already exists" in str(exc).lower():
            logger.info("Qdrant collection '%s' already exists (race condition — OK)", collection_name)
            return
        raise RuntimeError(
            f"Failed to create Qdrant collection '{collection_name}': {exc}"
        ) from exc
    except Exception as exc:
        raise RuntimeError(
            f"Unexpected error creating Qdrant collection '{collection_name}': {exc}"
        ) from exc

    # ── Create payload indexes ────────────────────────────────────────────────
    await _create_payload_indexes(client, collection_name)


async def _create_payload_indexes(
    client: AsyncQdrantClient,
    collection_name: str,
) -> None:
    """
    Create keyword payload indexes on filterable fields.

    Qdrant requires explicit index creation for payload fields used in filters.
    Without indexes, filter queries perform full collection scans.

    Fields indexed:
        doc_hash     — deduplication (exact match)
        source_type  — filter by mitre/nvd/sigma/owasp/cisa/playbook/custom
        technique_id — MITRE ATT&CK technique filter
        cve_id       — CVE identifier filter
        severity     — critical/high/medium/low/info filter
    """
    INDEXED_FIELDS: list[str] = [
        "doc_hash",
        "source_type",
        "technique_id",
        "cve_id",
        "severity",
    ]

    for field_name in INDEXED_FIELDS:
        try:
            await client.create_payload_index(
                collection_name=collection_name,
                field_name=field_name,
                field_schema=PayloadSchemaType.KEYWORD,
            )
            logger.debug("  Created payload index: %s", field_name)
        except Exception as exc:
            # Indexes are nice-to-have; don't abort startup if one fails
            logger.warning(
                "Could not create payload index '%s' on '%s': %s",
                field_name,
                collection_name,
                exc,
            )

    logger.info(
        "✅ Payload indexes created on '%s': %s",
        collection_name,
        ", ".join(INDEXED_FIELDS),
    )


# =============================================================================
# Collection info helpers
# =============================================================================

async def get_collection_info(
    client: AsyncQdrantClient | None = None,
) -> dict:
    """
    Return a summary dict with collection stats for the health/stats API.

    Returns a dict with 'status' key even on error so the caller can
    include it in the health response without raising.
    """
    if client is None:
        from vector_db.qdrant_client import get_qdrant_client
        client = get_qdrant_client()

    collection_name = settings.QDRANT_KNOWLEDGE_COLLECTION

    try:
        info = await client.get_collection(collection_name)
        return {
            "collection": collection_name,
            "status": info.status.value if info.status else "unknown",
            "points_count": info.points_count or 0,
            "vectors_count": info.vectors_count or 0,
            "indexed_vectors_count": info.indexed_vectors_count or 0,
            "vector_dim": settings.EMBEDDING_DIM,
            "distance": "cosine",
        }
    except Exception as exc:
        logger.warning("Could not fetch collection info for '%s': %s", collection_name, exc)
        return {
            "collection": collection_name,
            "status": "unavailable",
            "error": str(exc),
        }
