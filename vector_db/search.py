"""
SentinelX AI — Qdrant Search & Upsert
=======================================
Handles writing ChunkedNodes to Qdrant and reading them back via
dense vector search (semantic) with optional payload filtering.

Operations:
  upsert_nodes()      — Write embedded chunks to Qdrant
  dense_search()      — Cosine similarity search using a query vector
  scroll_by_filter()  — Paginated retrieval by payload filter (no vector)
  delete_by_doc_hash()— Remove all chunks belonging to a document

Conventions:
  - Each Qdrant Point ID is a UUID4 string (from ChunkedNode.node_id).
  - Qdrant requires UUID or unsigned int as point IDs; we use UUID strings.
  - The full chunk text is stored in the payload so retrieval does not
    require a second DB lookup.
  - All vector operations use the collection set in settings.QDRANT_KNOWLEDGE_COLLECTION.
"""
from __future__ import annotations

import logging
from typing import Any

from qdrant_client import AsyncQdrantClient
from qdrant_client.http.models import (
    FieldCondition,
    Filter,
    MatchValue,
    PointStruct,
    SearchRequest,
    ScoredPoint,
)

from backend.config import settings
from rag.chunking.splitter import ChunkedNode

logger = logging.getLogger(__name__)

# How many points to upsert per batch (Qdrant default max is 100 MB per request)
_UPSERT_BATCH_SIZE = 100


# =============================================================================
# Upsert
# =============================================================================

async def upsert_nodes(
    nodes: list[ChunkedNode],
    vectors: list[list[float]],
    client: AsyncQdrantClient | None = None,
) -> int:
    """
    Upsert a batch of ChunkedNodes with their pre-computed embedding vectors.

    Nodes and vectors must be the same length and in the same order.
    If a point with the same node_id already exists in Qdrant, it will
    be overwritten (upsert semantics).

    Args:
        nodes:   ChunkedNodes to index.
        vectors: Corresponding embedding vectors (length must equal len(nodes)).
        client:  AsyncQdrantClient. If None, uses the shared singleton.

    Returns:
        Number of nodes upserted.

    Raises:
        ValueError:   If nodes and vectors have different lengths or are empty.
        RuntimeError: If the Qdrant upsert fails.
    """
    if not nodes:
        raise ValueError("nodes must not be empty")
    if len(nodes) != len(vectors):
        raise ValueError(
            f"nodes and vectors must have the same length "
            f"(got {len(nodes)} nodes and {len(vectors)} vectors)"
        )

    if client is None:
        from vector_db.qdrant_client import get_qdrant_client
        client = get_qdrant_client()

    collection_name = settings.QDRANT_KNOWLEDGE_COLLECTION

    # Build PointStructs
    points = [
        PointStruct(
            id=node.node_id,           # UUID string — Qdrant accepts UUID strings
            vector=vector,
            payload=node.to_payload(), # Full provenance + chunk text
        )
        for node, vector in zip(nodes, vectors)
    ]

    # Upsert in batches
    total_upserted = 0
    for batch_start in range(0, len(points), _UPSERT_BATCH_SIZE):
        batch = points[batch_start : batch_start + _UPSERT_BATCH_SIZE]
        try:
            await client.upsert(
                collection_name=collection_name,
                points=batch,
                wait=True,  # Wait for indexing to complete before returning
            )
            total_upserted += len(batch)
            logger.debug(
                "Upserted batch %d/%d (%d points) to '%s'",
                batch_start // _UPSERT_BATCH_SIZE + 1,
                (len(points) - 1) // _UPSERT_BATCH_SIZE + 1,
                len(batch),
                collection_name,
            )
        except Exception as exc:
            raise RuntimeError(
                f"Qdrant upsert failed for batch starting at index {batch_start}: {exc}"
            ) from exc

    logger.info(
        "✅ Upserted %d nodes to Qdrant collection '%s'",
        total_upserted,
        collection_name,
    )
    return total_upserted


# =============================================================================
# Dense Search
# =============================================================================

async def dense_search(
    query_vector: list[float],
    top_k: int | None = None,
    filters: dict[str, str] | None = None,
    score_threshold: float | None = None,
    client: AsyncQdrantClient | None = None,
) -> list[dict[str, Any]]:
    """
    Perform cosine similarity search against the knowledge collection.

    Args:
        query_vector:    L2-normalised query embedding (length=EMBEDDING_DIM).
        top_k:           Number of results to return. Default: settings.KNOWLEDGE_DENSE_TOP_K
        filters:         Optional dict of payload field → value for pre-filtering.
                         E.g. {"source_type": "mitre", "technique_id": "T1059"}
        score_threshold: Minimum cosine score. Default: settings.KNOWLEDGE_SCORE_THRESHOLD
        client:          AsyncQdrantClient. If None, uses the shared singleton.

    Returns:
        List of result dicts, each containing:
            - score:       Cosine similarity score (0.0–1.0)
            - node_id:     UUID of the matching chunk
            - text:        Chunk text
            - source_type, source_path, technique_id, cve_id, severity,
              chunk_index, total_chunks, doc_hash  (all provenance fields)

    Raises:
        RuntimeError: If the search fails.
    """
    if client is None:
        from vector_db.qdrant_client import get_qdrant_client
        client = get_qdrant_client()

    collection_name = settings.QDRANT_KNOWLEDGE_COLLECTION
    k = top_k or settings.KNOWLEDGE_DENSE_TOP_K
    threshold = score_threshold if score_threshold is not None else settings.KNOWLEDGE_SCORE_THRESHOLD

    # Build optional payload filter
    qdrant_filter: Filter | None = None
    if filters:
        must_conditions = [
            FieldCondition(key=field, match=MatchValue(value=value))
            for field, value in filters.items()
            if value  # Skip empty filter values
        ]
        if must_conditions:
            qdrant_filter = Filter(must=must_conditions)

    try:
        results: list[ScoredPoint] = await client.search(
            collection_name=collection_name,
            query_vector=query_vector,
            limit=k,
            query_filter=qdrant_filter,
            score_threshold=threshold,
            with_payload=True,
            with_vectors=False,
        )
    except Exception as exc:
        raise RuntimeError(
            f"Qdrant dense search failed: {exc}"
        ) from exc

    return [_scored_point_to_dict(r) for r in results]


# =============================================================================
# Scroll (filter-only, no vector)
# =============================================================================

async def scroll_by_filter(
    filters: dict[str, str],
    limit: int = 100,
    offset: str | None = None,
    client: AsyncQdrantClient | None = None,
) -> tuple[list[dict[str, Any]], str | None]:
    """
    Paginated retrieval of points matching a payload filter (no vector needed).

    Useful for: listing all chunks from a document, auditing indexed data,
    or checking if a doc_hash is already indexed.

    Args:
        filters: Dict of payload field → value. All conditions are ANDed.
        limit:   Max points per page.
        offset:  Pagination cursor from a previous call (or None for first page).
        client:  AsyncQdrantClient. If None, uses the shared singleton.

    Returns:
        Tuple of (list of point dicts, next_offset or None if last page).
    """
    if client is None:
        from vector_db.qdrant_client import get_qdrant_client
        client = get_qdrant_client()

    collection_name = settings.QDRANT_KNOWLEDGE_COLLECTION

    must_conditions = [
        FieldCondition(key=field, match=MatchValue(value=value))
        for field, value in filters.items()
        if value
    ]
    qdrant_filter = Filter(must=must_conditions) if must_conditions else None

    try:
        points, next_offset = await client.scroll(
            collection_name=collection_name,
            scroll_filter=qdrant_filter,
            limit=limit,
            offset=offset,
            with_payload=True,
            with_vectors=False,
        )
    except Exception as exc:
        raise RuntimeError(f"Qdrant scroll failed: {exc}") from exc

    results = [
        {
            "node_id": str(p.id),
            **(_payload_to_dict(p.payload)),
        }
        for p in points
    ]
    return results, (str(next_offset) if next_offset else None)


# =============================================================================
# Delete
# =============================================================================

async def delete_by_doc_hash(
    doc_hash: str,
    client: AsyncQdrantClient | None = None,
) -> int:
    """
    Delete all Qdrant points whose payload.doc_hash equals doc_hash.

    Used when re-ingesting a document after content update.

    Args:
        doc_hash: SHA-256 hash of the document to remove.
        client:   AsyncQdrantClient. If None, uses the shared singleton.

    Returns:
        Number of points deleted (0 if the document was not indexed).
    """
    if client is None:
        from vector_db.qdrant_client import get_qdrant_client
        client = get_qdrant_client()

    collection_name = settings.QDRANT_KNOWLEDGE_COLLECTION

    # First, count how many points we are about to delete
    points, _ = await client.scroll(
        collection_name=collection_name,
        scroll_filter=Filter(
            must=[FieldCondition(key="doc_hash", match=MatchValue(value=doc_hash))]
        ),
        limit=10_000,  # Practical cap: very large documents
        with_payload=False,
        with_vectors=False,
    )
    if not points:
        logger.debug("delete_by_doc_hash: no points found for hash %s…", doc_hash[:16])
        return 0

    point_ids = [p.id for p in points]

    try:
        await client.delete(
            collection_name=collection_name,
            points_selector=point_ids,
            wait=True,
        )
        logger.info(
            "Deleted %d points for doc_hash=%s… from '%s'",
            len(point_ids),
            doc_hash[:16],
            collection_name,
        )
        return len(point_ids)
    except Exception as exc:
        raise RuntimeError(
            f"Qdrant delete failed for doc_hash={doc_hash[:16]}…: {exc}"
        ) from exc


# =============================================================================
# Private helpers
# =============================================================================

def _scored_point_to_dict(point: ScoredPoint) -> dict[str, Any]:
    """Convert a Qdrant ScoredPoint to a clean result dict."""
    return {
        "score": round(float(point.score), 6),
        "node_id": str(point.id),
        **_payload_to_dict(point.payload),
    }


def _payload_to_dict(payload: dict | None) -> dict[str, Any]:
    """Return payload as a plain dict, defaulting missing keys."""
    if not payload:
        return {}
    return {
        "text": payload.get("text", ""),
        "doc_hash": payload.get("doc_hash", ""),
        "source_path": payload.get("source_path", ""),
        "source_type": payload.get("source_type", ""),
        "source_url": payload.get("source_url", ""),
        "technique_id": payload.get("technique_id", ""),
        "cve_id": payload.get("cve_id", ""),
        "severity": payload.get("severity", ""),
        "chunk_index": payload.get("chunk_index", 0),
        "total_chunks": payload.get("total_chunks", 1),
    }
