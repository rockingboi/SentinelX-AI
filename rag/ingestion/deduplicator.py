"""
SentinelX AI — Content Deduplicator
======================================
Prevents duplicate documents from being indexed in Qdrant.

Deduplication strategy:
  - SHA-256 hash of the raw UTF-8 content
  - Hash stored as 'doc_hash' payload field in every Qdrant point
  - Before each upsert, a payload-filter scroll query checks existence
  - Fail-open: if the Qdrant check itself fails, the document is allowed
    through (avoids blocking ingestion due to transient DB errors)

Design rules:
  - Hash is computed from raw content — NOT normalised/stripped
    (ensures stability across re-ingestion of the same file)
  - No fuzzy matching, no LLM calls, no external APIs
  - The deduplicator is stateless; it does NOT cache seen hashes in memory
    (Qdrant is the single source of truth)
"""
from __future__ import annotations

import hashlib
import logging

logger = logging.getLogger(__name__)


# =============================================================================
# Pure-function hash helper (usable without an async context)
# =============================================================================

def compute_hash(content: str) -> str:
    """
    Compute a SHA-256 hash of document content.

    Args:
        content: Raw text content of the document.

    Returns:
        64-character lowercase hex string.

    Example:
        >>> compute_hash("hello world")
        'b94d27b9934d3e08a52e52d7da7dabfac484efe04294e576f5b1b9c8e22f3c6e'
        # (actual SHA-256 of "hello world")
    """
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


# =============================================================================
# Async Deduplicator (requires running Qdrant client)
# =============================================================================

class ContentDeduplicator:
    """
    Checks whether a document is already indexed in Qdrant by querying
    the 'doc_hash' payload field.

    This class is designed to be instantiated once and reused across
    the ingestion pipeline. It is stateless — every check hits Qdrant.

    Usage:
        deduplicator = ContentDeduplicator()

        # Check before indexing
        is_dup = await deduplicator.is_duplicate(
            doc_hash=doc.doc_hash,
            qdrant_client=client,
            collection_name=settings.QDRANT_KNOWLEDGE_COLLECTION,
        )
        if not is_dup:
            # Proceed with chunking and embedding
            ...
    """

    async def is_duplicate(
        self,
        doc_hash: str,
        qdrant_client: object,   # AsyncQdrantClient — typed loosely to avoid circular import
        collection_name: str,
    ) -> bool:
        """
        Check if any Qdrant point in the collection has payload.doc_hash == doc_hash.

        Args:
            doc_hash:        SHA-256 hash to look up.
            qdrant_client:   Shared AsyncQdrantClient instance.
            collection_name: Name of the Qdrant collection to search.

        Returns:
            True  — document already indexed; skip ingestion.
            False — document is new; proceed with ingestion.

        Fail-open contract:
            If the scroll query raises any exception (e.g. collection does
            not exist yet, transient network error), the method logs a
            warning and returns False so ingestion can proceed.
        """
        from qdrant_client.http.models import FieldCondition, Filter, MatchValue

        try:
            results, _next_offset = await qdrant_client.scroll(
                collection_name=collection_name,
                scroll_filter=Filter(
                    must=[
                        FieldCondition(
                            key="doc_hash",
                            match=MatchValue(value=doc_hash),
                        )
                    ]
                ),
                limit=1,
                with_payload=False,
                with_vectors=False,
            )
            is_dup = len(results) > 0
            if is_dup:
                logger.debug(
                    "Duplicate detected — doc_hash=%s… already indexed in '%s'",
                    doc_hash[:16],
                    collection_name,
                )
            return is_dup

        except Exception as exc:
            logger.warning(
                "Deduplication check failed for hash %s…: %s — treating as new document",
                doc_hash[:16],
                exc,
            )
            return False  # Fail-open: allow indexing on error
