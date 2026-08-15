"""
SentinelX AI — BM25 Sparse Retrieval Index
============================================
In-memory BM25 index over the chunk corpus for keyword-based sparse retrieval.

Why BM25 alongside dense vectors?
  Dense (semantic) search excels at paraphrase and concept matching.
  BM25 excels at exact keyword matching (e.g. "CVE-2021-44228", "T1059.001",
  "mimikatz", exact tool names, rare terms). Combining both with Reciprocal
  Rank Fusion (Milestone 3.8) gives better recall than either alone.

Architecture:
  - The BM25 index is built from all ChunkedNodes currently in Qdrant.
  - At startup (or on-demand rebuild), the pipeline fetches all indexed
    chunk texts via scroll and builds the BM25Okapi index.
  - The index lives in memory — it is NOT persisted to disk.
  - For the search API, both dense and sparse results are fetched and fused.

Design constraints:
  - rank-bm25==0.2.2 (already in requirements.txt)
  - Tokenisation: simple whitespace + lowercase (no NLTK dependency)
  - The index is rebuilt on every application startup to stay consistent
    with Qdrant. Re-build time is O(N) where N = total chunks indexed.
  - Thread-safe reads; index rebuild holds a lock.
"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

# How many points to fetch per scroll page when building the index
_SCROLL_PAGE_SIZE = 500


# =============================================================================
# Data model
# =============================================================================

@dataclass
class BM25Result:
    """A single BM25 search result."""
    node_id: str
    score: float
    text: str
    source_type: str
    source_path: str
    technique_id: str
    cve_id: str
    severity: str
    chunk_index: int
    total_chunks: int
    doc_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "score": self.score,
            "text": self.text,
            "source_type": self.source_type,
            "source_path": self.source_path,
            "technique_id": self.technique_id,
            "cve_id": self.cve_id,
            "severity": self.severity,
            "chunk_index": self.chunk_index,
            "total_chunks": self.total_chunks,
            "doc_hash": self.doc_hash,
        }


# =============================================================================
# BM25 Index
# =============================================================================

class BM25Index:
    """
    In-memory BM25 index built from all chunks currently in Qdrant.

    Usage:
        index = BM25Index()
        await index.build(qdrant_client)      # populate from Qdrant
        results = index.search(query, top_k=30)
    """

    def __init__(self) -> None:
        self._bm25 = None               # rank_bm25.BM25Okapi instance
        self._corpus: list[dict] = []   # Raw payload dicts (same order as BM25 corpus)
        self._lock = threading.RLock()
        self._built = False

    # ── Build ─────────────────────────────────────────────────────────────────

    async def build(self, qdrant_client: object | None = None) -> int:
        """
        (Re)build the BM25 index from all chunks in Qdrant.

        Fetches all points from the knowledge collection via paginated scroll,
        extracts chunk texts, tokenises them, and builds BM25Okapi.

        Args:
            qdrant_client: AsyncQdrantClient. Uses singleton if None.

        Returns:
            Number of chunks indexed in BM25.

        Raises:
            RuntimeError: If rank-bm25 is not installed or BM25 build fails.
        """
        try:
            from rank_bm25 import BM25Okapi
        except ImportError as exc:
            raise RuntimeError(
                "rank-bm25 is required for sparse retrieval. "
                "Add 'rank-bm25>=0.2.2' to requirements.txt and rebuild."
            ) from exc

        if qdrant_client is None:
            from vector_db.qdrant_client import get_qdrant_client
            qdrant_client = get_qdrant_client()

        from backend.config import settings
        collection_name = settings.QDRANT_KNOWLEDGE_COLLECTION

        # ── Fetch all chunks from Qdrant via paginated scroll ─────────────────
        logger.info("Building BM25 index from Qdrant collection '%s'…", collection_name)
        all_payloads: list[dict] = []
        offset = None

        while True:
            try:
                points, next_offset = await qdrant_client.scroll(
                    collection_name=collection_name,
                    limit=_SCROLL_PAGE_SIZE,
                    offset=offset,
                    with_payload=True,
                    with_vectors=False,
                )
            except Exception as exc:
                raise RuntimeError(
                    f"Failed to scroll Qdrant for BM25 index build: {exc}"
                ) from exc

            for p in points:
                payload = p.payload or {}
                if payload.get("text"):
                    all_payloads.append({
                        "node_id": str(p.id),
                        "text": payload.get("text", ""),
                        "source_type": payload.get("source_type", ""),
                        "source_path": payload.get("source_path", ""),
                        "technique_id": payload.get("technique_id", ""),
                        "cve_id": payload.get("cve_id", ""),
                        "severity": payload.get("severity", ""),
                        "chunk_index": payload.get("chunk_index", 0),
                        "total_chunks": payload.get("total_chunks", 1),
                        "doc_hash": payload.get("doc_hash", ""),
                    })

            if not next_offset:
                break
            offset = next_offset

        if not all_payloads:
            logger.warning("BM25 index: 0 chunks fetched — index will be empty")
            with self._lock:
                self._bm25 = None
                self._corpus = []
                self._built = True
            return 0

        # ── Tokenise and build BM25 ───────────────────────────────────────────
        tokenised_corpus = [_tokenise(p["text"]) for p in all_payloads]

        with self._lock:
            self._corpus = all_payloads
            self._bm25 = BM25Okapi(tokenised_corpus)
            self._built = True

        logger.info(
            "✅ BM25 index built: %d chunks from '%s'",
            len(all_payloads), collection_name
        )
        return len(all_payloads)

    # ── Search ────────────────────────────────────────────────────────────────

    def search(self, query: str, top_k: int | None = None) -> list[BM25Result]:
        """
        Search the BM25 index for the given query.

        Args:
            query: Free-text search query.
            top_k: Maximum results to return. Default: settings.KNOWLEDGE_SPARSE_TOP_K

        Returns:
            List of BM25Result sorted by descending BM25 score.
            Returns empty list if the index is empty or not yet built.
        """
        from backend.config import settings
        k = top_k or settings.KNOWLEDGE_SPARSE_TOP_K

        if not query or not query.strip():
            return []

        with self._lock:
            if not self._built or self._bm25 is None or not self._corpus:
                return []

            tokens = _tokenise(query)
            scores = self._bm25.get_scores(tokens)

        # Pair each score with its corpus entry and sort descending
        scored = sorted(
            zip(scores, self._corpus),
            key=lambda x: x[0],
            reverse=True,
        )

        results = []
        for score, payload in scored[:k]:
            if score <= 0:
                continue  # Skip zero-score results (no overlap with query)
            results.append(BM25Result(
                node_id=payload["node_id"],
                score=float(score),
                text=payload["text"],
                source_type=payload["source_type"],
                source_path=payload["source_path"],
                technique_id=payload["technique_id"],
                cve_id=payload["cve_id"],
                severity=payload["severity"],
                chunk_index=payload["chunk_index"],
                total_chunks=payload["total_chunks"],
                doc_hash=payload["doc_hash"],
            ))

        return results

    # ── Status ────────────────────────────────────────────────────────────────

    @property
    def is_built(self) -> bool:
        return self._built

    @property
    def corpus_size(self) -> int:
        with self._lock:
            return len(self._corpus)


# =============================================================================
# Module-level singleton
# =============================================================================

_index_instance: BM25Index | None = None
_index_lock = threading.Lock()


def get_bm25_index() -> BM25Index:
    """Return the shared BM25Index singleton (not yet built — call build() first)."""
    global _index_instance
    if _index_instance is None:
        with _index_lock:
            if _index_instance is None:
                _index_instance = BM25Index()
    return _index_instance


def reset_bm25_index() -> None:
    """Reset the singleton. For tests only."""
    global _index_instance
    with _index_lock:
        _index_instance = None


# =============================================================================
# Tokeniser
# =============================================================================

def _tokenise(text: str) -> list[str]:
    """
    Simple whitespace tokeniser with lowercase normalisation.

    Designed to be fast and dependency-free. BM25 performance is not very
    sensitive to tokenisation quality — the main gains come from term weighting.

    Args:
        text: Raw text to tokenise.

    Returns:
        List of lowercase tokens. Empty list for empty input.
    """
    if not text:
        return []
    return text.lower().split()
