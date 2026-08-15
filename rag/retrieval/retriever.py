"""
SentinelX AI — Reciprocal Rank Fusion (RRF) + Hybrid Retriever
================================================================
Combines dense (semantic) and sparse (BM25) search results into a single
ranked list using Reciprocal Rank Fusion.

Why RRF?
  RRF is parameter-free (the k=60 constant is well-studied) and consistently
  outperforms weighted score averaging in retrieval benchmarks. It treats each
  result list independently, so the scale difference between cosine similarity
  scores and BM25 scores is irrelevant.

  Formula: RRF_score(d) = Σ 1 / (k + rank(d, list_i))
  where k=60 (standard), rank is 1-based position in each result list.

Architecture:
  HybridRetriever.search(query) →
    1. embed_query()        → dense query vector
    2. dense_search()       → top KNOWLEDGE_DENSE_TOP_K results from Qdrant
    3. bm25_index.search()  → top KNOWLEDGE_SPARSE_TOP_K results from BM25
    4. rrf_fuse()           → merged + re-ranked list
    5. score_threshold      → filter low-confidence results
    6. Return top KNOWLEDGE_TOP_K results

  All parameters are read from settings so they can be tuned without
  a code change.
"""
from __future__ import annotations

import logging
from typing import Any

from backend.config import settings

logger = logging.getLogger(__name__)

# RRF constant — standard value from the original paper (Cormack et al., 2009)
_RRF_K = 60


# =============================================================================
# RRF Fusion (pure function — no I/O)
# =============================================================================

def rrf_fuse(
    dense_results: list[dict[str, Any]],
    sparse_results: list[dict[str, Any]],
    dense_weight: float | None = None,
    sparse_weight: float | None = None,
    k: int = _RRF_K,
) -> list[dict[str, Any]]:
    """
    Combine dense and sparse results using Reciprocal Rank Fusion.

    Args:
        dense_results:  Ranked list of dense search results (dicts with 'node_id').
        sparse_results: Ranked list of sparse (BM25) results (dicts with 'node_id').
        dense_weight:   Multiplier for dense RRF scores. Default: settings.KNOWLEDGE_DENSE_WEIGHT
        sparse_weight:  Multiplier for sparse RRF scores. Default: settings.KNOWLEDGE_SPARSE_WEIGHT
        k:              RRF smoothing constant. Default: 60 (standard).

    Returns:
        Merged list of result dicts sorted by descending RRF score.
        Each result contains an 'rrf_score' field.
        Results from dense take priority for payload fields when there is a tie.
    """
    dw = dense_weight if dense_weight is not None else settings.KNOWLEDGE_DENSE_WEIGHT
    sw = sparse_weight if sparse_weight is not None else settings.KNOWLEDGE_SPARSE_WEIGHT

    # ── Build RRF score map: node_id → cumulative RRF score ──────────────────
    rrf_scores: dict[str, float] = {}
    # Merge payloads — dense takes precedence
    payloads: dict[str, dict[str, Any]] = {}

    # Dense pass (1-based ranks)
    for rank, result in enumerate(dense_results, start=1):
        nid = result["node_id"]
        rrf_scores[nid] = rrf_scores.get(nid, 0.0) + dw / (k + rank)
        if nid not in payloads:
            payloads[nid] = result

    # Sparse pass
    for rank, result in enumerate(sparse_results, start=1):
        nid = result["node_id"]
        rrf_scores[nid] = rrf_scores.get(nid, 0.0) + sw / (k + rank)
        if nid not in payloads:
            payloads[nid] = result

    if not rrf_scores:
        return []

    # ── Sort by descending RRF score ──────────────────────────────────────────
    sorted_ids = sorted(rrf_scores, key=lambda x: rrf_scores[x], reverse=True)

    merged: list[dict[str, Any]] = []
    for nid in sorted_ids:
        entry = dict(payloads[nid])
        entry["rrf_score"] = round(rrf_scores[nid], 8)
        # Preserve original dense score if present (useful for debugging)
        merged.append(entry)

    return merged


# =============================================================================
# Hybrid Retriever
# =============================================================================

class HybridRetriever:
    """
    Combines BGE dense search and BM25 sparse search via RRF.

    Designed to be instantiated once at startup and reused per request.
    All heavy components (embedder, BM25 index) are fetched from their
    module-level singletons.

    Usage:
        retriever = HybridRetriever()
        results = await retriever.search(
            query=\"What is a SQL injection attack?\",
            filters={\"source_type\": \"owasp\"},
        )
    """

    def __init__(self) -> None:
        self._embedder = None
        self._bm25 = None

    async def search(
        self,
        query: str,
        top_k: int | None = None,
        filters: dict[str, str] | None = None,
        score_threshold: float | None = None,
    ) -> list[dict[str, Any]]:
        """
        Hybrid search: dense + BM25 → RRF fusion → top_k results.

        Args:
            query:           Search query string.
            top_k:           Max results to return. Default: settings.KNOWLEDGE_TOP_K
            filters:         Optional payload filters (e.g. {"source_type": "mitre"}).
                             Applied to dense search only (BM25 is not filterable).
            score_threshold: Minimum RRF score. Default: settings.KNOWLEDGE_SCORE_THRESHOLD

        Returns:
            List of result dicts with 'rrf_score', 'text', provenance fields.
            Sorted by descending rrf_score. Empty list if nothing found.
        """
        if not query or not query.strip():
            return []

        k = top_k or settings.KNOWLEDGE_TOP_K
        threshold = score_threshold if score_threshold is not None else settings.KNOWLEDGE_SCORE_THRESHOLD

        # ── 1. Embed query ────────────────────────────────────────────────────
        embedder = self._get_embedder()
        try:
            query_vector = embedder.embed_query(query)
        except Exception as exc:
            logger.error("Query embedding failed: %s", exc)
            return []

        # ── 2. Dense search ───────────────────────────────────────────────────
        from vector_db.search import dense_search
        try:
            dense_results = await dense_search(
                query_vector=query_vector,
                top_k=settings.KNOWLEDGE_DENSE_TOP_K,
                filters=filters,
                score_threshold=0.0,   # No threshold here — apply after fusion
            )
        except Exception as exc:
            logger.error("Dense search failed: %s", exc)
            dense_results = []

        # ── 3. BM25 sparse search ─────────────────────────────────────────────
        bm25_index = self._get_bm25()
        try:
            sparse_raw = bm25_index.search(query, top_k=settings.KNOWLEDGE_SPARSE_TOP_K)
            sparse_results = [r.to_dict() for r in sparse_raw]
        except Exception as exc:
            logger.error("BM25 search failed: %s", exc)
            sparse_results = []

        # ── 4. RRF Fusion ─────────────────────────────────────────────────────
        fused = rrf_fuse(dense_results, sparse_results)

        # ── 5. Score threshold ────────────────────────────────────────────────
        filtered = [r for r in fused if r.get("rrf_score", 0) >= threshold]

        # ── 6. Top K ──────────────────────────────────────────────────────────
        final = filtered[:k]

        logger.debug(
            "HybridRetriever: dense=%d, sparse=%d, fused=%d, threshold=%g, returned=%d",
            len(dense_results), len(sparse_results), len(fused), threshold, len(final),
        )

        return final

    # ── Private helpers ───────────────────────────────────────────────────────

    def _get_embedder(self):
        if self._embedder is None:
            from rag.embeddings.bge_embedder import get_embedder
            self._embedder = get_embedder()
        return self._embedder

    def _get_bm25(self):
        if self._bm25 is None:
            from rag.retrieval.bm25_index import get_bm25_index
            self._bm25 = get_bm25_index()
        return self._bm25


# =============================================================================
# Module-level singleton
# =============================================================================

_retriever_instance: HybridRetriever | None = None


def get_retriever() -> HybridRetriever:
    """Return the shared HybridRetriever singleton."""
    global _retriever_instance
    if _retriever_instance is None:
        _retriever_instance = HybridRetriever()
    return _retriever_instance
