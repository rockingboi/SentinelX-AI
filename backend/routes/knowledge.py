"""
SentinelX AI — Knowledge Intelligence API Routes (Phase 3)
============================================================
Exposes the RAG Knowledge Intelligence Layer over HTTP.

Endpoints:
  POST   /api/v1/knowledge/search              — Hybrid semantic + BM25 search
  GET    /api/v1/knowledge/stats               — Qdrant + BM25 index statistics
  POST   /api/v1/knowledge/ingest/file         — Ingest a single document [admin]
  POST   /api/v1/knowledge/ingest/directory    — Batch-ingest a directory  [admin]
  POST   /api/v1/knowledge/index/rebuild       — Rebuild BM25 index        [admin]

Authentication:
  All endpoints require a valid JWT Bearer token.
  Ingestion and rebuild endpoints additionally require the 'admin' role.

Design:
  - Routes are thin orchestrators — all logic lives in the service/retrieval layers.
  - Errors from the retrieval layer are caught and returned as structured 503/400.
  - Duration tracking is done in the route layer for accurate end-to-end latency.
"""
from __future__ import annotations

import logging
import time

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse

from backend.dependencies import AdminOnly, CurrentUser
from backend.schemas.knowledge import (
    BM25RebuildResponse,
    FileIngestionResult,
    KnowledgeIngestDirectoryRequest,
    KnowledgeIngestFileRequest,
    KnowledgeIngestResponse,
    KnowledgeSearchRequest,
    KnowledgeSearchResponse,
    KnowledgeSearchResult,
    KnowledgeStatsResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter()


# =============================================================================
# Search
# =============================================================================

@router.post(
    "/search",
    response_model=KnowledgeSearchResponse,
    summary="Hybrid Knowledge Search",
    response_description="Ranked list of knowledge chunks relevant to the query",
)
async def search_knowledge(
    request: KnowledgeSearchRequest,
    _current_user: CurrentUser,
) -> KnowledgeSearchResponse:
    """
    Search the knowledge base using hybrid dense + BM25 retrieval with RRF fusion.

    Combines:
    - **Dense (semantic) search**: BGE-large-en-v1.5 embeddings + Qdrant cosine similarity
    - **Sparse (keyword) search**: BM25 Okapi over in-memory corpus
    - **Fusion**: Reciprocal Rank Fusion (RRF, k=60) to merge ranked lists

    Optional payload filters (source_type, technique_id, cve_id) are applied
    to the dense search leg only.

    Returns results sorted by descending RRF score. An empty results list means
    no chunks met the score threshold — not an error.
    """
    t0 = time.monotonic()

    try:
        from rag.retrieval.retriever import get_retriever
        from rag.retrieval.bm25_index import get_bm25_index

        retriever = get_retriever()
        bm25 = get_bm25_index()

        raw_results = await retriever.search(
            query=request.query,
            top_k=request.top_k,
            filters=request.to_filters() or None,
            score_threshold=request.score_threshold,
        )
    except RuntimeError as exc:
        logger.error("Knowledge search failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Knowledge search unavailable: {exc}",
        )
    except Exception as exc:
        logger.exception("Unexpected error during knowledge search")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Search error: {exc}",
        )

    duration_ms = round((time.monotonic() - t0) * 1000, 1)

    results = [
        KnowledgeSearchResult(
            node_id=r.get("node_id", ""),
            rrf_score=r.get("rrf_score", r.get("score", 0.0)),
            text=r.get("text", ""),
            source_type=r.get("source_type", ""),
            source_path=r.get("source_path", ""),
            source_url=r.get("source_url", ""),
            technique_id=r.get("technique_id", ""),
            cve_id=r.get("cve_id", ""),
            severity=r.get("severity", ""),
            chunk_index=r.get("chunk_index", 0),
            total_chunks=r.get("total_chunks", 1),
            doc_hash=r.get("doc_hash", ""),
        )
        for r in raw_results
    ]

    return KnowledgeSearchResponse(
        query=request.query,
        total_results=len(results),
        results=results,
        duration_ms=duration_ms,
        bm25_available=bm25.is_built,
    )


# =============================================================================
# Stats
# =============================================================================

@router.get(
    "/stats",
    response_model=KnowledgeStatsResponse,
    summary="Knowledge Base Statistics",
    response_description="Qdrant collection and BM25 index statistics",
)
async def get_knowledge_stats(_current_user: CurrentUser) -> KnowledgeStatsResponse:
    """
    Returns statistics about the knowledge vector store and in-memory BM25 index.

    Useful for monitoring how many documents are indexed and whether the
    embedding model and search indices are ready.
    """
    from vector_db.collections import get_collection_info
    from rag.retrieval.bm25_index import get_bm25_index
    from rag.embeddings.bge_embedder import _embedder_instance
    from backend.config import settings

    # Qdrant collection stats
    try:
        col_info = await get_collection_info()
    except Exception as exc:
        logger.warning("Could not fetch collection info: %s", exc)
        col_info = {"collection": settings.QDRANT_KNOWLEDGE_COLLECTION,
                    "status": "unavailable", "points_count": 0,
                    "vectors_count": 0, "vector_dim": settings.EMBEDDING_DIM,
                    "distance": "cosine"}

    bm25 = get_bm25_index()

    return KnowledgeStatsResponse(
        collection=col_info.get("collection", settings.QDRANT_KNOWLEDGE_COLLECTION),
        collection_status=col_info.get("status", "unknown"),
        points_count=col_info.get("points_count", 0),
        vectors_count=col_info.get("vectors_count", 0),
        vector_dim=col_info.get("vector_dim", settings.EMBEDDING_DIM),
        distance=col_info.get("distance", "cosine"),
        bm25_corpus_size=bm25.corpus_size,
        bm25_is_built=bm25.is_built,
        embedding_model=settings.EMBEDDING_MODEL,
        embedding_model_loaded=(_embedder_instance is not None and _embedder_instance.is_loaded),
    )


# =============================================================================
# Ingestion — single file
# =============================================================================

@router.post(
    "/ingest/file",
    response_model=KnowledgeIngestResponse,
    summary="Ingest a Single Knowledge Document",
    response_description="Ingestion result for the specified file",
    dependencies=[AdminOnly],
)
async def ingest_single_file(
    request: KnowledgeIngestFileRequest,
    _current_user: CurrentUser,
) -> KnowledgeIngestResponse:
    """
    Ingest a single document into the knowledge base.

    **Admin only.** The file must exist at the specified path inside the container.

    Pipeline stages: Load → Validate → Deduplicate → Chunk → Embed → Upsert → Move

    - On success: file is moved to the processed/ directory.
    - On failure: file is moved to the failed/ directory and `status=failed` is returned.
    - Duplicate: file stays in place and `status=skipped_duplicate` is returned.
    """
    from pathlib import Path
    from rag.pipeline import get_pipeline

    file_path = Path(request.file_path)
    if not file_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"File not found: {request.file_path}",
        )

    try:
        pipeline = get_pipeline()
        result = await pipeline.ingest_file(file_path)
    except Exception as exc:
        logger.exception("Ingestion pipeline error for file %s", request.file_path)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ingestion error: {exc}",
        )

    # Map FileResult → response
    file_result = FileIngestionResult(
        path=result.path,
        status=result.status,
        doc_hash=result.doc_hash,
        chunks_indexed=result.chunks_indexed,
        reason=result.reason,
        duration_ms=result.duration_ms,
    )

    return KnowledgeIngestResponse(
        total_files=1,
        indexed_files=1 if result.status == "indexed" else 0,
        skipped_duplicates=1 if result.status == "skipped_duplicate" else 0,
        skipped_unsupported=1 if result.status == "skipped_unsupported" else 0,
        failed_files=1 if result.status == "failed" else 0,
        total_chunks_indexed=result.chunks_indexed,
        duration_seconds=round(result.duration_ms / 1000, 3),
        success_rate_pct=100.0 if result.status == "indexed" else 0.0,
        warnings=[],
        file_results=[file_result],
    )


# =============================================================================
# Ingestion — directory batch
# =============================================================================

@router.post(
    "/ingest/directory",
    response_model=KnowledgeIngestResponse,
    summary="Batch Ingest Knowledge Directory",
    response_description="Aggregated ingestion results for all files in the directory",
    dependencies=[AdminOnly],
)
async def ingest_directory(
    request: KnowledgeIngestDirectoryRequest,
    _current_user: CurrentUser,
) -> KnowledgeIngestResponse:
    """
    Batch-ingest all supported documents in a directory.

    **Admin only.** Defaults to the configured `KNOWLEDGE_RAW_DIR` if `dir_path` is not set.

    Processes files sequentially. Each file is handled atomically:
    - Success → moves file to processed/
    - Failure → moves file to failed/, continues with remaining files

    Returns aggregate statistics and per-file results.
    """
    from rag.pipeline import get_pipeline

    try:
        pipeline = get_pipeline()
        report = await pipeline.ingest_directory(
            dir_path=request.dir_path,
            recursive=request.recursive,
        )
    except Exception as exc:
        logger.exception("Directory ingestion error")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Directory ingestion error: {exc}",
        )

    return KnowledgeIngestResponse(
        total_files=report.total_files,
        indexed_files=report.indexed_files,
        skipped_duplicates=report.skipped_duplicates,
        skipped_unsupported=report.skipped_unsupported,
        failed_files=report.failed_files,
        total_chunks_indexed=report.total_chunks_indexed,
        duration_seconds=round(report.duration_seconds, 3),
        success_rate_pct=report.success_rate,
        warnings=report.warnings,
        file_results=[
            FileIngestionResult(
                path=fr.path,
                status=fr.status,
                doc_hash=fr.doc_hash,
                chunks_indexed=fr.chunks_indexed,
                reason=fr.reason,
                duration_ms=fr.duration_ms,
            )
            for fr in report.file_results
        ],
    )


# =============================================================================
# BM25 Index Rebuild
# =============================================================================

@router.post(
    "/index/rebuild",
    response_model=BM25RebuildResponse,
    summary="Rebuild BM25 Sparse Index",
    response_description="Result of the BM25 index rebuild operation",
    dependencies=[AdminOnly],
)
async def rebuild_bm25_index(_current_user: CurrentUser) -> BM25RebuildResponse:
    """
    Rebuild the in-memory BM25 sparse index from all currently indexed Qdrant chunks.

    **Admin only.** Call this after a large batch ingestion to update the BM25 index.
    The index is rebuilt automatically at startup, but is NOT updated incrementally
    after each document ingest (for performance reasons).

    Typical rebuild time: < 1 second for up to 100,000 chunks.
    """
    t0 = time.monotonic()

    try:
        from rag.retrieval.bm25_index import get_bm25_index
        bm25 = get_bm25_index()
        count = await bm25.build()
        duration_ms = round((time.monotonic() - t0) * 1000, 1)
        return BM25RebuildResponse(
            chunks_indexed=count,
            duration_ms=duration_ms,
            status="ok",
            message=f"BM25 index rebuilt with {count} chunks in {duration_ms:.0f}ms",
        )
    except Exception as exc:
        duration_ms = round((time.monotonic() - t0) * 1000, 1)
        logger.error("BM25 rebuild failed: %s", exc)
        return BM25RebuildResponse(
            chunks_indexed=0,
            duration_ms=duration_ms,
            status="error",
            message=str(exc),
        )
