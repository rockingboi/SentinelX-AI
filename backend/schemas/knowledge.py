"""
SentinelX AI — Knowledge API Schemas (Phase 3)
================================================
Pydantic v2 request and response models for the Knowledge Intelligence Layer.
"""
from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


# =============================================================================
# Search
# =============================================================================

class KnowledgeSearchRequest(BaseModel):
    """Request body for POST /api/v1/knowledge/search"""

    query: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description="Free-text search query",
        examples=["What is a SQL injection attack?"],
    )
    top_k: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum number of results to return (1–50)",
    )
    source_type: str | None = Field(
        default=None,
        description=(
            "Optional filter by knowledge source. "
            "One of: mitre, nvd, sigma, owasp, cisa, playbook, custom"
        ),
        examples=["mitre"],
    )
    technique_id: str | None = Field(
        default=None,
        description="Optional MITRE ATT&CK technique filter (e.g. T1059.001)",
        examples=["T1059"],
    )
    cve_id: str | None = Field(
        default=None,
        description="Optional CVE identifier filter (e.g. CVE-2021-44228)",
        examples=["CVE-2021-44228"],
    )
    score_threshold: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Minimum RRF score threshold (overrides settings default if set)",
    )

    @field_validator("query")
    @classmethod
    def query_must_not_be_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("query must not be blank")
        return v.strip()

    def to_filters(self) -> dict[str, str]:
        """Build the payload filter dict for the Qdrant dense search."""
        filters: dict[str, str] = {}
        if self.source_type:
            filters["source_type"] = self.source_type
        if self.technique_id:
            filters["technique_id"] = self.technique_id
        if self.cve_id:
            filters["cve_id"] = self.cve_id
        return filters


class KnowledgeSearchResult(BaseModel):
    """A single knowledge chunk returned by the search API."""

    node_id: str = Field(description="UUID of the knowledge chunk")
    rrf_score: float = Field(description="Reciprocal Rank Fusion score (higher is better)")
    text: str = Field(description="Chunk text content")
    source_type: str = Field(description="Knowledge source category (mitre, nvd, owasp, …)")
    source_path: str = Field(description="File path of the source document")
    source_url: str = Field(description="URL of the source document (if available)")
    technique_id: str = Field(description="MITRE ATT&CK technique ID (e.g. T1059.001)")
    cve_id: str = Field(description="CVE identifier (e.g. CVE-2021-44228)")
    severity: str = Field(description="Severity label (critical/high/medium/low/info)")
    chunk_index: int = Field(description="Zero-based index of this chunk in the source document")
    total_chunks: int = Field(description="Total number of chunks from the source document")
    doc_hash: str = Field(description="SHA-256 hash of the source document")

    model_config = {"from_attributes": True}


class KnowledgeSearchResponse(BaseModel):
    """Response body for POST /api/v1/knowledge/search"""

    query: str = Field(description="The original search query")
    total_results: int = Field(description="Number of results returned")
    results: list[KnowledgeSearchResult] = Field(description="Ranked search results")
    duration_ms: float = Field(description="Total search duration in milliseconds")
    bm25_available: bool = Field(
        description="Whether BM25 sparse index was available for this search"
    )


# =============================================================================
# Ingestion
# =============================================================================

class KnowledgeIngestFileRequest(BaseModel):
    """Request body for POST /api/v1/knowledge/ingest/file"""

    file_path: str = Field(
        ...,
        min_length=1,
        description="Absolute path to the knowledge document to ingest",
        examples=["/data/knowledge/raw/mitre/T1059.001.md"],
    )

    @field_validator("file_path")
    @classmethod
    def path_must_not_be_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("file_path must not be blank")
        return v.strip()


class KnowledgeIngestDirectoryRequest(BaseModel):
    """Request body for POST /api/v1/knowledge/ingest/directory"""

    dir_path: str | None = Field(
        default=None,
        description=(
            "Absolute path to the directory to ingest. "
            "Defaults to the configured KNOWLEDGE_RAW_DIR if not provided."
        ),
    )
    recursive: bool = Field(
        default=True,
        description="If true, scans all subdirectories. Default: true",
    )


class FileIngestionResult(BaseModel):
    """Result for a single file within a batch ingestion."""

    path: str
    status: str = Field(
        description="indexed | skipped_duplicate | skipped_unsupported | failed"
    )
    doc_hash: str = ""
    chunks_indexed: int = 0
    reason: str = ""
    duration_ms: float = 0.0


class KnowledgeIngestResponse(BaseModel):
    """Response body for both ingest endpoints."""

    total_files: int
    indexed_files: int
    skipped_duplicates: int
    skipped_unsupported: int
    failed_files: int
    total_chunks_indexed: int
    duration_seconds: float
    success_rate_pct: float
    warnings: list[str] = Field(default_factory=list)
    file_results: list[FileIngestionResult] = Field(default_factory=list)


# =============================================================================
# BM25 Index Rebuild
# =============================================================================

class BM25RebuildResponse(BaseModel):
    """Response for POST /api/v1/knowledge/index/rebuild"""

    chunks_indexed: int = Field(description="Number of chunks in the rebuilt BM25 index")
    duration_ms: float = Field(description="Rebuild duration in milliseconds")
    status: str = Field(description="'ok' on success, 'error' on failure")
    message: str = ""


# =============================================================================
# Stats
# =============================================================================

class KnowledgeStatsResponse(BaseModel):
    """Response for GET /api/v1/knowledge/stats"""

    collection: str = Field(description="Qdrant collection name")
    collection_status: str = Field(description="Qdrant collection status (green/yellow/red)")
    points_count: int = Field(description="Total number of chunks indexed in Qdrant")
    vectors_count: int = Field(description="Total number of vectors in Qdrant")
    vector_dim: int = Field(description="Embedding dimension (should be 1024 for BGE-large)")
    distance: str = Field(description="Vector distance metric (cosine)")
    bm25_corpus_size: int = Field(description="Number of chunks in the in-memory BM25 index")
    bm25_is_built: bool = Field(description="Whether the BM25 index has been built")
    embedding_model: str = Field(description="Embedding model identifier")
    embedding_model_loaded: bool = Field(description="Whether the BGE model is loaded in memory")
