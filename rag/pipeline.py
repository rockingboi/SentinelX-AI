"""
SentinelX AI — Knowledge Ingestion Orchestrator
==================================================
Wires together all Phase 3 ingestion components:

  LoaderRegistry → DocumentValidator → ContentDeduplicator
      → KnowledgeSplitter → BGEEmbedder → Qdrant upsert

Entry points:
  ingest_file(path)          — Ingest a single file
  ingest_directory(dir_path) — Batch-ingest all supported files in a directory tree
  IngestionReport            — Structured result object returned by both functions

Design rules:
  - Each file is processed atomically: if any stage fails the file is
    moved to KNOWLEDGE_FAILED_DIR and counted in failed_files, but
    processing of other files continues.
  - Duplicate documents (same SHA-256) are skipped — not counted as errors.
  - Every successfully indexed file is moved to KNOWLEDGE_PROCESSED_DIR
    so re-runs do not re-process files.
  - All directory movement is best-effort; a move failure is logged but
    does not abort the pipeline.
  - The pipeline is async so embedding and Qdrant I/O can overlap.
  - Batch size for embedding is controlled by BGEEmbedder.batch_size
    (default: 32 chunks per forward pass).
"""
from __future__ import annotations

import asyncio
import logging
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from backend.config import settings
from rag.ingestion.base import KnowledgeDocument
from rag.ingestion.deduplicator import ContentDeduplicator
from rag.ingestion.loaders import LoaderRegistry
from rag.ingestion.validator import DocumentValidator

logger = logging.getLogger(__name__)


# =============================================================================
# Report data model
# =============================================================================

@dataclass
class FileResult:
    """Result for a single file processed by the pipeline."""
    path: str
    status: str          # 'indexed' | 'skipped_duplicate' | 'skipped_unsupported' | 'failed'
    doc_hash: str = ""
    chunks_indexed: int = 0
    reason: str = ""     # Populated on failure or skip
    duration_ms: float = 0.0


@dataclass
class IngestionReport:
    """
    Aggregate result returned after ingesting a file or directory.

    All counts are non-negative integers.
    """
    # File-level counts
    total_files: int = 0
    indexed_files: int = 0
    skipped_duplicates: int = 0
    skipped_unsupported: int = 0
    failed_files: int = 0

    # Chunk-level counts
    total_chunks_indexed: int = 0

    # Timing
    duration_seconds: float = 0.0

    # Per-file details
    file_results: list[FileResult] = field(default_factory=list)

    # Any non-fatal warnings accumulated during processing
    warnings: list[str] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        """Percentage of files successfully indexed (0.0–100.0)."""
        if self.total_files == 0:
            return 0.0
        return round(self.indexed_files / self.total_files * 100, 1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_files": self.total_files,
            "indexed_files": self.indexed_files,
            "skipped_duplicates": self.skipped_duplicates,
            "skipped_unsupported": self.skipped_unsupported,
            "failed_files": self.failed_files,
            "total_chunks_indexed": self.total_chunks_indexed,
            "duration_seconds": round(self.duration_seconds, 3),
            "success_rate_pct": self.success_rate,
            "warnings": self.warnings,
        }

    def __str__(self) -> str:
        return (
            f"IngestionReport("
            f"files={self.total_files}, "
            f"indexed={self.indexed_files}, "
            f"dupes={self.skipped_duplicates}, "
            f"failed={self.failed_files}, "
            f"chunks={self.total_chunks_indexed}, "
            f"duration={self.duration_seconds:.1f}s)"
        )


# =============================================================================
# Ingestion Pipeline
# =============================================================================

class IngestionPipeline:
    """
    Orchestrates the full knowledge ingestion pipeline.

    Instantiate once at startup and reuse. The pipeline is stateless between
    calls — each ingest_file() call is independent.

    Args:
        qdrant_client:   AsyncQdrantClient. Fetched from singleton if None.
        collection_name: Qdrant collection. Defaults to settings value.
    """

    def __init__(
        self,
        qdrant_client: object | None = None,
        collection_name: str | None = None,
    ) -> None:
        self._qdrant_client = qdrant_client
        self._collection_name = collection_name or settings.QDRANT_KNOWLEDGE_COLLECTION

        # Component instances (lazy-loaded)
        self._loader_registry = LoaderRegistry()
        self._validator = DocumentValidator()
        self._deduplicator = ContentDeduplicator()
        self._splitter: object | None = None   # KnowledgeSplitter (loaded lazily)
        self._embedder: object | None = None   # BGEEmbedder (loaded lazily)

    # ── Public API ─────────────────────────────────────────────────────────────

    async def ingest_file(self, file_path: str | Path) -> FileResult:
        """
        Ingest a single file through the full pipeline.

        Stages:
          1. Extension check (LoaderRegistry.supports)
          2. Load → KnowledgeDocument
          3. Validate (DocumentValidator)
          4. Deduplicate (ContentDeduplicator → Qdrant scroll)
          5. Chunk (KnowledgeSplitter)
          6. Embed (BGEEmbedder)
          7. Upsert (upsert_nodes → Qdrant)
          8. Move file to processed/ or failed/

        Args:
            file_path: Path to the source file.

        Returns:
            FileResult with status and details.
        """
        path = Path(file_path).resolve()
        start = time.monotonic()

        logger.info("▶ Ingesting: %s", path.name)

        # ── Stage 1: Extension check ──────────────────────────────────────────
        if not self._loader_registry.supports(path):
            logger.debug("Unsupported file type: %s", path.suffix)
            return FileResult(
                path=str(path),
                status="skipped_unsupported",
                reason=f"File type '{path.suffix}' is not supported by any loader",
                duration_ms=self._elapsed_ms(start),
            )

        # ── Stage 2: Load ─────────────────────────────────────────────────────
        try:
            loader = self._loader_registry.get_loader(path)
            docs: list[KnowledgeDocument] = loader.load(path)
        except Exception as exc:
            logger.error("Load failed for %s: %s", path.name, exc)
            self._move_to_failed(path)
            return FileResult(
                path=str(path),
                status="failed",
                reason=f"Load error: {exc}",
                duration_ms=self._elapsed_ms(start),
            )

        if not docs:
            logger.warning("Loader returned 0 documents for %s", path.name)
            self._move_to_failed(path)
            return FileResult(
                path=str(path),
                status="failed",
                reason="Loader returned 0 documents",
                duration_ms=self._elapsed_ms(start),
            )

        # For now, use the first document (JSONL files may return multiple —
        # they are handled as a batch in ingest_directory)
        doc = docs[0]

        # ── Stage 3: Validate ─────────────────────────────────────────────────
        validation = self._validator.validate(doc)
        if not validation.is_valid:
            logger.warning("Validation failed for %s: %s", path.name, validation.reason)
            self._move_to_failed(path)
            return FileResult(
                path=str(path),
                status="failed",
                reason=f"Validation: {validation.reason}",
                doc_hash=doc.doc_hash,
                duration_ms=self._elapsed_ms(start),
            )

        # ── Stage 4: Deduplicate ──────────────────────────────────────────────
        client = self._get_qdrant_client()
        is_dup = await self._deduplicator.is_duplicate(
            doc_hash=doc.doc_hash,
            qdrant_client=client,
            collection_name=self._collection_name,
        )
        if is_dup:
            logger.info("Duplicate skipped: %s (hash=%s…)", path.name, doc.doc_hash[:12])
            return FileResult(
                path=str(path),
                status="skipped_duplicate",
                doc_hash=doc.doc_hash,
                reason="Document already indexed (same SHA-256)",
                duration_ms=self._elapsed_ms(start),
            )

        # ── Stage 5: Chunk ────────────────────────────────────────────────────
        splitter = self._get_splitter()
        try:
            nodes = splitter.split(doc)
        except Exception as exc:
            logger.error("Chunking failed for %s: %s", path.name, exc)
            self._move_to_failed(path)
            return FileResult(
                path=str(path),
                status="failed",
                reason=f"Chunking error: {exc}",
                doc_hash=doc.doc_hash,
                duration_ms=self._elapsed_ms(start),
            )

        if not nodes:
            logger.warning("Chunking produced 0 nodes for %s", path.name)
            self._move_to_failed(path)
            return FileResult(
                path=str(path),
                status="failed",
                reason="Chunking produced 0 nodes",
                doc_hash=doc.doc_hash,
                duration_ms=self._elapsed_ms(start),
            )

        # ── Stage 6: Embed ────────────────────────────────────────────────────
        embedder = self._get_embedder()
        try:
            texts = [n.text for n in nodes]
            vectors = embedder.embed_texts(texts)
        except Exception as exc:
            logger.error("Embedding failed for %s: %s", path.name, exc)
            self._move_to_failed(path)
            return FileResult(
                path=str(path),
                status="failed",
                reason=f"Embedding error: {exc}",
                doc_hash=doc.doc_hash,
                duration_ms=self._elapsed_ms(start),
            )

        # ── Stage 7: Upsert ───────────────────────────────────────────────────
        from vector_db.search import upsert_nodes
        try:
            await upsert_nodes(nodes, vectors, client)
        except Exception as exc:
            logger.error("Upsert failed for %s: %s", path.name, exc)
            self._move_to_failed(path)
            return FileResult(
                path=str(path),
                status="failed",
                reason=f"Qdrant upsert error: {exc}",
                doc_hash=doc.doc_hash,
                duration_ms=self._elapsed_ms(start),
            )

        # ── Stage 8: Move to processed/ ──────────────────────────────────────
        self._move_to_processed(path)

        elapsed = self._elapsed_ms(start)
        logger.info(
            "✅ Indexed: %s → %d chunks (%.0f ms)",
            path.name, len(nodes), elapsed
        )

        return FileResult(
            path=str(path),
            status="indexed",
            doc_hash=doc.doc_hash,
            chunks_indexed=len(nodes),
            duration_ms=elapsed,
        )

    async def ingest_directory(
        self,
        dir_path: str | Path | None = None,
        recursive: bool = True,
    ) -> IngestionReport:
        """
        Batch-ingest all supported files in a directory (or KNOWLEDGE_RAW_DIR).

        Files are processed sequentially (not concurrently) to avoid OOM from
        loading many models/documents at once. Each file's result is independent.

        Args:
            dir_path:  Directory to scan. Defaults to settings.KNOWLEDGE_RAW_DIR.
            recursive: If True, scans all subdirectories. Default: True.

        Returns:
            IngestionReport with per-file results and aggregate stats.
        """
        base_dir = Path(dir_path) if dir_path else Path(settings.KNOWLEDGE_RAW_DIR)

        if not base_dir.exists():
            logger.warning("Knowledge directory does not exist: %s", base_dir)
            report = IngestionReport()
            report.warnings.append(f"Directory does not exist: {base_dir}")
            return report

        pattern = "**/*" if recursive else "*"
        all_files = [
            f for f in base_dir.glob(pattern)
            if f.is_file() and f.name != ".gitkeep"
        ]

        report = IngestionReport(total_files=len(all_files))
        pipeline_start = time.monotonic()

        logger.info(
            "Starting batch ingestion: %d files in %s",
            len(all_files), base_dir
        )

        for file_path in all_files:
            result = await self.ingest_file(file_path)
            report.file_results.append(result)

            if result.status == "indexed":
                report.indexed_files += 1
                report.total_chunks_indexed += result.chunks_indexed
            elif result.status == "skipped_duplicate":
                report.skipped_duplicates += 1
            elif result.status == "skipped_unsupported":
                report.skipped_unsupported += 1
            elif result.status == "failed":
                report.failed_files += 1

        report.duration_seconds = time.monotonic() - pipeline_start

        logger.info(
            "Batch ingestion complete: %s", report
        )
        return report

    # ── Private helpers ───────────────────────────────────────────────────────

    def _get_qdrant_client(self):
        if self._qdrant_client is None:
            from vector_db.qdrant_client import get_qdrant_client
            self._qdrant_client = get_qdrant_client()
        return self._qdrant_client

    def _get_splitter(self):
        if self._splitter is None:
            from rag.chunking.splitter import KnowledgeSplitter
            self._splitter = KnowledgeSplitter()
        return self._splitter

    def _get_embedder(self):
        if self._embedder is None:
            from rag.embeddings.bge_embedder import get_embedder
            self._embedder = get_embedder()
        return self._embedder

    def _move_to_processed(self, path: Path) -> None:
        """Move a successfully processed file to KNOWLEDGE_PROCESSED_DIR."""
        try:
            dest_dir = Path(settings.KNOWLEDGE_PROCESSED_DIR)
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest = dest_dir / path.name
            # Avoid collision: append hash suffix if name already exists
            if dest.exists():
                dest = dest_dir / f"{path.stem}_{path.stat().st_mtime_ns}{path.suffix}"
            shutil.move(str(path), str(dest))
            logger.debug("Moved to processed/: %s → %s", path.name, dest.name)
        except Exception as exc:
            logger.warning("Could not move %s to processed/: %s", path.name, exc)

    def _move_to_failed(self, path: Path) -> None:
        """Move a failed file to KNOWLEDGE_FAILED_DIR."""
        try:
            dest_dir = Path(settings.KNOWLEDGE_FAILED_DIR)
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest = dest_dir / path.name
            if dest.exists():
                dest = dest_dir / f"{path.stem}_{path.stat().st_mtime_ns}{path.suffix}"
            shutil.move(str(path), str(dest))
            logger.debug("Moved to failed/: %s", path.name)
        except Exception as exc:
            logger.warning("Could not move %s to failed/: %s", path.name, exc)

    @staticmethod
    def _elapsed_ms(start: float) -> float:
        return round((time.monotonic() - start) * 1000, 1)


# =============================================================================
# Module-level convenience functions
# =============================================================================

_pipeline_instance: IngestionPipeline | None = None


def get_pipeline(qdrant_client: object | None = None) -> IngestionPipeline:
    """Return the shared IngestionPipeline singleton."""
    global _pipeline_instance
    if _pipeline_instance is None:
        _pipeline_instance = IngestionPipeline(qdrant_client=qdrant_client)
    return _pipeline_instance


async def ingest_file(file_path: str | Path) -> FileResult:
    """Convenience wrapper: ingest a single file using the shared pipeline."""
    return await get_pipeline().ingest_file(file_path)


async def ingest_directory(
    dir_path: str | Path | None = None,
    recursive: bool = True,
) -> IngestionReport:
    """Convenience wrapper: batch-ingest a directory using the shared pipeline."""
    return await get_pipeline().ingest_directory(dir_path, recursive)
