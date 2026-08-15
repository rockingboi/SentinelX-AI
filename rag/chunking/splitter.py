"""
SentinelX AI — Knowledge Chunking Engine
==========================================
Splits KnowledgeDocuments into fixed-size, overlapping text chunks
using LlamaIndex SentenceSplitter.

Design decisions:
  - LlamaIndex SentenceSplitter respects sentence boundaries; it never
    cuts in the middle of a sentence (unlike naive character splitters).
  - Chunk size and overlap are read from settings so they can be tuned
    without a code change.
  - The output type is ChunkedNode — our own dataclass — so the rest of
    the pipeline has NO dependency on LlamaIndex internals. Swapping
    out the splitter implementation later requires only changing this file.
  - Every ChunkedNode carries the FULL provenance of its parent document
    (doc_hash, source_type, source_path, source_url, technique_id, …).
    Anonymous chunks are prohibited by design.
  - chunk_index (0-based) and total_chunks are embedded in every node
    so retrieval results can be presented in reading order if needed.

Requires: llama-index-core>=0.10.0
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Any

from backend.config import settings
from rag.ingestion.base import KnowledgeDocument

logger = logging.getLogger(__name__)


# =============================================================================
# Output data model
# =============================================================================

@dataclass
class ChunkedNode:
    """
    A single text chunk derived from a KnowledgeDocument.

    This is the atomic unit that gets embedded and upserted into Qdrant.
    Every field needed for provenance, filtering, and re-ranking is present.
    """

    # ── Core content ──────────────────────────────────────────────────────────
    text: str
    """The chunk text that will be embedded."""

    node_id: str
    """Unique ID for this specific chunk (UUID4). Used as the Qdrant point ID."""

    # ── Chunk position ────────────────────────────────────────────────────────
    chunk_index: int
    """0-based position of this chunk within its parent document."""

    total_chunks: int
    """Total number of chunks produced from the parent document."""

    # ── Parent document provenance (ALL fields from KnowledgeDocument) ────────
    doc_hash: str
    """SHA-256 of the parent document's full content. Deduplication key."""

    source_path: str
    """Absolute path to the source file on disk."""

    source_type: str
    """SourceType value: mitre | nvd | sigma | owasp | cisa | playbook | custom."""

    source_url: str
    """Original URL of the source document (empty string if not available)."""

    technique_id: str
    """MITRE ATT&CK technique ID, e.g. 'T1059.001' (empty string if none)."""

    cve_id: str
    """CVE identifier, e.g. 'CVE-2021-44228' (empty string if none)."""

    severity: str
    """Severity level: critical | high | medium | low | info (empty string if none)."""

    # ── Extra metadata ────────────────────────────────────────────────────────
    metadata: dict[str, Any] = field(default_factory=dict)
    """Additional loader-provided metadata (filename, page_count, etc.)."""

    # ── Computed ──────────────────────────────────────────────────────────────
    @property
    def word_count(self) -> int:
        return len(self.text.split())

    @property
    def char_count(self) -> int:
        return len(self.text)

    def to_payload(self) -> dict[str, Any]:
        """
        Return a Qdrant-compatible payload dict.

        All values must be JSON-serialisable primitives (str, int, float, bool).
        This is exactly what gets stored alongside the vector in Qdrant.
        """
        return {
            # Deduplication & retrieval keys
            "doc_hash": self.doc_hash,
            "node_id": self.node_id,
            # Provenance
            "source_path": self.source_path,
            "source_type": self.source_type,
            "source_url": self.source_url,
            # Enrichment
            "technique_id": self.technique_id,
            "cve_id": self.cve_id,
            "severity": self.severity,
            # Chunk position
            "chunk_index": self.chunk_index,
            "total_chunks": self.total_chunks,
            # Content (stored for retrieval without re-fetching from disk)
            "text": self.text,
            # Pass-through loader metadata (scalar values only)
            **{k: v for k, v in self.metadata.items()
               if isinstance(v, (str, int, float, bool))},
        }

    def __repr__(self) -> str:
        return (
            f"ChunkedNode("
            f"chunk={self.chunk_index}/{self.total_chunks - 1}, "
            f"chars={self.char_count}, "
            f"source_type={self.source_type!r}, "
            f"doc_hash={self.doc_hash[:12]}…)"
        )


# =============================================================================
# Splitter
# =============================================================================

class KnowledgeSplitter:
    """
    Splits KnowledgeDocuments into ChunkedNodes using LlamaIndex SentenceSplitter.

    SentenceSplitter respects sentence boundaries — it will never cut a
    sentence in the middle. It falls back to token-level splitting only when
    a single sentence exceeds chunk_size tokens.

    The splitter is stateless and thread-safe. Instantiate once at startup
    and reuse across the ingestion pipeline.

    Args:
        chunk_size:    Token budget per chunk. Default: settings.KNOWLEDGE_CHUNK_SIZE
        chunk_overlap: Token overlap between adjacent chunks.
                       Default: settings.KNOWLEDGE_CHUNK_OVERLAP

    Usage:
        splitter = KnowledgeSplitter()
        nodes: list[ChunkedNode] = splitter.split(doc)
    """

    def __init__(
        self,
        chunk_size: int | None = None,
        chunk_overlap: int | None = None,
    ) -> None:
        self._chunk_size = chunk_size or settings.KNOWLEDGE_CHUNK_SIZE
        self._chunk_overlap = chunk_overlap or settings.KNOWLEDGE_CHUNK_OVERLAP
        self._splitter = self._build_splitter()

    def _build_splitter(self):
        """
        Construct and return a LlamaIndex SentenceSplitter.

        Raises:
            ImportError: If llama-index-core is not installed.
        """
        try:
            from llama_index.core.node_parser import SentenceSplitter
        except ImportError as exc:
            raise ImportError(
                "llama-index-core is required for the chunking engine. "
                "Add 'llama-index-core>=0.10.0' to requirements.txt and rebuild."
            ) from exc

        return SentenceSplitter(
            chunk_size=self._chunk_size,
            chunk_overlap=self._chunk_overlap,
            # Paragraph separator — double newline is the natural boundary
            # for most plaintext knowledge documents
            paragraph_separator="\n\n",
        )

    def split(self, doc: KnowledgeDocument) -> list[ChunkedNode]:
        """
        Split a single KnowledgeDocument into ChunkedNodes.

        Args:
            doc: The document to split.

        Returns:
            List of ChunkedNodes. Will contain at least one node for any
            non-empty document. Returns empty list if content is blank.

        Raises:
            ImportError: If llama-index-core is not installed.
        """
        from llama_index.core import Document as LlamaDocument

        if not doc.content or not doc.content.strip():
            logger.warning("Skipping empty document during chunking: %s", doc.source_path)
            return []

        # ── Convert KnowledgeDocument → LlamaIndex Document ──────────────────
        # Metadata is passed through so LlamaIndex can reference it internally,
        # but we re-populate from doc fields directly when building ChunkedNode.
        llama_doc = LlamaDocument(
            text=doc.content,
            doc_id=doc.doc_hash,
            metadata=doc.to_metadata_dict(),
        )

        # ── Split into TextNodes ──────────────────────────────────────────────
        try:
            text_nodes = self._splitter.get_nodes_from_documents([llama_doc])
        except Exception as exc:
            logger.error(
                "Chunking failed for %s: %s — returning single full-text node",
                doc.source_path,
                exc,
            )
            # Fallback: return the whole document as a single chunk
            text_nodes = []

        if not text_nodes:
            # Fallback: if splitter produces nothing (e.g. very short doc),
            # return the full content as a single chunk
            logger.debug(
                "SentenceSplitter produced 0 nodes for %s — using full content as single chunk",
                doc.source_path,
            )
            return [self._make_node(doc.content, doc, chunk_index=0, total_chunks=1)]

        total = len(text_nodes)
        logger.debug(
            "Chunked %s → %d nodes (chunk_size=%d, overlap=%d)",
            doc.source_path,
            total,
            self._chunk_size,
            self._chunk_overlap,
        )

        return [
            self._make_node(
                text=node.get_content(),
                doc=doc,
                chunk_index=i,
                total_chunks=total,
            )
            for i, node in enumerate(text_nodes)
        ]

    def split_many(self, docs: list[KnowledgeDocument]) -> list[ChunkedNode]:
        """
        Split multiple KnowledgeDocuments into ChunkedNodes.

        Args:
            docs: List of documents to split.

        Returns:
            Flat list of all ChunkedNodes from all documents, in document order.
        """
        all_nodes: list[ChunkedNode] = []
        for doc in docs:
            nodes = self.split(doc)
            all_nodes.extend(nodes)
        return all_nodes

    # ── Private helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _make_node(
        text: str,
        doc: KnowledgeDocument,
        chunk_index: int,
        total_chunks: int,
    ) -> ChunkedNode:
        """
        Construct a ChunkedNode from a text string + parent document.
        Propagates ALL provenance fields from the parent.
        """
        return ChunkedNode(
            text=text.strip(),
            node_id=str(uuid.uuid4()),
            chunk_index=chunk_index,
            total_chunks=total_chunks,
            doc_hash=doc.doc_hash,
            source_path=doc.source_path,
            source_type=doc.source_type,
            source_url=doc.source_url or "",
            technique_id=doc.technique_id or "",
            cve_id=doc.cve_id or "",
            severity=doc.severity or "",
            metadata=dict(doc.metadata),
        )
