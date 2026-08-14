"""
SentinelX AI — Knowledge Ingestion Base Classes
=================================================
Defines the foundational data structures and abstract interfaces
for the Knowledge Intelligence Layer (Phase 3).

All document loaders, validators, and processors MUST implement
these interfaces to participate in the ingestion pipeline.

Design principles:
  - Every document carries full source provenance (never anonymous)
  - doc_hash (SHA-256) is the single deduplication key
  - Metadata is propagated from document → every derived chunk
  - No external LLM calls anywhere in this module
"""
from __future__ import annotations

import hashlib
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# =============================================================================
# Source Type Vocabulary
# =============================================================================

class SourceType(str, Enum):
    """
    Controlled vocabulary for knowledge document source types.
    Maps to the directory structure under data/knowledge/raw/.
    """
    MITRE = "mitre"       # MITRE ATT&CK techniques / groups / software
    NVD = "nvd"           # NVD/CVE vulnerability descriptions
    SIGMA = "sigma"       # Sigma detection rules
    OWASP = "owasp"       # OWASP guidelines and cheat sheets
    CISA = "cisa"         # CISA advisories and KEV entries
    PLAYBOOK = "playbook" # Incident response and investigation playbooks
    CUSTOM = "custom"     # User-supplied documents not matching above


# =============================================================================
# Core Data Model
# =============================================================================

@dataclass
class KnowledgeDocument:
    """
    Represents a single knowledge artifact BEFORE chunking.

    doc_hash is computed automatically from content via SHA-256.
    It is the primary deduplication key stored in Qdrant payload.

    Provenance fields (source_type, source_path, source_url) are
    MANDATORY and propagated to every TextNode chunk derived from
    this document. Anonymous vectors are prohibited by design.

    Enrichment fields (technique_id, cve_id, severity) are optional
    and populated by loaders from file content or naming conventions.
    """

    # ── Required ────────────────────────────────────────────────────────────
    content: str
    """Full extracted text content of the document."""

    source_path: str
    """Absolute path to the source file on disk."""

    source_type: str
    """SourceType enum value or custom string. Stored in Qdrant payload."""

    # ── Optional provenance ──────────────────────────────────────────────────
    metadata: dict[str, Any] = field(default_factory=dict)
    """Arbitrary key-value metadata from the loader (filename, page_count, etc.)."""

    source_url: str | None = None
    """Original URL of the document (e.g. NVD entry URL, MITRE page)."""

    # ── Computed ─────────────────────────────────────────────────────────────
    doc_hash: str = field(default="")
    """SHA-256 of UTF-8 encoded content. Auto-computed in __post_init__."""

    # ── Enrichment (optional) ────────────────────────────────────────────────
    technique_id: str | None = None
    """MITRE ATT&CK technique ID, e.g. 'T1059.001'."""

    cve_id: str | None = None
    """CVE identifier, e.g. 'CVE-2021-44228'."""

    severity: str | None = None
    """Severity level: 'critical' | 'high' | 'medium' | 'low' | 'info'."""

    def __post_init__(self) -> None:
        if not self.doc_hash:
            self.doc_hash = self._compute_hash(self.content)

    # ── Static helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _compute_hash(content: str) -> str:
        """
        SHA-256 of UTF-8 encoded content.
        Deterministic, collision-resistant, and stable across re-ingestion.
        Content is NOT normalised before hashing.
        """
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def word_count(self) -> int:
        """Approximate word count (whitespace split)."""
        return len(self.content.split())

    @property
    def char_count(self) -> int:
        """Character count of the full content."""
        return len(self.content)

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_metadata_dict(self) -> dict[str, Any]:
        """
        Return a flat dict suitable for a Qdrant point payload.
        All values must be JSON-serialisable primitives.
        """
        return {
            "doc_hash": self.doc_hash,
            "source_path": self.source_path,
            "source_type": self.source_type,
            "source_url": self.source_url or "",
            "technique_id": self.technique_id or "",
            "cve_id": self.cve_id or "",
            "severity": self.severity or "",
            **{k: v for k, v in self.metadata.items()
               if isinstance(v, (str, int, float, bool))},
        }

    def __repr__(self) -> str:
        return (
            f"KnowledgeDocument("
            f"source_type={self.source_type!r}, "
            f"source_path={self.source_path!r}, "
            f"chars={self.char_count}, "
            f"hash={self.doc_hash[:12]}…)"
        )


# =============================================================================
# Validation Result
# =============================================================================

@dataclass
class ValidationResult:
    """
    Result of running a DocumentValidator against a KnowledgeDocument.
    Documents where is_valid=False are moved to data/knowledge/failed/.
    """
    is_valid: bool
    reason: str = ""
    warnings: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.is_valid


# =============================================================================
# Abstract Interfaces
# =============================================================================

class BaseDocumentLoader(ABC):
    """
    Abstract base class for all document loaders.

    Each concrete loader handles a specific file format and is
    responsible for extracting raw text while preserving provenance.

    Loaders MUST NOT call any external APIs or LLMs.
    Loaders MUST populate source_path, source_type, and metadata.
    """

    #: File extensions this loader handles (lowercase, with dot, e.g. {".txt"})
    supported_extensions: frozenset[str] = frozenset()

    @abstractmethod
    def load(self, path: Path) -> list[KnowledgeDocument]:
        """
        Load one or more KnowledgeDocuments from the given path.

        Args:
            path: Absolute path to the source file.

        Returns:
            List of KnowledgeDocuments. May be empty if the file
            contains no extractable content.

        Raises:
            FileNotFoundError: If path does not exist.
            ValueError: If the file cannot be parsed.
        """
        ...

    def can_load(self, path: Path) -> bool:
        """Return True if this loader supports the given file extension."""
        return path.suffix.lower() in self.supported_extensions


class BaseDocumentValidator(ABC):
    """
    Abstract base class for document validators.

    Validators run BEFORE chunking and indexing. A document that
    fails validation is excluded from the pipeline and logged.
    """

    @abstractmethod
    def validate(self, doc: KnowledgeDocument) -> ValidationResult:
        """
        Validate a KnowledgeDocument.

        Args:
            doc: The document to validate.

        Returns:
            ValidationResult indicating whether the document is acceptable.
        """
        ...
