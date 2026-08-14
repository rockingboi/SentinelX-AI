"""
SentinelX AI — Document Loaders
=================================
Concrete loader implementations for:
  - Plain text / Markdown / log files   (.txt, .md, .markdown, .log, .rst)
  - JSON / JSON Lines                   (.json, .jsonl)
  - PDF (requires pymupdf)              (.pdf)

All loaders populate full source provenance metadata and attempt to
auto-detect MITRE technique IDs and CVE identifiers from filenames
or the first 500 characters of content.

Directory convention (auto source_type detection):
  data/knowledge/raw/mitre/   → source_type = "mitre"
  data/knowledge/raw/nvd/     → source_type = "nvd"
  data/knowledge/raw/sigma/   → source_type = "sigma"
  data/knowledge/raw/owasp/   → source_type = "owasp"
  data/knowledge/raw/cisa/    → source_type = "cisa"
  data/knowledge/raw/playbooks/ → source_type = "playbook"
  anything else               → source_type = "custom"
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from rag.ingestion.base import BaseDocumentLoader, KnowledgeDocument, SourceType

logger = logging.getLogger(__name__)

# ── Compile patterns once ─────────────────────────────────────────────────────
# Note: \b breaks on '.' so sub-techniques (T1059.001) need a lookahead.
# Pattern explanation:
#   T\d{4}       — base technique  e.g. T1059
#   (?:\.\d{3})? — optional subtechnique e.g. .001
#   (?![.\d])    — negative lookahead: don't match if followed by more digits/dots
_TECHNIQUE_RE = re.compile(r"(?<![\w])(T\d{4}(?:\.\d{3})?)(?![.\d])")
_CVE_RE = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.IGNORECASE)
_SEVERITY_KEYWORDS = {"critical", "high", "medium", "low", "info", "informational"}

# Severity aliases from NVD/CVSS
_SEVERITY_ALIASES: dict[str, str] = {
    "informational": "info",
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "info",
}


# =============================================================================
# Helpers (module-private)
# =============================================================================

# Map plural directory names → singular SourceType values
_PLURAL_ALIASES: dict[str, str] = {
    "playbooks": SourceType.PLAYBOOK.value,
    "advisories": SourceType.CISA.value,
    "vulnerabilities": SourceType.NVD.value,
    "techniques": SourceType.MITRE.value,
    "rules": SourceType.SIGMA.value,
}


def _infer_source_type(path: Path) -> str:
    """
    Infer source_type by checking directory names against SourceType values.
    Handles both singular (mitre) and plural (playbooks) directory naming conventions.
    Returns 'custom' if no match found.
    """
    parts_lower = [p.lower() for p in path.parts]
    for part in parts_lower:
        # Direct match against SourceType values
        for st in SourceType:
            if part == st.value:
                return st.value
        # Plural alias match
        if part in _PLURAL_ALIASES:
            return _PLURAL_ALIASES[part]
    return SourceType.CUSTOM.value


def _infer_technique_id(path: Path, content_prefix: str) -> str | None:
    """Extract first MITRE technique ID from filename stem or content prefix."""
    m = _TECHNIQUE_RE.search(path.stem) or _TECHNIQUE_RE.search(content_prefix)
    return m.group(1) if m else None


def _infer_cve_id(path: Path, content_prefix: str) -> str | None:
    """Extract first CVE ID from filename stem or content prefix."""
    m = _CVE_RE.search(path.stem) or _CVE_RE.search(content_prefix)
    return m.group(1).upper() if m else None


def _normalise_severity(raw: Any) -> str | None:
    """Normalise a raw severity string to a controlled vocabulary value."""
    if not raw or not isinstance(raw, str):
        return None
    normalised = raw.strip().lower()
    return _SEVERITY_ALIASES.get(normalised)


# =============================================================================
# Plain Text / Markdown Loader
# =============================================================================

class PlainTextLoader(BaseDocumentLoader):
    """
    Loads plain text, Markdown, reStructuredText, and log files.
    Returns a single KnowledgeDocument per file.

    Supported extensions: .txt .md .markdown .log .rst
    """

    supported_extensions: frozenset[str] = frozenset(
        {".txt", ".md", ".markdown", ".log", ".rst"}
    )

    def load(self, path: Path) -> list[KnowledgeDocument]:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        try:
            content = path.read_text(encoding="utf-8", errors="replace").strip()
        except OSError as exc:
            raise ValueError(f"Cannot read file {path}: {exc}") from exc

        if not content:
            logger.warning("Skipping empty file: %s", path)
            return []

        prefix = content[:500]
        return [
            KnowledgeDocument(
                content=content,
                source_path=str(path.resolve()),
                source_type=_infer_source_type(path),
                metadata={
                    "filename": path.name,
                    "file_extension": path.suffix.lower(),
                    "loader": "PlainTextLoader",
                },
                technique_id=_infer_technique_id(path, prefix),
                cve_id=_infer_cve_id(path, prefix),
            )
        ]


# =============================================================================
# JSON / JSON Lines Loader
# =============================================================================

class JSONLoader(BaseDocumentLoader):
    """
    Loads JSON and JSON Lines (JSONL) files.

    - .json  → root dict → single document; root list → one doc per item
    - .jsonl → one document per non-empty line

    Content extraction strategy (in priority order):
    1. Known content keys: 'content', 'text', 'description', 'body', 'summary'
    2. Fallback: JSON-serialise the object (excluding vector/hash fields)

    Metadata keys recognised automatically:
    - source_url / url
    - technique_id
    - cve_id / id (if starts with "CVE-")
    - severity / baseSeverity (NVD convention)

    Supported extensions: .json .jsonl
    """

    supported_extensions: frozenset[str] = frozenset({".json", ".jsonl"})

    _CONTENT_KEYS: tuple[str, ...] = (
        "content", "text", "description", "body", "summary",
        "details", "narrative", "rule", "definition",
    )
    _EXCLUDE_FROM_FALLBACK: frozenset[str] = frozenset(
        {"id", "_id", "hash", "embedding", "vector", "embeddings"}
    )

    def _extract_content(self, obj: dict[str, Any]) -> str:
        for key in self._CONTENT_KEYS:
            val = obj.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
        # Fallback: serialise remaining scalar fields
        filtered = {
            k: v for k, v in obj.items()
            if k not in self._EXCLUDE_FROM_FALLBACK
            and isinstance(v, (str, int, float, bool))
        }
        return json.dumps(filtered, ensure_ascii=False, indent=2) if filtered else ""

    def _extract_source_url(self, obj: dict[str, Any]) -> str | None:
        return obj.get("source_url") or obj.get("url") or obj.get("link") or None

    def _extract_cve_id(self, obj: dict[str, Any], path: Path, prefix: str) -> str | None:
        # NVD convention: root "id" field like "CVE-2021-44228"
        raw_id = str(obj.get("id", ""))
        if _CVE_RE.match(raw_id):
            return raw_id.upper()
        explicit = obj.get("cve_id") or obj.get("cveId")
        if explicit:
            return str(explicit).upper()
        return _infer_cve_id(path, prefix)

    def _doc_from_obj(
        self, obj: dict[str, Any], path: Path, line_number: int | None = None
    ) -> KnowledgeDocument | None:
        content = self._extract_content(obj)
        if not content:
            return None

        prefix = content[:500]
        meta: dict[str, Any] = {
            "filename": path.name,
            "loader": "JSONLoader",
        }
        if line_number is not None:
            meta["jsonl_line"] = line_number

        # Copy scalar metadata fields (exclude content/vector fields)
        skip = set(self._CONTENT_KEYS) | self._EXCLUDE_FROM_FALLBACK | {
            "source_url", "url", "link", "technique_id", "cve_id", "cveId",
            "severity", "baseSeverity",
        }
        for k, v in obj.items():
            if k not in skip and isinstance(v, (str, int, float, bool)):
                meta[k] = v

        return KnowledgeDocument(
            content=content,
            source_path=str(path.resolve()),
            source_type=_infer_source_type(path),
            metadata=meta,
            source_url=self._extract_source_url(obj),
            technique_id=(
                obj.get("technique_id")
                or obj.get("techniqueId")
                or _infer_technique_id(path, prefix)
            ),
            cve_id=self._extract_cve_id(obj, path, prefix),
            severity=_normalise_severity(
                obj.get("severity") or obj.get("baseSeverity")
            ),
        )

    def load(self, path: Path) -> list[KnowledgeDocument]:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise ValueError(f"Cannot read file {path}: {exc}") from exc

        docs: list[KnowledgeDocument] = []

        if path.suffix.lower() == ".jsonl":
            for lineno, line in enumerate(raw.splitlines(), 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        doc = self._doc_from_obj(obj, path, line_number=lineno)
                        if doc:
                            docs.append(doc)
                except json.JSONDecodeError as exc:
                    logger.warning(
                        "JSONL parse error at line %d in %s: %s", lineno, path, exc
                    )
        else:
            try:
                data = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON in {path}: {exc}") from exc

            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        doc = self._doc_from_obj(item, path)
                        if doc:
                            docs.append(doc)
            elif isinstance(data, dict):
                doc = self._doc_from_obj(data, path)
                if doc:
                    docs.append(doc)
            else:
                logger.warning("Unexpected JSON root type in %s: %s", path, type(data))

        return docs


# =============================================================================
# PDF Loader
# =============================================================================

class PDFLoader(BaseDocumentLoader):
    """
    Loads PDF files using PyMuPDF (fitz).

    Requires: pymupdf >= 1.24.0
    Install: pip install pymupdf

    All pages are concatenated into a single KnowledgeDocument.
    If pymupdf is not installed, raises ImportError with install instructions.

    Supported extensions: .pdf
    """

    supported_extensions: frozenset[str] = frozenset({".pdf"})

    def load(self, path: Path) -> list[KnowledgeDocument]:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        try:
            import fitz  # type: ignore[import-untyped]  # PyMuPDF
        except ImportError as exc:
            raise ImportError(
                "PyMuPDF is required for PDF loading. "
                "Add 'pymupdf>=1.24.0' to requirements.txt and rebuild the image."
            ) from exc

        try:
            pdf = fitz.open(str(path))
            pages: list[str] = []
            for page_num in range(len(pdf)):
                page_text = pdf.load_page(page_num).get_text("text")
                if page_text.strip():
                    pages.append(page_text.strip())
            pdf.close()
        except Exception as exc:
            raise ValueError(f"Failed to parse PDF {path}: {exc}") from exc

        if not pages:
            logger.warning("No extractable text found in PDF: %s", path)
            return []

        content = "\n\n".join(pages)
        prefix = content[:500]

        return [
            KnowledgeDocument(
                content=content,
                source_path=str(path.resolve()),
                source_type=_infer_source_type(path),
                metadata={
                    "filename": path.name,
                    "file_extension": ".pdf",
                    "page_count": len(pages),
                    "loader": "PDFLoader",
                },
                technique_id=_infer_technique_id(path, prefix),
                cve_id=_infer_cve_id(path, prefix),
            )
        ]


# =============================================================================
# Loader Registry
# =============================================================================

class LoaderRegistry:
    """
    Maps file extensions to appropriate loader instances.

    Follows a singleton-friendly design: instantiate once at startup
    and reuse across the ingestion pipeline.

    Usage:
        registry = LoaderRegistry()
        if registry.supports(path):
            loader = registry.get_loader(path)
            docs = loader.load(path)
    """

    def __init__(self) -> None:
        self._loaders: list[BaseDocumentLoader] = [
            PlainTextLoader(),
            JSONLoader(),
            PDFLoader(),
        ]
        self._ext_map: dict[str, BaseDocumentLoader] = {}
        for loader in self._loaders:
            for ext in loader.supported_extensions:
                self._ext_map[ext] = loader

    def get_loader(self, path: Path) -> BaseDocumentLoader:
        """
        Return the registered loader for this file's extension.

        Raises:
            ValueError: If no loader supports the file extension.
        """
        ext = Path(path).suffix.lower()
        loader = self._ext_map.get(ext)
        if loader is None:
            raise ValueError(
                f"No loader registered for extension '{ext}'. "
                f"Supported: {sorted(self._ext_map)}"
            )
        return loader

    def supports(self, path: Path) -> bool:
        """Return True if a loader is available for this file extension."""
        return Path(path).suffix.lower() in self._ext_map

    @property
    def supported_extensions(self) -> list[str]:
        """Sorted list of all supported file extensions."""
        return sorted(self._ext_map.keys())
