"""
SentinelX AI — Document Validator
====================================
Validates KnowledgeDocuments before they enter the chunking and
embedding stages of the ingestion pipeline.

Documents that fail validation are:
  1. Logged with the failure reason
  2. Excluded from chunking and indexing
  3. Moved to data/knowledge/failed/ by the pipeline orchestrator

Checks performed (in order):
  1. Non-empty content
  2. Minimum character length   (default: 50 chars)
  3. Maximum character length   (default: 5,000,000 chars  ≈ 5 MB)
  4. Minimum word count         (default: 10 words)
  5. UTF-8 re-encodability      (defensive; loaders should already handle this)
  6. Non-empty source_path
  7. Non-empty source_type
"""
from __future__ import annotations

import logging

from rag.ingestion.base import BaseDocumentValidator, KnowledgeDocument, ValidationResult

logger = logging.getLogger(__name__)

# Default thresholds — override via DocumentValidator constructor
_MIN_CONTENT_LENGTH: int = 50
_MAX_CONTENT_LENGTH: int = 5_000_000   # ≈ 5 MB; chunker will split further
_MIN_WORD_COUNT: int = 10


class DocumentValidator(BaseDocumentValidator):
    """
    Standard document validator for the SentinelX knowledge pipeline.

    All thresholds are configurable at construction time so tests can
    use tight limits without relying on magic numbers.

    Non-fatal issues are surfaced as warnings in ValidationResult.warnings
    and logged at DEBUG level.
    """

    def __init__(
        self,
        min_length: int = _MIN_CONTENT_LENGTH,
        max_length: int = _MAX_CONTENT_LENGTH,
        min_words: int = _MIN_WORD_COUNT,
    ) -> None:
        self.min_length = min_length
        self.max_length = max_length
        self.min_words = min_words

    def validate(self, doc: KnowledgeDocument) -> ValidationResult:
        """
        Run all validation checks on the document.

        Args:
            doc: KnowledgeDocument to validate.

        Returns:
            ValidationResult with is_valid=True (and optional warnings)
            or is_valid=False with a human-readable reason string.
        """
        warnings: list[str] = []

        # ── 1. Non-empty ──────────────────────────────────────────────────────
        if not doc.content or not doc.content.strip():
            return ValidationResult(
                is_valid=False,
                reason="Content is empty or whitespace-only",
            )

        content = doc.content.strip()

        # ── 2. Minimum character length ───────────────────────────────────────
        if len(content) < self.min_length:
            return ValidationResult(
                is_valid=False,
                reason=(
                    f"Content too short: {len(content)} chars "
                    f"(minimum is {self.min_length})"
                ),
            )

        # ── 3. Maximum character length ───────────────────────────────────────
        if len(content) > self.max_length:
            return ValidationResult(
                is_valid=False,
                reason=(
                    f"Content exceeds maximum size: {len(content):,} chars "
                    f"(maximum is {self.max_length:,})"
                ),
            )

        # ── 4. Minimum word count ─────────────────────────────────────────────
        word_count = len(content.split())
        if word_count < self.min_words:
            return ValidationResult(
                is_valid=False,
                reason=(
                    f"Too few words: {word_count} "
                    f"(minimum is {self.min_words})"
                ),
            )

        # ── 5. UTF-8 encodability ─────────────────────────────────────────────
        try:
            content.encode("utf-8")
        except UnicodeEncodeError as exc:
            return ValidationResult(
                is_valid=False,
                reason=f"UTF-8 encoding error: {exc}",
            )

        # ── 6. Source path ────────────────────────────────────────────────────
        if not doc.source_path or not doc.source_path.strip():
            return ValidationResult(
                is_valid=False,
                reason="source_path is required but missing",
            )

        # ── 7. Source type ────────────────────────────────────────────────────
        if not doc.source_type or not doc.source_type.strip():
            return ValidationResult(
                is_valid=False,
                reason="source_type is required but missing",
            )

        # ── Non-fatal warnings ────────────────────────────────────────────────
        if word_count < 50:
            warnings.append(
                f"Low word count ({word_count}); document may produce poor-quality chunks"
            )

        if len(content) < 200:
            warnings.append(
                "Very short document; may not chunk meaningfully — consider merging with related content"
            )

        if not doc.doc_hash:
            warnings.append(
                "doc_hash is empty; deduplication will not work for this document"
            )

        if warnings:
            for w in warnings:
                logger.debug("Validation warning [%s]: %s", doc.source_path, w)

        return ValidationResult(is_valid=True, warnings=warnings)
