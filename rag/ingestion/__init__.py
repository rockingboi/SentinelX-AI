"""
SentinelX AI — Ingestion sub-package
"""
from rag.ingestion.base import (
    KnowledgeDocument,
    SourceType,
    ValidationResult,
    BaseDocumentLoader,
    BaseDocumentValidator,
)
from rag.ingestion.loaders import LoaderRegistry, PlainTextLoader, JSONLoader, PDFLoader
from rag.ingestion.validator import DocumentValidator
from rag.ingestion.deduplicator import ContentDeduplicator, compute_hash

__all__ = [
    "KnowledgeDocument",
    "SourceType",
    "ValidationResult",
    "BaseDocumentLoader",
    "BaseDocumentValidator",
    "LoaderRegistry",
    "PlainTextLoader",
    "JSONLoader",
    "PDFLoader",
    "DocumentValidator",
    "ContentDeduplicator",
    "compute_hash",
]
