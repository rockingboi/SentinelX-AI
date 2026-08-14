"""
SentinelX AI — IOC Extractor Sub-package
==========================================
Contains all IOC extraction logic: compiled patterns and the extractor engine.

Public API:
    from backend.nlp.extractor import ioc_extractor
    extractor = IOCExtractor()
    iocs = extractor.extract_from_text("185.24.18.15 accessed evil.com")
    iocs = extractor.extract_from_event(normalized_event)
"""
from __future__ import annotations
