"""
SentinelX AI — Parsers Sub-package
=====================================
Importing this package does NOT auto-load parsers.
Parsers are loaded explicitly by the pipeline via _load_parsers().

Why lazy loading?
- Avoids circular imports at package import time
- Keeps startup fast (parsers are heavy — they compile many regex patterns)
- Allows the registry to be queried before parsers are loaded (e.g. in tests)

All parsers register themselves with the global `parser_registry`
singleton when their module is imported (via @register_parser decorator).
"""
from __future__ import annotations
