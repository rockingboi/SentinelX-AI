"""
SentinelX AI — NLP Package
============================
Phase 2: Rule-based Security Log Processing & NLP Engine.

Package structure:
  nlp/
  ├── detector.py          — Log type auto-detection (heuristic fingerprinting)
  ├── normalizer.py        — Unified event schema normalization   [Step 8]
  ├── pipeline.py          — Full pipeline orchestrator           [Step 8]
  ├── parsers/
  │   ├── base.py          — Abstract BaseParser interface
  │   ├── registry.py      — Parser registry (LogType → Parser)
  │   ├── windows_event.py — Windows Event Log / Sysmon          [Step 3]
  │   ├── linux_syslog.py  — Linux Syslog (RFC 3164/5424)        [Step 3]
  │   ├── apache_access.py — Apache Combined Log Format          [Step 3]
  │   ├── nginx_access.py  — Nginx access + error log            [Step 3]
  │   └── sysmon.py        — Sysmon XML event log                [Step 3]
  ├── extractor/
  │   └── ioc_extractor.py — IOC extraction (16 types)           [Step 4]
  ├── classifier/
  │   └── event_classifier.py — Rule-based classification        [Step 5]
  ├── severity/
  │   └── severity_engine.py  — Deterministic severity scoring   [Step 6]
  └── mitre/
      ├── mitre_knowledge_base.py — Static MITRE rules DB        [Step 7]
      └── mitre_mapper.py         — Rule-based ATT&CK mapping    [Step 7]
"""
from __future__ import annotations
