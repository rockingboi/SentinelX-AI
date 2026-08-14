"""
SentinelX AI — NLP Pipeline Orchestrator
==========================================
The central processing engine that wires all Phase 2 components together.

Pipeline stages (executed sequentially, in order):
  Stage 1 — DETECT:    LogTypeDetector  → DetectionResult
  Stage 2 — PARSE:     BaseParser       → Iterator[NormalizedEvent]
  Stage 3 — EXTRACT:   IOCExtractor     → List[ExtractedIOC] per event
  Stage 4 — CLASSIFY:  EventClassifier  → ClassificationResult per event
  Stage 5 — ENRICH:    Write MITRE + severity back into NormalizedEvent

Output:
  PipelineResult containing:
  - processed_events:  List[ProcessedEvent]  (event + classification + iocs)
  - all_iocs:          List[ExtractedIOC]    (deduplicated across all events)
  - stats:             PipelineStats
  - log_type:          LogType
  - detection_confidence: float

Design contracts:
  - Thread-safe: no shared mutable state between pipeline runs
  - Error-isolated: one bad line never kills the whole pipeline
  - Lazy parser loading: parsers imported on first process() call
  - Async-capable: process_async() wraps process() in asyncio.to_thread
  - Max output: capped at MAX_EVENTS_PER_RUN (10,000) to prevent OOM
  - Encoding: auto-detects UTF-8 / Latin-1 / Windows-1252
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Iterator

from backend.models.security_log import LogType
from backend.nlp.classifier.event_classifier import ClassificationResult, EventClassifier
from backend.nlp.classifier.mitre_rules import SeverityLevel
from backend.nlp.detector import LogTypeDetector
from backend.nlp.extractor.ioc_extractor import ExtractedIOC, IOCExtractor
from backend.nlp.parsers.registry import parser_registry
from backend.schemas.logs import NormalizedEvent

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────
MAX_EVENTS_PER_RUN:   int = 10_000
MAX_CONTENT_BYTES:    int = 100 * 1024 * 1024   # 100 MB hard ceiling
MAX_IOC_PER_EVENT:    int = 50                   # Prevent IOC explosion on noisy lines
_PARSERS_LOADED:      bool = False               # Lazy load sentinel


# ── Output types ──────────────────────────────────────────────────────────────

@dataclass
class ProcessedEvent:
    """
    A single fully-processed event — the atom of the pipeline output.

    Contains the NormalizedEvent (enriched in-place with MITRE + severity)
    plus its classification result and extracted IOCs.
    """
    event:          NormalizedEvent
    classification: ClassificationResult
    iocs:           list[ExtractedIOC] = field(default_factory=list)

    @property
    def is_threat(self) -> bool:
        return self.classification.is_threat

    @property
    def severity_score(self) -> int:
        return self.classification.severity_score


@dataclass
class PipelineStats:
    """Counters and timing metrics for one pipeline run."""
    total_lines:         int   = 0
    parsed_events:       int   = 0
    failed_lines:        int   = 0
    skipped_lines:       int   = 0
    iocs_extracted:      int   = 0
    unique_iocs:         int   = 0
    threats_detected:    int   = 0
    critical_events:     int   = 0
    high_events:         int   = 0
    medium_events:       int   = 0
    low_events:          int   = 0
    info_events:         int   = 0
    processing_time_ms:  float = 0.0
    ioc_type_counts:     dict  = field(default_factory=dict)

    def severity_counts(self) -> dict[str, int]:
        return {
            "critical": self.critical_events,
            "high":     self.high_events,
            "medium":   self.medium_events,
            "low":      self.low_events,
            "info":     self.info_events,
        }

    def to_dict(self) -> dict:
        return {
            "total_lines":        self.total_lines,
            "parsed_events":      self.parsed_events,
            "failed_lines":       self.failed_lines,
            "skipped_lines":      self.skipped_lines,
            "iocs_extracted":     self.iocs_extracted,
            "unique_iocs":        self.unique_iocs,
            "threats_detected":   self.threats_detected,
            "severity_counts":    self.severity_counts(),
            "processing_time_ms": round(self.processing_time_ms, 2),
            "ioc_type_counts":    self.ioc_type_counts,
        }


@dataclass
class PipelineResult:
    """
    The complete output of one NLP pipeline run.

    Consumers (FastAPI routes, repository layer) use this object to:
    - Persist ProcessedEvents to the parsed_events table
    - Persist all_iocs to the ioc_entities table
    - Update the SecurityLog record with stats
    """
    log_type:             LogType
    detection_confidence: float
    processed_events:     list[ProcessedEvent]
    all_iocs:             list[ExtractedIOC]
    stats:                PipelineStats

    @property
    def is_empty(self) -> bool:
        return len(self.processed_events) == 0

    @property
    def threat_events(self) -> list[ProcessedEvent]:
        """Return only threat-level events (MEDIUM severity or higher)."""
        return [e for e in self.processed_events if e.is_threat]

    @property
    def critical_events(self) -> list[ProcessedEvent]:
        return [e for e in self.processed_events if e.classification.is_critical]

    def top_source_ips(self, n: int = 10) -> list[tuple[str, int]]:
        """Return the N most frequent source IPs across all events."""
        from collections import Counter
        c: Counter = Counter()
        for pe in self.processed_events:
            if pe.event.source_ip:
                c[pe.event.source_ip] += 1
        return c.most_common(n)

    def mitre_hit_summary(self) -> list[dict]:
        """Return MITRE technique hit counts across all events."""
        from collections import Counter
        c: Counter = Counter()
        names: dict[str, str] = {}
        tactics: dict[str, str] = {}
        for pe in self.processed_events:
            tid = pe.classification.technique_id
            if tid:
                c[tid] += 1
                names[tid] = pe.classification.technique_name or ""
                tactics[tid] = pe.classification.tactic_name or ""
        return [
            {"technique_id": tid, "technique_name": names[tid], "tactic": tactics[tid], "count": cnt}
            for tid, cnt in c.most_common()
        ]

    def to_summary_dict(self) -> dict:
        """Lightweight summary for API responses."""
        return {
            "log_type":             self.log_type.value,
            "detection_confidence": round(self.detection_confidence, 3),
            "stats":                self.stats.to_dict(),
            "top_source_ips":       self.top_source_ips(5),
            "mitre_hits":           self.mitre_hit_summary()[:10],
        }


# ── Pipeline ──────────────────────────────────────────────────────────────────

class NLPPipeline:
    """
    The NLP Pipeline Orchestrator.

    Singleton-friendly: construct once and reuse across requests.
    All instance attributes are read-only after __init__.

    Usage (sync):
        pipeline = NLPPipeline()
        result = pipeline.process(raw_content)

    Usage (async):
        pipeline = NLPPipeline()
        result = await pipeline.process_async(raw_content)
    """

    def __init__(
        self,
        include_private_ips: bool = False,
        max_events: int = MAX_EVENTS_PER_RUN,
    ) -> None:
        self._detector   = LogTypeDetector()
        self._extractor  = IOCExtractor(include_private_ips=include_private_ips)
        self._classifier = EventClassifier()
        self._max_events = max_events

    # ── Public API ────────────────────────────────────────────────────────────

    def process(
        self,
        raw_content: str | bytes,
        force_log_type: LogType | None = None,
        include_context: bool = True,
    ) -> PipelineResult:
        """
        Process raw log content through all pipeline stages.

        Args:
            raw_content:     Raw log content as str or bytes.
            force_log_type:  Skip auto-detection and use this type.
            include_context: Include raw line snippets in IOC context fields.

        Returns:
            PipelineResult with all processed events, IOCs, and stats.
        """
        _ensure_parsers_loaded()
        t_start = time.perf_counter()

        # ── Decode bytes ──────────────────────────────────────────────────────
        if isinstance(raw_content, bytes):
            raw_content = self._decode(raw_content)

        # ── Content size guard ────────────────────────────────────────────────
        if len(raw_content.encode("utf-8", errors="replace")) > MAX_CONTENT_BYTES:
            logger.warning("Content exceeds 100MB limit — truncating")
            raw_content = raw_content[:MAX_CONTENT_BYTES]

        stats = PipelineStats()
        stats.total_lines = raw_content.count("\n") + (1 if raw_content and not raw_content.endswith("\n") else 0)

        # ── Stage 1: Detect ───────────────────────────────────────────────────
        if force_log_type is not None:
            detection = self._detector.detect_with_override(raw_content, force_log_type)
        else:
            detection = self._detector.detect(raw_content)

        log_type   = detection.log_type
        confidence = detection.confidence
        logger.info("Pipeline: detected log_type=%s confidence=%.2f", log_type.value, confidence)

        # ── Stage 2: Get parser ───────────────────────────────────────────────
        parser = parser_registry.get(log_type)
        if parser is None:
            logger.warning("No parser for log_type=%s — returning empty result", log_type.value)
            stats.processing_time_ms = (time.perf_counter() - t_start) * 1000
            return PipelineResult(
                log_type=log_type,
                detection_confidence=confidence,
                processed_events=[],
                all_iocs=[],
                stats=stats,
            )

        # ── Stages 3–5: Parse + Extract + Classify ────────────────────────────
        processed_events: list[ProcessedEvent] = []
        global_ioc_map: dict[tuple, ExtractedIOC] = {}   # (type, value) → IOC

        for normalized_event in parser.parse(raw_content):
            if len(processed_events) >= self._max_events:
                logger.warning("Hit max_events=%d — stopping", self._max_events)
                break

            try:
                pe = self._process_one_event(normalized_event, global_ioc_map, include_context)
                processed_events.append(pe)
                stats.parsed_events += 1
                self._update_stats(stats, pe)
            except Exception as exc:
                stats.failed_lines += 1
                logger.debug("Event processing error at line %s: %s", normalized_event.line_number, exc)

        # Compile deduplicated IOC list
        all_iocs = list(global_ioc_map.values())
        stats.unique_iocs        = len(all_iocs)
        stats.processing_time_ms = (time.perf_counter() - t_start) * 1000

        logger.info(
            "Pipeline complete: events=%d iocs=%d threats=%d time=%.0fms",
            stats.parsed_events, stats.unique_iocs,
            stats.threats_detected, stats.processing_time_ms,
        )

        return PipelineResult(
            log_type=log_type,
            detection_confidence=confidence,
            processed_events=processed_events,
            all_iocs=all_iocs,
            stats=stats,
        )

    async def process_async(
        self,
        raw_content: str | bytes,
        force_log_type: LogType | None = None,
    ) -> PipelineResult:
        """
        Async wrapper — runs the synchronous pipeline in a thread pool.
        Use this in FastAPI route handlers to avoid blocking the event loop.
        """
        return await asyncio.to_thread(self.process, raw_content, force_log_type)

    # ── Per-event processing ──────────────────────────────────────────────────

    def _process_one_event(
        self,
        event: NormalizedEvent,
        global_ioc_map: dict,
        include_context: bool,
    ) -> ProcessedEvent:
        """
        Run Stages 3 (Extract) + 4 (Classify) + 5 (Enrich) on one event.
        Mutates the event in-place to write MITRE and severity fields.
        """
        # Stage 3: Extract IOCs
        raw_iocs = self._extractor.extract_from_event(event)
        event_iocs = raw_iocs[:MAX_IOC_PER_EVENT]   # guard against noisy lines

        # Merge into global deduplication map
        for ioc in event_iocs:
            key = (ioc.ioc_type, ioc.value)
            if key not in global_ioc_map:
                global_ioc_map[key] = ioc

        # Stage 4: Classify
        classification = self._classifier.classify(event)

        # Stage 5: Enrich event in-place
        self._enrich_event(event, classification, event_iocs)

        return ProcessedEvent(
            event=event,
            classification=classification,
            iocs=event_iocs,
        )

    @staticmethod
    def _enrich_event(
        event:          NormalizedEvent,
        classification: ClassificationResult,
        iocs:           list[ExtractedIOC],
    ) -> None:
        """
        Write classification and IOC data back into the NormalizedEvent.

        This makes NormalizedEvent self-contained — when persisted to the
        parsed_events table, all fields are already populated.
        """
        # MITRE fields
        event.mitre_tactic_id      = classification.tactic_id
        event.mitre_tactic         = classification.tactic_name
        event.mitre_technique_id   = classification.technique_id
        event.mitre_technique_name = classification.technique_name

        # Severity fields
        event.severity             = classification.severity.value
        event.severity_score       = classification.severity_score

        # IOC compact summary (stored in normalized_data)
        if iocs:
            ioc_summary = [
                {"type": i.ioc_type.value, "value": i.value, "confidence": i.confidence}
                for i in iocs[:20]   # Keep summary compact
            ]
            event.normalized_data["extracted_iocs"] = ioc_summary

        # Write full classification dict for audit trail
        event.normalized_data["classification"] = classification.to_dict()

    # ── Stats updater ─────────────────────────────────────────────────────────

    @staticmethod
    def _update_stats(stats: PipelineStats, pe: ProcessedEvent) -> None:
        """Update aggregate counters from a single ProcessedEvent."""
        # Severity counters
        s = pe.classification.severity
        if s == SeverityLevel.CRITICAL:
            stats.critical_events += 1
        elif s == SeverityLevel.HIGH:
            stats.high_events += 1
        elif s == SeverityLevel.MEDIUM:
            stats.medium_events += 1
        elif s == SeverityLevel.LOW:
            stats.low_events += 1
        else:
            stats.info_events += 1

        if pe.is_threat:
            stats.threats_detected += 1

        # IOC counters
        stats.iocs_extracted += len(pe.iocs)
        for ioc in pe.iocs:
            key = ioc.ioc_type.value
            stats.ioc_type_counts[key] = stats.ioc_type_counts.get(key, 0) + 1

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _decode(raw: bytes) -> str:
        """Decode bytes with automatic encoding detection fallback chain."""
        for encoding in ("utf-8", "utf-8-sig", "latin-1", "cp1252"):
            try:
                return raw.decode(encoding)
            except (UnicodeDecodeError, LookupError):
                continue
        return raw.decode("utf-8", errors="replace")


# ── Lazy parser loader ────────────────────────────────────────────────────────

def _ensure_parsers_loaded() -> None:
    """
    Lazily import all concrete parser modules so their @register_parser
    decorators fire and populate parser_registry.

    Safe to call multiple times — idempotent after first call.
    """
    global _PARSERS_LOADED
    if _PARSERS_LOADED:
        return

    try:
        from backend.nlp.parsers import (   # noqa: F401
            apache_access,
            linux_syslog,
            nginx_access,
            sysmon,
            windows_event,
        )
        _PARSERS_LOADED = True
        logger.info(
            "NLP parsers loaded: %d registered",
            len(parser_registry),
        )
    except ImportError as exc:
        logger.error("Failed to load parsers: %s", exc)
        raise


# ── Module-level singleton ────────────────────────────────────────────────────
# Pre-built instance for dependency injection in FastAPI routes.
# Routes should import `nlp_pipeline` and call `nlp_pipeline.process_async()`.

nlp_pipeline = NLPPipeline()
