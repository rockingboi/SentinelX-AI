# SentinelX Phase 2 — NLP Security Pipeline

> Full technical reference for the deterministic, rule-based log analysis engine.
> **No LLMs, no LangGraph, no agents.** All logic is pure Python with compiled regex and weighted scoring.

---

## Table of Contents

1. [Overview](#overview)
2. [Pipeline Stages](#pipeline-stages)
3. [Log Type Detector](#log-type-detector)
4. [Parsers](#parsers)
5. [IOC Extractor](#ioc-extractor)
6. [Event Classifier](#event-classifier)
7. [MITRE ATT&CK Rules](#mitre-attck-rules)
8. [Pipeline Orchestrator](#pipeline-orchestrator)
9. [Persistence Layer](#persistence-layer)
10. [REST API Integration](#rest-api-integration)
11. [Data Models](#data-models)
12. [Performance Notes](#performance-notes)

---

## Overview

The NLP pipeline converts a raw log file into structured intelligence:

```
Raw bytes / str
      │
      ▼
┌──────────────────────────────────────────────────────────────────┐
│                     NLPPipeline.process()                         │
│                                                                    │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────┐  │
│  │LogTypeDetect │──▶│   Parser     │──▶│    IOCExtractor      │  │
│  │(confidence)  │   │(NormalizedEv)│   │(16 types, dedup'd)   │  │
│  └──────────────┘   └──────────────┘   └──────────┬───────────┘  │
│                                                    │              │
│  ┌──────────────────────────────────────────────┐  │              │
│  │           EventClassifier                    │◀─┘              │
│  │  47 MITRE rules → technique + tactic + score │                 │
│  └──────────────────────────────────┬───────────┘                 │
│                                     │                             │
│  ┌──────────────────────────────────▼───────────┐                 │
│  │               PipelineResult                 │                 │
│  │  events[] · iocs[] · stats · threats[]       │                 │
│  └──────────────────────────────────────────────┘                 │
└──────────────────────────────────────────────────────────────────┘
      │
      ▼
PostgreSQL (parsed_events + ioc_entities + incident_events)
```

All stages are **synchronous by default** with a `process_async()` wrapper for FastAPI.

---

## Pipeline Stages

### Stage Flow

| # | Stage | Input | Output | Class |
|---|-------|-------|--------|-------|
| 1 | Detect | `bytes\|str` | `DetectionResult(log_type, confidence)` | `LogTypeDetector` |
| 2 | Parse | `bytes\|str` | `list[NormalizedEvent]` | `BaseParser` subclass |
| 3 | Extract | `NormalizedEvent` | `list[ExtractedIOC]` | `IOCExtractor` |
| 4 | Classify | `NormalizedEvent` | `ClassificationResult` | `EventClassifier` |
| 5 | Persist | `PipelineResult` | DB rows committed | `LogService.process_log()` |

---

## Log Type Detector

**File:** `backend/nlp/detector.py`

`LogTypeDetector` scores a log sample against signature patterns and returns the type with the highest confidence.

### How it works

```python
detector = LogTypeDetector()
result = detector.detect(raw_content)
# DetectionResult(log_type=LogType.LINUX_SYSLOG, confidence=0.95)
```

### Detection signatures

Each log type has a set of regex signatures. The detector:
1. Samples up to the first 100 lines
2. Counts pattern hits for each type
3. Returns `log_type` with highest hit ratio as confidence score
4. Falls back to `LogType.UNKNOWN` if all confidences < 0.3

| LogType | Key Patterns |
|---------|-------------|
| `linux_syslog` | `\w{3}\s+\d+ \d{2}:\d{2}:\d{2}`, `sshd\[`, `sudo:`, `PAM` |
| `windows_event` | `EventID=\d+`, `Level=\w+`, `Source=Security` |
| `apache_access` | Combined Log Format `"GET /path HTTP/1.1"`, status codes |
| `nginx_access` | Nginx format — similar to Apache but with distinct user-agents |
| `sysmon` | `<EventID>`, `<EventData>`, XML structure |

### Force override

```python
result = detector.detect_with_override(content, force_type=LogType.SYSMON)
# Always returns SYSMON regardless of content
```

---

## Parsers

**Files:** `backend/nlp/parsers/*.py`

All parsers extend `BaseParser` and implement a single method:

```python
class BaseParser(ABC):
    log_type: LogType

    @abstractmethod
    def parse(self, content: str | bytes) -> list[NormalizedEvent]:
        ...
```

### NormalizedEvent

The universal output structure from all parsers:

```python
@dataclass
class NormalizedEvent:
    # Identity
    log_type: LogType
    event_type: str | None        # "Failed Login", "SQL Injection Attempt", etc.
    line_number: int

    # Network
    source_ip: str | None
    dest_ip: str | None
    source_port: int | None
    dest_port: int | None
    protocol: str | None

    # Auth
    username: str | None
    hostname: str | None
    service: str | None

    # Process (Sysmon)
    process_name: str | None
    process_id: int | None
    command_line: str | None

    # Web (Apache/Nginx)
    http_method: str | None
    http_status_code: int | None
    url: str | None
    user_agent: str | None

    # File system
    file_path: str | None

    # Timing
    event_timestamp: datetime | None
    timestamp_raw: str | None

    # Enrichment (filled by classifier)
    severity: str | None
    severity_score: int | None
    mitre_technique_id: str | None
    mitre_technique_name: str | None
    mitre_tactic: str | None

    # Raw
    raw_line: str
    normalized_data: dict
```

### LinuxSyslogParser

Parses standard RFC 3164 syslog format:
```
Jul  1 10:23:45 server sshd[1234]: Failed password for root from 185.24.18.15 port 54321
```

Detects: Failed Login, Accepted Login, Sudo Privilege Escalation, SU Attempt, Cron Job, Kernel Event.

### WindowsEventParser

Parses text-format Windows Security Event logs:
```
2025-07-01T10:23:45 EventID=4625 Level=Warning Source=Security Message=An account failed to log on
```

Maps Event IDs to event types:

| EventID | Event Type |
|---------|-----------|
| 4624 | Successful Login |
| 4625 | Failed Login |
| 4648 | Explicit Credential Login |
| 4720 | User Account Created |
| 4728/4732/4756 | Group Membership Changed |
| 4776 | Credential Validation |
| 4768/4769 | Kerberos Ticket Request |

### ApacheAccessParser

Parses Apache Combined Log Format:
```
203.0.113.100 - - [01/Jul/2025:10:23:45 +0000] "GET /admin HTTP/1.1" 403 512 "-" "sqlmap/1.7"
```

Detects: SQL Injection Attempt (`UNION SELECT`, `1=1`), Directory Traversal (`../`), XSS Attempt (`<script>`), Scanner Activity (sqlmap, nikto, dirbuster UAs), Brute Force Login.

### NginxAccessParser

Same format as Apache. Additional detection for Nginx-specific patterns.

### SysmonParser

Parses Sysmon XML events (one per line or full XML file):
```xml
<Event><System><EventID>10</EventID>...</System><EventData>
  <Data Name="TargetImage">lsass.exe</Data>
  <Data Name="GrantedAccess">0x1010</Data>
</EventData></Event>
```

Maps EventIDs:

| EventID | Event Type | Criticality |
|---------|-----------|-------------|
| 1 | Process Create | HIGH if cmd.exe/powershell |
| 3 | Network Connect | HIGH if unusual port |
| 7 | Image Load | MEDIUM |
| 10 | Process Access | CRITICAL if target=lsass.exe |
| 11 | File Create | HIGH if suspicious path |
| 12/13 | Registry Modify | HIGH if Run key |
| 22 | DNS Query | MEDIUM |

### Parser Registry

```python
from backend.nlp.parsers.registry import ParserRegistry

registry = ParserRegistry()
parser = registry.get(LogType.LINUX_SYSLOG)
events = parser.parse(content)
```

---

## IOC Extractor

**Files:** `backend/nlp/extractor/patterns.py`, `backend/nlp/extractor/ioc_extractor.py`

### IOC Types

| Type | Pattern |
|------|---------|
| `ipv4` | `\b(?:\d{1,3}\.){3}\d{1,3}\b` with validity check |
| `ipv6` | Full IPv6 regex |
| `domain` | FQDN with TLD validation via `tldextract` |
| `url` | Full URL with scheme |
| `md5` | `[a-f0-9]{32}` |
| `sha1` | `[a-f0-9]{40}` |
| `sha256` | `[a-f0-9]{64}` |
| `email` | RFC 5321 compliant |
| `cve` | `CVE-\d{4}-\d{4,7}` |
| `username` | Contextual extraction from parsed events |
| `hostname` | From event fields |
| `filename` | Path-based extraction |
| `registry_key` | `HKLM\|HKCU\|HKCC\\...` |
| `command_line` | From `command_line` field |
| `port` | Contextual port numbers |
| `mac_address` | `([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}` |

### Allowlists (auto-excluded)

- **Benign IPs:** `127.0.0.1`, `0.0.0.0`, `255.255.255.255`, `::1`
- **Private ranges:** `10.x`, `172.16–31.x`, `192.168.x` (excluded by default, can enable with `include_private_ips=True`)
- **Benign hashes:** Known-clean hashes (SHA256 of empty string, common system binaries)
- **Benign domains:** `localhost`, `example.com`, `test.com`, etc.

### Usage

```python
extractor = IOCExtractor()

# From raw text
iocs = extractor.extract_from_text("Failed auth from 185.24.18.15 port 22")

# From NormalizedEvent (uses all fields)
iocs = extractor.extract_from_event(event)

# Include private IPs
iocs = extractor.extract_from_text(text, include_private_ips=True)
```

### ExtractedIOC

```python
@dataclass
class ExtractedIOC:
    ioc_type: str          # one of 16 types above
    value: str             # normalised value
    confidence: float      # 0.0 – 1.0
    source_field: str      # which field it came from
    context: str           # surrounding text snippet
```

**Deduplication:** IOCs with the same `(type, value)` pair are deduplicated — the one with the highest confidence is kept.

---

## Event Classifier

**Files:** `backend/nlp/classifier/mitre_rules.py`, `backend/nlp/classifier/event_classifier.py`

### ClassificationResult

```python
@dataclass
class ClassificationResult:
    technique_id: str          # e.g. "T1110"
    technique_name: str        # e.g. "Brute Force"
    sub_technique_id: str | None
    tactic: str                # e.g. "Credential Access"
    tactic_id: str             # e.g. "TA0006"
    severity: SeverityLevel    # CRITICAL / HIGH / MEDIUM / LOW / INFO
    score: int                 # 1–10
    is_threat: bool            # score >= 4
    is_critical: bool          # score >= 9
    description: str
    tags: list[str]
    matched_rules: list[str]
    confidence: float
```

### Severity scale

| Score | Level | `is_threat` | `is_critical` |
|-------|-------|-------------|---------------|
| 9–10 | CRITICAL | ✓ | ✓ |
| 7–8 | HIGH | ✓ | ✗ |
| 5–6 | MEDIUM | ✓ | ✗ |
| 3–4 | LOW | ✗ | ✗ |
| 1–2 | INFO | ✗ | ✗ |

### Classify an event

```python
classifier = EventClassifier()
result = classifier.classify(event)        # NormalizedEvent → ClassificationResult
enriched = classifier.enrich_event(event)  # in-place MITRE field injection
```

---

## MITRE ATT&CK Rules

**File:** `backend/nlp/classifier/mitre_rules.py`

47 `ClassificationRule` objects, matched by `event_type` regex against `NormalizedEvent.event_type`.

### Rule structure

```python
@dataclass
class ClassificationRule:
    event_type_pattern: str    # Regex matched against NormalizedEvent.event_type
    technique_id: str
    technique_name: str
    sub_technique_id: str | None
    tactic: str
    tactic_id: str
    severity: SeverityLevel
    score: int                 # 1–10
    description: str
    tags: list[str]
```

### Rule examples

```python
# T1110 — Brute Force
ClassificationRule(
    event_type_pattern=r"(?i)failed.*(login|password|auth)",
    technique_id="T1110",
    technique_name="Brute Force",
    tactic="Credential Access",
    tactic_id="TA0006",
    severity=SeverityLevel.MEDIUM,
    score=5,
    ...
)

# T1003.001 — LSASS Memory Dump (CRITICAL)
ClassificationRule(
    event_type_pattern=r"(?i)lsass.*(access|dump|credential)",
    technique_id="T1003",
    technique_name="OS Credential Dumping",
    sub_technique_id="T1003.001",
    tactic="Credential Access",
    severity=SeverityLevel.CRITICAL,
    score=10,
    ...
)
```

### Adding new rules

Append to `CLASSIFICATION_RULES` list in `mitre_rules.py`. No code changes needed elsewhere.

---

## Pipeline Orchestrator

**File:** `backend/nlp/pipeline.py`

### NLPPipeline

```python
pipeline = NLPPipeline()

# Synchronous
result: PipelineResult = pipeline.process(content, force_log_type=None)

# Asynchronous (for FastAPI)
result: PipelineResult = await pipeline.process_async(content)
```

### PipelineResult

```python
@dataclass
class PipelineResult:
    log_type: LogType
    detection_confidence: float
    parsed_events: list[NormalizedEvent]
    all_iocs: list[ExtractedIOC]            # deduplicated across all events
    threat_events: list[NormalizedEvent]    # events with is_threat=True
    critical_events: list[NormalizedEvent]  # events with is_critical=True
    stats: PipelineStats
    is_empty: bool
```

### PipelineStats

```python
@dataclass
class PipelineStats:
    total_lines: int
    parsed_events: int
    skipped_lines: int
    threats_detected: int
    critical_events: int
    unique_iocs: int
    ioc_type_counts: dict[str, int]
    processing_time_ms: int
    top_event_types: list[tuple[str, int]]
```

### Pipeline → Summary dict

```python
summary = result.to_summary_dict()
# {
#   "log_type": "linux_syslog",
#   "parsed_events": 31,
#   "threats_detected": 8,
#   "critical_events": 2,
#   "unique_iocs": 36,
#   "processing_time_ms": 45,
#   ...
# }
```

---

## Persistence Layer

**Files:** `backend/repositories/*.py`, `backend/services/log_service.py`

### Repository Pattern

```
LogService
  ├── LogRepository       → security_logs table
  ├── EventRepository     → parsed_events table
  ├── IOCRepository       → ioc_entities table
  └── IncidentRepository  → incident_events table
```

### process_log() flow

```python
async def process_log(self, log_id: int, force_log_type: str | None = None):
    # 1. Load raw bytes from security_logs
    log = await self._logs.get_by_id(log_id)

    # 2. Run NLP pipeline
    result = await self._pipeline.process_async(
        log.raw_content, force_log_type=force_log_type
    )

    # 3. Update log metadata (log_type, status=processing)
    await self._logs.update_pipeline_start(log_id, result.log_type)

    # 4. Bulk-insert ParsedEvents
    await self._events.bulk_insert(log_id, result.parsed_events)

    # 5. Upsert IOCEntities (seen_count++)
    await self._iocs.bulk_upsert_from_extracted(log_id, result.all_iocs)

    # 6. Auto-create Incidents for critical events
    for event in result.critical_events:
        await self._incidents.create_from_event(log_id, event)

    # 7. Mark log as completed
    await self._logs.update_pipeline_complete(log_id, result.stats)
```

### IOC Deduplication (DB level)

`ioc_entities` has a `UniqueConstraint("value", "ioc_type", "log_id")`. On upsert:
- First seen → INSERT with `seen_count=1`
- Seen again → UPDATE `seen_count++`, `last_seen=now()`

---

## REST API Integration

### Upload + Parse (two-step)

The API deliberately separates upload from parsing to allow:
- Large file uploads without timeout risk
- Retry parsing without re-uploading
- Future: async queue-based processing

```
POST /api/v1/logs/upload     → 201, log_id, status=pending
POST /api/v1/logs/{id}/parse → 200, parsed_event_count, ioc_count, status=completed
```

### Event filtering

```
GET /api/v1/logs/{id}/events
  ?severity=critical|high|medium|low|info
  ?threats_only=true
  ?event_type=Failed+Login
  ?page=1&per_page=50
```

### IOC search

```
GET /api/v1/iocs/search              → list all IOCs
GET /api/v1/iocs/search?q=185.24     → substring match
GET /api/v1/iocs/search?ioc_type=ipv4
GET /api/v1/iocs/search?q=mimikatz&ioc_type=command_line
```

---

## Data Models

### security_logs

| Column | Type | Notes |
|--------|------|-------|
| `id` | SERIAL PK | |
| `filename` | VARCHAR(255) | Original filename |
| `log_type` | VARCHAR(50) | `linux_syslog`, `unknown`, etc. |
| `status` | VARCHAR(20) | `pending` → `processing` → `completed` \| `failed` |
| `file_size_bytes` | INTEGER | |
| `raw_content` | BYTEA | Raw uploaded bytes |
| `uploaded_by` | INTEGER FK | users.id |
| `pipeline_summary` | JSONB | `{parsed_events, threats, iocs, time_ms}` |
| `created_at` | TIMESTAMPTZ | |

### parsed_events

| Column | Type | Notes |
|--------|------|-------|
| `id` | SERIAL PK | |
| `log_id` | INTEGER FK | ON DELETE CASCADE |
| `event_type` | VARCHAR(100) | "Failed Login", "SQL Injection Attempt" |
| `log_type` | VARCHAR(50) | Mirrors parent |
| `source_ip` | VARCHAR(45) | IPv4 or IPv6 |
| `severity` | VARCHAR(20) | CRITICAL / HIGH / MEDIUM / LOW / INFO |
| `severity_score` | INTEGER | 1–10 |
| `mitre_technique_id` | VARCHAR(20) | "T1110" |
| `mitre_technique_name` | VARCHAR(200) | "Brute Force" |
| `mitre_tactic` | VARCHAR(100) | "Credential Access" |
| `normalized_data` | JSONB | All remaining fields |
| `created_at` | TIMESTAMPTZ | |

Indexes: `log_id`, `event_type`, `severity`, `source_ip`, `mitre_technique_id`, `event_timestamp`, `username`, `created_at`

### ioc_entities

| Column | Type | Notes |
| `id` | SERIAL PK | |
| `log_id` | INTEGER FK | |
| `ioc_type` | VARCHAR(30) | One of 16 types |
| `value` | TEXT | Normalised value |
| `confidence` | FLOAT | 0.0–1.0 |
| `context` | TEXT | Surrounding text |
| `seen_count` | INTEGER | Incremented on upsert |
| `first_seen` | TIMESTAMPTZ | |
| `last_seen` | TIMESTAMPTZ | |

UniqueConstraint: `(value, ioc_type, log_id)`

---

## Performance Notes

| Metric | Value |
|--------|-------|
| Linux syslog (31 lines) | ~15ms |
| Apache access (25 lines) | ~10ms |
| Sysmon XML (10 events) | ~20ms |
| IOC extraction per event | ~2ms |
| MITRE classification per event | <1ms |
| DB insert (31 events + 36 IOCs) | ~150ms |

**Bottleneck:** Database write (bulk insert). The pipeline itself is CPU-bound and < 50ms for typical SOC log files (< 10,000 lines). For very large files (> 100,000 lines), streaming parsing should be implemented.

**Memory:** Each `NormalizedEvent` is ~500 bytes. 10,000 events ≈ 5 MB peak. Acceptable for in-process batch processing.
