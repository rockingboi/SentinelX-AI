"""
SentinelX AI — Log Type Detector
===================================
Heuristic fingerprinting engine that auto-detects the format of a raw log file.

Detection Strategy:
- Sample the first N non-empty lines of the raw content
- Run each registered format's signature patterns against the sample
- Score each format based on pattern match ratio
- Return the highest-scoring LogType above the confidence threshold

This approach is used by Elastic Filebeat, Splunk UF, and Graylog.
It is deterministic, requires no ML, and is O(formats × sample_lines).

Supported formats and their key heuristics:
┌─────────────────┬─────────────────────────────────────────────────────────┐
│ Format          │ Key Signatures                                          │
├─────────────────┼─────────────────────────────────────────────────────────┤
│ Windows Event   │ EventID=, <Event xmlns, Keywords=, Channel=, Provider   │
│ Linux Syslog    │ RFC3164: "Mon DD HH:MM:SS host process[pid]:"           │
│ Apache Access   │ Combined: IP - - [DD/Mon/YYYY] "METHOD /path HTTP/1.x"  │
│ Nginx Access    │ Similar to Apache + upstream/proxy headers              │
│ Sysmon XML      │ <EventID> inside <System> with Sysmon ProviderName     │
└─────────────────┴─────────────────────────────────────────────────────────┘
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from backend.models.security_log import LogType

logger = logging.getLogger(__name__)

# Minimum confidence to accept a detection result (0.0–1.0)
CONFIDENCE_THRESHOLD: float = 0.40

# Lines to sample from the top of the file for detection
SAMPLE_LINES: int = 30


# =============================================================================
# Detection Signatures
# =============================================================================

@dataclass
class DetectionSignature:
    """
    A set of compiled regex patterns and weights for detecting a log format.

    Each pattern has a weight — stronger indicators have higher weights.
    The final confidence = sum(matched_weights) / sum(all_weights).
    """

    log_type: LogType
    patterns: list[tuple[re.Pattern, float]]  # (pattern, weight)

    def score(self, sample_lines: list[str]) -> float:
        """
        Score this format against a list of sample lines.

        Applies each pattern to every sample line. If any line matches,
        the pattern's weight is counted once. Returns 0.0–1.0.
        """
        if not sample_lines:
            return 0.0

        total_weight = sum(w for _, w in self.patterns)
        matched_weight = 0.0

        for pattern, weight in self.patterns:
            # Pattern scores if ANY sample line matches it
            if any(pattern.search(line) for line in sample_lines):
                matched_weight += weight

        return matched_weight / total_weight if total_weight > 0 else 0.0


# ---------------------------------------------------------------------------
# Windows Event Log signatures
# ---------------------------------------------------------------------------
_WINDOWS_EVENT_SIGNATURES = DetectionSignature(
    log_type=LogType.WINDOWS_EVENT,
    patterns=[
        # XML format (<Event xmlns= or <EventID>)
        (re.compile(r"<Event\s+xmlns=", re.IGNORECASE), 3.0),
        (re.compile(r"<EventID>?\d+</EventID>?", re.IGNORECASE), 2.5),
        (re.compile(r"<Channel>.*</Channel>", re.IGNORECASE), 2.0),
        (re.compile(r"<Provider\s+Name=", re.IGNORECASE), 2.0),
        # Text/CSV export format
        (re.compile(r"EventID\s*[=:]\s*\d+", re.IGNORECASE), 2.5),
        (re.compile(r"Keywords\s*[=:]", re.IGNORECASE), 1.5),
        (re.compile(r"Log Name\s*:", re.IGNORECASE), 2.0),
        (re.compile(r"Source Name\s*:", re.IGNORECASE), 1.5),
        (re.compile(r"Event Type\s*:", re.IGNORECASE), 1.5),
        # Security-specific
        (re.compile(r"Security\s+ID\s*:", re.IGNORECASE), 1.5),
        (re.compile(r"Account\s+Name\s*:", re.IGNORECASE), 1.0),
        (re.compile(r"Logon\s+Type\s*:", re.IGNORECASE), 1.5),
        # EVTX binary marker
        (re.compile(r"ElfFile", re.IGNORECASE), 2.0),
    ],
)

# ---------------------------------------------------------------------------
# Linux Syslog (RFC 3164 + RFC 5424) signatures
# ---------------------------------------------------------------------------
_LINUX_SYSLOG_SIGNATURES = DetectionSignature(
    log_type=LogType.LINUX_SYSLOG,
    patterns=[
        # RFC 3164: "Mon DD HH:MM:SS hostname process[pid]: message"
        (
            re.compile(
                r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}",
                re.IGNORECASE | re.MULTILINE,
            ),
            3.0,
        ),
        # RFC 5424: "<priority>VERSION TIMESTAMP HOSTNAME APP-NAME"
        (re.compile(r"^<\d{1,3}>\d+\s+\d{4}-\d{2}-\d{2}T"), 3.0),
        # Common syslog services
        (re.compile(r"\b(sshd|sudo|su|kernel|cron|systemd|auth|authpriv)\[?\d*\]?:", re.IGNORECASE), 2.5),
        # SSH patterns
        (re.compile(r"(Failed password|Accepted password|Invalid user|Disconnected from|authentication failure)", re.IGNORECASE), 2.0),
        # sudo/su
        (re.compile(r"(sudo|su)\s*:.*TTY=", re.IGNORECASE), 2.0),
        # PAM
        (re.compile(r"pam_unix\(", re.IGNORECASE), 1.5),
        # Kernel
        (re.compile(r"kernel:\s+\[[\d.]+\]", re.IGNORECASE), 2.0),
    ],
)

# ---------------------------------------------------------------------------
# Apache Access Log (Combined Log Format) signatures
# ---------------------------------------------------------------------------
_APACHE_ACCESS_SIGNATURES = DetectionSignature(
    log_type=LogType.APACHE_ACCESS,
    patterns=[
        # Combined Log Format: IP - - [DD/Mon/YYYY:HH:MM:SS +ZONE] "METHOD /path HTTP/1.x" status bytes
        (
            re.compile(
                r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+-\s+-\s+\[\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\]'
            ),
            4.0,
        ),
        # HTTP method in quoted string
        (re.compile(r'"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT)\s+/'), 2.5),
        # HTTP/1.x or HTTP/2
        (re.compile(r'HTTP/\d\.\d"\s+\d{3}\s+\d+'), 2.5),
        # Apache error log format
        (re.compile(r"\[error\]|\[warn\]|\[notice\]|\[info\]|\[debug\]", re.IGNORECASE), 1.5),
        (re.compile(r"AH\d{5}:", re.IGNORECASE), 2.0),  # Apache error codes
        # Referer / User-Agent (extended combined format)
        (re.compile(r'"-"\s+"Mozilla/'), 1.0),
    ],
)

# ---------------------------------------------------------------------------
# Nginx Access Log signatures
# ---------------------------------------------------------------------------
_NGINX_ACCESS_SIGNATURES = DetectionSignature(
    log_type=LogType.NGINX_ACCESS,
    patterns=[
        # Nginx default: IP - user [date] "request" status bytes "referer" "agent"
        (
            re.compile(
                r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+-\s+\S+\s+\[\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\]'
            ),
            3.5,
        ),
        # Nginx error log format: "YYYY/MM/DD HH:MM:SS [level] PID#TID: *CID message"
        (
            re.compile(
                r"^\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\s+\[(error|warn|notice|info|debug|crit|emerg|alert)\]",
                re.IGNORECASE,
            ),
            3.5,
        ),
        # Nginx-specific upstream/proxy fields
        (re.compile(r"upstream|proxy_pass|fastcgi|uwsgi", re.IGNORECASE), 2.0),
        # Nginx error keywords
        (re.compile(r"(connect\(\) failed|no live upstreams|recv\(\) failed)", re.IGNORECASE), 2.0),
        # HTTP method (shared with Apache but weighted lower here)
        (re.compile(r'"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+/'), 1.5),
        # Nginx worker process
        (re.compile(r"nginx/\d+\.\d+\.\d+", re.IGNORECASE), 2.5),
    ],
)

# ---------------------------------------------------------------------------
# Sysmon XML Event Log signatures
# ---------------------------------------------------------------------------
_SYSMON_SIGNATURES = DetectionSignature(
    log_type=LogType.SYSMON,
    patterns=[
        # Sysmon provider name in XML
        (re.compile(r"Microsoft-Windows-Sysmon", re.IGNORECASE), 4.0),
        # Sysmon event IDs (1–29) in XML
        (re.compile(r"<EventID>(1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29)</EventID>"), 3.0),
        # Sysmon-specific field names
        (re.compile(r"<Data\s+Name=\"(ProcessGuid|ProcessId|Image|CommandLine|CurrentDirectory|Hashes|ParentImage)\"", re.IGNORECASE), 3.0),
        (re.compile(r"<Data\s+Name=\"(TargetFilename|CreationUtcTime|SourceIp|DestinationIp|DestinationPort)\"", re.IGNORECASE), 2.5),
        # RuleName field (unique to Sysmon)
        (re.compile(r"<Data\s+Name=\"RuleName\"", re.IGNORECASE), 2.5),
        # MD5/SHA256 hash in Hashes field
        (re.compile(r"MD5=[A-Fa-f0-9]{32}|SHA256=[A-Fa-f0-9]{64}", re.IGNORECASE), 2.0),
    ],
)


# =============================================================================
# All signatures in priority order (most specific first)
# =============================================================================

_ALL_SIGNATURES: list[DetectionSignature] = [
    _SYSMON_SIGNATURES,         # Must come before Windows Event (more specific)
    _WINDOWS_EVENT_SIGNATURES,
    _LINUX_SYSLOG_SIGNATURES,
    _APACHE_ACCESS_SIGNATURES,
    _NGINX_ACCESS_SIGNATURES,
]


# =============================================================================
# Detector
# =============================================================================

@dataclass
class DetectionResult:
    """Result of log type detection."""

    log_type: LogType
    confidence: float
    scores: dict[str, float] = field(default_factory=dict)

    @property
    def is_confident(self) -> bool:
        return self.confidence >= CONFIDENCE_THRESHOLD

    def __str__(self) -> str:
        return (
            f"DetectionResult(type={self.log_type.value!r}, "
            f"confidence={self.confidence:.2f}, "
            f"confident={self.is_confident})"
        )


class LogTypeDetector:
    """
    Heuristic-based log type detector.

    Samples the first SAMPLE_LINES lines of raw content and scores
    each supported format using its signature patterns.

    Returns the highest-scoring format, or LogType.UNKNOWN if no
    format exceeds the CONFIDENCE_THRESHOLD.

    Usage:
        detector = LogTypeDetector()
        result = detector.detect(raw_content)
        print(result.log_type, result.confidence)
    """

    def detect(self, raw_content: str) -> DetectionResult:
        """
        Detect the log type of the given raw content.

        Args:
            raw_content: Full raw text of the uploaded log file.

        Returns:
            DetectionResult with the best-matching LogType and confidence.
        """
        sample = self._extract_sample(raw_content)

        if not sample:
            logger.warning("Empty log content — returning UNKNOWN")
            return DetectionResult(
                log_type=LogType.UNKNOWN,
                confidence=0.0,
            )

        # Score every signature
        scores: dict[LogType, float] = {}
        for sig in _ALL_SIGNATURES:
            score = sig.score(sample)
            scores[sig.log_type] = score
            logger.debug(
                "Detection score: %s → %.2f",
                sig.log_type.value,
                score,
            )

        best_type = max(scores, key=lambda t: scores[t])
        best_score = scores[best_type]

        if best_score < CONFIDENCE_THRESHOLD:
            logger.info(
                "No format exceeded confidence threshold %.2f — "
                "best was %s at %.2f. Returning UNKNOWN.",
                CONFIDENCE_THRESHOLD,
                best_type.value,
                best_score,
            )
            return DetectionResult(
                log_type=LogType.UNKNOWN,
                confidence=best_score,
                scores={t.value: s for t, s in scores.items()},
            )

        logger.info(
            "Detected log type: %s (confidence=%.2f)",
            best_type.value,
            best_score,
        )
        return DetectionResult(
            log_type=best_type,
            confidence=best_score,
            scores={t.value: s for t, s in scores.items()},
        )

    def detect_with_override(
        self,
        raw_content: str,
        force_log_type: LogType | None,
    ) -> DetectionResult:
        """
        Detect log type, but allow caller to force a specific type.

        If force_log_type is provided, skip detection and return it
        with confidence=1.0. Used when the user specifies the format
        explicitly via the API.

        Args:
            raw_content: Full raw text of the log file.
            force_log_type: Optional override.

        Returns:
            DetectionResult.
        """
        if force_log_type is not None and force_log_type != LogType.UNKNOWN:
            logger.info(
                "Log type forced by caller: %s",
                force_log_type.value,
            )
            return DetectionResult(
                log_type=force_log_type,
                confidence=1.0,
                scores={force_log_type.value: 1.0},
            )
        return self.detect(raw_content)

    def _extract_sample(self, raw_content: str) -> list[str]:
        """Extract the first SAMPLE_LINES non-empty lines for scoring."""
        lines: list[str] = []
        for line in raw_content.splitlines():
            stripped = line.strip()
            if stripped:
                lines.append(stripped)
            if len(lines) >= SAMPLE_LINES:
                break
        return lines
