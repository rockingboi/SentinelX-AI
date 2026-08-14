"""
SentinelX AI — IOC Extractor Engine
======================================
Core extraction class that applies all IOC patterns to text or NormalizedEvent
objects and returns validated, deduplicated ExtractedIOC results.

Architecture:
  - IOCExtractor.extract_from_text()  → for raw text input
  - IOCExtractor.extract_from_event() → for NormalizedEvent (uses all text fields)
  - All extraction is deterministic — no LLMs, no external calls
  - Thread-safe: all state is in local variables, not instance attributes
  - Validation pipeline:
      raw_match → refang → validate → deduplicate → score confidence

Confidence scoring:
  1.0 — high-confidence validated IOC (valid IP, known TLD, correct hash length)
  0.7 — moderate confidence (domain without TLD validation, labelled field)
  0.5 — low confidence (unlabelled, heuristic match only)

Output type: List[ExtractedIOC]
  - ExtractedIOC is a Pydantic model that maps 1:1 to the IOCEntity ORM model.
  - The NLP pipeline passes this list to the repository layer for persistence.
"""
from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from typing import Iterator

try:
    import tldextract  # type: ignore[import-untyped]
    _HAS_TLDEXTRACT = True
except ImportError:
    _HAS_TLDEXTRACT = False

from backend.models.ioc_entity import IOCType
from backend.nlp.extractor import patterns as P
from backend.schemas.logs import NormalizedEvent

logger = logging.getLogger(__name__)


# ── Output dataclass ──────────────────────────────────────────────────────────

@dataclass(frozen=True, order=True)
class ExtractedIOC:
    """
    A single validated, deduplicated Indicator of Compromise.

    This is the contract between the NLP extractor and the persistence layer.
    It maps directly to the IOCEntity ORM model fields.
    """
    ioc_type: IOCType
    value: str
    confidence: float = field(compare=False)
    context: str | None = field(default=None, compare=False)
    source_field: str | None = field(default=None, compare=False)  # Which field it came from

    def __hash__(self) -> int:  # type: ignore[override]
        return hash((self.ioc_type, self.value))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ExtractedIOC):
            return NotImplemented
        return self.ioc_type == other.ioc_type and self.value == other.value


# ── Main Extractor ────────────────────────────────────────────────────────────

class IOCExtractor:
    """
    Deterministic IOC extractor using compiled regex patterns + validation.

    Usage:
        extractor = IOCExtractor()
        iocs = extractor.extract_from_text("185.24.18.15 hit evil.com/payload")
        iocs = extractor.extract_from_event(normalized_event)
    """

    def __init__(self, include_private_ips: bool = False) -> None:
        """
        Args:
            include_private_ips: If True, private/RFC1918 IPs are included.
                                  Default False — only routable IPs emitted.
        """
        self._include_private_ips = include_private_ips

    # ── Public API ────────────────────────────────────────────────────────────

    def extract_from_text(
        self,
        text: str,
        context: str | None = None,
        source_field: str | None = None,
    ) -> list[ExtractedIOC]:
        """
        Extract all IOCs from a raw text string.

        Args:
            text:         Raw text to scan.
            context:      Optional label for where this text came from.
            source_field: Name of the NormalizedEvent field this came from.

        Returns:
            Deduplicated, validated list of ExtractedIOC objects.
        """
        if not text or not text.strip():
            return []

        # Refang defanged indicators before extracting
        refanged = P._refang(text)
        seen: dict[tuple[IOCType, str], ExtractedIOC] = {}

        for ioc in self._extract_all(refanged, text, context, source_field):
            key = (ioc.ioc_type, ioc.value)
            # Keep the higher-confidence match on duplicate
            if key not in seen or ioc.confidence > seen[key].confidence:
                seen[key] = ioc

        return list(seen.values())

    def extract_from_event(self, event: NormalizedEvent) -> list[ExtractedIOC]:
        """
        Extract IOCs from all text fields of a NormalizedEvent.

        Scans: raw_line, source_ip, dest_ip, url, username, hostname,
               command_line, process_name, file_path, user_agent,
               and all values inside normalized_data.

        Returns:
            Deduplicated, validated list of ExtractedIOC objects.
        """
        seen: dict[tuple[IOCType, str], ExtractedIOC] = {}

        def _add(iocs: list[ExtractedIOC]) -> None:
            for ioc in iocs:
                key = (ioc.ioc_type, ioc.value)
                if key not in seen or ioc.confidence > seen[key].confidence:
                    seen[key] = ioc

        # ── Structured fields — high confidence ───────────────────────────────
        if event.source_ip:
            _add(self._extract_ip_from_field(event.source_ip, "source_ip"))
        if event.dest_ip:
            _add(self._extract_ip_from_field(event.dest_ip, "dest_ip"))
        if event.url:
            _add(self.extract_from_text(event.url, source_field="url"))
        if event.username:
            ioc = self._validate_username(event.username, "username")
            if ioc:
                _add([ioc])
        if event.hostname:
            ioc = self._validate_domain(event.hostname, "hostname", confidence=0.8)
            if ioc:
                _add([ioc])
        if event.process_name:
            ioc = self._validate_filename(event.process_name, "process_name")
            if ioc:
                _add([ioc])
        if event.command_line:
            _add(self.extract_from_text(event.command_line, source_field="command_line"))
        if event.file_path:
            _add(self.extract_from_text(event.file_path, source_field="file_path"))
        if event.user_agent:
            # Don't extract IOCs from UA strings — too noisy
            pass

        # ── Ports ─────────────────────────────────────────────────────────────
        if event.source_port and self._is_interesting_port(event.source_port):
            _add([ExtractedIOC(
                ioc_type=IOCType.PORT,
                value=str(event.source_port),
                confidence=0.9,
                source_field="source_port",
            )])
        if event.dest_port and self._is_interesting_port(event.dest_port):
            _add([ExtractedIOC(
                ioc_type=IOCType.PORT,
                value=str(event.dest_port),
                confidence=0.9,
                source_field="dest_port",
            )])

        # ── Normalized data dict ──────────────────────────────────────────────
        if event.normalized_data:
            for key, val in event.normalized_data.items():
                if isinstance(val, str) and len(val) > 2:
                    _add(self.extract_from_text(val, source_field=f"normalized_data.{key}"))

        # ── Raw line (catch anything missed above) ────────────────────────────
        if event.raw_line:
            raw_iocs = self.extract_from_text(
                event.raw_line, source_field="raw_line"
            )
            # Lower confidence for raw line — may have been captured above already
            for ioc in raw_iocs:
                key = (ioc.ioc_type, ioc.value)
                if key not in seen:
                    seen[key] = ExtractedIOC(
                        ioc_type=ioc.ioc_type,
                        value=ioc.value,
                        confidence=ioc.confidence * 0.8,
                        context=ioc.context,
                        source_field="raw_line",
                    )

        return list(seen.values())

    # ── Extraction methods ────────────────────────────────────────────────────

    def _extract_all(
        self,
        refanged: str,
        original: str,
        context: str | None,
        source_field: str | None,
    ) -> Iterator[ExtractedIOC]:
        """Run all pattern extractors over the text."""
        yield from self._extract_hashes(refanged, context, source_field)
        yield from self._extract_ipv4(refanged, context, source_field)
        yield from self._extract_ipv6(refanged, context, source_field)
        yield from self._extract_cve(refanged, context, source_field)
        yield from self._extract_emails(refanged, context, source_field)
        yield from self._extract_urls(refanged, context, source_field)
        yield from self._extract_domains(refanged, context, source_field)
        yield from self._extract_file_paths(refanged, context, source_field)
        yield from self._extract_registry_keys(refanged, context, source_field)
        yield from self._extract_suspicious_filenames(refanged, context, source_field)
        yield from self._extract_sysmon_hashes(refanged, context, source_field)

    def _extract_hashes(
        self, text: str, context: str | None, source_field: str | None
    ) -> Iterator[ExtractedIOC]:
        """Extract SHA256 > SHA1 > MD5 — ordered most specific first."""
        sha256_spans: set[tuple[int, int]] = set()
        sha1_spans: set[tuple[int, int]] = set()

        for m in P.SHA256.finditer(text):
            val = m.group("sha256").lower()
            if val in P.BENIGN_HASHES:
                continue
            sha256_spans.add((m.start(), m.end()))
            yield ExtractedIOC(
                ioc_type=IOCType.SHA256,
                value=val,
                confidence=1.0,
                context=self._snippet(text, m.start()),
                source_field=source_field,
            )

        for m in P.SHA1.finditer(text):
            # Skip if overlaps with a SHA256 match
            if any(s <= m.start() < e for s, e in sha256_spans):
                continue
            val = m.group("sha1").lower()
            if val in P.BENIGN_HASHES:
                continue
            sha1_spans.add((m.start(), m.end()))
            yield ExtractedIOC(
                ioc_type=IOCType.SHA1,
                value=val,
                confidence=1.0,
                context=self._snippet(text, m.start()),
                source_field=source_field,
            )

        for m in P.MD5.finditer(text):
            if any(s <= m.start() < e for s, e in sha256_spans | sha1_spans):
                continue
            val = m.group("md5").lower()
            if val in P.BENIGN_HASHES:
                continue
            # MD5 false positive guard: skip if surrounded by hex context (part of larger hash)
            before = text[max(0, m.start()-1):m.start()]
            after = text[m.end():m.end()+1]
            if (before and re.match(r"[0-9a-fA-F]", before)) or \
               (after and re.match(r"[0-9a-fA-F]", after)):
                continue
            yield ExtractedIOC(
                ioc_type=IOCType.MD5,
                value=val,
                confidence=0.9,  # MD5 slightly lower — higher collision risk
                context=self._snippet(text, m.start()),
                source_field=source_field,
            )

    def _extract_sysmon_hashes(
        self, text: str, context: str | None, source_field: str | None
    ) -> Iterator[ExtractedIOC]:
        """Parse Sysmon-style 'MD5=...,SHA1=...,SHA256=...' hash fields."""
        for m in P.SYSMON_HASHES.finditer(text):
            if m.group("sha256"):
                val = m.group("sha256").lower()
                if val not in P.BENIGN_HASHES:
                    yield ExtractedIOC(IOCType.SHA256, val, 1.0, source_field=source_field)
            elif m.group("sha1"):
                val = m.group("sha1").lower()
                if val not in P.BENIGN_HASHES:
                    yield ExtractedIOC(IOCType.SHA1, val, 1.0, source_field=source_field)
            elif m.group("md5"):
                val = m.group("md5").lower()
                if val not in P.BENIGN_HASHES:
                    yield ExtractedIOC(IOCType.MD5, val, 0.9, source_field=source_field)

    def _extract_ipv4(
        self, text: str, context: str | None, source_field: str | None
    ) -> Iterator[ExtractedIOC]:
        """Extract and validate IPv4 addresses."""
        for m in P.IPV4.finditer(text):
            # Normalise: strip defang chars from the matched IP
            raw = m.group("ip")
            ip_str = re.sub(r"[\[\](){}]", "", raw)
            if ip_str in P.BENIGN_IPS:
                continue
            try:
                addr = ipaddress.IPv4Address(ip_str)
            except ValueError:
                continue
            if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
                continue
            if not self._include_private_ips and addr.is_private:
                continue
            yield ExtractedIOC(
                ioc_type=IOCType.IPV4,
                value=str(addr),
                confidence=1.0,
                context=self._snippet(text, m.start()),
                source_field=source_field,
            )

    def _extract_ipv6(
        self, text: str, context: str | None, source_field: str | None
    ) -> Iterator[ExtractedIOC]:
        """Extract and validate IPv6 addresses."""
        for m in P.IPV6.finditer(text):
            raw = m.group("ip6")
            try:
                addr = ipaddress.IPv6Address(raw)
            except ValueError:
                continue
            if addr.is_loopback or addr.is_unspecified:
                continue
            yield ExtractedIOC(
                ioc_type=IOCType.IPV6,
                value=str(addr),
                confidence=1.0,
                context=self._snippet(text, m.start()),
                source_field=source_field,
            )

    def _extract_cve(
        self, text: str, context: str | None, source_field: str | None
    ) -> Iterator[ExtractedIOC]:
        """Extract CVE identifiers."""
        for m in P.CVE.finditer(text):
            val = m.group("cve").upper()
            yield ExtractedIOC(
                ioc_type=IOCType.CVE,
                value=val,
                confidence=1.0,
                context=self._snippet(text, m.start()),
                source_field=source_field,
            )

    def _extract_emails(
        self, text: str, context: str | None, source_field: str | None
    ) -> Iterator[ExtractedIOC]:
        """Extract email addresses."""
        for m in P.EMAIL.finditer(text):
            val = m.group("email").lower()
            yield ExtractedIOC(
                ioc_type=IOCType.EMAIL,
                value=val,
                confidence=0.95,
                context=self._snippet(text, m.start()),
                source_field=source_field,
            )

    def _extract_urls(
        self, text: str, context: str | None, source_field: str | None
    ) -> Iterator[ExtractedIOC]:
        """Extract URLs (http/https/ftp/hxxp)."""
        for m in P.URL.finditer(text):
            val = m.group("url")
            # Normalise defanged scheme
            val = re.sub(r"(?i)hxxps?", lambda x: x.group().replace("xx", "tt"), val)
            # Truncate very long URLs
            val = val[:2048]
            yield ExtractedIOC(
                ioc_type=IOCType.URL,
                value=val,
                confidence=0.95,
                context=self._snippet(text, m.start()),
                source_field=source_field,
            )

    def _extract_domains(
        self, text: str, context: str | None, source_field: str | None
    ) -> Iterator[ExtractedIOC]:
        """
        Extract domain names.

        Uses tldextract when available for accurate TLD validation.
        Falls back to regex-based TLD check.
        """
        seen_in_urls: set[str] = {
            m.group("url") for m in P.URL.finditer(text)
        }
        for m in P.DOMAIN.finditer(text):
            # Skip if this domain is already captured as part of a URL
            raw = m.group("domain").lower()
            raw = re.sub(r"[\[\](){}]", "", raw)  # de-defang
            if raw in P.BENIGN_DOMAINS:
                continue
            if raw.replace(".", "").isdigit():
                continue  # pure IP, skip

            confidence = 0.8
            if _HAS_TLDEXTRACT:
                parsed = tldextract.extract(raw)
                if not parsed.suffix:
                    continue  # No valid TLD
                if not parsed.domain:
                    continue  # No domain label
                canonical = f"{parsed.domain}.{parsed.suffix}"
                if parsed.subdomain:
                    canonical = f"{parsed.subdomain}.{canonical}"
                raw = canonical
                confidence = 0.9

            yield ExtractedIOC(
                ioc_type=IOCType.DOMAIN,
                value=raw,
                confidence=confidence,
                context=self._snippet(text, m.start()),
                source_field=source_field,
            )

    def _extract_file_paths(
        self, text: str, context: str | None, source_field: str | None
    ) -> Iterator[ExtractedIOC]:
        """Extract Windows and Unix file paths."""
        for m in P.WIN_PATH.finditer(text):
            val = m.group("winpath")
            yield ExtractedIOC(
                ioc_type=IOCType.FILE_PATH,
                value=val,
                confidence=0.9,
                context=self._snippet(text, m.start()),
                source_field=source_field,
            )
        for m in P.UNIX_PATH.finditer(text):
            val = m.group("unixpath")
            # Skip very short paths like /a/b
            if len(val) < 6:
                continue
            yield ExtractedIOC(
                ioc_type=IOCType.FILE_PATH,
                value=val,
                confidence=0.85,
                context=self._snippet(text, m.start()),
                source_field=source_field,
            )

    def _extract_registry_keys(
        self, text: str, context: str | None, source_field: str | None
    ) -> Iterator[ExtractedIOC]:
        """Extract Windows registry key paths."""
        for m in P.REGISTRY_KEY.finditer(text):
            val = m.group("regkey")
            yield ExtractedIOC(
                ioc_type=IOCType.FILE_PATH,  # stored as FILE_PATH (registry path)
                value=val,
                confidence=1.0,
                context=self._snippet(text, m.start()),
                source_field=source_field,
            )

    def _extract_suspicious_filenames(
        self, text: str, context: str | None, source_field: str | None
    ) -> Iterator[ExtractedIOC]:
        """Extract suspicious filenames (executable/script extensions)."""
        for m in P.SUSPICIOUS_FILENAME.finditer(text):
            val = m.group("filename").lower()
            yield ExtractedIOC(
                ioc_type=IOCType.FILENAME,
                value=val,
                confidence=0.75,
                context=self._snippet(text, m.start()),
                source_field=source_field,
            )

    # ── Field-specific helpers ────────────────────────────────────────────────

    def _extract_ip_from_field(
        self, ip_str: str, source_field: str
    ) -> list[ExtractedIOC]:
        """Validate a known IP field value — highest confidence."""
        ip_str = ip_str.strip()
        if not ip_str or ip_str in ("-", "::1", "127.0.0.1", "0.0.0.0"):
            return []
        try:
            if ":" in ip_str:
                addr = ipaddress.IPv6Address(ip_str)
                return [ExtractedIOC(IOCType.IPV6, str(addr), 1.0, source_field=source_field)]
            else:
                addr = ipaddress.IPv4Address(ip_str)
                if addr.is_loopback or addr.is_unspecified:
                    return []
                if not self._include_private_ips and addr.is_private:
                    return []
                return [ExtractedIOC(IOCType.IPV4, str(addr), 1.0, source_field=source_field)]
        except ValueError:
            return []

    def _validate_username(self, username: str, source_field: str) -> ExtractedIOC | None:
        """Validate and emit a username IOC from a structured field."""
        username = username.strip()
        skip = {"-", "N/A", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE",
                "anonymous", "nobody", "", "null", "none"}
        if not username or username.upper() in {s.upper() for s in skip}:
            return None
        if len(username) < 2 or len(username) > 64:
            return None
        return ExtractedIOC(IOCType.USERNAME, username, 0.9, source_field=source_field)

    def _validate_domain(
        self, hostname: str, source_field: str, confidence: float = 0.8
    ) -> ExtractedIOC | None:
        """Validate a hostname/domain field."""
        hostname = hostname.strip().lower()
        if not hostname or hostname in P.BENIGN_DOMAINS:
            return None
        if hostname.replace(".", "").isdigit():
            return None  # It's an IP, handled elsewhere
        if len(hostname) < 3:
            return None
        return ExtractedIOC(IOCType.DOMAIN, hostname, confidence, source_field=source_field)

    def _validate_filename(self, fname: str, source_field: str) -> ExtractedIOC | None:
        """Extract filename from a full path or standalone name."""
        fname = fname.strip()
        if not fname:
            return None
        # Extract basename
        basename = fname.split("\\")[-1].split("/")[-1].lower()
        if not basename or len(basename) < 2:
            return None
        # Only emit executables/scripts as filename IOCs
        if P.SUSPICIOUS_FILENAME.match(basename):
            return ExtractedIOC(IOCType.FILENAME, basename, 0.85, source_field=source_field)
        return None

    @staticmethod
    def _is_interesting_port(port: int) -> bool:
        """Return True if the port is security-relevant (non-standard)."""
        boring = {80, 443, 22, 21, 25, 53, 8080, 8443, 3389, 445, 139,
                  135, 137, 138, 389, 636, 1433, 3306, 5432, 6379, 27017}
        return port not in boring and 1 <= port <= 65535

    @staticmethod
    def _snippet(text: str, pos: int, window: int = 80) -> str:
        """Return a short context snippet around a match position."""
        start = max(0, pos - window // 2)
        end = min(len(text), pos + window // 2)
        snippet = text[start:end].replace("\n", " ").strip()
        return snippet[:200]
