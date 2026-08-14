"""
SentinelX AI — Apache Access Log Parser
==========================================
Parses Apache HTTP Server logs in Combined Log Format and Common Log Format.

Combined Log Format:
  %h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"

Example:
  192.168.1.1 - frank [01/Jul/2025:10:23:11 +0000] "GET /admin HTTP/1.1" 200 4823 "-" "Mozilla/5.0"

Apache Error Log:
  [Fri Jul 01 10:23:11.123456 2025] [error] [pid 1234] [client 1.2.3.4:52431] message

Security patterns detected:
  - SQL Injection in URL/path        → T1190
  - XSS attempts in params           → T1059.007
  - Directory traversal              → T1083
  - 4xx/5xx status anomalies         → Web App Scanning
  - Large response bodies (exfil)    → T1041
  - Scanner User-Agent signatures    → T1595
  - Path scanning / 404 storms       → T1046
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from urllib.parse import unquote

from backend.models.security_log import LogType
from backend.nlp.parsers.base import BaseParser
from backend.nlp.parsers.registry import register_parser
from backend.schemas.logs import NormalizedEvent

logger = logging.getLogger(__name__)


@register_parser
class ApacheAccessParser(BaseParser):
    """
    Parser for Apache HTTP Server access and error logs.

    Extracts IP, method, path, status, bytes, referer, user-agent,
    and detects common web attack patterns in the request URI.
    """

    LOG_TYPE = LogType.APACHE_ACCESS

    # ── Combined / Common Log Format ──────────────────────────────────────────
    # %h   %l  %u  %t                           "%r"                 %>s %b  "%{Referer}i"  "%{UA}i"
    _COMBINED = re.compile(
        r'^(?P<ip>[\d.:a-fA-F]+)\s+'           # Client IP
        r'(?P<ident>\S+)\s+'                   # Ident (usually -)
        r'(?P<user>\S+)\s+'                    # Auth user
        r'\[(?P<time>[^\]]+)\]\s+'             # Timestamp [DD/Mon/YYYY:HH:MM:SS ±HHMM]
        r'"(?P<method>[A-Z]+)\s+'              # HTTP Method
        r'(?P<path>[^\s"]+)\s+'               # Request path
        r'(?P<protocol>HTTP/[\d.]+)"\s+'       # Protocol
        r'(?P<status>\d{3})\s+'               # Status code
        r'(?P<bytes>\d+|-)'                    # Response bytes
        r'(?:\s+"(?P<referer>[^"]*)"\s+'       # Referer (optional)
        r'"(?P<ua>[^"]*)")?',                  # User-Agent (optional)
    )

    # ── Apache error log ──────────────────────────────────────────────────────
    _ERROR = re.compile(
        r'^\[(?P<time>[^\]]+)\]\s+'
        r'\[(?P<level>[a-z]+)\]\s+'
        r'(?:\[pid\s+(?P<pid>\d+)\]\s+)?'
        r'(?:\[client\s+(?P<ip>[\d.:a-fA-F]+)(?::\d+)?\]\s+)?'
        r'(?P<message>.+)$',
        re.IGNORECASE,
    )

    # ── Apache timestamp format ───────────────────────────────────────────────
    _TS_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

    # ── Security attack patterns in URL ───────────────────────────────────────
    _SQL_INJECTION = re.compile(
        r"(?i)(\bunion\b.+\bselect\b|"
        r"\bselect\b.+\bfrom\b|"
        r"(?:--|#|/\*).+|"
        r"\b(drop|truncate|insert|update|delete)\s+\b(table|into|from)\b|"
        r"(?:OR|AND)\s+['\"]?\d+['\"]?\s*[=<>]|"
        r"information_schema|"
        r"sleep\s*\(\s*\d+|"
        r"benchmark\s*\()"
    )
    _XSS = re.compile(
        r"(?i)(<script|javascript:|vbscript:|"
        r"on(?:load|click|error|mouseover|focus|blur|change|submit|keyup|keydown)\s*=|"
        r"eval\s*\(|alert\s*\(|document\.cookie|"
        r"<iframe|<img[^>]+onerror|"
        r"&#x?\d+;)"
    )
    _DIR_TRAVERSAL = re.compile(r"\.\./|\.\.\\|%2e%2e|%252e%252e", re.IGNORECASE)
    _CMD_INJECTION = re.compile(
        r"(?i)([;&|`$]\s*(?:ls|cat|id|whoami|uname|pwd|wget|curl|bash|sh|nc|ncat|python|perl|php)\b|"
        r"\|\s*(?:bash|sh|cmd\.exe)|"
        r"(?:exec|system|shell_exec|passthru|popen)\s*\()"
    )
    _SCANNER_UA = re.compile(
        r"(?i)(sqlmap|nmap|nikto|masscan|nessus|openvas|burpsuite|"
        r"metasploit|hydra|gobuster|dirbuster|w3af|acunetix|"
        r"havij|pangolin|ZmEu|zgrab|python-requests|go-http-client|"
        r"scanbot|crawler|spider|scraper)",
    )
    _PATH_SCAN_PATTERNS = re.compile(
        r"(?i)(?:/wp-admin|/wp-login|/admin|/phpmyadmin|/\.env|/\.git|"
        r"/web\.config|/etc/passwd|/proc/self|/manager/html|"
        r"\.php\?|xmlrpc\.php|/cgi-bin/|shell\.|cmd\.php)",
    )

    # Known security-relevant extensions
    _SENSITIVE_EXTS = re.compile(
        r"\.(?:php|asp|aspx|jsp|cgi|sh|bash|py|pl|rb|exe|dll|bat|cmd|ps1)(?:\?|$)",
        re.IGNORECASE,
    )

    # ─────────────────────────────────────────────────────────────────────────

    def can_parse(self, raw_content: str) -> float:
        sample = self._sample_lines(raw_content)
        combined_hits = self._count_pattern_matches(sample, self._COMBINED)
        error_hits = self._count_pattern_matches(sample, self._ERROR)
        total = len(sample) or 1
        return min(1.0, (combined_hits * 2 + error_hits) / (total * 2))

    def parse_line(self, line: str, line_number: int) -> NormalizedEvent | None:
        # Try Combined/Common Log Format first
        m = self._COMBINED.match(line)
        if m:
            return self._parse_access_line(m, line, line_number)

        # Try Apache error log
        m = self._ERROR.match(line)
        if m:
            return self._parse_error_line(m, line, line_number)

        return None

    def _parse_access_line(self, m: re.Match, line: str, line_number: int) -> NormalizedEvent:
        ip = m.group("ip")
        user = m.group("user")
        method = m.group("method")
        path = m.group("path")
        status = int(m.group("status"))
        bytes_str = m.group("bytes")
        referer = m.group("referer") or None
        ua = m.group("ua") or None
        time_str = m.group("time")

        # Decode URL encoding for attack detection
        decoded_path = self._safe_unquote(path)

        # Parse timestamp
        timestamp_raw = time_str
        event_timestamp = self._parse_apache_ts(time_str)

        # Detect attack patterns
        event_type, extra = self._classify_request(decoded_path, status, ua, method, bytes_str)

        event = NormalizedEvent(
            log_type=self.LOG_TYPE.value,
            raw_line=line,
            line_number=line_number,
            event_type=event_type,
            source_ip=ip,
            username=user if user != "-" else None,
            url=path,
            http_method=method,
            http_status_code=status,
            user_agent=ua,
            timestamp_raw=timestamp_raw,
            event_timestamp=event_timestamp,
            service="HTTP",
            dest_port=80,
            protocol="HTTP",
            normalized_data={
                "referer": referer,
                "bytes": int(bytes_str) if bytes_str and bytes_str.isdigit() else 0,
                "decoded_path": decoded_path if decoded_path != path else None,
                **extra,
            },
        )
        return event

    def _parse_error_line(self, m: re.Match, line: str, line_number: int) -> NormalizedEvent:
        level = m.group("level").lower()
        ip = m.group("ip")
        pid_str = m.group("pid")
        message = m.group("message")
        time_str = m.group("time")

        return NormalizedEvent(
            log_type=self.LOG_TYPE.value,
            raw_line=line,
            line_number=line_number,
            event_type="Web Server Error",
            source_ip=ip,
            process_id=int(pid_str) if pid_str else None,
            timestamp_raw=time_str,
            event_timestamp=self._parse_error_ts(time_str),
            service="HTTP",
            normalized_data={
                "level": level,
                "message": message,
                "is_error": level in ("error", "crit", "emerg", "alert"),
            },
        )

    def _classify_request(
        self,
        path: str,
        status: int,
        ua: str | None,
        method: str,
        bytes_str: str,
    ) -> tuple[str, dict]:
        """Classify the HTTP request and return (event_type, extra_data)."""
        extra: dict = {}

        # SQL injection
        if self._SQL_INJECTION.search(path):
            extra["attack_type"] = "sql_injection"
            return "SQL Injection Attempt", extra

        # XSS
        if self._XSS.search(path):
            extra["attack_type"] = "xss"
            return "XSS Attempt", extra

        # Directory traversal
        if self._DIR_TRAVERSAL.search(path):
            extra["attack_type"] = "directory_traversal"
            return "Directory Traversal", extra

        # Command injection
        if self._CMD_INJECTION.search(path):
            extra["attack_type"] = "command_injection"
            return "Command Injection Attempt", extra

        # Scanner User-Agent
        if ua and self._SCANNER_UA.search(ua):
            extra["scanner_ua"] = ua
            return "Web Scanner", extra

        # Scanning patterns
        if self._PATH_SCAN_PATTERNS.search(path):
            extra["scan_path"] = path
            return "Web Scanning", extra

        # Large data transfer (potential exfil)
        if bytes_str and bytes_str.isdigit():
            size = int(bytes_str)
            if size > 10_000_000:  # 10MB response
                extra["response_bytes"] = size
                return "Large Data Transfer", extra

        # Status-based classification
        if status == 401:
            return "Unauthorized Access Attempt", extra
        if status == 403:
            return "Forbidden Access Attempt", extra
        if status >= 400:
            return "HTTP Client Error", extra
        if status >= 500:
            return "HTTP Server Error", extra

        return "HTTP Request", extra

    def _safe_unquote(self, path: str) -> str:
        try:
            return unquote(unquote(path))  # Double decode for %25xx
        except Exception:
            return path

    def _parse_apache_ts(self, ts: str) -> datetime | None:
        try:
            return datetime.strptime(ts.strip(), self._TS_FORMAT).astimezone(timezone.utc)
        except Exception:
            return None

    def _parse_error_ts(self, ts: str) -> datetime | None:
        """Apache error log: '[Fri Jul 01 10:23:11.123456 2025]'"""
        formats = [
            "%a %b %d %H:%M:%S.%f %Y",
            "%a %b %d %H:%M:%S %Y",
        ]
        for fmt in formats:
            try:
                return datetime.strptime(ts.strip(), fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None
