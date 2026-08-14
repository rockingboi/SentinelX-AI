"""
SentinelX AI — Nginx Access & Error Log Parser
================================================
Parses Nginx HTTP server logs in the default combined access format
and the standard Nginx error log format.

Nginx Default Access Format (log_format combined):
  $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
  "$http_referer" "$http_user_agent"

Nginx Error Format:
  YYYY/MM/DD HH:MM:SS [level] PID#TID: *CID message, client: IP, server: HOST,
  request: "METHOD /path HTTP/1.x", host: "HOST"

Security patterns detected (same web attack taxonomy as Apache):
  - SQL Injection        → T1190
  - XSS                 → T1059.007
  - Directory Traversal → T1083
  - Command Injection   → T1059
  - Web Scanning        → T1595
  - 4xx/5xx anomalies
  - Upstream/proxy errors (infrastructure recon)
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

# ── Shared attack patterns (same logic as Apache, centralised here) ──────────
_SQL_INJECTION = re.compile(
    r"(?i)(\bunion\b.+\bselect\b|\bselect\b.+\bfrom\b|(?:--|#|/\*)"
    r"|information_schema|sleep\s*\(\s*\d+|benchmark\s*\(|"
    r"\b(drop|truncate|insert|update|delete)\s+\b(table|into|from)\b|"
    r"(?:OR|AND)\s+['\"]?\d+['\"]?\s*[=<>])"
)
_XSS = re.compile(
    r"(?i)(<script|javascript:|on(?:load|click|error|mouseover|focus|blur)\s*=|"
    r"eval\s*\(|alert\s*\(|document\.cookie|<iframe|<img[^>]+onerror)"
)
_DIR_TRAVERSAL = re.compile(r"\.\./|\.\.\\|%2e%2e|%252e%252e", re.IGNORECASE)
_CMD_INJECTION = re.compile(
    r"(?i)([;&|`$]\s*(?:ls|cat|id|whoami|wget|curl|bash|sh|nc|python|perl)\b|"
    r"\|\s*(?:bash|sh|cmd\.exe)|(?:exec|system|shell_exec|passthru)\s*\()"
)
_SCANNER_UA = re.compile(
    r"(?i)(sqlmap|nmap|nikto|masscan|nessus|openvas|burpsuite|metasploit|"
    r"hydra|gobuster|dirbuster|w3af|acunetix|havij|ZmEu|zgrab|"
    r"python-requests|go-http-client|scanbot)"
)
_PATH_SCAN = re.compile(
    r"(?i)(/wp-admin|/wp-login|/admin|/phpmyadmin|/\.env|/\.git|"
    r"/web\.config|/etc/passwd|/proc/self|/manager/html|xmlrpc\.php|"
    r"/cgi-bin/|shell\.|cmd\.php)"
)


@register_parser
class NginxAccessParser(BaseParser):
    """
    Parser for Nginx access and error logs.

    Handles the default Nginx combined access format and the standard
    Nginx error log format. Applies the same web attack pattern detection
    as the Apache parser.
    """

    LOG_TYPE = LogType.NGINX_ACCESS

    # ── Nginx access log (combined format — same as Apache) ───────────────────
    _ACCESS = re.compile(
        r'^(?P<ip>[\d.:a-fA-F]+)\s+'
        r'(?P<ident>\S+)\s+'
        r'(?P<user>\S+)\s+'
        r'\[(?P<time>[^\]]+)\]\s+'
        r'"(?:(?P<method>[A-Z]+)\s+(?P<path>[^\s"]+)\s+(?P<protocol>HTTP/[\d.]+)|(?P<raw_req>[^"]+))"\s+'
        r'(?P<status>\d{3})\s+'
        r'(?P<bytes>\d+|-)'
        r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?',
    )

    # ── Nginx error log ───────────────────────────────────────────────────────
    # 2025/07/01 10:23:11 [error] 1234#5678: *91 connect() failed ...
    _ERROR = re.compile(
        r'^(?P<date>\d{4}/\d{2}/\d{2})\s+'
        r'(?P<time_part>\d{2}:\d{2}:\d{2})\s+'
        r'\[(?P<level>[a-z]+)\]\s+'
        r'(?P<pid>\d+)#(?P<tid>\d+):\s+'
        r'(?:\*(?P<cid>\d+)\s+)?'
        r'(?P<message>.+)$',
        re.IGNORECASE,
    )

    # ── Fields extracted from Nginx error message tail ────────────────────────
    _ERR_CLIENT = re.compile(r"client:\s+(?P<ip>[\d.:a-fA-F]+)", re.IGNORECASE)
    _ERR_SERVER = re.compile(r"server:\s+(?P<host>[^,]+)", re.IGNORECASE)
    _ERR_REQUEST = re.compile(
        r'request:\s+"(?P<method>[A-Z]+)\s+(?P<path>[^\s"]+)', re.IGNORECASE
    )
    _ERR_HOST = re.compile(r'host:\s+"(?P<host>[^"]+)"', re.IGNORECASE)
    _ERR_UPSTREAM = re.compile(
        r"(?:upstream:\s+\"?(?P<upstream>[^\s\",]+)|(?:connecting\s+to|from|timed?\s+out\s+(?:reading|while\s+sending)\s+to)\s+upstream)",
        re.IGNORECASE,
    )

    # ── Access timestamp format (same as Apache combined) ─────────────────────
    _TS_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

    # ─────────────────────────────────────────────────────────────────────────

    def can_parse(self, raw_content: str) -> float:
        sample = self._sample_lines(raw_content)
        access_hits = self._count_pattern_matches(sample, self._ACCESS)
        error_hits = self._count_pattern_matches(sample, self._ERROR)
        # Nginx error log has a unique YYYY/MM/DD timestamp prefix
        nginx_err_hits = sum(
            1 for l in sample
            if re.match(r"\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\s+\[", l)
        )
        total = len(sample) or 1
        return min(1.0, (access_hits * 1.5 + nginx_err_hits * 2 + error_hits) / (total * 2))

    def parse_line(self, line: str, line_number: int) -> NormalizedEvent | None:
        # Nginx error log (YYYY/MM/DD prefix is distinctive)
        if re.match(r"\d{4}/\d{2}/\d{2}", line):
            m = self._ERROR.match(line)
            if m:
                return self._parse_error_line(m, line, line_number)

        # Nginx access log
        m = self._ACCESS.match(line)
        if m:
            return self._parse_access_line(m, line, line_number)

        return None

    def _parse_access_line(self, m: re.Match, line: str, line_number: int) -> NormalizedEvent:
        ip = m.group("ip")
        user = m.group("user")
        method = m.group("method") or ""
        path = m.group("path") or m.group("raw_req") or ""
        status = int(m.group("status"))
        bytes_str = m.group("bytes") or "0"
        ua = m.group("ua")
        referer = m.group("referer")
        time_str = m.group("time")

        decoded_path = self._safe_unquote(path)
        event_type, extra = self._classify(decoded_path, status, ua, method, bytes_str)

        event = NormalizedEvent(
            log_type=self.LOG_TYPE.value,
            raw_line=line,
            line_number=line_number,
            event_type=event_type,
            source_ip=ip,
            username=user if user != "-" else None,
            url=path,
            http_method=method or None,
            http_status_code=status,
            user_agent=ua,
            timestamp_raw=time_str,
            event_timestamp=self._parse_ts(time_str),
            service="HTTP",
            protocol="HTTP",
            dest_port=80,
            normalized_data={
                "referer": referer if referer and referer != "-" else None,
                "bytes": int(bytes_str) if bytes_str.isdigit() else 0,
                **extra,
            },
        )
        return event

    def _parse_error_line(self, m: re.Match, line: str, line_number: int) -> NormalizedEvent:
        date_str = m.group("date")
        time_str = m.group("time_part")
        level = m.group("level").lower()
        pid = m.group("pid")
        message = m.group("message")

        # Parse timestamp
        try:
            event_timestamp = datetime.strptime(
                f"{date_str} {time_str}", "%Y/%m/%d %H:%M:%S"
            ).replace(tzinfo=timezone.utc)
            timestamp_raw = f"{date_str} {time_str}"
        except ValueError:
            event_timestamp = None
            timestamp_raw = f"{date_str} {time_str}"

        # Extract embedded fields from error message
        ip = None
        m_c = self._ERR_CLIENT.search(message)
        if m_c:
            ip = m_c.group("ip")

        method = path = None
        m_r = self._ERR_REQUEST.search(message)
        if m_r:
            method = m_r.group("method")
            path = m_r.group("path")

        hostname = None
        m_h = self._ERR_HOST.search(message) or self._ERR_SERVER.search(message)
        if m_h:
            hostname = m_h.group("host").strip()

        upstream = None
        m_u = self._ERR_UPSTREAM.search(message)
        if m_u:
            # Named group 'upstream' only exists for 'upstream: URL' pattern
            upstream = m_u.group("upstream") if m_u.lastindex and m_u.group("upstream") else "upstream"

        # Classify error event type — upstream takes priority over level
        if upstream:
            event_type = "Upstream Proxy Error"
        elif level in ("error", "crit", "emerg", "alert"):
            event_type = "Web Server Error"
        elif level == "warn":
            event_type = "Web Server Warning"
        else:
            event_type = "Web Server Event"

        return NginxAccessParser._make_event(
            log_type=self.LOG_TYPE.value,
            raw_line=line,
            line_number=line_number,
            event_type=event_type,
            source_ip=ip,
            http_method=method,
            url=path,
            hostname=hostname,
            process_id=int(pid) if pid else None,
            timestamp_raw=timestamp_raw,
            event_timestamp=event_timestamp,
            normalized_data={
                "level": level,
                "message": message[:500],
                "upstream": upstream,
            },
        )

    @staticmethod
    def _make_event(**kwargs) -> NormalizedEvent:
        return NormalizedEvent(**kwargs)

    def _classify(
        self,
        path: str,
        status: int,
        ua: str | None,
        method: str,
        bytes_str: str,
    ) -> tuple[str, dict]:
        extra: dict = {}
        if _SQL_INJECTION.search(path):
            extra["attack_type"] = "sql_injection"
            return "SQL Injection Attempt", extra
        if _XSS.search(path):
            extra["attack_type"] = "xss"
            return "XSS Attempt", extra
        if _DIR_TRAVERSAL.search(path):
            extra["attack_type"] = "directory_traversal"
            return "Directory Traversal", extra
        if _CMD_INJECTION.search(path):
            extra["attack_type"] = "command_injection"
            return "Command Injection Attempt", extra
        if ua and _SCANNER_UA.search(ua):
            extra["scanner_ua"] = ua
            return "Web Scanner", extra
        if _PATH_SCAN.search(path):
            extra["scan_path"] = path
            return "Web Scanning", extra
        if bytes_str.isdigit() and int(bytes_str) > 10_000_000:
            extra["response_bytes"] = int(bytes_str)
            return "Large Data Transfer", extra
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
            return unquote(unquote(path))
        except Exception:
            return path

    def _parse_ts(self, ts: str) -> datetime | None:
        try:
            return datetime.strptime(ts.strip(), self._TS_FORMAT).astimezone(timezone.utc)
        except Exception:
            return None
