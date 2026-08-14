"""
SentinelX AI — Linux Syslog Parser
=====================================
Parses Linux/Unix system logs in RFC 3164 and RFC 5424 formats.

Supported formats:
  RFC 3164: "Mon DD HH:MM:SS hostname process[pid]: message"
  RFC 5424: "<priority>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID MSG"
  Journald:  "YYYY-MM-DDTHH:MM:SS+TZ hostname process[pid]: message"

Key events detected:
  - SSH failed/accepted login (T1110 — Brute Force)
  - Invalid user (T1078 — Valid Accounts)
  - sudo/su privilege escalation (T1548.003)
  - PAM authentication failures
  - Kernel/OOM events
  - Cron job execution
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

from backend.models.security_log import LogType
from backend.nlp.parsers.base import BaseParser
from backend.nlp.parsers.registry import register_parser
from backend.schemas.logs import NormalizedEvent

logger = logging.getLogger(__name__)


@register_parser
class LinuxSyslogParser(BaseParser):
    """
    Parser for Linux Syslog (RFC 3164 / RFC 5424 / Journald).

    Detects security-relevant events: SSH brute force, privilege
    escalation, PAM failures, process execution, and kernel events.
    """

    LOG_TYPE = LogType.LINUX_SYSLOG

    # ── RFC 3164 Header ───────────────────────────────────────────────────────
    # Example: "Jul  1 10:23:11 server sshd[1234]: message"
    _RFC3164 = re.compile(
        r"^(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
        r"\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
        r"\s+(?P<hostname>\S+)"
        r"\s+(?P<process>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?"
        r":\s+(?P<message>.+)$",
        re.IGNORECASE,
    )

    # ── RFC 5424 Header ───────────────────────────────────────────────────────
    # Example: "<13>1 2025-07-01T10:23:11+00:00 server sshd 1234 - - message"
    _RFC5424 = re.compile(
        r"^<\d{1,3}>(?P<version>\d+)\s+"
        r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s]*)\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<process>\S+)\s+"
        r"(?P<pid>\S+)\s+\S+\s+\S+\s+"
        r"(?P<message>.+)$",
    )

    # ── Journald format ───────────────────────────────────────────────────────
    _JOURNALD = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s]*)\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<process>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s+"
        r"(?P<message>.+)$",
    )

    # ── SSH patterns ──────────────────────────────────────────────────────────
    _SSH_FAILED = re.compile(
        r"Failed (?P<method>password|publickey|keyboard-interactive) for "
        r"(?:invalid user )?(?P<username>\S+) from (?P<ip>[\d.:a-fA-F]+)"
        r"(?:\s+port\s+(?P<port>\d+))?",
        re.IGNORECASE,
    )
    _SSH_ACCEPTED = re.compile(
        r"Accepted (?P<method>password|publickey|keyboard-interactive) for "
        r"(?P<username>\S+) from (?P<ip>[\d.:a-fA-F]+)"
        r"(?:\s+port\s+(?P<port>\d+))?",
        re.IGNORECASE,
    )
    _SSH_INVALID = re.compile(
        r"Invalid user (?P<username>\S+) from (?P<ip>[\d.:a-fA-F]+)"
        r"(?:\s+port\s+(?P<port>\d+))?",
        re.IGNORECASE,
    )
    _SSH_DISCONNECT = re.compile(
        r"Disconnected from (?:invalid user )?(?P<username>\S+)?\s*"
        r"(?P<ip>[\d.:a-fA-F]+)(?:\s+port\s+(?P<port>\d+))?",
        re.IGNORECASE,
    )
    _SSH_MAX_AUTH = re.compile(
        r"error: maximum authentication attempts exceeded",
        re.IGNORECASE,
    )

    # ── Sudo/Su patterns ──────────────────────────────────────────────────────
    _SUDO = re.compile(
        r"(?P<username>\S+)\s*:\s*TTY=(?P<tty>\S+)\s*;\s*PWD=(?P<pwd>\S+)"
        r"\s*;\s*USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.+)$",
        re.IGNORECASE,
    )
    _SU = re.compile(
        r"(?:Successful su for|pam_unix\(su[^)]*\): session opened) "
        r"(?P<target_user>\S+) by (?P<username>\S+)",
        re.IGNORECASE,
    )
    _SU_FAILED = re.compile(
        r"(?:FAILED su for|pam_unix\(su[^)]*\): authentication failure.*user=(?P<username>\S+))",
        re.IGNORECASE,
    )

    # ── PAM ──────────────────────────────────────────────────────────────────
    _PAM_FAILURE = re.compile(
        r"pam_unix\([^)]*\): authentication failure.*?"
        r"(?:user=(?P<username>\S+))?.*?"
        r"(?:rhost=(?P<ip>[\d.:a-fA-F]+))?",
        re.IGNORECASE,
    )

    # ── OOM/Kernel ───────────────────────────────────────────────────────────
    _OOM = re.compile(
        r"Out of memory: Kill process (?P<pid>\d+) \((?P<process>[^)]+)\)",
        re.IGNORECASE,
    )
    _KERNEL_PANIC = re.compile(r"Kernel panic|kernel BUG|BUG: soft lockup", re.IGNORECASE)

    # ── Timestamp months ─────────────────────────────────────────────────────
    _MONTH_MAP = {
        "jan": 1, "feb": 2, "mar": 3, "apr": 4,
        "may": 5, "jun": 6, "jul": 7, "aug": 8,
        "sep": 9, "oct": 10, "nov": 11, "dec": 12,
    }

    # ─────────────────────────────────────────────────────────────────────────

    def can_parse(self, raw_content: str) -> float:
        sample = self._sample_lines(raw_content)
        rfc3164_hits = self._count_pattern_matches(sample, self._RFC3164)
        rfc5424_hits = self._count_pattern_matches(sample, self._RFC5424)
        journald_hits = self._count_pattern_matches(sample, self._JOURNALD)
        total = len(sample) or 1
        return min(1.0, (rfc3164_hits + rfc5424_hits + journald_hits) / total)

    def parse_line(self, line: str, line_number: int) -> NormalizedEvent | None:
        """Parse one syslog line into a NormalizedEvent."""
        m = self._RFC3164.match(line) or self._RFC5424.match(line) or self._JOURNALD.match(line)
        if m is None:
            return None

        groups = m.groupdict()
        process = groups.get("process", "").lower()
        message = groups.get("message", "")
        hostname = groups.get("hostname")
        pid_str = groups.get("pid")
        process_id = int(pid_str) if pid_str and pid_str.isdigit() else None
        timestamp_raw, event_timestamp = self._parse_timestamp(groups)

        event = NormalizedEvent(
            log_type=self.LOG_TYPE.value,
            raw_line=line,
            line_number=line_number,
            hostname=hostname,
            process_name=groups.get("process"),
            process_id=process_id,
            timestamp_raw=timestamp_raw,
            event_timestamp=event_timestamp,
            service=self._detect_service(process),
        )

        # ── SSH failed login ────────────────────────────────────────────
        if "sshd" in process:
            m2 = self._SSH_FAILED.search(message)
            if m2:
                event.event_type = "Failed Login"
                event.username = m2.group("username")
                event.source_ip = m2.group("ip")
                port = m2.group("port")
                event.source_port = int(port) if port else None
                event.service = "SSH"
                return event

            m2 = self._SSH_ACCEPTED.search(message)
            if m2:
                event.event_type = "Successful Login"
                event.username = m2.group("username")
                event.source_ip = m2.group("ip")
                port = m2.group("port")
                event.source_port = int(port) if port else None
                event.service = "SSH"
                return event

            m2 = self._SSH_INVALID.search(message)
            if m2:
                event.event_type = "Invalid User"
                event.username = m2.group("username")
                event.source_ip = m2.group("ip")
                event.service = "SSH"
                return event

            if self._SSH_MAX_AUTH.search(message):
                event.event_type = "Brute Force"
                event.service = "SSH"
                return event

        # ── Sudo escalation ──────────────────────────────────────────────
        if "sudo" in process:
            m2 = self._SUDO.search(message)
            if m2:
                event.event_type = "Privilege Escalation"
                event.username = m2.group("username")
                event.command_line = m2.group("command")
                event.service = "sudo"
                event.normalized_data = {
                    "tty": m2.group("tty"),
                    "working_dir": m2.group("pwd"),
                    "target_user": m2.group("target_user"),
                }
                return event

        # ── PAM auth failure ─────────────────────────────────────────────
        if "pam_unix" in message.lower():
            m2 = self._PAM_FAILURE.search(message)
            if m2:
                event.event_type = "Authentication Failure"
                username = m2.group("username")
                ip = m2.group("ip")
                if username:
                    event.username = username
                if ip:
                    event.source_ip = ip
                return event

        # ── OOM Killer ───────────────────────────────────────────────────
        m2 = self._OOM.search(message)
        if m2:
            event.event_type = "System Event"
            event.process_name = m2.group("process")
            event.process_id = int(m2.group("pid"))
            event.normalized_data = {"oom_kill": True}
            return event

        # ── Kernel panic ─────────────────────────────────────────────────
        if self._KERNEL_PANIC.search(message):
            event.event_type = "System Event"
            event.normalized_data = {"kernel_panic": True}
            return event

        # ── Generic syslog line (parsed but not specifically classified) ──
        event.event_type = "System Log"
        return event

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _parse_timestamp(self, groups: dict) -> tuple[str, datetime | None]:
        """Return (raw_str, UTC datetime) from parsed groups."""
        raw = ""
        dt = None
        try:
            if "month" in groups and groups.get("month"):
                raw = f"{groups['month']} {groups['day']} {groups['time']}"
                year = datetime.now(timezone.utc).year
                month = self._MONTH_MAP.get(groups["month"].lower(), 1)
                day = int(groups["day"])
                h, mi, s = (int(x) for x in groups["time"].split(":"))
                dt = datetime(year, month, day, h, mi, s, tzinfo=timezone.utc)
            elif "timestamp" in groups and groups.get("timestamp"):
                raw = groups["timestamp"]
                ts = groups["timestamp"].replace("Z", "+00:00")
                # Truncate nanoseconds if present
                if "." in ts:
                    base, frac = ts.split(".", 1)
                    frac_clean = frac[:6] + frac[6:].lstrip("0123456789")
                    ts = base + "." + frac_clean
                dt = datetime.fromisoformat(ts).astimezone(timezone.utc)
        except Exception:
            pass
        return raw, dt

    def _detect_service(self, process: str) -> str | None:
        service_map = {
            "sshd": "SSH", "ssh": "SSH",
            "sudo": "sudo", "su": "su",
            "cron": "cron", "crond": "cron",
            "httpd": "HTTP", "apache2": "HTTP", "nginx": "HTTP",
            "mysqld": "MySQL", "postgres": "PostgreSQL",
            "kernel": "kernel", "systemd": "systemd",
        }
        for key, svc in service_map.items():
            if key in process:
                return svc
        return None
