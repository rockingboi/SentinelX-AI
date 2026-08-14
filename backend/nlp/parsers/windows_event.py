"""
SentinelX AI — Windows Event Log Parser
==========================================
Parses Windows Event Logs in text export format (Event Viewer .txt/.csv)
and XML export format.

Supported EventIDs and their security significance:
  4624 — Successful Account Logon
  4625 — Failed Account Logon           → T1110 Brute Force
  4627 — Group Membership Info
  4648 — Logon with Explicit Credentials → T1550
  4656 — Handle to Object Requested
  4663 — Attempt to Access Object
  4672 — Special Privileges Assigned     → T1548
  4688 — Process Created                 → T1059
  4698 — Scheduled Task Created          → T1053
  4720 — User Account Created            → T1136
  4722 — User Account Enabled
  4724 — Password Reset Attempt
  4726 — User Account Deleted
  4732 — Member Added to Security Group
  4768 — Kerberos TGT Request
  4771 — Kerberos Pre-auth Failure       → T1558
  4776 — NTLM Auth Attempt
  7045 — New Service Installed           → T1543.003
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
class WindowsEventParser(BaseParser):
    """
    Parser for Windows Event Log text/XML exports.

    Handles both the structured text format produced by Event Viewer
    and the XML format from wevtutil or PowerShell Get-WinEvent.
    """

    LOG_TYPE = LogType.WINDOWS_EVENT

    # ── Text export patterns ──────────────────────────────────────────────────
    # Matches "Log Name:      Security" style key-value lines
    _KV_LINE = re.compile(r"^(?P<key>[A-Za-z\s]+):\s*(?P<value>.+)$")

    # Block separator — blank line or dashed line between events
    _BLOCK_SEP = re.compile(r"^[-=]{10,}$|^$")

    # EventID line detection
    _EVENTID_LINE = re.compile(r"Event\s*ID\s*[:\s=]\s*(?P<id>\d+)", re.IGNORECASE)

    # ── XML patterns ──────────────────────────────────────────────────────────
    _XML_EVENTID = re.compile(r"<EventID[^>]*>(?P<id>\d+)</EventID>", re.IGNORECASE)
    _XML_TIMESTAMP = re.compile(r"SystemTime='(?P<ts>[^']+)'", re.IGNORECASE)
    _XML_COMPUTER = re.compile(r"<Computer>(?P<host>[^<]+)</Computer>", re.IGNORECASE)
    _XML_CHANNEL = re.compile(r"<Channel>(?P<ch>[^<]+)</Channel>", re.IGNORECASE)
    _XML_DATA = re.compile(r"<Data\s+Name='(?P<name>[^']+)'>(?P<value>[^<]*)</Data>", re.IGNORECASE)

    # ── Field extraction from message text ───────────────────────────────────
    _ACCOUNT_NAME = re.compile(r"Account\s+Name\s*:\s*(?P<v>\S+)", re.IGNORECASE)
    _ACCOUNT_DOMAIN = re.compile(r"Account\s+Domain\s*:\s*(?P<v>\S+)", re.IGNORECASE)
    _LOGON_TYPE = re.compile(r"Logon\s+Type\s*:\s*(?P<v>\d+)", re.IGNORECASE)
    _SOURCE_IP = re.compile(
        r"(?:Source Network Address|Client Address|Network Address)\s*:\s*(?P<ip>[\d.:a-fA-F]+)",
        re.IGNORECASE,
    )
    _SOURCE_PORT = re.compile(
        r"(?:Source Port|Client Port)\s*:\s*(?P<port>\d+)",
        re.IGNORECASE,
    )
    _PROCESS_NAME = re.compile(r"(?:Process Name|New Process Name)\s*:\s*(?P<v>.+)", re.IGNORECASE)
    _PROCESS_ID = re.compile(r"(?:New Process ID|Process ID)\s*:\s*0x(?P<v>[0-9a-fA-F]+)", re.IGNORECASE)
    _COMMAND_LINE = re.compile(r"(?:Command Line|Process Command Line)\s*:\s*(?P<v>.+)", re.IGNORECASE)
    _SERVICE_NAME = re.compile(r"Service Name\s*:\s*(?P<v>.+)", re.IGNORECASE)
    _TASK_NAME = re.compile(r"Task Name\s*:\s*(?P<v>.+)", re.IGNORECASE)
    _DEST_ADDRESS = re.compile(
        r"(?:Destination Address|Network Destination Address)\s*:\s*(?P<ip>[\d.:a-fA-F]+)",
        re.IGNORECASE,
    )
    _DEST_PORT = re.compile(
        r"(?:Destination Port)\s*:\s*(?P<port>\d+)",
        re.IGNORECASE,
    )
    _DATE_TIME = re.compile(
        r"(?:Date|Date and Time|Logged)\s*:\s*(?P<ts>\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM)?)",
        re.IGNORECASE,
    )
    _ISO_TIMESTAMP = re.compile(
        r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))",
    )

    # ── EventID → event type mapping ──────────────────────────────────────────
    _EVENTID_TYPE_MAP: dict[int, str] = {
        4624: "Successful Login",
        4625: "Failed Login",
        4627: "Group Membership",
        4648: "Explicit Credential Logon",
        4656: "Object Access",
        4663: "Object Access",
        4672: "Privilege Escalation",
        4688: "Process Creation",
        4698: "Scheduled Task Created",
        4699: "Scheduled Task Deleted",
        4702: "Scheduled Task Modified",
        4720: "User Account Created",
        4722: "User Account Enabled",
        4724: "Password Reset",
        4725: "User Account Disabled",
        4726: "User Account Deleted",
        4732: "Security Group Modified",
        4740: "Account Lockout",
        4768: "Kerberos TGT Request",
        4769: "Kerberos Service Ticket",
        4771: "Kerberos Pre-auth Failure",
        4776: "NTLM Authentication",
        7045: "Service Installed",
        4657: "Registry Value Modified",
        4660: "Object Deleted",
        4670: "Permissions Changed",
    }

    # ─────────────────────────────────────────────────────────────────────────

    def can_parse(self, raw_content: str) -> float:
        sample = self._sample_lines(raw_content)
        score = 0.0
        total = len(sample) or 1

        eventid_hits = self._count_pattern_matches(sample, self._EVENTID_LINE)
        xml_hits = self._count_pattern_matches(sample, self._XML_EVENTID)
        kv_hits = self._count_pattern_matches(sample, self._KV_LINE)
        logname_hits = sum(
            1 for l in sample
            if re.search(r"Log Name\s*:", l, re.IGNORECASE)
        )

        score = (eventid_hits * 2 + xml_hits * 2 + logname_hits * 3) / (total * 3)
        return min(1.0, score)

    def parse_line(self, line: str, line_number: int) -> NormalizedEvent | None:
        """
        Parse a single Windows Event log line.

        Windows Event logs are multi-line records in text export.
        We detect the EventID line and extract all key fields from it.
        Since the pipeline calls parse_line() per-line, we handle
        both XML single-line events and detect EventID-bearing lines.
        """
        # ── XML format (one event per line) ──────────────────────────────────
        if line.strip().startswith("<Event"):
            return self._parse_xml_line(line, line_number)

        # ── EventID key-value line ────────────────────────────────────────────
        m = self._EVENTID_LINE.search(line)
        if m:
            event_id = int(m.group("id"))
            return self._parse_eventid_line(line, line_number, event_id)

        # ── Lines containing security field data (part of a multi-line block) ─
        # These carry useful fields — extract what we can and return as context
        if any(p.search(line) for p in [
            self._ACCOUNT_NAME, self._SOURCE_IP, self._PROCESS_NAME,
            self._COMMAND_LINE, self._SERVICE_NAME, self._TASK_NAME,
        ]):
            return self._parse_field_line(line, line_number)

        return None

    def _parse_eventid_line(
        self, line: str, line_number: int, event_id: int
    ) -> NormalizedEvent:
        """Create a NormalizedEvent from an EventID-containing line."""
        event_type = self._EVENTID_TYPE_MAP.get(event_id, "Windows Event")

        event = NormalizedEvent(
            log_type=self.LOG_TYPE.value,
            raw_line=line,
            line_number=line_number,
            event_type=event_type,
            normalized_data={"event_id": event_id},
        )

        # Extract additional fields from same line if present
        self._extract_fields_into(line, event)

        # Parse timestamp
        m_dt = self._DATE_TIME.search(line) or self._ISO_TIMESTAMP.search(line)
        if m_dt:
            ts_str = m_dt.group("ts")
            event.timestamp_raw = ts_str
            event.event_timestamp = self._parse_datetime(ts_str)

        return event

    def _parse_xml_line(self, line: str, line_number: int) -> NormalizedEvent | None:
        """Parse a single-line XML event."""
        m_id = self._XML_EVENTID.search(line)
        if not m_id:
            return None

        event_id = int(m_id.group("id"))
        event_type = self._EVENTID_TYPE_MAP.get(event_id, "Windows Event")

        # Extract computer name
        m_host = self._XML_COMPUTER.search(line)
        hostname = m_host.group("host") if m_host else None

        # Extract timestamp
        m_ts = self._XML_TIMESTAMP.search(line)
        timestamp_raw = m_ts.group("ts") if m_ts else None
        event_timestamp = self._parse_datetime(timestamp_raw) if timestamp_raw else None

        # Extract all <Data Name='...'> fields
        data_fields: dict[str, str] = {}
        for dm in self._XML_DATA.finditer(line):
            data_fields[dm.group("name").lower()] = dm.group("value")

        event = NormalizedEvent(
            log_type=self.LOG_TYPE.value,
            raw_line=line,
            line_number=line_number,
            event_type=event_type,
            hostname=hostname,
            timestamp_raw=timestamp_raw,
            event_timestamp=event_timestamp,
            username=data_fields.get("targetusername") or data_fields.get("subjectusername"),
            source_ip=data_fields.get("ipaddress") or data_fields.get("sourceaddress"),
            process_name=data_fields.get("newprocessname") or data_fields.get("processname"),
            command_line=data_fields.get("commandline"),
            normalized_data={"event_id": event_id, "data_fields": data_fields},
        )

        # Parse numeric port
        port_str = data_fields.get("ipport") or data_fields.get("sourceport")
        if port_str and port_str.isdigit():
            event.source_port = int(port_str)

        return event

    def _parse_field_line(self, line: str, line_number: int) -> NormalizedEvent | None:
        """Extract fields from a free-standing key-value line."""
        event = NormalizedEvent(
            log_type=self.LOG_TYPE.value,
            raw_line=line,
            line_number=line_number,
            event_type="Windows Event",
        )
        self._extract_fields_into(line, event)
        # Only return if we extracted something meaningful
        if any([event.username, event.source_ip, event.process_name, event.command_line]):
            return event
        return None

    def _extract_fields_into(self, text: str, event: NormalizedEvent) -> None:
        """Extract all recognisable fields from text into event in-place."""
        if not event.username:
            m = self._ACCOUNT_NAME.search(text)
            if m and m.group("v") not in ("-", "SYSTEM", ""):
                event.username = m.group("v")
        if not event.source_ip:
            m = self._SOURCE_IP.search(text)
            if m and m.group("ip") not in ("-", "::1", "127.0.0.1", ""):
                event.source_ip = m.group("ip")
        if not event.source_port:
            m = self._SOURCE_PORT.search(text)
            if m:
                event.source_port = int(m.group("port"))
        if not event.process_name:
            m = self._PROCESS_NAME.search(text)
            if m:
                event.process_name = m.group("v").strip()
        if not event.process_id:
            m = self._PROCESS_ID.search(text)
            if m:
                event.process_id = int(m.group("v"), 16)
        if not event.command_line:
            m = self._COMMAND_LINE.search(text)
            if m:
                event.command_line = m.group("v").strip()
        if not event.dest_ip:
            m = self._DEST_ADDRESS.search(text)
            if m and m.group("ip") not in ("-", ""):
                event.dest_ip = m.group("ip")
        if not event.dest_port:
            m = self._DEST_PORT.search(text)
            if m:
                event.dest_port = int(m.group("port"))

    def _parse_datetime(self, ts_str: str) -> datetime | None:
        """Attempt to parse a datetime string to UTC datetime."""
        if not ts_str:
            return None
        formats = [
            "%m/%d/%Y %I:%M:%S %p",
            "%m/%d/%Y %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
        ]
        for fmt in formats:
            try:
                return datetime.strptime(ts_str.strip(), fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        try:
            ts = ts_str.replace("Z", "+00:00")
            return datetime.fromisoformat(ts).astimezone(timezone.utc)
        except Exception:
            return None
