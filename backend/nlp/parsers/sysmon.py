"""
SentinelX AI — Sysmon XML Event Log Parser
============================================
Parses Microsoft Sysinternals Sysmon event logs in XML format.

Sysmon is a Windows system service and device driver that logs detailed
system activity to the Windows event log. It is the gold standard for
endpoint detection in enterprise environments.

Supported Sysmon Event IDs:
  ID  1  — Process Create          → T1059 (Execution)
  ID  2  — File Creation Time      → T1070.006 (Timestomping)
  ID  3  — Network Connection      → T1071 (C2), T1046 (Port Scan)
  ID  5  — Process Terminated
  ID  7  — Image Loaded (DLL)      → T1055 (Process Injection)
  ID  8  — CreateRemoteThread      → T1055 (Process Injection)
  ID  10 — ProcessAccess           → T1003 (LSASS dump)
  ID  11 — FileCreate              → T1560 (Archive), T1105 (Ingress Tool)
  ID  12 — RegistryEvent (Create)  → T1547 (Persistence)
  ID  13 — RegistryEvent (Set)     → T1547 (Persistence)
  ID  15 — FileCreateStreamHash    → T1553 (ADS)
  ID  17 — PipeEvent (Created)     → T1559 (IPC)
  ID  22 — DNSEvent                → T1071.004 (DNS C2)
  ID  23 — FileDelete              → T1070.004 (File Deletion)
  ID  25 — ProcessTampering        → T1562 (Defence Evasion)

XML can appear as:
  1. One event per line (exported with wevtutil)
  2. Wrapped in <Events> root element (multi-line with newlines stripped)
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
class SysmonParser(BaseParser):
    """
    Parser for Microsoft Sysmon XML event logs.

    Extracts process, network, file, registry, and DNS events with
    full MITRE ATT&CK context from Sysmon-specific data fields.
    """

    LOG_TYPE = LogType.SYSMON

    # ── Core XML field extraction patterns ────────────────────────────────────
    _EVENT_ID = re.compile(r"<EventID>(\d+)</EventID>", re.IGNORECASE)
    _SYSTEM_TIME = re.compile(
        r"SystemTime='(?P<ts>[^']+)'", re.IGNORECASE
    )
    _COMPUTER = re.compile(r"<Computer>([^<]+)</Computer>", re.IGNORECASE)
    _DATA = re.compile(
        r"<Data\s+Name='(?P<name>[^']+)'>(?P<value>[^<]*)</Data>",
        re.IGNORECASE,
    )

    # ── Suspicious pattern detection ──────────────────────────────────────────
    _LOLBIN = re.compile(
        r"(?i)\\(powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|"
        r"certutil|bitsadmin|msiexec|wmic|msbuild|installutil|cmstp|"
        r"odbcconf|regasm|regsvcs|xwizard|appsyncpublishingserver)\.exe",
    )
    _SUSPICIOUS_CHILD = re.compile(
        r"(?i)\\(word|excel|outlook|winword|powerpnt)\.exe",
    )
    _LSASS_ACCESS = re.compile(r"(?i)lsass\.exe", )
    _ENCODED_CMD = re.compile(
        r"(?i)-(?:enc|encode|encodedcommand)\s+[A-Za-z0-9+/=]{4,}",
    )
    _SUSPICIOUS_PATH = re.compile(
        r"(?i)(\\temp\\|\\appdata\\|\\public\\|\\programdata\\|"
        r"\\windows\\temp\\|/tmp/|\\users\\public\\)",
    )
    _MIMIKATZ_PATTERNS = re.compile(
        r"(?i)(sekurlsa|kerberos::ptt|lsadump|privilege::debug|token::elevate)",
    )

    # ── EventID → security event type ────────────────────────────────────────
    _EVENT_TYPE_MAP: dict[int, str] = {
        1:  "Process Creation",
        2:  "File Timestamp Modified",
        3:  "Network Connection",
        5:  "Process Terminated",
        7:  "DLL Loaded",
        8:  "Remote Thread Created",
        10: "Process Access",
        11: "File Created",
        12: "Registry Key Created",
        13: "Registry Value Set",
        15: "Alternate Data Stream",
        17: "Pipe Created",
        18: "Pipe Connected",
        22: "DNS Query",
        23: "File Deleted",
        25: "Process Tampering",
    }

    # ─────────────────────────────────────────────────────────────────────────

    def can_parse(self, raw_content: str) -> float:
        sample = self._sample_lines(raw_content)
        sysmon_hits = sum(
            1 for l in sample
            if re.search(r"Microsoft-Windows-Sysmon", l, re.IGNORECASE)
        )
        xml_hits = self._count_pattern_matches(sample, self._EVENT_ID)
        data_hits = self._count_pattern_matches(sample, self._DATA)
        total = len(sample) or 1
        return min(1.0, (sysmon_hits * 4 + xml_hits * 2 + data_hits) / (total * 5))

    def parse_line(self, line: str, line_number: int) -> NormalizedEvent | None:
        # Must contain at least an EventID to be parseable
        m_id = self._EVENT_ID.search(line)
        if not m_id:
            return None

        event_id = int(m_id.group(1))

        # Extract all Data fields into a dict
        fields: dict[str, str] = {}
        for m in self._DATA.finditer(line):
            fields[m.group("name").lower()] = m.group("value").strip()

        # Extract metadata
        hostname = self._extract_single(self._COMPUTER, line)
        timestamp_raw, event_timestamp = self._extract_timestamp(line)

        event_type = self._EVENT_TYPE_MAP.get(event_id, f"Sysmon Event {event_id}")

        event = NormalizedEvent(
            log_type=self.LOG_TYPE.value,
            raw_line=line[:500],  # Truncate XML for storage
            line_number=line_number,
            event_type=event_type,
            hostname=hostname,
            timestamp_raw=timestamp_raw,
            event_timestamp=event_timestamp,
            normalized_data={"event_id": event_id, "sysmon_fields": fields},
        )

        # ── Dispatch to event-specific enrichment ────────────────────────────
        dispatch = {
            1:  self._enrich_process_create,
            3:  self._enrich_network,
            7:  self._enrich_image_load,
            8:  self._enrich_remote_thread,
            10: self._enrich_process_access,
            11: self._enrich_file_create,
            12: self._enrich_registry,
            13: self._enrich_registry,
            22: self._enrich_dns,
            23: self._enrich_file_delete,
        }
        if event_id in dispatch:
            dispatch[event_id](event, fields)

        return event

    # ── Event-specific enrichers ──────────────────────────────────────────────

    def _enrich_process_create(self, event: NormalizedEvent, f: dict) -> None:
        """Event ID 1 — Process Create."""
        event.process_name = f.get("image", "").split("\\")[-1] if f.get("image") else None
        event.process_id = self._parse_int(f.get("processid"))
        event.command_line = f.get("commandline")
        event.username = f.get("user")
        event.file_path = f.get("image")

        cmd = event.command_line or ""
        img = f.get("image", "")
        parent_img = f.get("parentimage", "")

        # Most specific detections first
        # Mimikatz strings in command line
        if self._MIMIKATZ_PATTERNS.search(cmd):
            event.event_type = "Credential Dumping Attempt"

        # Encoded PowerShell (more specific than generic LOLBin)
        elif self._ENCODED_CMD.search(cmd):
            event.event_type = "Encoded PowerShell"

        # Suspicious office app spawning a LOLBin
        elif self._SUSPICIOUS_CHILD.search(parent_img) and self._LOLBIN.search(img):
            event.event_type = "Suspicious Child Process"

        # Generic LOLBin execution
        elif self._LOLBIN.search(img):
            event.event_type = "LOLBin Execution"

        # Execution from suspicious path
        if self._SUSPICIOUS_PATH.search(img):
            event.normalized_data["suspicious_path"] = True  # type: ignore[index]

        # Hash data
        event.normalized_data["hashes"] = f.get("hashes", "")  # type: ignore[index]
        event.normalized_data["parent_image"] = parent_img  # type: ignore[index]

    def _enrich_network(self, event: NormalizedEvent, f: dict) -> None:
        """Event ID 3 — Network Connection."""
        event.source_ip = f.get("sourceip")
        event.dest_ip = f.get("destinationip")
        event.source_port = self._parse_int(f.get("sourceport"))
        event.dest_port = self._parse_int(f.get("destinationport"))
        event.protocol = f.get("protocol", "tcp").upper()
        event.process_name = f.get("image", "").split("\\")[-1] if f.get("image") else None
        event.username = f.get("user")
        event.hostname = f.get("destinationhostname") or event.hostname

        # Known C2 ports
        c2_ports = {4444, 5555, 8080, 8443, 1337, 31337, 6666, 6667}
        if event.dest_port in c2_ports:
            event.event_type = "Suspicious Network Connection"

    def _enrich_image_load(self, event: NormalizedEvent, f: dict) -> None:
        """Event ID 7 — Image Loaded (DLL)."""
        event.file_path = f.get("imagepath") or f.get("imageloaded")
        event.process_name = f.get("image", "").split("\\")[-1] if f.get("image") else None
        event.normalized_data["signature_status"] = f.get("signaturestatus", "")  # type: ignore[index]
        event.normalized_data["hashes"] = f.get("hashes", "")  # type: ignore[index]

        # Unsigned DLL loaded by a process
        if f.get("signaturestatus", "").lower() not in ("valid", ""):
            event.event_type = "Unsigned DLL Loaded"

        # DLL from suspicious path
        if event.file_path and self._SUSPICIOUS_PATH.search(event.file_path):
            event.event_type = "DLL from Suspicious Path"

    def _enrich_remote_thread(self, event: NormalizedEvent, f: dict) -> None:
        """Event ID 8 — CreateRemoteThread (Process Injection)."""
        event.process_name = f.get("sourceimage", "").split("\\")[-1] if f.get("sourceimage") else None
        event.normalized_data["source_image"] = f.get("sourceimage", "")  # type: ignore[index]
        event.normalized_data["target_image"] = f.get("targetimage", "")  # type: ignore[index]
        event.normalized_data["start_address"] = f.get("startaddress", "")  # type: ignore[index]
        target = f.get("targetimage", "")
        if self._LSASS_ACCESS.search(target):
            event.event_type = "LSASS Injection"

    def _enrich_process_access(self, event: NormalizedEvent, f: dict) -> None:
        """Event ID 10 — ProcessAccess (LSASS dump)."""
        event.process_name = f.get("sourceimage", "").split("\\")[-1] if f.get("sourceimage") else None
        target = f.get("targetimage", "")
        event.normalized_data["target_image"] = target  # type: ignore[index]
        event.normalized_data["granted_access"] = f.get("grantedaccess", "")  # type: ignore[index]
        if self._LSASS_ACCESS.search(target):
            event.event_type = "LSASS Access (Credential Dump)"

    def _enrich_file_create(self, event: NormalizedEvent, f: dict) -> None:
        """Event ID 11 — FileCreate."""
        event.file_path = f.get("targetfilename")
        event.process_name = f.get("image", "").split("\\")[-1] if f.get("image") else None
        if event.file_path and self._SUSPICIOUS_PATH.search(event.file_path):
            event.event_type = "File Created in Suspicious Location"

    def _enrich_registry(self, event: NormalizedEvent, f: dict) -> None:
        """Event ID 12/13 — Registry events."""
        event.file_path = f.get("targetobject")  # registry key path
        event.process_name = f.get("image", "").split("\\")[-1] if f.get("image") else None
        event.normalized_data["registry_value"] = f.get("details", "")  # type: ignore[index]

        # Persistence-related registry keys
        persistence_keys = (
            "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "\\SYSTEM\\CurrentControlSet\\Services",
        )
        key = event.file_path or ""
        if any(k.lower() in key.lower() for k in persistence_keys):
            event.event_type = "Registry Persistence"

    def _enrich_dns(self, event: NormalizedEvent, f: dict) -> None:
        """Event ID 22 — DNS Query."""
        event.url = f.get("queryname")
        event.process_name = f.get("image", "").split("\\")[-1] if f.get("image") else None
        event.normalized_data["query_type"] = f.get("querytype", "")  # type: ignore[index]
        event.normalized_data["query_results"] = f.get("queryresults", "")  # type: ignore[index]

    def _enrich_file_delete(self, event: NormalizedEvent, f: dict) -> None:
        """Event ID 23 — FileDelete."""
        event.file_path = f.get("targetfilename")
        event.process_name = f.get("image", "").split("\\")[-1] if f.get("image") else None

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _extract_single(self, pattern: re.Pattern, text: str) -> str | None:
        m = pattern.search(text)
        return m.group(1).strip() if m else None

    def _extract_timestamp(self, text: str) -> tuple[str, datetime | None]:
        m = self._SYSTEM_TIME.search(text)
        if not m:
            return "", None
        ts_raw = m.group("ts")
        try:
            ts = ts_raw.replace("Z", "+00:00")
            return ts_raw, datetime.fromisoformat(ts).astimezone(timezone.utc)
        except Exception:
            return ts_raw, None

    def _parse_int(self, value: str | None) -> int | None:
        if value is None:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None
