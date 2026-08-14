"""
SentinelX AI — MITRE ATT&CK Rule Definitions
===============================================
All classification rules in one place — zero logic here, pure data.

Each ClassificationRule defines:
  - Which event_type strings it matches (exact or prefix)
  - Optional secondary conditions (log_type, process_name, keywords in
    command_line or url) applied as AND filters
  - The MITRE Tactic, Technique, and Sub-technique to assign
  - A base severity score (1–10)
  - A human-readable threat_category label
  - Tags for downstream consumers (SIEM queries, dashboards)

Rule evaluation order matters — rules are tested in priority order
(highest priority first). The FIRST matching rule wins for the primary
classification. All matching rules are recorded in matched_rules.

MITRE ATT&CK Reference: https://attack.mitre.org/
  Tactics (Enterprise): TA0001–TA0043
  Techniques: T1xxx, Sub-techniques: T1xxx.xxx

Severity Scale:
  10 = CRITICAL  — Active compromise, data exfiltration, destructive
   8 = HIGH       — Privilege escalation, persistence, lateral movement
   6 = MEDIUM     — Suspicious activity, reconnaissance, failed attacks
   4 = LOW        — Informational security events, web scans, probing
   2 = INFO       — Normal operations flagged for audit
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable


# ── Severity enumeration ──────────────────────────────────────────────────────

class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"

    @classmethod
    def from_score(cls, score: int) -> "SeverityLevel":
        """Map numeric 1–10 score to severity label."""
        if score >= 9:
            return cls.CRITICAL
        if score >= 7:
            return cls.HIGH
        if score >= 5:
            return cls.MEDIUM
        if score >= 3:
            return cls.LOW
        return cls.INFO


# ── MITRE ATT&CK data structures ─────────────────────────────────────────────

@dataclass(frozen=True)
class MitreTechnique:
    """A single MITRE ATT&CK technique or sub-technique reference."""
    tactic_id:        str           # e.g. "TA0006"
    tactic_name:      str           # e.g. "Credential Access"
    technique_id:     str           # e.g. "T1110"
    technique_name:   str           # e.g. "Brute Force"
    sub_technique_id:   str | None = None   # e.g. "T1110.001"
    sub_technique_name: str | None = None   # e.g. "Password Guessing"


@dataclass
class ClassificationRule:
    """
    A single classification rule.

    Matching logic:
      1. event_type_patterns are checked against NormalizedEvent.event_type
         (case-insensitive, substring match).
      2. If log_types is non-empty, NormalizedEvent.log_type must be in the set.
      3. extra_conditions is an optional callable(NormalizedEvent) → bool for
         fine-grained filtering (e.g. checking command_line content).
      4. All conditions are AND'd together.
    """
    rule_id:             str
    description:         str
    event_type_patterns: list[str]         # Substring match against event_type
    mitre:               MitreTechnique
    severity_score:      int               # 1–10
    threat_category:     str
    tags:                list[str] = field(default_factory=list)
    log_types:           frozenset[str] = field(default_factory=frozenset)
    extra_conditions:    Callable | None = field(default=None, compare=False)
    priority:            int = 50          # Lower = checked first


# ── Rule registry ─────────────────────────────────────────────────────────────

RULES: list[ClassificationRule] = []


def _r(
    rule_id: str,
    description: str,
    event_type_patterns: list[str],
    tactic_id: str,
    tactic_name: str,
    technique_id: str,
    technique_name: str,
    severity_score: int,
    threat_category: str,
    sub_technique_id: str | None = None,
    sub_technique_name: str | None = None,
    tags: list[str] | None = None,
    log_types: frozenset[str] | None = None,
    extra_conditions: Callable | None = None,
    priority: int = 50,
) -> None:
    """Shorthand rule constructor — appends directly to RULES."""
    RULES.append(ClassificationRule(
        rule_id=rule_id,
        description=description,
        event_type_patterns=event_type_patterns,
        mitre=MitreTechnique(
            tactic_id=tactic_id,
            tactic_name=tactic_name,
            technique_id=technique_id,
            technique_name=technique_name,
            sub_technique_id=sub_technique_id,
            sub_technique_name=sub_technique_name,
        ),
        severity_score=severity_score,
        threat_category=threat_category,
        tags=tags or [],
        log_types=log_types or frozenset(),
        extra_conditions=extra_conditions,
        priority=priority,
    ))


# =============================================================================
# RULE DEFINITIONS
# Priority: 10 = highest (checked first), 90 = lowest
# =============================================================================

# ── CRITICAL — Active Compromise ─────────────────────────────────────────────

_r(
    rule_id="CR-001",
    description="LSASS process memory access — credential dumping",
    event_type_patterns=["LSASS Access", "LSASS Injection", "Credential Dumping"],
    tactic_id="TA0006", tactic_name="Credential Access",
    technique_id="T1003", technique_name="OS Credential Dumping",
    sub_technique_id="T1003.001", sub_technique_name="LSASS Memory",
    severity_score=10,
    threat_category="Credential Dumping",
    tags=["mimikatz", "lsass", "credential_access"],
    priority=10,
)

_r(
    rule_id="CR-002",
    description="Mimikatz or credential dumping tool detected in command line",
    event_type_patterns=["Credential Dumping Attempt"],
    tactic_id="TA0006", tactic_name="Credential Access",
    technique_id="T1003", technique_name="OS Credential Dumping",
    severity_score=10,
    threat_category="Credential Dumping",
    tags=["mimikatz", "credential_access"],
    priority=10,
)

_r(
    rule_id="CR-003",
    description="Process injection via CreateRemoteThread",
    event_type_patterns=["Remote Thread Created"],
    tactic_id="TA0005", tactic_name="Defense Evasion",
    technique_id="T1055", technique_name="Process Injection",
    sub_technique_id="T1055.003", sub_technique_name="Thread Execution Hijacking",
    severity_score=9,
    threat_category="Process Injection",
    tags=["injection", "evasion", "sysmon"],
    priority=10,
)

# ── HIGH — Execution & Persistence ───────────────────────────────────────────

_r(
    rule_id="HI-001",
    description="Encoded PowerShell command detected",
    event_type_patterns=["Encoded PowerShell"],
    tactic_id="TA0002", tactic_name="Execution",
    technique_id="T1059", technique_name="Command and Scripting Interpreter",
    sub_technique_id="T1059.001", sub_technique_name="PowerShell",
    severity_score=8,
    threat_category="Malicious PowerShell",
    tags=["powershell", "encoded", "execution", "lolbin"],
    priority=15,
)

_r(
    rule_id="HI-002",
    description="LOLBin (Living off the Land Binary) execution",
    event_type_patterns=["LOLBin Execution", "Suspicious Child Process"],
    tactic_id="TA0005", tactic_name="Defense Evasion",
    technique_id="T1218", technique_name="System Binary Proxy Execution",
    severity_score=7,
    threat_category="LOLBin Execution",
    tags=["lolbin", "evasion", "execution", "sysmon"],
    priority=15,
)

_r(
    rule_id="HI-003",
    description="Registry run key persistence established",
    event_type_patterns=["Registry Persistence"],
    tactic_id="TA0003", tactic_name="Persistence",
    technique_id="T1547", technique_name="Boot or Logon Autostart Execution",
    sub_technique_id="T1547.001", sub_technique_name="Registry Run Keys",
    severity_score=8,
    threat_category="Registry Persistence",
    tags=["persistence", "registry", "startup", "sysmon"],
    priority=15,
)

_r(
    rule_id="HI-004",
    description="Scheduled task created for persistence",
    event_type_patterns=["Scheduled Task Created", "Scheduled Task Modified"],
    tactic_id="TA0003", tactic_name="Persistence",
    technique_id="T1053", technique_name="Scheduled Task/Job",
    sub_technique_id="T1053.005", sub_technique_name="Scheduled Task",
    severity_score=8,
    threat_category="Scheduled Task Persistence",
    tags=["persistence", "scheduled_task", "windows"],
    priority=15,
)

_r(
    rule_id="HI-005",
    description="New Windows service installed",
    event_type_patterns=["Service Installed"],
    tactic_id="TA0003", tactic_name="Persistence",
    technique_id="T1543", technique_name="Create or Modify System Process",
    sub_technique_id="T1543.003", sub_technique_name="Windows Service",
    severity_score=8,
    threat_category="Malicious Service",
    tags=["persistence", "service", "windows"],
    priority=15,
)

_r(
    rule_id="HI-006",
    description="Privilege escalation via sudo/su",
    event_type_patterns=["Privilege Escalation"],
    tactic_id="TA0004", tactic_name="Privilege Escalation",
    technique_id="T1548", technique_name="Abuse Elevation Control Mechanism",
    sub_technique_id="T1548.003", sub_technique_name="Sudo and Sudo Caching",
    severity_score=7,
    threat_category="Privilege Escalation",
    tags=["privilege_escalation", "sudo", "linux"],
    log_types=frozenset({"linux_syslog"}),
    priority=20,
)

_r(
    rule_id="HI-007",
    description="Special privileges (SeDebugPrivilege etc.) assigned to logon",
    event_type_patterns=["Privilege Escalation", "Special Priv"],
    tactic_id="TA0004", tactic_name="Privilege Escalation",
    technique_id="T1548", technique_name="Abuse Elevation Control Mechanism",
    severity_score=7,
    threat_category="Privilege Escalation",
    tags=["privilege_escalation", "windows", "event_4672"],
    log_types=frozenset({"windows_event"}),
    priority=20,
)

_r(
    rule_id="HI-008",
    description="Suspicious network connection to C2-associated port",
    event_type_patterns=["Suspicious Network Connection"],
    tactic_id="TA0011", tactic_name="Command and Control",
    technique_id="T1071", technique_name="Application Layer Protocol",
    severity_score=8,
    threat_category="C2 Communication",
    tags=["c2", "network", "sysmon"],
    priority=15,
)

_r(
    rule_id="HI-009",
    description="Unsigned DLL loaded — potential DLL hijacking or side-loading",
    event_type_patterns=["Unsigned DLL Loaded", "DLL from Suspicious Path"],
    tactic_id="TA0005", tactic_name="Defense Evasion",
    technique_id="T1574", technique_name="Hijack Execution Flow",
    sub_technique_id="T1574.001", sub_technique_name="DLL Search Order Hijacking",
    severity_score=7,
    threat_category="DLL Hijacking",
    tags=["dll", "hijacking", "evasion", "sysmon"],
    priority=20,
)

_r(
    rule_id="HI-010",
    description="New local user account created",
    event_type_patterns=["User Account Created"],
    tactic_id="TA0003", tactic_name="Persistence",
    technique_id="T1136", technique_name="Create Account",
    sub_technique_id="T1136.001", sub_technique_name="Local Account",
    severity_score=7,
    threat_category="Account Creation",
    tags=["persistence", "account", "windows"],
    priority=20,
)

_r(
    rule_id="HI-011",
    description="Logon with explicit credentials (pass-the-hash risk)",
    event_type_patterns=["Explicit Credential Logon"],
    tactic_id="TA0008", tactic_name="Lateral Movement",
    technique_id="T1550", technique_name="Use Alternate Authentication Material",
    sub_technique_id="T1550.002", sub_technique_name="Pass the Hash",
    severity_score=8,
    threat_category="Lateral Movement",
    tags=["lateral_movement", "pass_the_hash", "windows"],
    priority=20,
)

_r(
    rule_id="HI-012",
    description="Large data transfer — potential exfiltration",
    event_type_patterns=["Large Data Transfer"],
    tactic_id="TA0010", tactic_name="Exfiltration",
    technique_id="T1041", technique_name="Exfiltration Over C2 Channel",
    severity_score=7,
    threat_category="Data Exfiltration",
    tags=["exfiltration", "http", "large_transfer"],
    priority=20,
)

_r(
    rule_id="HI-013",
    description="SQL injection attempt against web application",
    event_type_patterns=["SQL Injection Attempt"],
    tactic_id="TA0001", tactic_name="Initial Access",
    technique_id="T1190", technique_name="Exploit Public-Facing Application",
    severity_score=7,
    threat_category="Web Application Attack",
    tags=["sqli", "web", "initial_access"],
    priority=20,
)

_r(
    rule_id="HI-014",
    description="Command injection attempt against web application",
    event_type_patterns=["Command Injection Attempt"],
    tactic_id="TA0001", tactic_name="Initial Access",
    technique_id="T1190", technique_name="Exploit Public-Facing Application",
    severity_score=8,
    threat_category="Web Application Attack",
    tags=["command_injection", "web", "initial_access"],
    priority=20,
)

_r(
    rule_id="HI-015",
    description="Process Tampering — security tool manipulation",
    event_type_patterns=["Process Tampering"],
    tactic_id="TA0005", tactic_name="Defense Evasion",
    technique_id="T1562", technique_name="Impair Defenses",
    severity_score=8,
    threat_category="Defense Evasion",
    tags=["defense_evasion", "tampering", "sysmon"],
    priority=15,
)

_r(
    rule_id="HI-016",
    description="Alternate Data Stream created — potential file hiding",
    event_type_patterns=["Alternate Data Stream"],
    tactic_id="TA0005", tactic_name="Defense Evasion",
    technique_id="T1564", technique_name="Hide Artifacts",
    sub_technique_id="T1564.004", sub_technique_name="NTFS File Attributes",
    severity_score=7,
    threat_category="Defense Evasion",
    tags=["ads", "ntfs", "hiding", "sysmon"],
    priority=20,
)

_r(
    rule_id="HI-017",
    description="Kerberoasting / Kerberos ticket request anomaly",
    event_type_patterns=["Kerberos Pre-auth Failure", "Kerberos TGT Request", "Kerberos Service Ticket"],
    tactic_id="TA0006", tactic_name="Credential Access",
    technique_id="T1558", technique_name="Steal or Forge Kerberos Tickets",
    sub_technique_id="T1558.003", sub_technique_name="Kerberoasting",
    severity_score=7,
    threat_category="Kerberoasting",
    tags=["kerberos", "credential_access", "windows"],
    priority=20,
)

# ── MEDIUM — Brute Force, Recon, Suspicious Access ───────────────────────────

_r(
    rule_id="ME-001",
    description="Failed login attempt — possible brute force",
    event_type_patterns=["Failed Login"],
    tactic_id="TA0006", tactic_name="Credential Access",
    technique_id="T1110", technique_name="Brute Force",
    sub_technique_id="T1110.001", sub_technique_name="Password Guessing",
    severity_score=5,
    threat_category="Brute Force",
    tags=["brute_force", "authentication", "failed_login"],
    priority=30,
)

_r(
    rule_id="ME-002",
    description="SSH invalid user — reconnaissance or brute force",
    event_type_patterns=["Invalid User"],
    tactic_id="TA0006", tactic_name="Credential Access",
    technique_id="T1110", technique_name="Brute Force",
    sub_technique_id="T1110.003", sub_technique_name="Password Spraying",
    severity_score=5,
    threat_category="Brute Force",
    tags=["brute_force", "ssh", "invalid_user"],
    priority=30,
)

_r(
    rule_id="ME-003",
    description="Brute force — maximum authentication attempts exceeded",
    event_type_patterns=["Brute Force"],
    tactic_id="TA0006", tactic_name="Credential Access",
    technique_id="T1110", technique_name="Brute Force",
    severity_score=6,
    threat_category="Brute Force",
    tags=["brute_force", "ssh", "max_attempts"],
    priority=25,
)

_r(
    rule_id="ME-004",
    description="Account lockout — possible brute force in progress",
    event_type_patterns=["Account Lockout"],
    tactic_id="TA0006", tactic_name="Credential Access",
    technique_id="T1110", technique_name="Brute Force",
    sub_technique_id="T1110.001", sub_technique_name="Password Guessing",
    severity_score=6,
    threat_category="Account Lockout",
    tags=["brute_force", "lockout", "windows"],
    priority=25,
)

_r(
    rule_id="ME-005",
    description="Authentication failure (PAM or generic)",
    event_type_patterns=["Authentication Failure"],
    tactic_id="TA0006", tactic_name="Credential Access",
    technique_id="T1110", technique_name="Brute Force",
    severity_score=4,
    threat_category="Authentication Failure",
    tags=["authentication", "failed", "pam"],
    priority=35,
)

_r(
    rule_id="ME-006",
    description="Unauthorized HTTP access attempt",
    event_type_patterns=["Unauthorized Access Attempt"],
    tactic_id="TA0001", tactic_name="Initial Access",
    technique_id="T1190", technique_name="Exploit Public-Facing Application",
    severity_score=5,
    threat_category="Unauthorized Access",
    tags=["http", "401", "unauthorized"],
    priority=30,
)

_r(
    rule_id="ME-007",
    description="Forbidden HTTP resource accessed",
    event_type_patterns=["Forbidden Access Attempt"],
    tactic_id="TA0007", tactic_name="Discovery",
    technique_id="T1083", technique_name="File and Directory Discovery",
    severity_score=4,
    threat_category="Access Control Violation",
    tags=["http", "403", "forbidden"],
    priority=35,
)

_r(
    rule_id="ME-008",
    description="XSS injection attempt in web request",
    event_type_patterns=["XSS Attempt"],
    tactic_id="TA0001", tactic_name="Initial Access",
    technique_id="T1059", technique_name="Command and Scripting Interpreter",
    sub_technique_id="T1059.007", sub_technique_name="JavaScript",
    severity_score=5,
    threat_category="Web Application Attack",
    tags=["xss", "web", "injection"],
    priority=30,
)

_r(
    rule_id="ME-009",
    description="Directory traversal attempt",
    event_type_patterns=["Directory Traversal"],
    tactic_id="TA0007", tactic_name="Discovery",
    technique_id="T1083", technique_name="File and Directory Discovery",
    severity_score=5,
    threat_category="Web Application Attack",
    tags=["traversal", "web", "path_manipulation"],
    priority=30,
)

_r(
    rule_id="ME-010",
    description="User account security group membership modified",
    event_type_patterns=["Security Group Modified"],
    tactic_id="TA0003", tactic_name="Persistence",
    technique_id="T1098", technique_name="Account Manipulation",
    sub_technique_id="T1098.001", sub_technique_name="Additional Cloud Credentials",
    severity_score=6,
    threat_category="Account Manipulation",
    tags=["account", "group", "windows"],
    priority=30,
)

_r(
    rule_id="ME-011",
    description="File created in suspicious location (temp/public)",
    event_type_patterns=["File Created in Suspicious Location"],
    tactic_id="TA0002", tactic_name="Execution",
    technique_id="T1105", technique_name="Ingress Tool Transfer",
    severity_score=6,
    threat_category="Suspicious File Activity",
    tags=["file_creation", "suspicious_path", "sysmon"],
    priority=30,
)

_r(
    rule_id="ME-012",
    description="File timestamp modified — anti-forensics",
    event_type_patterns=["File Timestamp Modified"],
    tactic_id="TA0005", tactic_name="Defense Evasion",
    technique_id="T1070", technique_name="Indicator Removal",
    sub_technique_id="T1070.006", sub_technique_name="Timestomp",
    severity_score=6,
    threat_category="Anti-Forensics",
    tags=["timestomping", "evasion", "sysmon"],
    priority=30,
)

_r(
    rule_id="ME-013",
    description="File deleted — possible evidence removal",
    event_type_patterns=["File Deleted"],
    tactic_id="TA0005", tactic_name="Defense Evasion",
    technique_id="T1070", technique_name="Indicator Removal",
    sub_technique_id="T1070.004", sub_technique_name="File Deletion",
    severity_score=5,
    threat_category="Anti-Forensics",
    tags=["file_deletion", "evasion", "sysmon"],
    priority=35,
)

_r(
    rule_id="ME-014",
    description="NTLM authentication attempt — potential hash relay",
    event_type_patterns=["NTLM Authentication"],
    tactic_id="TA0006", tactic_name="Credential Access",
    technique_id="T1557", technique_name="Adversary-in-the-Middle",
    sub_technique_id="T1557.001", sub_technique_name="LLMNR/NBT-NS Poisoning",
    severity_score=5,
    threat_category="Credential Relay",
    tags=["ntlm", "credential_access", "windows"],
    priority=35,
)

_r(
    rule_id="ME-015",
    description="Password reset attempt on user account",
    event_type_patterns=["Password Reset"],
    tactic_id="TA0003", tactic_name="Persistence",
    technique_id="T1098", technique_name="Account Manipulation",
    severity_score=5,
    threat_category="Account Manipulation",
    tags=["account", "password_reset", "windows"],
    priority=35,
)

_r(
    rule_id="ME-016",
    description="Upstream proxy error — potential infrastructure probing",
    event_type_patterns=["Upstream Proxy Error"],
    tactic_id="TA0043", tactic_name="Reconnaissance",
    technique_id="T1595", technique_name="Active Scanning",
    severity_score=3,
    threat_category="Reconnaissance",
    tags=["proxy", "scanning", "nginx"],
    priority=40,
)

# ── LOW — Scanning, Recon ─────────────────────────────────────────────────────

_r(
    rule_id="LO-001",
    description="Web application scanner or crawl tool detected",
    event_type_patterns=["Web Scanner"],
    tactic_id="TA0043", tactic_name="Reconnaissance",
    technique_id="T1595", technique_name="Active Scanning",
    sub_technique_id="T1595.002", sub_technique_name="Vulnerability Scanning",
    severity_score=4,
    threat_category="Vulnerability Scanning",
    tags=["scanner", "recon", "web"],
    priority=40,
)

_r(
    rule_id="LO-002",
    description="Web path scanning — probing for admin panels or sensitive paths",
    event_type_patterns=["Web Scanning"],
    tactic_id="TA0043", tactic_name="Reconnaissance",
    technique_id="T1595", technique_name="Active Scanning",
    severity_score=4,
    threat_category="Path Scanning",
    tags=["path_scan", "recon", "web"],
    priority=40,
)

_r(
    rule_id="LO-003",
    description="Object/file access attempt",
    event_type_patterns=["Object Access"],
    tactic_id="TA0007", tactic_name="Discovery",
    technique_id="T1083", technique_name="File and Directory Discovery",
    severity_score=3,
    threat_category="File Discovery",
    tags=["file_access", "audit", "windows"],
    priority=45,
)

_r(
    rule_id="LO-004",
    description="DNS query to potentially suspicious domain",
    event_type_patterns=["DNS Query"],
    tactic_id="TA0011", tactic_name="Command and Control",
    technique_id="T1071", technique_name="Application Layer Protocol",
    sub_technique_id="T1071.004", sub_technique_name="DNS",
    severity_score=3,
    threat_category="DNS Activity",
    tags=["dns", "c2_potential", "sysmon"],
    priority=45,
)

_r(
    rule_id="LO-005",
    description="Successful login — audit event",
    event_type_patterns=["Successful Login"],
    tactic_id="TA0001", tactic_name="Initial Access",
    technique_id="T1078", technique_name="Valid Accounts",
    severity_score=2,
    threat_category="Authentication",
    tags=["authentication", "successful_login", "audit"],
    priority=50,
)

# ── INFO — Normal operations ──────────────────────────────────────────────────

_r(
    rule_id="IN-001",
    description="Normal HTTP request — logged for audit",
    event_type_patterns=["HTTP Request"],
    tactic_id="TA0043", tactic_name="Reconnaissance",
    technique_id="T1595", technique_name="Active Scanning",
    severity_score=1,
    threat_category="Web Traffic",
    tags=["http", "audit"],
    priority=90,
)

_r(
    rule_id="IN-002",
    description="Generic system log event",
    event_type_patterns=["System Log", "System Event"],
    tactic_id="TA0040", tactic_name="Impact",
    technique_id="T1499", technique_name="Endpoint Denial of Service",
    severity_score=2,
    threat_category="System Event",
    tags=["system", "audit"],
    priority=90,
)

_r(
    rule_id="IN-003",
    description="Web server error — monitoring event",
    event_type_patterns=["HTTP Server Error", "HTTP Client Error", "Web Server Error", "Web Server Warning"],
    tactic_id="TA0043", tactic_name="Reconnaissance",
    technique_id="T1595", technique_name="Active Scanning",
    severity_score=2,
    threat_category="Web Error",
    tags=["http", "error", "monitoring"],
    priority=80,
)

_r(
    rule_id="IN-004",
    description="Windows Event — general audit log",
    event_type_patterns=["Windows Event"],
    tactic_id="TA0007", tactic_name="Discovery",
    technique_id="T1082", technique_name="System Information Discovery",
    severity_score=1,
    threat_category="Audit Event",
    tags=["windows", "audit"],
    priority=90,
)

_r(
    rule_id="IN-005",
    description="Sysmon generic event (unclassified)",
    event_type_patterns=["Sysmon Event"],
    tactic_id="TA0007", tactic_name="Discovery",
    technique_id="T1082", technique_name="System Information Discovery",
    severity_score=1,
    threat_category="Sysmon Event",
    tags=["sysmon", "audit"],
    priority=90,
)

_r(
    rule_id="IN-006",
    description="Process creation — normal audit",
    event_type_patterns=["Process Creation"],
    tactic_id="TA0002", tactic_name="Execution",
    technique_id="T1059", technique_name="Command and Scripting Interpreter",
    severity_score=2,
    threat_category="Process Execution",
    tags=["process", "audit", "sysmon"],
    priority=80,
)

# Sort rules by priority (ascending — lower number = higher priority = checked first)
RULES.sort(key=lambda r: r.priority)
