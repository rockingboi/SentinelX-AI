"""
Unit tests for all 5 log parsers and the parser registry.
Tests: parse(), field mapping, line_number, registry registration.
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://u:p@localhost/db")
os.environ.setdefault("JWT_SECRET", "test")
os.environ.setdefault("APP_ENV", "development")

import pytest
from backend.nlp.pipeline import _ensure_parsers_loaded
from backend.nlp.parsers.registry import parser_registry
from backend.models.security_log import LogType
from backend.schemas.logs import NormalizedEvent

FIXTURES = Path(__file__).parent.parent / "fixtures"

# Must call before accessing registry
_ensure_parsers_loaded()


def _load(filename: str) -> str:
    return (FIXTURES / filename).read_text(encoding="utf-8")


# ── Registry ──────────────────────────────────────────────────────────────────

class TestParserRegistry:
    def test_all_five_types_registered(self):
        """All 5 log types must be registered in the parser registry."""
        registered = parser_registry.registered_types()
        for lt in [
            LogType.LINUX_SYSLOG, LogType.WINDOWS_EVENT,
            LogType.APACHE_ACCESS, LogType.NGINX_ACCESS, LogType.SYSMON,
        ]:
            assert lt in registered, f"{lt.value} not registered"

    def test_registry_length_is_five(self):
        assert len(parser_registry) == 5

    def test_get_returns_parser_instance(self):
        parser = parser_registry.get(LogType.LINUX_SYSLOG)
        assert parser is not None

    def test_get_unknown_returns_none(self):
        assert parser_registry.get(LogType.UNKNOWN) is None


# ── Linux Syslog Parser ───────────────────────────────────────────────────────

class TestLinuxSyslogParser:
    @pytest.fixture(scope="class")
    def events(self):
        p = parser_registry.get(LogType.LINUX_SYSLOG)
        return list(p.parse(_load("linux_syslog.log")))

    def test_parses_multiple_events(self, events):
        """Parser must yield at least 15 events from the fixture."""
        assert len(events) >= 15

    def test_all_events_are_normalized(self, events):
        """All yielded objects must be NormalizedEvent instances."""
        for ev in events:
            assert isinstance(ev, NormalizedEvent)

    def test_line_numbers_set(self, events):
        """Every event must have a line_number set."""
        for ev in events:
            assert ev.line_number is not None
            assert ev.line_number >= 1

    def test_log_type_field(self, events):
        """All events must carry log_type = 'linux_syslog'."""
        for ev in events:
            assert ev.log_type == "linux_syslog"

    def test_failed_login_extracted(self, events):
        """At least one 'Failed Login' event type extracted."""
        types = {ev.event_type for ev in events}
        assert "Failed Login" in types

    def test_source_ip_extracted(self, events):
        """SSH failed login events must include a source IP."""
        ssh_fails = [ev for ev in events if ev.event_type == "Failed Login"]
        assert any(ev.source_ip is not None for ev in ssh_fails)

    def test_username_extracted(self, events):
        """Usernames must be extracted from failed login events."""
        ssh_fails = [ev for ev in events if ev.event_type == "Failed Login"]
        assert any(ev.username is not None for ev in ssh_fails)

    def test_raw_line_preserved(self, events):
        """raw_line must be set to the original log line text."""
        for ev in events:
            assert ev.raw_line is not None
            assert len(ev.raw_line) > 0

    def test_skip_blank_lines(self):
        """Parser must not crash or emit events on blank/whitespace lines."""
        p = parser_registry.get(LogType.LINUX_SYSLOG)
        events = list(p.parse("\n\n\n   \n"))
        assert len(events) == 0


# ── Windows Event Parser ──────────────────────────────────────────────────────

class TestWindowsEventParser:
    @pytest.fixture(scope="class")
    def events(self):
        p = parser_registry.get(LogType.WINDOWS_EVENT)
        return list(p.parse(_load("windows_event.log")))

    def test_parses_events(self, events):
        assert len(events) >= 10

    def test_log_type_field(self, events):
        for ev in events:
            assert ev.log_type == "windows_event"

    def test_failed_logon_event_type(self, events):
        types = {ev.event_type for ev in events}
        assert "Failed Login" in types

    def test_failed_logon_has_attacker_info(self, events):
        """Windows failed logon events must carry either source_ip or raw_line with attacker IP."""
        fails = [ev for ev in events if ev.event_type == "Failed Login"]
        assert len(fails) >= 5, f"Expected >=5 failed logins, got {len(fails)}"
        # Attacker IP is in raw_line even if source_ip field is None
        attacker_ip = "203.0.113.100"
        found = any(
            (ev.source_ip == attacker_ip) or
            (ev.raw_line and attacker_ip in ev.raw_line)
            for ev in fails
        )
        assert found, f"Attacker IP {attacker_ip} not found in any failed login"

    def test_line_numbers_set(self, events):
        for ev in events:
            assert ev.line_number is not None


# ── Apache Access Parser ──────────────────────────────────────────────────────

class TestApacheAccessParser:
    @pytest.fixture(scope="class")
    def events(self):
        p = parser_registry.get(LogType.APACHE_ACCESS)
        return list(p.parse(_load("apache_access.log")))

    def test_parses_events(self, events):
        assert len(events) >= 15

    def test_log_type_field(self, events):
        for ev in events:
            assert ev.log_type == "apache_access"

    def test_url_extracted(self, events):
        for ev in events:
            assert ev.url is not None

    def test_http_method_extracted(self, events):
        methods = {ev.http_method for ev in events if ev.http_method}
        assert "GET" in methods or "POST" in methods

    def test_status_code_extracted(self, events):
        codes = {ev.http_status_code for ev in events if ev.http_status_code}
        assert len(codes) > 1

    def test_source_ip_extracted(self, events):
        ips = {ev.source_ip for ev in events if ev.source_ip}
        assert len(ips) >= 3

    def test_sql_injection_or_traversal_detected(self, events):
        """At least SQLi or directory traversal must be detected."""
        types = {ev.event_type for ev in events}
        attack_types = {"SQL Injection Attempt", "Directory Traversal", "Web Scanner",
                        "Unauthorized Access Attempt", "XSS Attempt"}
        assert len(types & attack_types) >= 2, f"Got types: {types}"

    def test_directory_traversal_detected(self, events):
        types = {ev.event_type for ev in events}
        assert "Directory Traversal" in types


# ── Nginx Access Parser ───────────────────────────────────────────────────────

class TestNginxAccessParser:
    @pytest.fixture(scope="class")
    def events(self):
        p = parser_registry.get(LogType.NGINX_ACCESS)
        return list(p.parse(_load("nginx_access.log")))

    def test_parses_events(self, events):
        assert len(events) >= 10

    def test_log_type_field(self, events):
        for ev in events:
            assert ev.log_type == "nginx_access"

    def test_url_and_method_extracted(self, events):
        for ev in events:
            assert ev.url is not None
            assert ev.http_method is not None

    def test_directory_traversal_detected(self, events):
        types = {ev.event_type for ev in events}
        assert "Directory Traversal" in types


# ── Sysmon Parser ─────────────────────────────────────────────────────────────

class TestSysmonParser:
    @pytest.fixture(scope="class")
    def events(self):
        p = parser_registry.get(LogType.SYSMON)
        return list(p.parse(_load("sysmon.log")))

    def test_parses_events(self, events):
        assert len(events) >= 8

    def test_log_type_field(self, events):
        for ev in events:
            assert ev.log_type == "sysmon"

    def test_encoded_powershell_detected(self, events):
        types = {ev.event_type for ev in events}
        assert "Encoded PowerShell" in types

    def test_lsass_access_detected(self, events):
        types = {ev.event_type for ev in events}
        assert any("LSASS" in (t or "") for t in types)

    def test_registry_persistence_detected(self, events):
        types = {ev.event_type for ev in events}
        assert "Registry Persistence" in types

    def test_hostname_extracted(self, events):
        hosts = {ev.hostname for ev in events if ev.hostname}
        assert "WS01" in hosts

    def test_process_name_extracted(self, events):
        procs = {ev.process_name for ev in events if ev.process_name}
        assert len(procs) >= 1
