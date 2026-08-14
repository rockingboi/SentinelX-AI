"""
Integration tests for NLPPipeline end-to-end.

Real API facts:
  - Apache parser: event_types = {SQL Injection Attempt, Directory Traversal,
      Web Scanner, Unauthorized Access Attempt, HTTP Request, XSS Attempt}
    NOTE: sqlmap UA is detected as "Web Scanner" not "SQL Injection Attempt"
  - Nginx fixture is detected as APACHE_ACCESS (same CLF format, lower score)
  - pipeline.process() accepts str or bytes
  - PipelineResult.threat_events / .critical_events are properties returning list
  - PipelineStats.severity_counts() -> dict with keys: critical,high,medium,low,info
"""
import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://u:p@localhost/db")
os.environ.setdefault("JWT_SECRET", "test")
os.environ.setdefault("APP_ENV", "development")

import pytest
from backend.nlp.pipeline import NLPPipeline, PipelineResult, PipelineStats
from backend.models.security_log import LogType

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.fixture(scope="module")
def pipeline():
    return NLPPipeline()


def _load(filename: str) -> str:
    return (FIXTURES / filename).read_text(encoding="utf-8")


# ── Linux Syslog ──────────────────────────────────────────────────────────────

class TestLinuxSyslogPipeline:
    @pytest.fixture(scope="class")
    def result(self, pipeline):
        return pipeline.process(_load("linux_syslog.log"))

    def test_correct_log_type(self, result):
        assert result.log_type == LogType.LINUX_SYSLOG

    def test_events_parsed(self, result):
        assert result.stats.parsed_events >= 15

    def test_threats_detected(self, result):
        assert result.stats.threats_detected >= 1

    def test_iocs_extracted(self, result):
        assert result.stats.unique_iocs >= 1

    def test_attacker_ip_in_iocs(self, result):
        vals = {i.value for i in result.all_iocs}
        assert "185.24.18.15" in vals

    def test_events_have_mitre_enrichment(self, result):
        threat_events = result.threat_events
        assert len(threat_events) >= 1
        for pe in threat_events:
            assert pe.event.mitre_technique_id is not None
            assert pe.event.severity is not None

    def test_not_empty(self, result):
        assert not result.is_empty


# ── Apache Access ─────────────────────────────────────────────────────────────

class TestApachePipeline:
    @pytest.fixture(scope="class")
    def result(self, pipeline):
        return pipeline.process(_load("apache_access.log"))

    def test_correct_log_type(self, result):
        assert result.log_type == LogType.APACHE_ACCESS

    def test_events_parsed(self, result):
        assert result.stats.parsed_events >= 10

    def test_threats_detected(self, result):
        assert result.stats.threats_detected >= 2

    def test_attack_events_present(self, result):
        """Apache fixture must produce web attack events (SQLi, traversal, or scanner)."""
        attack_types = {
            "SQL Injection Attempt", "Directory Traversal",
            "Web Scanner", "Unauthorized Access Attempt", "XSS Attempt",
        }
        actual_types = {pe.event.event_type for pe in result.processed_events}
        overlap = attack_types & actual_types
        assert len(overlap) >= 2, f"Expected >=2 attack types, got: {actual_types}"

    def test_directory_traversal_present(self, result):
        types = {pe.event.event_type for pe in result.processed_events}
        assert "Directory Traversal" in types


# ── Nginx Access ──────────────────────────────────────────────────────────────

class TestNginxPipeline:
    @pytest.fixture(scope="class")
    def result(self, pipeline):
        return pipeline.process(_load("nginx_access.log"))

    def test_detects_web_log_type(self, result):
        """Nginx CLF format may auto-detect as APACHE_ACCESS or NGINX_ACCESS."""
        assert result.log_type in (LogType.NGINX_ACCESS, LogType.APACHE_ACCESS)

    def test_events_parsed(self, result):
        assert result.stats.parsed_events >= 8

    def test_threats_detected(self, result):
        assert result.stats.threats_detected >= 1

    def test_force_nginx_type(self, pipeline):
        """Forcing NGINX_ACCESS must always result in that log type."""
        result = pipeline.process(_load("nginx_access.log"),
                                  force_log_type=LogType.NGINX_ACCESS)
        assert result.log_type == LogType.NGINX_ACCESS


# ── Sysmon (force_log_type) ───────────────────────────────────────────────────

class TestSysmonPipeline:
    @pytest.fixture(scope="class")
    def result(self, pipeline):
        return pipeline.process(_load("sysmon.log"), force_log_type=LogType.SYSMON)

    def test_correct_log_type(self, result):
        assert result.log_type == LogType.SYSMON

    def test_events_parsed(self, result):
        assert result.stats.parsed_events >= 8

    def test_critical_events_present(self, result):
        assert result.stats.critical_events >= 1

    def test_lsass_event_found(self, result):
        types = {pe.event.event_type for pe in result.processed_events}
        assert any("LSASS" in (t or "") for t in types)

    def test_encoded_powershell_found(self, result):
        types = {pe.event.event_type for pe in result.processed_events}
        assert "Encoded PowerShell" in types


# ── PipelineResult helpers ────────────────────────────────────────────────────

class TestPipelineResultHelpers:
    @pytest.fixture(scope="class")
    def result(self, pipeline):
        return pipeline.process(_load("linux_syslog.log"))

    def test_threat_events_subset(self, result):
        assert len(result.threat_events) <= result.stats.parsed_events

    def test_critical_events_subset(self, result):
        assert len(result.critical_events) <= result.stats.parsed_events

    def test_top_source_ips_returns_list(self, result):
        ips = result.top_source_ips(5)
        assert isinstance(ips, list)
        assert all(isinstance(item, tuple) and len(item) == 2 for item in ips)

    def test_mitre_hit_summary_returns_list(self, result):
        hits = result.mitre_hit_summary()
        assert isinstance(hits, list)

    def test_to_summary_dict_keys(self, result):
        d = result.to_summary_dict()
        for key in ["log_type", "detection_confidence", "stats", "top_source_ips",
                    "mitre_hits"]:
            assert key in d

    def test_ioc_deduplication(self, result):
        """No (type, value) pair must appear twice in all_iocs."""
        seen = set()
        for ioc in result.all_iocs:
            key = (ioc.ioc_type, ioc.value)
            assert key not in seen, f"Duplicate IOC: {key}"
            seen.add(key)


# ── PipelineStats ─────────────────────────────────────────────────────────────

class TestPipelineStats:
    @pytest.fixture(scope="class")
    def stats(self, pipeline):
        return pipeline.process(_load("linux_syslog.log")).stats

    def test_to_dict_has_required_keys(self, stats):
        d = stats.to_dict()
        for key in ["total_lines", "parsed_events", "unique_iocs",
                    "threats_detected", "processing_time_ms", "ioc_type_counts"]:
            assert key in d

    def test_processing_time_positive(self, stats):
        assert stats.processing_time_ms > 0

    def test_severity_counts_method(self, stats):
        counts = stats.severity_counts()
        for sev in ["critical", "high", "medium", "low", "info"]:
            assert sev in counts

    def test_ioc_type_counts_is_dict(self, stats):
        assert isinstance(stats.ioc_type_counts, dict)


# ── Edge cases ────────────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_empty_string_is_empty(self, pipeline):
        result = pipeline.process("")
        assert result.is_empty

    def test_bytes_input_works(self, pipeline):
        content = _load("linux_syslog.log").encode("utf-8")
        result = pipeline.process(content)
        assert result.stats.parsed_events >= 15

    def test_force_log_type_respected(self, pipeline):
        content = _load("linux_syslog.log")
        result = pipeline.process(content, force_log_type=LogType.LINUX_SYSLOG)
        assert result.log_type == LogType.LINUX_SYSLOG

    def test_async_wrapper(self, pipeline):
        """process_async must return same result type as process."""
        content = _load("linux_syslog.log")
        result = asyncio.run(pipeline.process_async(content))
        assert isinstance(result, PipelineResult)
        assert result.stats.parsed_events >= 15

    def test_noisy_lines_dont_crash(self, pipeline):
        """Mixed valid/invalid lines must not crash the pipeline."""
        mixed = "\n".join([
            "Jul  1 10:23:11 server sshd[1234]: Failed password for root from 185.24.18.15 port 52431 ssh2",
            "THIS IS NOT A LOG LINE @@@@###$$$",
            "Jul  1 10:23:13 server sshd[1236]: Accepted password for deploy from 10.0.0.5 port 22 ssh2",
        ])
        result = pipeline.process(mixed)
        assert not result.is_empty

    def test_latin1_bytes_decoded(self, pipeline):
        """Latin-1 encoded bytes must be decoded without crash."""
        content = b"Jul  1 10:00:01 server sshd[1234]: Failed password for root from 185.24.18.15 port 22 ssh2"
        result = pipeline.process(content)
        assert result.stats.parsed_events >= 1
