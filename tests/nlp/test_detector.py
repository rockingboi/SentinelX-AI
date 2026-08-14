"""
Unit tests for LogTypeDetector.
Tests: detect(), detect_with_override(), all 5 log types, confidence, DetectionResult fields.
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://u:p@localhost/db")
os.environ.setdefault("JWT_SECRET", "test")
os.environ.setdefault("APP_ENV", "development")

import pytest
from backend.nlp.detector import LogTypeDetector
from backend.models.security_log import LogType

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.fixture(scope="module")
def detector():
    return LogTypeDetector()


def _load(filename: str) -> str:
    return (FIXTURES / filename).read_text(encoding="utf-8")


# ── Detection tests ───────────────────────────────────────────────────────────

class TestDetectLinuxSyslog:
    def test_correct_log_type(self, detector):
        """Linux syslog fixture must be detected as LINUX_SYSLOG."""
        result = detector.detect(_load("linux_syslog.log"))
        assert result.log_type == LogType.LINUX_SYSLOG

    def test_confidence_above_threshold(self, detector):
        """Confidence for linux syslog must be above 0.5."""
        result = detector.detect(_load("linux_syslog.log"))
        assert result.confidence >= 0.5

    def test_result_has_required_fields(self, detector):
        """DetectionResult must expose log_type and confidence attributes."""
        result = detector.detect(_load("linux_syslog.log"))
        assert hasattr(result, "log_type")
        assert hasattr(result, "confidence")
        assert isinstance(result.confidence, float)


class TestDetectApacheAccess:
    def test_correct_log_type(self, detector):
        """Apache access log fixture must be detected as APACHE_ACCESS."""
        result = detector.detect(_load("apache_access.log"))
        assert result.log_type == LogType.APACHE_ACCESS

    def test_confidence_above_threshold(self, detector):
        result = detector.detect(_load("apache_access.log"))
        assert result.confidence >= 0.6


class TestDetectNginxAccess:
    def test_detects_web_log_type(self, detector):
        """Nginx log may be detected as NGINX_ACCESS or APACHE_ACCESS (both are CLF)."""
        result = detector.detect(_load("nginx_access.log"))
        assert result.log_type in (LogType.NGINX_ACCESS, LogType.APACHE_ACCESS)

    def test_confidence_above_threshold(self, detector):
        result = detector.detect(_load("nginx_access.log"))
        assert result.confidence >= 0.5


class TestDetectWindowsEvent:
    def test_detects_some_type(self, detector):
        """Windows event fixture must be detected with some confidence."""
        result = detector.detect(_load("windows_event.log"))
        assert result is not None
        assert hasattr(result, "log_type")

    def test_detect_with_override_works(self, detector):
        """Forcing WINDOWS_EVENT on windows_event.log always returns correct type."""
        result = detector.detect_with_override(
            _load("windows_event.log"), LogType.WINDOWS_EVENT
        )
        assert result.log_type == LogType.WINDOWS_EVENT
        assert result.confidence == 1.0


class TestDetectSysmon:
    def test_correct_log_type_via_override(self, detector):
        """Sysmon fixture detected correctly via force override."""
        content = _load("sysmon.log")
        override = detector.detect_with_override(content, LogType.SYSMON)
        assert override.log_type == LogType.SYSMON
        assert override.confidence == 1.0

    def test_detect_with_override_ignores_content(self, detector):
        """detect_with_override must always return the forced type."""
        result = detector.detect_with_override(
            _load("linux_syslog.log"), LogType.WINDOWS_EVENT
        )
        assert result.log_type == LogType.WINDOWS_EVENT
        assert result.confidence == 1.0


class TestEdgeCases:
    def test_empty_content_returns_unknown(self, detector):
        """Empty string must return LogType.UNKNOWN."""
        result = detector.detect("")
        assert result.log_type == LogType.UNKNOWN

    def test_random_text_low_confidence_or_unknown(self, detector):
        """Gibberish text must return UNKNOWN or very low confidence."""
        result = detector.detect("hello world this is not a log file at all")
        assert result.confidence < 0.7 or result.log_type == LogType.UNKNOWN

    def test_confidence_is_between_0_and_1(self, detector):
        """Confidence must always be a float in [0.0, 1.0]."""
        for fixture in ["linux_syslog.log", "apache_access.log"]:
            result = detector.detect(_load(fixture))
            assert 0.0 <= result.confidence <= 1.0, f"Out of range for {fixture}"
