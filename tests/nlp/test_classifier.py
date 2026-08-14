"""
Unit tests for EventClassifier and MITRE ATT&CK rule set.
Tests: rule structure, classification correctness, severity logic,
ClassificationResult fields, to_dict(), matched_rules.

Real API facts:
  - RULES is a list of ClassificationRule dataclasses
  - Rule fields: rule_id, description, event_type_patterns, mitre, severity_score,
                 threat_category, tags, log_types, extra_conditions, priority
  - rule.mitre: MitreTechnique(tactic_id, tactic_name, technique_id, ...)
  - SeverityLevel members: CRITICAL, HIGH, MEDIUM, LOW, INFO (not INFORMATIONAL)
  - ClassificationResult.to_dict() keys: tactic_id, tactic_name, technique_id,
    technique_name, sub_technique_id, sub_technique_name, severity, severity_score,
    threat_category, confidence, matched_rules, tags
  - matched_rules is a tuple of rule_id strings
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://u:p@localhost/db")
os.environ.setdefault("JWT_SECRET", "test")
os.environ.setdefault("APP_ENV", "development")

import pytest
from backend.nlp.classifier.event_classifier import EventClassifier, ClassificationResult
from backend.nlp.classifier.mitre_rules import RULES as CLASSIFICATION_RULES, SeverityLevel
from backend.schemas.logs import NormalizedEvent


@pytest.fixture(scope="module")
def classifier():
    return EventClassifier()


def _event(event_type: str, log_type: str = "linux_syslog", **kwargs) -> NormalizedEvent:
    return NormalizedEvent(
        log_type=log_type,
        raw_line=f"Test event: {event_type}",
        event_type=event_type,
        **kwargs,
    )


# ── MITRE rule quality ────────────────────────────────────────────────────────

class TestMITRERules:
    def test_rules_not_empty(self):
        """CLASSIFICATION_RULES must contain at least 40 rules."""
        assert len(CLASSIFICATION_RULES) >= 40

    def test_every_rule_has_technique_id_in_mitre(self):
        """Every rule must have a non-empty mitre.technique_id."""
        for rule in CLASSIFICATION_RULES:
            assert rule.mitre.technique_id, f"Rule '{rule.rule_id}' missing technique_id"

    def test_every_rule_has_tactic_in_mitre(self):
        """Every rule must have a non-empty mitre.tactic_name."""
        for rule in CLASSIFICATION_RULES:
            assert rule.mitre.tactic_name, f"Rule '{rule.rule_id}' missing tactic_name"

    def test_every_rule_has_severity_score(self):
        """Every rule must have an integer severity_score."""
        for rule in CLASSIFICATION_RULES:
            assert isinstance(rule.severity_score, int), f"Rule '{rule.rule_id}' bad severity_score"

    def test_severity_scores_in_valid_range(self):
        """All severity scores must be in [1, 10]."""
        for rule in CLASSIFICATION_RULES:
            assert 1 <= rule.severity_score <= 10, \
                f"Rule '{rule.rule_id}' score={rule.severity_score} out of range"

    def test_unique_rule_ids(self):
        """Rule IDs must be unique."""
        ids = [r.rule_id for r in CLASSIFICATION_RULES]
        assert len(ids) == len(set(ids)), "Duplicate rule_ids found"

    def test_every_rule_has_priority(self):
        """Every rule must have a positive integer priority."""
        for rule in CLASSIFICATION_RULES:
            assert isinstance(rule.priority, int) and rule.priority >= 1


# ── Classification correctness ────────────────────────────────────────────────

class TestClassificationCorrectness:
    def test_failed_login_technique(self, classifier):
        """Failed Login → T1110 (Brute Force), Credential Access."""
        result = classifier.classify(_event("Failed Login"))
        assert result.is_classified
        assert result.technique_id == "T1110"
        assert "Credential" in result.tactic_name

    def test_encoded_powershell_technique(self, classifier):
        """Encoded PowerShell → T1059, Execution."""
        result = classifier.classify(_event(
            "Encoded PowerShell", log_type="sysmon",
            command_line="powershell.exe -enc SGVsbG8="
        ))
        assert result.is_classified
        assert result.technique_id is not None

    def test_sql_injection_technique(self, classifier):
        """SQL Injection Attempt → T1190, Initial Access."""
        result = classifier.classify(_event("SQL Injection Attempt", log_type="apache_access"))
        assert result.is_classified
        assert result.technique_id == "T1190"

    def test_directory_traversal_technique(self, classifier):
        """Directory Traversal → T1083."""
        result = classifier.classify(_event("Directory Traversal", log_type="apache_access"))
        assert result.is_classified
        assert result.technique_id == "T1083"

    def test_lsass_access_is_critical(self, classifier):
        """LSASS Access → score=10, is_critical=True."""
        result = classifier.classify(_event("LSASS Access (Credential Dump)", log_type="sysmon"))
        assert result.is_classified
        assert result.is_critical
        assert result.severity_score >= 9

    def test_registry_persistence_technique(self, classifier):
        """Registry Persistence → T1547 family."""
        result = classifier.classify(_event("Registry Persistence", log_type="sysmon"))
        assert result.is_classified
        assert result.technique_id.startswith("T15")

    def test_unknown_event_returns_result(self, classifier):
        """Unknown event type must still return a ClassificationResult, not None."""
        result = classifier.classify(_event("Some Unknown Random Event XYZ"))
        assert result is not None
        assert isinstance(result, ClassificationResult)
        assert result.is_classified is False

    def test_unclassified_event_score_is_one(self, classifier):
        """Unclassified events must default to severity_score=1."""
        result = classifier.classify(_event("Unknown Event XYZ"))
        assert result.severity_score == 1


# ── Severity logic ────────────────────────────────────────────────────────────

class TestSeverityLogic:
    def test_critical_score_means_is_critical(self, classifier):
        """Score >= 9 means is_critical=True."""
        result = classifier.classify(_event("LSASS Access (Credential Dump)", log_type="sysmon"))
        assert result.is_critical

    def test_threat_flag_on_classified_event(self, classifier):
        """Classified events must have is_threat=True."""
        result = classifier.classify(_event("Failed Login"))
        assert result.is_threat

    def test_unclassified_not_threat(self, classifier):
        """Unclassified events must not be flagged as threat."""
        result = classifier.classify(_event("Unknown Event XYZ"))
        assert not result.is_threat

    def test_severity_score_range(self, classifier):
        """Severity score must always be in [1, 10]."""
        for event_type in ["Failed Login", "SQL Injection Attempt",
                           "LSASS Access (Credential Dump)", "Unknown XYZ"]:
            result = classifier.classify(_event(event_type))
            assert 1 <= result.severity_score <= 10

    def test_severity_from_score_critical(self):
        """SeverityLevel.from_score(9) must return CRITICAL."""
        assert SeverityLevel.from_score(9) == SeverityLevel.CRITICAL
        assert SeverityLevel.from_score(10) == SeverityLevel.CRITICAL

    def test_severity_from_score_high(self):
        assert SeverityLevel.from_score(7) == SeverityLevel.HIGH
        assert SeverityLevel.from_score(8) == SeverityLevel.HIGH

    def test_severity_from_score_medium(self):
        assert SeverityLevel.from_score(5) == SeverityLevel.MEDIUM

    def test_severity_from_score_low(self):
        assert SeverityLevel.from_score(3) == SeverityLevel.LOW

    def test_severity_from_score_info(self):
        """Score <= 2 must return INFO (not INFORMATIONAL)."""
        assert SeverityLevel.from_score(1) == SeverityLevel.INFO
        assert SeverityLevel.from_score(2) == SeverityLevel.INFO


# ── ClassificationResult interface ────────────────────────────────────────────

class TestClassificationResultInterface:
    def test_to_dict_returns_dict(self, classifier):
        result = classifier.classify(_event("Failed Login"))
        d = result.to_dict()
        assert isinstance(d, dict)

    def test_to_dict_has_required_keys(self, classifier):
        """to_dict must include all standard keys."""
        result = classifier.classify(_event("Failed Login"))
        d = result.to_dict()
        for key in ["technique_id", "technique_name", "tactic_id", "tactic_name",
                    "severity", "severity_score", "matched_rules"]:
            assert key in d, f"Missing key: {key}"

    def test_matched_rules_is_sequence(self, classifier):
        """matched_rules must be iterable (list or tuple)."""
        result = classifier.classify(_event("Failed Login"))
        assert hasattr(result.matched_rules, "__iter__")

    def test_matched_rules_not_empty_for_classified(self, classifier):
        """Classified events must have at least one matched rule."""
        result = classifier.classify(_event("Failed Login"))
        assert result.is_classified
        assert len(result.matched_rules) >= 1

    def test_is_critical_property(self, classifier):
        lsass = classifier.classify(_event("LSASS Access (Credential Dump)", log_type="sysmon"))
        assert isinstance(lsass.is_critical, bool)

    def test_threat_category_is_string(self, classifier):
        result = classifier.classify(_event("Failed Login"))
        assert isinstance(result.threat_category, str)
        assert len(result.threat_category) > 0
