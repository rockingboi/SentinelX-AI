"""
SentinelX AI — Event Classifier Engine
========================================
Applies MITRE ATT&CK classification rules to NormalizedEvent objects.

Architecture:
  EventClassifier.classify(event) → ClassificationResult

Matching algorithm:
  1. Iterate rules in priority order (lowest priority number = first)
  2. For each rule, test all conditions (event_type, log_type, extra)
  3. Collect ALL matching rules (multi-label)
  4. Primary classification = first (highest priority) match
  5. Severity = max across all matched rules
  6. Confidence = function of number of conditions matched + rule specificity

Output: ClassificationResult
  - Immutable dataclass
  - Contains primary MITRE mapping + all matched rule IDs
  - Maps directly to NLP pipeline output fields

Thread-safety: all state in local variables only; no shared mutable state.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from backend.nlp.classifier.mitre_rules import (
    RULES,
    ClassificationRule,
    MitreTechnique,
    SeverityLevel,
)
from backend.schemas.logs import NormalizedEvent

logger = logging.getLogger(__name__)


# ── Output dataclass ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ClassificationResult:
    """
    The classification output for a single NormalizedEvent.

    Primary fields map directly to the ParsedEvent ORM model.
    """
    # Primary MITRE classification (from highest-priority matching rule)
    tactic_id:           str | None
    tactic_name:         str | None
    technique_id:        str | None
    technique_name:      str | None
    sub_technique_id:    str | None
    sub_technique_name:  str | None

    # Severity
    severity:            SeverityLevel
    severity_score:      int          # 1–10

    # Threat label
    threat_category:     str

    # Confidence 0.0–1.0
    confidence:          float

    # All matching rule IDs (for audit / explainability)
    matched_rules:       tuple[str, ...]

    # All tags from all matched rules
    tags:                tuple[str, ...]

    # Was a rule matched at all?
    is_classified:       bool

    @property
    def is_threat(self) -> bool:
        """True if classified as MEDIUM or above."""
        return self.severity_score >= 5

    @property
    def is_critical(self) -> bool:
        return self.severity == SeverityLevel.CRITICAL

    def to_dict(self) -> dict:
        """Serialise for storage in NormalizedEvent.normalized_data."""
        return {
            "tactic_id":          self.tactic_id,
            "tactic_name":        self.tactic_name,
            "technique_id":       self.technique_id,
            "technique_name":     self.technique_name,
            "sub_technique_id":   self.sub_technique_id,
            "sub_technique_name": self.sub_technique_name,
            "severity":           self.severity.value,
            "severity_score":     self.severity_score,
            "threat_category":    self.threat_category,
            "confidence":         self.confidence,
            "matched_rules":      list(self.matched_rules),
            "tags":               list(self.tags),
        }


# Sentinel for unclassified events
_UNCLASSIFIED = ClassificationResult(
    tactic_id=None,
    tactic_name=None,
    technique_id=None,
    technique_name=None,
    sub_technique_id=None,
    sub_technique_name=None,
    severity=SeverityLevel.INFO,
    severity_score=1,
    threat_category="Unclassified",
    confidence=0.0,
    matched_rules=(),
    tags=(),
    is_classified=False,
)


# ── Classifier ────────────────────────────────────────────────────────────────

class EventClassifier:
    """
    Rule-based MITRE ATT&CK event classifier.

    Usage:
        classifier = EventClassifier()
        result = classifier.classify(normalized_event)
        print(result.technique_id, result.severity.value)
    """

    def classify(self, event: NormalizedEvent) -> ClassificationResult:
        """
        Classify a NormalizedEvent against all MITRE ATT&CK rules.

        Args:
            event: A NormalizedEvent from any parser.

        Returns:
            ClassificationResult with the primary classification and
            all matched rules.
        """
        if not event.event_type:
            return _UNCLASSIFIED

        matched: list[ClassificationRule] = []
        for rule in RULES:
            if self._matches(rule, event):
                matched.append(rule)

        if not matched:
            return _UNCLASSIFIED

        # Primary = highest-priority (lowest rule.priority number = first in sorted list)
        primary = matched[0]

        # Severity = max across all matched rules
        max_score = max(r.severity_score for r in matched)

        # Collect all unique tags
        all_tags: list[str] = []
        seen_tags: set[str] = set()
        for r in matched:
            for tag in r.tags:
                if tag not in seen_tags:
                    all_tags.append(tag)
                    seen_tags.add(tag)

        # Confidence heuristic:
        #   - base = 0.7 for event_type match only
        #   - +0.1 if log_type also matched
        #   - +0.1 if extra_conditions matched
        #   - +0.05 per additional matched rule (convergent evidence)
        confidence = 0.7
        if primary.log_types and event.log_type in primary.log_types:
            confidence += 0.1
        if primary.extra_conditions is not None:
            confidence += 0.1
        confidence += min(0.1, len(matched) * 0.02)
        confidence = min(1.0, round(confidence, 2))

        mitre = primary.mitre

        return ClassificationResult(
            tactic_id=mitre.tactic_id,
            tactic_name=mitre.tactic_name,
            technique_id=mitre.technique_id,
            technique_name=mitre.technique_name,
            sub_technique_id=mitre.sub_technique_id,
            sub_technique_name=mitre.sub_technique_name,
            severity=SeverityLevel.from_score(max_score),
            severity_score=max_score,
            threat_category=primary.threat_category,
            confidence=confidence,
            matched_rules=tuple(r.rule_id for r in matched),
            tags=tuple(all_tags),
            is_classified=True,
        )

    def classify_batch(
        self, events: list[NormalizedEvent]
    ) -> list[ClassificationResult]:
        """
        Classify a list of events.

        Args:
            events: List of NormalizedEvent objects.

        Returns:
            List of ClassificationResult objects in the same order.
        """
        return [self.classify(e) for e in events]

    # ── Matching logic ────────────────────────────────────────────────────────

    def _matches(self, rule: ClassificationRule, event: NormalizedEvent) -> bool:
        """Return True if the rule matches the event — all conditions AND'd."""
        # ── Condition 1: event_type pattern match ─────────────────────────────
        if not self._event_type_matches(rule, event):
            return False

        # ── Condition 2: log_type filter ──────────────────────────────────────
        if rule.log_types and event.log_type not in rule.log_types:
            return False

        # ── Condition 3: extra conditions ─────────────────────────────────────
        if rule.extra_conditions is not None:
            try:
                if not rule.extra_conditions(event):
                    return False
            except Exception:
                return False

        return True

    @staticmethod
    def _event_type_matches(rule: ClassificationRule, event: NormalizedEvent) -> bool:
        """
        Check if any rule pattern matches the event's event_type.
        Matching is case-insensitive substring match.
        """
        event_type = (event.event_type or "").lower()
        for pattern in rule.event_type_patterns:
            if pattern.lower() in event_type:
                return True
        return False

    # ── Utility ───────────────────────────────────────────────────────────────

    def get_rule_by_id(self, rule_id: str) -> ClassificationRule | None:
        """Look up a rule by its ID (for testing / admin inspection)."""
        for rule in RULES:
            if rule.rule_id == rule_id:
                return rule
        return None

    @property
    def rule_count(self) -> int:
        """Total number of loaded rules."""
        return len(RULES)

    def rules_for_severity(self, severity: SeverityLevel) -> list[ClassificationRule]:
        """Return all rules at or above the given severity level."""
        target_score = {
            SeverityLevel.CRITICAL: 9,
            SeverityLevel.HIGH:     7,
            SeverityLevel.MEDIUM:   5,
            SeverityLevel.LOW:      3,
            SeverityLevel.INFO:     1,
        }[severity]
        return [r for r in RULES if r.severity_score >= target_score]
