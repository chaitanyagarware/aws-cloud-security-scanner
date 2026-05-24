from __future__ import annotations

from datetime import date
from typing import Iterable

from .config import AnalyzerConfig, SeverityOverride, SuppressionRule
from .models import Finding


def _matches(value: str | None, actual: str) -> bool:
    return value is None or value == actual


def _not_expired(rule: SuppressionRule) -> bool:
    if not rule.expires:
        return True
    try:
        return date.fromisoformat(rule.expires) >= date.today()
    except ValueError:
        return False


def matches_suppression(finding: Finding, rule: SuppressionRule) -> bool:
    if not _not_expired(rule):
        return False
    if not _matches(rule.rule_id, finding.rule_id):
        return False
    if not _matches(rule.source, finding.source):
        return False
    if not _matches(rule.principal, finding.principal):
        return False
    if not _matches(rule.resource, finding.resource):
        return False
    if rule.title_contains and rule.title_contains.lower() not in finding.title.lower():
        return False
    return True


def apply_suppressions_and_overrides(findings: Iterable[Finding], config: AnalyzerConfig) -> tuple[list[Finding], dict[str, int]]:
    override_by_rule: dict[str, SeverityOverride] = {item.rule_id: item for item in config.severity_overrides}
    kept: list[Finding] = []
    suppressed = 0
    overridden = 0
    for finding in findings:
        if any(matches_suppression(finding, rule) for rule in config.suppressions):
            suppressed += 1
            continue
        override = override_by_rule.get(finding.rule_id)
        if override and finding.severity != override.severity:
            finding.evidence = {**finding.evidence, "severity_override_reason": override.reason, "original_severity": finding.severity}
            finding.severity = override.severity
            overridden += 1
        kept.append(finding)
    return kept, {"suppressed_findings": suppressed, "severity_overrides_applied": overridden}
