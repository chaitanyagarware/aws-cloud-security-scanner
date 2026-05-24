from __future__ import annotations

from collections import defaultdict

from .models import Finding


def correlate_findings(findings: list[Finding]) -> list[Finding]:
    """Create incident-storyline findings across IAM, CloudTrail, GuardDuty, and Access Analyzer."""
    by_principal: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        if finding.principal and finding.principal != "unknown":
            by_principal[finding.principal].append(finding)

    correlated: list[Finding] = []
    for principal, items in by_principal.items():
        sources = {i.source for i in items}
        rules = {i.rule_id for i in items}
        if len(sources) >= 2:
            severity = "CRITICAL" if any(i.severity == "CRITICAL" for i in items) else "HIGH"
            correlated.append(Finding(
                source="Correlation",
                rule_id="COR-001",
                title="Multi-source identity risk storyline",
                severity=severity,
                detail=(
                    f"Principal {principal} appears across {', '.join(sorted(sources))}. "
                    "This raises confidence because static permissions and runtime behavior overlap."
                ),
                principal=principal,
                resource="identity",
                evidence={"sources": sorted(sources), "rules": sorted(rules), "finding_count": len(items)},
                remediation="Prioritize this principal for containment review, credential rotation, permission reduction, and session audit.",
            ))
        if "CT-004" in rules and any(rule in rules for rule in {"CT-003", "GD-Recon:IAMUser", "GD-Stealth:IAMUser"}):
            correlated.append(Finding(
                source="Correlation",
                rule_id="COR-002",
                title="Denied calls followed by sensitive or threat activity",
                severity="HIGH",
                detail=(
                    f"Principal {principal} generated denied API calls and later appears in sensitive activity. "
                    "This may indicate probing before successful misuse."
                ),
                principal=principal,
                resource="identity",
                evidence={"rules": sorted(rules)},
                remediation="Investigate the full CloudTrail timeline, review source IPs/user agents, and reduce excessive permissions.",
            ))
    return correlated
