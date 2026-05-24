from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from ..models import Finding
from ..remediation import terraform_snippet
from ..risk_model import sort_findings


def render_markdown(findings: list[Finding], least_privilege: list[dict[str, Any]], metrics: dict[str, Any] | None = None) -> str:
    ordered = sort_findings(findings)
    counts = Counter(f.severity for f in ordered)
    metrics = metrics or {}
    lines: list[str] = []
    lines.append("# AWS Cloud Security Assessment Report")
    lines.append("")
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(
        f"The lab analyzed IAM policies, CloudTrail events, GuardDuty findings, and optional IAM Access Analyzer exports. "
        f"It identified {len(ordered)} total security findings: "
        f"{counts.get('CRITICAL', 0)} critical, {counts.get('HIGH', 0)} high, "
        f"{counts.get('MEDIUM', 0)} medium, {counts.get('LOW', 0)} low, and {counts.get('INFO', 0)} informational."
    )
    lines.append("")
    lines.append("Top security concern: reduce identity blast radius by replacing broad IAM permissions with scoped role-based access, MFA conditions, ABAC tags, and monitored change control.")
    lines.append("")
    lines.append("## Impact Metrics")
    lines.append("")
    lines.append(f"- Wildcard permission findings: `{metrics.get('wildcard_permission_findings', 0)}`")
    lines.append(f"- Principals with least-privilege drafts: `{metrics.get('principals_with_least_privilege_drafts', 0)}`")
    lines.append(f"- Unique observed actions modeled: `{metrics.get('unique_observed_actions_modeled', 0)}`")
    lines.append(f"- Portfolio value: {metrics.get('portfolio_value', 'Security engineering evidence artifact.')}")
    lines.append("")
    lines.append("## Top Findings")
    lines.append("")
    lines.append("| Severity | Source | Rule | MITRE | Principal | Resource | Finding |")
    lines.append("|---|---|---|---|---|---|---|")
    for f in ordered[:25]:
        lines.append(f"| {f.severity} | {f.source} | {f.rule_id} | {', '.join(f.mitre_attack) or 'n/a'} | `{f.principal}` | `{f.resource}` | {f.title} |")
    lines.append("")
    lines.append("## Detailed Remediation Plan")
    lines.append("")
    for i, f in enumerate(ordered, 1):
        lines.append(f"### {i}. [{f.severity}] {f.title}")
        lines.append("")
        lines.append(f"- Source: `{f.source}`")
        lines.append(f"- Rule: `{f.rule_id}`")
        lines.append(f"- Principal: `{f.principal}`")
        lines.append(f"- Resource: `{f.resource}`")
        lines.append(f"- MITRE ATT&CK: `{', '.join(f.mitre_attack) or 'n/a'}`")
        lines.append(f"- Detail: {f.detail}")
        lines.append(f"- Remediation: {f.remediation}")
        lines.append("- Terraform remediation review draft:")
        lines.append("")
        lines.append("```hcl")
        lines.append(terraform_snippet(f).strip())
        lines.append("```")
        lines.append("")
    lines.append("## Least-Privilege Recommendations")
    lines.append("")
    if not least_privilege:
        lines.append("No CloudTrail-derived least-privilege recommendations were generated.")
    for rec in least_privilege:
        lines.append(f"### Principal: `{rec['principal']}`")
        lines.append(f"- Observed action count: {rec['observed_action_count']}")
        lines.append(f"- Unique observed events: `{', '.join(rec['unique_observed_events'])}`")
        lines.append(f"- Recommendation: {rec['least_privilege_note']}")
        if rec.get("review_required"):
            lines.append(f"- Sensitive actions requiring human review: `{', '.join(rec['review_required'])}`")
        lines.append("- Draft policy generated from observed behavior:")
        lines.append("")
        lines.append("```json")
        import json
        lines.append(json.dumps(rec.get("draft_policy", {}), indent=2))
        lines.append("```")
        lines.append("")
    lines.append("## Security Engineering Narrative")
    lines.append("")
    lines.append(
        "This lab demonstrates an end-to-end AWS security workflow: IAM blast-radius analysis, CloudTrail behavior review, "
        "GuardDuty triage, Access Analyzer ingestion, cross-source correlation, least-privilege policy drafting, SARIF export for GitHub, "
        "and ASFF-shaped output for Security Hub style pipelines."
    )
    lines.append("")
    return "\n".join(lines)
