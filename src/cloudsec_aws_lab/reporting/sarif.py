from __future__ import annotations

from ..models import Finding

_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}


def build_sarif(findings: list[Finding]) -> dict:
    rules = {}
    results = []
    for f in findings:
        rules.setdefault(f.rule_id, {
            "id": f.rule_id,
            "name": f.title,
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.detail[:1000]},
            "help": {"text": f.remediation or "Review and remediate."},
            "properties": {"source": f.source, "severity": f.severity},
        })
        results.append({
            "ruleId": f.rule_id,
            "level": _LEVEL.get(f.severity, "warning"),
            "message": {"text": f"{f.title}: {f.detail}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.resource if f.resource != "unknown" else "cloud-security-input"},
                    "region": {"startLine": 1},
                }
            }],
            "properties": {"source": f.source, "principal": f.principal, "severity": f.severity},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "aws-cloud-security-scanner", "informationUri": "https://github.com/chaitanyagarware010/aws-cloud-security-scanner", "rules": list(rules.values())}},
            "results": results,
        }],
    }
