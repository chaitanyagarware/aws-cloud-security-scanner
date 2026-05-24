from __future__ import annotations

from typing import Any

from ..models import Finding


def build_json(findings: list[Finding], least_privilege: list[dict[str, Any]], metrics: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "project": "aws-cloud-security-scanner",
        "summary": {
            "total_findings": len(findings),
            "critical": sum(1 for f in findings if f.severity == "CRITICAL"),
            "high": sum(1 for f in findings if f.severity == "HIGH"),
            "medium": sum(1 for f in findings if f.severity == "MEDIUM"),
            "low": sum(1 for f in findings if f.severity == "LOW"),
        },
        "impact_metrics": metrics or {},
        "findings": [f.as_dict() for f in findings],
        "least_privilege": least_privilege,
    }
