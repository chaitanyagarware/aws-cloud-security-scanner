from __future__ import annotations

from datetime import datetime, timezone

from ..models import Finding

SEVERITY_ID = {"INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}

def build_ocsf(findings: list[Finding]) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    events = []
    for f in findings:
        events.append({
            "activity_name": "Security Finding",
            "category_name": "Findings",
            "class_name": "Detection Finding",
            "metadata": {"product": {"name": "aws-cloud-security-scanner"}, "version": "1.0.0"},
            "severity": f.severity.title(),
            "severity_id": SEVERITY_ID.get(f.severity, 0),
            "time": now,
            "finding_info": {"uid": f.rule_id, "title": f.title, "desc": f.detail, "types": f.mitre_attack},
            "resources": [{"name": f.resource}],
            "actor": {"user": {"uid": f.principal}},
            "remediation": {"desc": f.remediation},
        })
    return {"schema": "OCSF-like detection finding export", "events": events}
