from __future__ import annotations

from datetime import datetime, timezone

from ..models import Finding

_SEV = {"CRITICAL": 90, "HIGH": 75, "MEDIUM": 50, "LOW": 20, "INFO": 1}


def build_asff(findings: list[Finding], account_id: str = "000000000000", region: str = "us-east-1") -> list[dict]:
    now = datetime.now(timezone.utc).isoformat()
    output = []
    for idx, f in enumerate(findings, 1):
        output.append({
            "SchemaVersion": "2018-10-08",
            "Id": f"aws-cloud-security-scanner/{f.rule_id}/{idx}",
            "ProductArn": f"arn:aws:securityhub:{region}:{account_id}:product/{account_id}/default",
            "GeneratorId": f.rule_id,
            "AwsAccountId": account_id,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "CreatedAt": now,
            "UpdatedAt": now,
            "Severity": {"Label": f.severity, "Normalized": _SEV.get(f.severity, 1)},
            "Title": f.title,
            "Description": f.detail[:1024],
            "Resources": [{"Type": "AwsIamRole" if "iam" in f.resource.lower() else "Other", "Id": f.resource}],
            "Remediation": {"Recommendation": {"Text": f.remediation or "Review finding."}},
            "ProductFields": {"source": f.source, "rule_id": f.rule_id, "principal": f.principal},
            "RecordState": "ACTIVE",
            "Workflow": {"Status": "NEW"},
        })
    return output
