from __future__ import annotations

from pathlib import Path
from typing import Any

from .io_utils import load_json
from .input_models import AccessAnalyzerFinding, validate_list
from .models import Finding
from .risk_model import normalize_severity

_FINDING_SEVERITY = {
    "ERROR": "HIGH",
    "SECURITY_WARNING": "MEDIUM",
    "SUGGESTION": "LOW",
    "WARNING": "MEDIUM",
}


def _items(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        for key in ("findings", "Findings", "policyChecks", "PolicyChecks"):
            if isinstance(raw.get(key), list):
                return raw[key]
    return []


def analyze_access_analyzer(path: str | Path) -> list[Finding]:
    findings: list[Finding] = []
    for validated in validate_list(AccessAnalyzerFinding, _items(load_json(path)), "IAM Access Analyzer"):
        item = validated.model_dump(exclude_none=True)
        check_type = str(item.get("findingType") or item.get("type") or item.get("finding_type") or "SUGGESTION")
        severity = normalize_severity(_FINDING_SEVERITY.get(check_type.upper(), item.get("severity", "LOW")))
        issue_code = str(item.get("issueCode") or item.get("code") or item.get("id") or "ACCESS-ANALYZER")
        resource = str(item.get("resource") or item.get("resourceArn") or item.get("policyName") or "policy")
        detail = str(item.get("findingDetails") or item.get("message") or item.get("detail") or "IAM Access Analyzer finding")
        findings.append(Finding(
            source="IAM Access Analyzer",
            rule_id=f"AA-{issue_code}",
            title=f"Access Analyzer: {issue_code.replace('_', ' ').title()}",
            severity=severity,
            detail=detail,
            resource=resource,
            principal=str(item.get("principal") or "unknown"),
            evidence=item,
            remediation=(
                "Validate the finding with IAM Access Analyzer policy validation, remove unused actions, "
                "scope resources, and add conditions such as MFA, source VPC, external ID, or ABAC tags."
            ),
        ))
    return findings


def generate_policy_from_observed_actions(principal: str, actions: list[str]) -> dict[str, Any]:
    """Create a safe review draft from CloudTrail-observed actions.

    This is intentionally a draft, not an automatic production policy. Resource scoping must be
    completed by the security owner before deployment.
    """
    service_actions = sorted({a for a in actions if ":" in a and "*" not in a})
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ObservedReadOrOperationalAccessReviewDraft",
                "Effect": "Allow",
                "Action": service_actions,
                "Resource": "REPLACE_WITH_SCOPED_ARNS",
                "Condition": {
                    "BoolIfExists": {"aws:MultiFactorAuthPresent": "true"},
                },
            }
        ],
        "_review_notes": [
            f"Draft generated for {principal} from observed CloudTrail actions.",
            "Replace Resource wildcard placeholder with scoped ARNs or ABAC tag conditions.",
            "Compare against AWS IAM Access Analyzer generated policy before production use.",
        ],
    }
