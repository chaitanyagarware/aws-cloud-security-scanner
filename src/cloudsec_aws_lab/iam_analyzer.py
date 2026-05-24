from __future__ import annotations

from pathlib import Path
from typing import Any

from .io_utils import iter_json_files, load_json
from .models import Finding

PRIV_ESC_ACTIONS = {
    "iam:PassRole",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:CreateAccessKey",
    "sts:AssumeRole",
}

SENSITIVE_SERVICES = ("iam:", "kms:", "s3:", "ec2:", "lambda:", "organizations:", "cloudtrail:")


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _statements(policy: dict[str, Any]) -> list[dict[str, Any]]:
    return _as_list(policy.get("Statement", []))


def _contains_action(actions: list[str], target: str) -> bool:
    target_service = target.split(":", 1)[0].lower()
    for action in actions:
        a = action.lower()
        if a == "*" or a == f"{target_service}:*" or a == target.lower():
            return True
    return False


def _has_mfa_condition(stmt: dict[str, Any]) -> bool:
    condition = stmt.get("Condition", {})
    text = str(condition).lower()
    return "aws:multifactorauthpresent" in text or "mfa" in text


def analyze_iam_path(path: str | Path) -> list[Finding]:
    findings: list[Finding] = []
    for file in iter_json_files(path):
        policy = load_json(file)
        findings.extend(analyze_policy(policy, source_name=file.name))
    return findings


def analyze_policy(policy: dict[str, Any], source_name: str = "inline_policy") -> list[Finding]:
    findings: list[Finding] = []
    for idx, stmt in enumerate(_statements(policy)):
        if stmt.get("Effect", "Allow") != "Allow":
            continue
        sid = stmt.get("Sid", f"Statement{idx}")
        actions = [str(a) for a in _as_list(stmt.get("Action"))]
        resources = [str(r) for r in _as_list(stmt.get("Resource"))]
        principals = _as_list(stmt.get("Principal"))

        if "*" in actions:
            findings.append(Finding(
                source="IAM",
                rule_id="IAM-001",
                title="Policy allows all AWS actions",
                severity="CRITICAL",
                detail=f"{source_name}:{sid} uses Action='*', which creates account-wide blast radius.",
                resource=", ".join(resources) or "*",
                evidence={"statement": sid, "actions": actions},
                remediation="Replace Action='*' with explicit service actions required by the workload.",
            ))

        service_wildcards = [a for a in actions if a.endswith(":*") and a.startswith(SENSITIVE_SERVICES)]
        if service_wildcards:
            findings.append(Finding(
                source="IAM",
                rule_id="IAM-002",
                title="Sensitive service wildcard permissions",
                severity="HIGH",
                detail=f"{source_name}:{sid} grants broad sensitive service permissions: {service_wildcards}.",
                resource=", ".join(resources) or "*",
                evidence={"statement": sid, "actions": service_wildcards},
                remediation="Scope permissions to exact API actions and resource ARNs where possible.",
            ))

        if "*" in resources and any(a.startswith(SENSITIVE_SERVICES) or a == "*" for a in actions):
            findings.append(Finding(
                source="IAM",
                rule_id="IAM-003",
                title="Sensitive permissions apply to all resources",
                severity="HIGH",
                detail=f"{source_name}:{sid} applies sensitive permissions to Resource='*'.",
                resource="*",
                evidence={"statement": sid, "actions": actions},
                remediation="Use resource-level constraints, tags, account boundaries, or conditions.",
            ))

        matched_priv_esc = [a for a in PRIV_ESC_ACTIONS if _contains_action(actions, a)]
        if matched_priv_esc:
            sev = "CRITICAL" if "*" in resources else "HIGH"
            findings.append(Finding(
                source="IAM",
                rule_id="IAM-004",
                title="Potential privilege escalation permission",
                severity=sev,
                detail=f"{source_name}:{sid} grants permissions commonly involved in privilege escalation: {matched_priv_esc}.",
                resource=", ".join(resources) or "*",
                evidence={"statement": sid, "matched_actions": matched_priv_esc},
                remediation="Restrict privileged IAM actions, add permission boundaries, MFA conditions, and approval workflow.",
            ))

        sensitive_without_mfa = any(
            a == "*" or a.startswith("iam:") or a in {"s3:DeleteBucket", "kms:ScheduleKeyDeletion"}
            for a in actions
        )
        if sensitive_without_mfa and not _has_mfa_condition(stmt):
            findings.append(Finding(
                source="IAM",
                rule_id="IAM-005",
                title="Sensitive action lacks MFA condition",
                severity="MEDIUM",
                detail=f"{source_name}:{sid} permits sensitive operations without an MFA condition.",
                resource=", ".join(resources) or "*",
                evidence={"statement": sid, "condition": stmt.get("Condition")},
                remediation="Add aws:MultiFactorAuthPresent condition for sensitive human-driven access.",
            ))

        if principals:
            principal_text = str(principals)
            if "*" in principal_text or "arn:aws:iam::*" in principal_text:
                findings.append(Finding(
                    source="IAM",
                    rule_id="IAM-006",
                    title="Trust policy allows broad principal access",
                    severity="HIGH",
                    detail=f"{source_name}:{sid} has a broad Principal in a trust/resource policy.",
                    resource=", ".join(resources) or "trust_policy",
                    evidence={"statement": sid, "principal": principals},
                    remediation="Restrict Principal to specific trusted account, role, service, and add ExternalId where required.",
                ))
    return findings
