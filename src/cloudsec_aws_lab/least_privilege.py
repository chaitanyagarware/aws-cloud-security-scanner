from __future__ import annotations

import re
from typing import Any

from .access_analyzer import generate_policy_from_observed_actions

SENSITIVE_ALWAYS_REVIEW = {"iam:PassRole", "iam:CreateAccessKey", "kms:Decrypt", "s3:PutBucketPolicy"}
AWS_EVENT_SOURCE_RE = re.compile(r"^(?P<service>[a-z0-9-]+)\.amazonaws\.com:(?P<action>[A-Za-z0-9*]+)$")
NON_POLICY_EVENT_SERVICES = {"signin", "monitoring"}


def normalize_cloudtrail_action(action: str) -> str | None:
    """Convert CloudTrail eventSource:eventName into IAM action syntax.

    Example: iam.amazonaws.com:CreateAccessKey -> iam:CreateAccessKey.
    Already-normalized actions such as s3:GetObject are preserved.
    Invalid or unknown action shapes return None instead of generating bad IAM policy JSON.
    """
    value = str(action).strip()
    match = AWS_EVENT_SOURCE_RE.match(value)
    if match:
        service = match.group("service")
        action_name = match.group("action")
        if service in NON_POLICY_EVENT_SERVICES:
            return None
        return f"{service}:{action_name}"
    if re.match(r"^[a-z0-9-]+:[A-Za-z0-9*]+$", value):
        service = value.split(":", 1)[0]
        if service in NON_POLICY_EVENT_SERVICES:
            return None
        return value
    return None


def recommend_from_cloudtrail(context: dict[str, Any]) -> list[dict[str, Any]]:
    recommendations = []
    for principal, actions in context.get("actions_by_principal", {}).items():
        normalized_actions = sorted({
            normalized
            for action in actions
            if (normalized := normalize_cloudtrail_action(action)) is not None
        })
        services = sorted({action.split(":", 1)[0] for action in normalized_actions})
        draft_policy = generate_policy_from_observed_actions(principal, normalized_actions)
        recommendations.append({
            "principal": principal,
            "observed_action_count": sum(actions.values()),
            "unique_observed_events": normalized_actions,
            "least_privilege_note": (
                "Review draft only: compare against IAM Access Analyzer generated policy, remove unused broad permissions, "
                "scope Resource by ARN/tag, and require MFA/conditional access for human users."
            ),
            "review_required": sorted(a for a in normalized_actions if a in SENSITIVE_ALWAYS_REVIEW),
            "service_scope_hint": services,
            "draft_policy": draft_policy,
        })
    return recommendations


def calculate_impact_metrics(findings: list[Any], least_privilege: list[dict[str, Any]]) -> dict[str, Any]:
    wildcard_findings = [f for f in findings if f.rule_id in {"IAM-001", "IAM-002", "IAM-003"}]
    principals_with_recommendations = len(least_privilege)
    observed_actions = sum(len(r.get("unique_observed_events", [])) for r in least_privilege)
    return {
        "wildcard_permission_findings": len(wildcard_findings),
        "principals_with_least_privilege_drafts": principals_with_recommendations,
        "unique_observed_actions_modeled": observed_actions,
        "portfolio_value": (
            "Shows identity blast-radius reduction, telemetry-driven policy review, "
            "Security Hub/SARIF export readiness, and multi-source cloud detection correlation."
        ),
    }
