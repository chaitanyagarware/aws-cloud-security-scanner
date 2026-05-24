from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .input_models import CloudTrailEvent, validate_list
from .io_utils import iter_json_records
from .mitre import attack_for
from .models import Finding

SENSITIVE_EVENTS = {
    "CreateAccessKey": "IAM access key created",
    "PutUserPolicy": "Inline user policy modified",
    "AttachUserPolicy": "Managed policy attached to user",
    "AttachRolePolicy": "Managed policy attached to role",
    "CreatePolicyVersion": "New policy version created",
    "SetDefaultPolicyVersion": "Default policy version changed",
    "PassRole": "Role pass attempted",
    "StopLogging": "CloudTrail logging stopped",
    "DeleteTrail": "CloudTrail deleted",
    "DeleteDetector": "GuardDuty detector deleted",
    "UpdateDetector": "GuardDuty detector updated",
    "DisableKey": "KMS key disabled",
    "ScheduleKeyDeletion": "KMS key scheduled for deletion",
}
RISKY_USER_AGENTS = ("kali", "nmap", "sqlmap", "curl", "python-requests")
DEFAULT_COMMON_REGIONS = {"us-east-1", "us-east-2", "us-west-2"}


def principal_from_event(event: dict[str, Any]) -> str:
    ident = event.get("userIdentity", {})
    return ident.get("arn") or ident.get("userName") or ident.get("accountId") or ident.get("type") or "unknown"


def _finding(**kwargs: Any) -> Finding:
    rule_id = kwargs.get("rule_id", "")
    title = kwargs.get("title", "")
    kwargs.setdefault("mitre_attack", attack_for(rule_id, title))
    return Finding(**kwargs)


def analyze_cloudtrail(path: str | Path, approved_regions: set[str] | None = None) -> tuple[list[Finding], dict[str, Any]]:
    raw_events = list(iter_json_records(path))
    events = [e.model_dump() for e in validate_list(CloudTrailEvent, raw_events, "CloudTrail")]
    common_regions = approved_regions or DEFAULT_COMMON_REGIONS
    findings: list[Finding] = []
    actions_by_principal: dict[str, Counter[str]] = defaultdict(Counter)
    denied_by_principal: Counter[str] = Counter()

    for event in events:
        name = event.get("eventName", "Unknown")
        source = event.get("eventSource", "unknown")
        principal = principal_from_event(event)
        region = event.get("awsRegion", "unknown")
        user_agent = str(event.get("userAgent", "")).lower()
        actions_by_principal[principal][f"{source}:{name}"] += 1

        ident_type = event.get("userIdentity", {}).get("type", "")
        if ident_type == "Root":
            findings.append(_finding(
                source="CloudTrail", rule_id="CT-001", title="Root account activity detected", severity="CRITICAL",
                detail=f"Root identity used {name} in {region} at {event.get('eventTime')}.", principal=principal, resource=source, evidence=event,
                remediation="Avoid root usage except for account-level tasks; enable MFA and move operations to least-privilege roles.",
            ))
        if name == "ConsoleLogin" and event.get("additionalEventData", {}).get("MFAUsed") == "No":
            findings.append(_finding(
                source="CloudTrail", rule_id="CT-002", title="Console login without MFA", severity="HIGH",
                detail=f"Console login without MFA by {principal} from {event.get('sourceIPAddress')}.", principal=principal, resource="console", evidence=event,
                remediation="Require MFA for all human identities and enforce through IAM Identity Center or conditional policies.",
            ))
        if name in SENSITIVE_EVENTS:
            sev = "CRITICAL" if name in {"StopLogging", "DeleteTrail", "DeleteDetector", "ScheduleKeyDeletion"} else "HIGH"
            findings.append(_finding(
                source="CloudTrail", rule_id="CT-003", title=SENSITIVE_EVENTS[name], severity=sev,
                detail=f"Sensitive API call {name} by {principal} in {region}.", principal=principal, resource=source, evidence=event,
                remediation="Review authorization, validate change ticket, rotate exposed credentials if unauthorized, and alert on repeat behavior.",
            ))
        if event.get("errorCode") in {"AccessDenied", "UnauthorizedOperation", "Client.UnauthorizedOperation"}:
            denied_by_principal[principal] += 1
            findings.append(_finding(
                source="CloudTrail", rule_id="CT-004", title="Denied AWS API call", severity="MEDIUM",
                detail=f"Denied call {name} by {principal}; may indicate reconnaissance or broken permissions.", principal=principal, resource=source, evidence=event,
                remediation="Investigate intent. For legitimate workload, add only the missing minimum action; otherwise alert and contain.",
            ))
        if any(token in user_agent for token in RISKY_USER_AGENTS):
            findings.append(_finding(
                source="CloudTrail", rule_id="CT-005", title="Suspicious automation user agent", severity="MEDIUM",
                detail=f"User agent '{event.get('userAgent')}' used for {name} by {principal}.", principal=principal, resource=source, evidence=event,
                remediation="Validate whether this is approved automation. If not, rotate credentials and investigate source host.",
            ))
        if region not in common_regions and region != "unknown":
            findings.append(_finding(
                source="CloudTrail", rule_id="CT-006", title="AWS API call from uncommon region", severity="LOW",
                detail=f"{name} occurred in uncommon region {region} by {principal}.", principal=principal, resource=source, evidence=event,
                remediation="Compare with expected business regions and restrict regions through SCPs where practical.",
            ))
    return findings, {"total_events": len(events), "actions_by_principal": {k: dict(v) for k, v in actions_by_principal.items()}, "denied_by_principal": dict(denied_by_principal)}
