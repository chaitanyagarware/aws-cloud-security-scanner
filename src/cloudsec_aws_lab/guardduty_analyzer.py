from __future__ import annotations

from pathlib import Path
from typing import Any

from .input_models import GuardDutyFinding, validate_list
from .io_utils import load_json
from .mitre import attack_for
from .models import Finding
from .risk_model import normalize_severity


def _items(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, dict) and "findings" in raw:
        return raw["findings"]
    if isinstance(raw, dict) and "Findings" in raw:
        return raw["Findings"]
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        return [raw]
    return []


def _first_non_empty(*values: Any) -> str | None:
    for value in values:
        if value is not None and str(value).strip() and str(value).strip().lower() != "none":
            return str(value)
    return None


def _principal(resource: dict[str, Any], service: dict[str, Any] | None = None, evidence: dict[str, Any] | None = None) -> str:
    service = service or {}
    evidence = evidence or {}
    access_key = resource.get("accessKeyDetails") or {}
    kubernetes = resource.get("kubernetesDetails") or {}
    eks_user = (kubernetes.get("kubernetesUserDetails") or {}).get("username")
    lambda_details = resource.get("lambdaDetails") or {}
    rds = resource.get("rdsDbInstanceDetails") or {}
    action = service.get("action") or {}
    aws_api = action.get("awsApiCallAction") or {}
    remote_account = aws_api.get("remoteAccountDetails") or {}
    return _first_non_empty(
        access_key.get("principalId"),
        access_key.get("userName"),
        access_key.get("userType"),
        eks_user,
        lambda_details.get("functionName"),
        rds.get("dbInstanceIdentifier"),
        remote_account.get("accountId"),
        evidence.get("AccountId"),
        evidence.get("accountId"),
        resource.get("resourceType"),
    ) or "unknown"


def _resource(resource: dict[str, Any], service: dict[str, Any] | None = None) -> str:
    instance = resource.get("instanceDetails") or {}
    if instance.get("instanceId"):
        return instance["instanceId"]
    buckets = resource.get("s3BucketDetails") or []
    names = [b.get("name") or b.get("arn") for b in buckets if isinstance(b, dict) and (b.get("name") or b.get("arn"))]
    if names:
        return ",".join(names)
    for key, identifier in [
        ("lambdaDetails", "functionArn"),
        ("eksClusterDetails", "arn"),
        ("rdsDbInstanceDetails", "dbInstanceArn"),
        ("ebsVolumeDetails", "volumeArn"),
        ("containerDetails", "containerRuntime"),
    ]:
        details = resource.get(key) or {}
        if details.get(identifier):
            return str(details[identifier])
    action = (service or {}).get("action") or {}
    aws_api = action.get("awsApiCallAction") or {}
    remote_ip = (aws_api.get("remoteIpDetails") or {}).get("ipAddressV4")
    return _first_non_empty(resource.get("resourceType"), remote_ip) or "unknown"


def recommendation_for_type(finding_type: str) -> str:
    lowered = finding_type.lower()
    if "rootcredentialusage" in lowered:
        return "Verify whether root access was necessary, require MFA, and move recurring operations to least-privilege roles."
    if "unauthorizedaccess" in lowered or "iamuser" in lowered:
        return "Disable suspected access key, review CloudTrail, rotate credentials, and check for persistence changes."
    if "s3" in lowered:
        return "Review bucket policy, block public access, inspect object access, and enable S3 data event logging."
    if "trojan" in lowered or "backdoor" in lowered or "crypto" in lowered:
        return "Isolate affected workload, snapshot for forensics, rotate instance role credentials, and rebuild from trusted image."
    return "Review finding details, validate principal activity, contain affected resource, and document response."


def _rule_id(ftype: str) -> str:
    first = str(ftype).split("/", 1)[0].replace(" ", "")
    return f"GD-{first or 'Unknown'}"


def analyze_guardduty(path: str | Path) -> list[Finding]:
    findings: list[Finding] = []
    for validated in validate_list(GuardDutyFinding, _items(load_json(path)), "GuardDuty"):
        item = validated.model_dump(by_alias=True, exclude_none=True)
        item = {**item, **{k[0].lower() + k[1:]: v for k, v in item.items() if k and k[0].isupper()}}
        ftype = item.get("type", "UnknownGuardDutyFinding")
        resource = item.get("resource") or {}
        rule_id = _rule_id(ftype)
        findings.append(Finding(
            source="GuardDuty", rule_id=rule_id, title=ftype, severity=normalize_severity(item.get("severity")),
            detail=item.get("description") or item.get("title") or ftype, principal=_principal(resource, item.get("service") or {}, item), resource=_resource(resource, item.get("service") or {}), evidence=item,
            remediation=recommendation_for_type(ftype), mitre_attack=attack_for(rule_id, ftype),
        ))
    return findings
