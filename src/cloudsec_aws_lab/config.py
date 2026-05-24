from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from .exceptions import InputValidationError
from .io_utils import safe_resolve


class SuppressionRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule_id: str | None = None
    source: str | None = None
    principal: str | None = None
    resource: str | None = None
    title_contains: str | None = None
    reason: str = "approved exception"
    expires: str | None = None

    @model_validator(mode="after")
    def at_least_one_matcher(self) -> "SuppressionRule":
        if not any([self.rule_id, self.source, self.principal, self.resource, self.title_contains]):
            raise ValueError("suppression rule must include at least one matcher")
        return self


class SeverityOverride(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule_id: str
    severity: str
    reason: str = "local risk override"

    @field_validator("severity")
    @classmethod
    def valid_severity(cls, value: str) -> str:
        normalized = value.upper()
        if normalized not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
            raise ValueError("severity must be CRITICAL, HIGH, MEDIUM, LOW, or INFO")
        return normalized


class AnalyzerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    trusted_principals: set[str] = Field(default_factory=set)
    approved_regions: set[str] = Field(default_factory=lambda: {"us-east-1", "us-east-2", "us-west-2"})
    sensitive_actions: set[str] = Field(default_factory=lambda: {
        "iam:PassRole",
        "iam:CreateAccessKey",
        "iam:AttachUserPolicy",
        "iam:PutUserPolicy",
        "iam:CreatePolicyVersion",
        "sts:AssumeRole",
        "kms:Decrypt",
        "kms:ScheduleKeyDeletion",
        "s3:PutBucketPolicy",
    })
    allowlisted_user_agents: set[str] = Field(default_factory=set)
    account_alias: str = "sample-account"
    organization_id: str | None = None
    environment: str = "lab"
    suppressions: list[SuppressionRule] = Field(default_factory=list)
    severity_overrides: list[SeverityOverride] = Field(default_factory=list)

    @field_validator("trusted_principals", "approved_regions", "sensitive_actions", "allowlisted_user_agents", mode="before")
    @classmethod
    def list_or_set(cls, value: Any) -> Any:
        if value is None:
            return set()
        if isinstance(value, str):
            return {v.strip() for v in value.split(",") if v.strip()}
        return value


def _apply_env_overrides(raw: dict[str, Any]) -> dict[str, Any]:
    mapping = {
        "CLOUDSEC_APPROVED_REGIONS": "approved_regions",
        "CLOUDSEC_TRUSTED_PRINCIPALS": "trusted_principals",
        "CLOUDSEC_ALLOWLISTED_USER_AGENTS": "allowlisted_user_agents",
        "CLOUDSEC_ACCOUNT_ALIAS": "account_alias",
        "CLOUDSEC_ORGANIZATION_ID": "organization_id",
        "CLOUDSEC_ENVIRONMENT": "environment",
    }
    merged = dict(raw)
    for env_name, cfg_key in mapping.items():
        if env_name in os.environ and os.environ[env_name].strip():
            merged[cfg_key] = os.environ[env_name]
    return merged


def load_config(path: str | None) -> AnalyzerConfig:
    raw: dict[str, Any] = {}
    if path:
        p = safe_resolve(path)
        if p.suffix.lower() not in {".yml", ".yaml"}:
            raise InputValidationError(f"Expected YAML config file: {p}")
        try:
            loaded = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise InputValidationError(f"Malformed YAML config {p}: {exc}") from exc
        except OSError as exc:
            raise InputValidationError(f"Cannot read config {p}: {exc}") from exc
        if not isinstance(loaded, dict):
            raise InputValidationError("Config root must be a YAML mapping/object")
        raw = loaded
    try:
        return AnalyzerConfig.model_validate(_apply_env_overrides(raw))
    except ValidationError as exc:
        raise InputValidationError(f"Invalid config schema: {exc.errors()[:3]}") from exc
