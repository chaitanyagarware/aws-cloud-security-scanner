from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator


class CloudTrailIdentity(BaseModel):
    model_config = ConfigDict(extra="allow")
    type: str | None = None
    arn: str | None = None
    userName: str | None = None
    accountId: str | None = None


class CloudTrailEvent(BaseModel):
    model_config = ConfigDict(extra="allow")
    eventSource: str
    eventName: str
    eventTime: str | None = None
    awsRegion: str = "unknown"
    userAgent: str | None = None
    sourceIPAddress: str | None = None
    errorCode: str | None = None
    userIdentity: CloudTrailIdentity = Field(default_factory=CloudTrailIdentity)
    additionalEventData: dict[str, Any] = Field(default_factory=dict)
    requestParameters: dict[str, Any] = Field(default_factory=dict)
    responseElements: dict[str, Any] | None = None

    @field_validator("eventSource", "eventName", "awsRegion", mode="before")
    @classmethod
    def coerce_required_str(cls, value: Any) -> str:
        if value is None or str(value).strip() == "":
            raise ValueError("field is required and cannot be empty")
        return str(value)


class CloudTrailFile(BaseModel):
    model_config = ConfigDict(extra="allow")
    Records: list[CloudTrailEvent] = Field(default_factory=list)


class AccessKeyDetails(BaseModel):
    model_config = ConfigDict(extra="allow")
    principalId: str | None = None
    userName: str | None = None
    userType: str | None = None


class InstanceDetails(BaseModel):
    model_config = ConfigDict(extra="allow")
    instanceId: str | None = None
    instanceType: str | None = None


class S3BucketDetail(BaseModel):
    model_config = ConfigDict(extra="allow")
    name: str | None = None
    arn: str | None = None


class GuardDutyResource(BaseModel):
    model_config = ConfigDict(extra="allow")
    resourceType: str | None = None
    accessKeyDetails: AccessKeyDetails = Field(default_factory=AccessKeyDetails)
    instanceDetails: InstanceDetails = Field(default_factory=InstanceDetails)
    s3BucketDetails: list[S3BucketDetail] = Field(default_factory=list)


class GuardDutyService(BaseModel):
    model_config = ConfigDict(extra="allow")
    serviceName: str | None = None
    eventFirstSeen: str | None = None
    eventLastSeen: str | None = None
    count: int | None = None


class GuardDutyFinding(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)
    Id: str | None = None
    Title: str | None = None
    Type: str | None = None
    Severity: float | int | str | None = None
    Description: str | None = None
    Resource: GuardDutyResource = Field(default_factory=GuardDutyResource)
    Service: GuardDutyService = Field(default_factory=GuardDutyService)

    @model_validator(mode="before")
    @classmethod
    def normalize_case(cls, data: Any) -> Any:
        if isinstance(data, dict):
            mapping = {"id":"Id", "title":"Title", "type":"Type", "severity":"Severity", "description":"Description", "resource":"Resource", "service":"Service"}
            return {mapping.get(k, k): v for k, v in data.items()}
        return data


class AccessAnalyzerFinding(BaseModel):
    model_config = ConfigDict(extra="allow")
    findingType: str | None = None
    type: str | None = None
    finding_type: str | None = None
    severity: str | None = None
    issueCode: str | None = None
    code: str | None = None
    id: str | None = None
    resource: str | None = None
    resourceArn: str | None = None
    policyName: str | None = None
    findingDetails: str | None = None
    message: str | None = None
    detail: str | None = None
    principal: str | None = None


def validate_list(model: type[BaseModel], items: list[Any], source_name: str) -> list[BaseModel]:
    valid: list[BaseModel] = []
    for idx, item in enumerate(items):
        try:
            valid.append(model.model_validate(item))
        except ValidationError as exc:
            raise ValueError(f"Invalid {source_name} record at index {idx}: {exc.errors()[:2]}") from exc
    return valid
