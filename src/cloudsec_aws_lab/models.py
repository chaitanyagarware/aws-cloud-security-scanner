from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    source: str
    rule_id: str
    title: str
    severity: str
    detail: str
    resource: str = "unknown"
    principal: str = "unknown"
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    mitre_attack: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "detail": self.detail,
            "resource": self.resource,
            "principal": self.principal,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "mitre_attack": self.mitre_attack,
        }
