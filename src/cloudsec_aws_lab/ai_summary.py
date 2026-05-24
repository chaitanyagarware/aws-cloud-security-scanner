from __future__ import annotations

import json
from typing import Any

from .models import Finding

def local_executive_summary(findings: list[Finding]) -> str:
    high = [f for f in findings if f.severity in {"CRITICAL", "HIGH"}]
    top = high[:5] or findings[:5]
    lines = ["Executive triage summary:", f"- Total findings: {len(findings)}", f"- High/Critical findings: {len(high)}"]
    for f in top:
        lines.append(f"- {f.severity}: {f.title} affecting {f.principal} / {f.resource}")
    lines.append("Human review required before applying remediation or generated least-privilege policies.")
    return "\n".join(lines)

def bedrock_summary(findings: list[Finding], *, model_id: str = "anthropic.claude-3-5-sonnet-20240620-v1:0") -> str:
    try:
        import boto3  # type: ignore
    except Exception as exc:  # pragma: no cover
        return local_executive_summary(findings) + f"\n\nBedrock not available locally: {exc}"
    client = boto3.client("bedrock-runtime")
    prompt = "Summarize these AWS security findings for an executive and a security engineer. Do not invent facts. Findings: " + json.dumps([f.as_dict() for f in findings[:20]])
    body: dict[str, Any] = {"anthropic_version": "bedrock-2023-05-31", "max_tokens": 700, "messages": [{"role": "user", "content": prompt}]}
    response = client.invoke_model(modelId=model_id, body=json.dumps(body))
    payload = json.loads(response["body"].read())
    return payload.get("content", [{}])[0].get("text", local_executive_summary(findings))
