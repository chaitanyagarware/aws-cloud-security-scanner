from __future__ import annotations

import json
import subprocess
import sys

from cloudsec_aws_lab.config import load_config
from cloudsec_aws_lab.guardduty_analyzer import analyze_guardduty
from cloudsec_aws_lab.suppressions import apply_suppressions_and_overrides
from cloudsec_aws_lab.models import Finding


def test_config_suppression_and_severity_override(tmp_path):
    cfg_path = tmp_path / "config.yml"
    cfg_path.write_text("""
suppressions:
  - rule_id: CT-006
    principal: demo
    reason: test
severity_overrides:
  - rule_id: CT-004
    severity: LOW
    reason: test override
""", encoding="utf-8")
    cfg = load_config(str(cfg_path))
    findings = [
        Finding(source="CloudTrail", rule_id="CT-006", title="Region", severity="LOW", detail="region", principal="demo"),
        Finding(source="CloudTrail", rule_id="CT-004", title="Denied", severity="MEDIUM", detail="denied", principal="other"),
    ]
    kept, metrics = apply_suppressions_and_overrides(findings, cfg)
    assert len(kept) == 1
    assert kept[0].severity == "LOW"
    assert metrics == {"suppressed_findings": 1, "severity_overrides_applied": 1}


def test_guardduty_extracts_principal_from_access_key_and_lambda(tmp_path):
    gd = tmp_path / "gd.json"
    gd.write_text(json.dumps({"findings": [
        {"Type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration", "Severity": 8, "Resource": {"accessKeyDetails": {"userName": "alice"}}},
        {"Type": "Execution:Lambda/MaliciousFile", "Severity": 5, "Resource": {"lambdaDetails": {"functionName": "prod-fn", "functionArn": "arn:aws:lambda:us-east-1:1:function:prod-fn"}}}
    ]}), encoding="utf-8")
    findings = analyze_guardduty(gd)
    assert findings[0].principal == "alice"
    assert findings[1].principal == "prod-fn"
    assert findings[1].resource.endswith(":prod-fn")


def test_cli_e2e_jsonl_and_config(tmp_path):
    ct = tmp_path / "ct.jsonl"
    ct.write_text(json.dumps({
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreateAccessKey",
        "eventTime": "2026-05-01T00:00:00Z",
        "awsRegion": "us-east-1",
        "userIdentity": {"arn": "arn:aws:iam::123:user/dev"}
    }) + "\n", encoding="utf-8")
    out = tmp_path / "report.json"
    cmd = [sys.executable, "-m", "cloudsec_aws_lab.cli", "analyze", "--cloudtrail", str(ct), "--json-out", str(out), "--out", str(tmp_path/"r.md"), "--sarif-out", str(tmp_path/"r.sarif.json"), "--asff-out", str(tmp_path/"r.asff.json"), "--ocsf-out", str(tmp_path/"r.ocsf.json"), "--ai-summary-out", str(tmp_path/"ai.md"), "--state-db", str(tmp_path/"state.sqlite")]
    result = subprocess.run(cmd, cwd=".", text=True, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr + result.stdout
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["summary"]["total_findings"] >= 1
