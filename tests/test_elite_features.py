import json
from pathlib import Path

import pytest

from cloudsec_aws_lab.ai_summary import local_executive_summary
from cloudsec_aws_lab.aws_ingestion import athena_cloudtrail_query, parse_s3_uri, write_athena_template
from cloudsec_aws_lab.cli import main
from cloudsec_aws_lab.guardduty_analyzer import analyze_guardduty, recommendation_for_type
from cloudsec_aws_lab.io_utils import iter_json_records, load_json, safe_resolve, write_json
from cloudsec_aws_lab.logging_utils import configure_logging
from cloudsec_aws_lab.mitre import attack_for
from cloudsec_aws_lab.models import Finding
from cloudsec_aws_lab.remediation import terraform_snippet
from cloudsec_aws_lab.reporting.markdown import render_markdown
from cloudsec_aws_lab.reporting.ocsf import build_ocsf
from cloudsec_aws_lab.risk_model import normalize_severity, sort_findings, SEVERITY_ORDER
from cloudsec_aws_lab.state import fingerprint, mark_seen


def test_jsonl_streaming_and_error_paths(tmp_path):
    p = tmp_path / "events.jsonl"
    p.write_text(json.dumps({"eventSource": "iam.amazonaws.com", "eventName": "CreateAccessKey"}) + "\n", encoding="utf-8")
    assert list(iter_json_records(p))[0]["eventName"] == "CreateAccessKey"
    bad = tmp_path / "bad.jsonl"
    bad.write_text("not-json\n", encoding="utf-8")
    with pytest.raises(Exception):
        list(iter_json_records(bad))
    txt = tmp_path / "bad.txt"
    txt.write_text("{}", encoding="utf-8")
    with pytest.raises(Exception):
        load_json(txt)
    with pytest.raises(Exception):
        safe_resolve("s3://bucket/key")


def test_write_json_ocsf_state_and_ai_summary(tmp_path):
    f = Finding("CloudTrail", "CT-003", "IAM access key created", "HIGH", "detail", principal="arn", resource="iam", mitre_attack=["TA0003 Persistence"])
    out = tmp_path / "out.json"
    write_json(out, {"ok": True})
    assert json.loads(out.read_text())["ok"] is True
    ocsf = build_ocsf([f])
    assert ocsf["events"][0]["severity_id"] == 4
    assert "High/Critical" in local_executive_summary([f])
    db = tmp_path / "state.sqlite"
    assert mark_seen(db, [f]) == {"new_findings": 1, "repeat_findings": 0}
    assert mark_seen(db, [f]) == {"new_findings": 0, "repeat_findings": 1}
    assert fingerprint(f)


def test_aws_ingestion_helpers(tmp_path):
    assert parse_s3_uri("s3://my-bucket/AWSLogs/file.json") == ("my-bucket", "AWSLogs/file.json")
    with pytest.raises(ValueError):
        parse_s3_uri("s3://bad")
    query = athena_cloudtrail_query("db", "cloudtrail", days=3)
    assert "db.cloudtrail" in query and "CreateAccessKey" in query
    qfile = tmp_path / "query.sql"
    write_athena_template(qfile, "db", "tbl")
    assert "db.tbl" in qfile.read_text()


def test_mitre_risk_remediation_logging_branches():
    assert attack_for("GD-UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration", "UnauthorizedAccess")
    assert attack_for("UNKNOWN", "credential discovery")
    assert normalize_severity(8.9) == "CRITICAL"
    assert normalize_severity(None) == "INFO"
    f1 = Finding("IAM", "IAM-001", "Admin", "CRITICAL", "d")
    f2 = Finding("IAM", "IAM-LOW", "Info", "LOW", "d")
    assert SEVERITY_ORDER[f1.severity] > SEVERITY_ORDER[f2.severity]
    assert sort_findings([f2, f1])[0] == f1
    assert "aws_cloudwatch_event_rule" in terraform_snippet(Finding("CloudTrail", "CT-001", "Root", "CRITICAL", "d"))
    assert "No automatic Terraform" in terraform_snippet(Finding("Other", "X", "Other", "LOW", "d"))
    configure_logging(verbose=True, json_logs=True)


def test_guardduty_extraction_and_recommendations(tmp_path):
    data = [
        {"type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration", "severity": 9, "description": "bad", "resource": {"accessKeyDetails": {"principalId": "AIDA", "userName": "dev"}}},
        {"type": "Discovery:S3/MaliciousIPCaller", "severity": 4, "resource": {"s3BucketDetails": [{"name": "prod-bucket"}]}},
        {"type": "Trojan:EC2/DNSDataExfiltration", "severity": 6, "resource": {"instanceDetails": {"instanceId": "i-123"}}},
    ]
    p = tmp_path / "gd.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    findings = analyze_guardduty(p)
    assert findings[0].principal == "AIDA"
    assert findings[1].resource == "prod-bucket"
    assert findings[2].resource == "i-123"
    assert "Disable suspected" in recommendation_for_type("UnauthorizedAccess:IAMUser")
    assert "block public access" in recommendation_for_type("S3/Public")
    assert "Isolate" in recommendation_for_type("Trojan:EC2")


def test_markdown_least_privilege_block_and_cli_full(tmp_path, monkeypatch):
    f = Finding("CloudTrail", "CT-003", "Sensitive", "HIGH", "d", principal="p", resource="r", mitre_attack=["TA0004 Privilege Escalation"])
    md = render_markdown([f], [{"principal": "p", "observed_action_count": 1, "unique_observed_events": ["iam:CreateAccessKey"], "least_privilege_note": "note", "draft_policy": {"Version": "2012-10-17"}, "review_required": ["iam:CreateAccessKey"]}], {"portfolio_value": "x"})
    assert "MITRE ATT&CK" in md and "Draft policy" in md
    repo = Path(__file__).resolve().parents[1]
    out = tmp_path / "r.md"
    monkeypatch.setattr("sys.argv", ["prog", "analyze", "--iam", str(repo/"samples/iam_policies"), "--cloudtrail", str(repo/"samples/cloudtrail/cloudtrail_events.json"), "--guardduty", str(repo/"samples/guardduty/guardduty_findings.json"), "--access-analyzer", str(repo/"samples/access_analyzer/findings.json"), "--out", str(out), "--json-out", str(tmp_path/"r.json"), "--sarif-out", str(tmp_path/"r.sarif.json"), "--asff-out", str(tmp_path/"r.asff.json"), "--ocsf-out", str(tmp_path/"r.ocsf.json"), "--state-db", str(tmp_path/"state.sqlite"), "--ai-summary-out", str(tmp_path/"ai.md")])
    assert main() == 0
    assert out.exists() and (tmp_path/"r.ocsf.json").exists() and (tmp_path/"ai.md").exists()
