from __future__ import annotations

from pathlib import Path

from cloudsec_aws_lab.config import load_config
from cloudsec_aws_lab.io_utils import iter_json_files
from cloudsec_aws_lab.models import Finding
from cloudsec_aws_lab.reporting.json_report import build_json
from cloudsec_aws_lab.reporting.markdown import render_markdown


def test_markdown_report_renders_sections():
    finding = Finding(
        source="unit",
        rule_id="T-001",
        title="Test finding",
        severity="HIGH",
        detail="Something happened",
        principal="alice",
        resource="resource-1",
        remediation="Fix it",
    )
    text = render_markdown([finding], [], {"unique_observed_actions_modeled": 0})
    assert "AWS Cloud Security Assessment Report" in text
    assert "Test finding" in text
    assert "Fix it" in text


def test_json_report_shape():
    finding = Finding(source="unit", rule_id="T-001", title="x", severity="LOW", detail="d")
    payload = build_json([finding], [], {})
    assert payload["summary"]["total_findings"] == 1
    assert payload["findings"][0]["rule_id"] == "T-001"


def test_iter_json_files_yields_sorted_json_only(tmp_path: Path):
    (tmp_path / "b.json").write_text("{}", encoding="utf-8")
    (tmp_path / "a.json").write_text("{}", encoding="utf-8")
    (tmp_path / "skip.txt").write_text("{}", encoding="utf-8")
    assert [p.name for p in iter_json_files(tmp_path)] == ["a.json", "b.json"]


def test_config_env_override(monkeypatch):
    monkeypatch.setenv("CLOUDSEC_APPROVED_REGIONS", "us-east-1,us-west-2")
    cfg = load_config(None)
    assert cfg.approved_regions == {"us-east-1", "us-west-2"}
