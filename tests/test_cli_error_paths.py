from __future__ import annotations

from cloudsec_aws_lab.cli import main


def test_cli_returns_one_for_missing_input(monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        ["cloudsec-aws-lab", "analyze", "--iam", "does-not-exist.json", "--out", "", "--json-out", "", "--sarif-out", "", "--asff-out", ""],
    )
    assert main() == 1
