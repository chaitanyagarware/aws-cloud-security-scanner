from pathlib import Path

from cloudsec_aws_lab.guardduty_analyzer import analyze_guardduty


def test_guardduty_severity_normalization():
    findings = analyze_guardduty(Path("samples/guardduty/guardduty_findings.json"))
    severities = {f.severity for f in findings}
    assert "HIGH" in severities
    assert "LOW" in severities
