from pathlib import Path

from cloudsec_aws_lab.access_analyzer import analyze_access_analyzer
from cloudsec_aws_lab.reporting.asff import build_asff
from cloudsec_aws_lab.reporting.sarif import build_sarif


def test_access_analyzer_sample_loads_findings():
    findings = analyze_access_analyzer(Path("samples/access_analyzer/findings.json"))
    assert len(findings) == 2
    assert any(f.source == "IAM Access Analyzer" for f in findings)


def test_sarif_and_asff_outputs_are_structured():
    findings = analyze_access_analyzer(Path("samples/access_analyzer/findings.json"))
    sarif = build_sarif(findings)
    asff = build_asff(findings)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"]
    assert asff[0]["SchemaVersion"] == "2018-10-08"
