from pathlib import Path

from cloudsec_aws_lab.cloudtrail_analyzer import analyze_cloudtrail


def test_cloudtrail_sample_flags_root_and_stop_logging():
    findings, context = analyze_cloudtrail(Path("samples/cloudtrail/cloudtrail_events.json"))
    titles = {f.title for f in findings}
    assert "Root account activity detected" in titles
    assert "CloudTrail logging stopped" in titles
    assert context["total_events"] == 5
