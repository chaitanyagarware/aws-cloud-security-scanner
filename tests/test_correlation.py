from cloudsec_aws_lab.correlation import correlate_findings
from cloudsec_aws_lab.models import Finding


def test_multi_source_correlation_by_principal():
    principal = "arn:aws:iam::123456789012:user/devops-user"
    findings = [
        Finding(source="IAM", rule_id="IAM-004", title="PassRole", severity="HIGH", detail="", principal=principal),
        Finding(source="CloudTrail", rule_id="CT-003", title="PassRole", severity="HIGH", detail="", principal=principal),
    ]
    correlated = correlate_findings(findings)
    assert any(f.rule_id == "COR-001" for f in correlated)
