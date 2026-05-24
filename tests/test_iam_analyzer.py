from cloudsec_aws_lab.iam_analyzer import analyze_policy


def test_detects_admin_wildcard():
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    findings = analyze_policy(policy)
    rule_ids = {f.rule_id for f in findings}
    assert "IAM-001" in rule_ids
    assert "IAM-003" in rule_ids


def test_detects_privilege_escalation_action():
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["iam:PassRole"], "Resource": "*"}],
    }
    findings = analyze_policy(policy)
    assert any(f.rule_id == "IAM-004" for f in findings)
