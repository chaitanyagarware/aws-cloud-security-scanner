# AWS Cloud Security Scanner — 30 Second Scan

Production-style AWS security engineering portfolio project for Security Engineer, Cloud Security Engineer, SOC, IAM, and Detection Engineering roles.

## What it does

- Scans IAM policy risk and identity blast radius.
- Hunts CloudTrail for root usage, no-MFA login, sensitive API calls, denied calls, suspicious user agents, and uncommon regions.
- Normalizes GuardDuty and IAM Access Analyzer findings.
- Correlates IAM + CloudTrail + GuardDuty into incident-style storylines.
- Maps findings to MITRE ATT&CK tactics.
- Exports Markdown, JSON, SARIF, ASFF, and OCSF-like outputs.
- Generates least-privilege policy review drafts from observed CloudTrail actions.
- Includes safe input handling, Pydantic validation, JSON logs, SQLite finding state, CI security scans, Docker, Lambda skeleton, Streamlit dashboard, and Terraform remediation examples.

## Fast demo

```bash
pip install -e .[dev]
scripts/run_demo.sh
pytest --cov=cloudsec_aws_lab --cov-fail-under=85
```

## GitHub repo name recommendation

Use: `aws-cloud-security-scanner`

Search keywords: AWS security, cloud security scanner, IAM security, CloudTrail analysis, GuardDuty triage, least privilege, Security Hub, SARIF, ASFF, OCSF, MITRE ATT&CK Cloud.


## Launch-ready additions
Suppression config, severity overrides, MITRE filters, Access Analyzer API option, S3/Athena docs, EventBridge/Lambda Terraform, and reusable GitHub Action are included.
