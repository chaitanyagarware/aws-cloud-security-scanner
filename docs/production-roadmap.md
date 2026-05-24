# Production Roadmap

This repository runs safely on local sample data, but it is designed like a real internal cloud-security tool.

## Current portfolio-grade capability

- Static IAM blast-radius analysis
- CloudTrail behavior analysis
- GuardDuty finding triage
- IAM Access Analyzer JSON ingestion
- Least-privilege review draft generation
- Cross-source identity correlation
- SARIF export for GitHub code scanning
- ASFF-shaped export for Security Hub style workflows
- Terraform remediation review snippets
- Container and Lambda deployment skeletons
- Streamlit dashboard stub

## Production gaps called out honestly

- Do not auto-remediate IAM in production without approval workflow.
- CloudTrail-derived policies need IAM Access Analyzer validation and resource scoping.
- S3/Athena/EventBridge ingestion should be added for high-volume organizations.
- Organization-wide support should include SCPs, permission boundaries, session policies, ABAC, IAM Identity Center, and AWS Organizations.
- Findings should be deduplicated and stored in a database before dashboarding.

## Senior-level extensions

- Multi-account aggregator using AWS Organizations and delegated admin.
- S3 + Athena ingestion for large CloudTrail lakes.
- EventBridge near-real-time detection mode.
- OCSF mapping and Security Hub batch import.
- Bedrock/Claude-assisted triage summaries with strict privacy controls.
- CIS AWS Foundations and NIST 800-53 mapping.
