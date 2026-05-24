# Design Notes

## Why this project exists

Most beginner AWS security projects show screenshots of GuardDuty or IAM. This project is structured as a lightweight internal security tool that could be used by a cloud security team to triage identity and telemetry risk.

## Detection philosophy

The engine separates checks into three layers:

1. Static IAM policy analysis
2. CloudTrail behavior analysis
3. GuardDuty alert triage

This matters because no single source is enough. IAM tells us theoretical blast radius. CloudTrail tells us observed behavior. GuardDuty tells us AWS-native threat signals. Good cloud security combines all three.

## Least-privilege logic

The least-privilege module uses CloudTrail-observed API calls to create an initial permission-reduction plan. This does not blindly auto-generate production policies because least privilege needs business context, resource scoping, and change approval. Instead, it gives a practical review starting point.

## Extensibility ideas

- Add AWS Organizations SCP analysis.
- Add IAM Access Analyzer JSON ingestion.
- Add Security Hub ASFF ingestion.
- Add mapping to MITRE ATT&CK Cloud techniques.
- Add SARIF output so findings appear inside GitHub code scanning.
- Add Streamlit dashboard for hiring-demo walkthroughs.
