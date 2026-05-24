# Interview Script

## 30-second explanation

I built an AWS cloud security lab that analyzes IAM policies, CloudTrail activity, and GuardDuty findings. It detects identity misconfigurations, suspicious AWS API behavior, and native GuardDuty alerts, then generates a risk-ranked report with least-privilege remediation recommendations.

## Why it matters

In AWS, the biggest security problem is usually identity blast radius. A role with broad IAM permissions may look harmless until CloudTrail shows it creating access keys, attaching AdministratorAccess, or stopping CloudTrail. This project connects those signals into a practical investigation workflow.

## What I would improve in production

- Pull logs from S3/Athena instead of local files.
- Add AWS Organizations context.
- Add account and region allowlists.
- Add Security Hub ASFF output.
- Push high-risk detections to Slack/Jira.
- Add permission-boundary and SCP recommendations.
