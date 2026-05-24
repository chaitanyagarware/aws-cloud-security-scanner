#!/usr/bin/env bash
set -euo pipefail

aws-cloud-security-scanner analyze \
  --iam samples/iam_policies \
  --cloudtrail samples/cloudtrail/cloudtrail_events.json \
  --guardduty samples/guardduty/guardduty_findings.json \
  --access-analyzer samples/access_analyzer/findings.json \
  --config config/example.yml \
  --out reports/demo_report.md \
  --json-out reports/demo_report.json \
  --sarif-out reports/demo_report.sarif.json \
  --asff-out reports/demo_report.asff.json \
  --ocsf-out reports/demo_report.ocsf.json \
  --state-db reports/finding_state.sqlite \
  --ai-summary-out reports/ai_summary.md
