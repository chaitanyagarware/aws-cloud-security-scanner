# S3, Athena, and IAM Access Analyzer production path

This repo stays safe by default: local files first, optional AWS APIs only when explicitly requested.

## S3 / Athena pattern

1. Send organization CloudTrail to an S3 data lake.
2. Create or reuse a Glue/Athena table over CloudTrail JSON.
3. Run `docs/queries/athena_cloudtrail_hunts.sql` to export high-signal events.
4. Convert Athena results to JSONL and scan locally:

```bash
aws athena start-query-execution \
  --query-string file://docs/queries/athena_cloudtrail_hunts.sql \
  --query-execution-context Database=security_lake \
  --result-configuration OutputLocation=s3://my-security-query-results/

aws s3 cp s3://my-security-query-results/results.jsonl ./cloudtrail.jsonl
aws-cloud-security-scanner analyze --cloudtrail ./cloudtrail.jsonl --config config/example.yml
```

## IAM Access Analyzer API mode

Optional install:

```bash
pip install -e .[aws]
```

Read-only IAM permissions for the caller:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["access-analyzer:ListFindings"],
    "Resource": "*"
  }]
}
```

Run:

```bash
aws-cloud-security-scanner analyze \
  --access-analyzer-api arn:aws:access-analyzer:us-east-1:111122223333:analyzer/org-analyzer \
  --region us-east-1
```

The tool writes `reports/access_analyzer_api_findings.json`, then analyzes it through the same validation/reporting path as local exports.

## Bedrock privacy and cost note

`--bedrock` is opt-in. Finding titles, severities, principals, resources, and remediations may be sent to Amazon Bedrock under your AWS account. Use the local fallback for sensitive investigations, regulated data, or cost-sensitive demos.
