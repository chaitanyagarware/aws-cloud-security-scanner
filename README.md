# AWS Cloud Security Scanner: IAM Risk, CloudTrail Triage, GuardDuty Correlation

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Pytest](https://img.shields.io/badge/tests-pytest-brightgreen)
![Ruff](https://img.shields.io/badge/lint-ruff-purple)
![Terraform](https://img.shields.io/badge/IaC-Terraform-844FBA)
![Security](https://img.shields.io/badge/focus-AWS%20Security-red)

A local-first AWS security analysis tool for reviewing IAM risk, CloudTrail activity, GuardDuty findings, and Access Analyzer results.

The project is designed to help security engineers turn raw AWS security artifacts into readable reports, machine-readable outputs, and remediation-focused findings.

It works with local sample data by default, so you can run the full demo without using real AWS credentials.

---

## What it does

`aws-cloud-security-scanner` analyzes AWS security data across four main areas:

- IAM policy and trust policy review
- CloudTrail activity analysis
- GuardDuty finding triage
- IAM Access Analyzer finding ingestion

It then generates reports and exports that can be used for review, automation, or security workflow integration.

Supported outputs include:

- Markdown report
- JSON report
- SARIF
- ASFF-style findings
- OCSF-style normalized output
- Optional executive summary
- SQLite finding state database

---

## Why I built it

AWS security findings are often noisy and disconnected.

An IAM policy issue, a CloudTrail event, and a GuardDuty alert may all point to the same identity risk, but they usually appear in separate places.

This project explores a simple question:

> Can we connect identity risk, runtime activity, detection findings, and remediation guidance into one practical workflow?

The goal is not to replace AWS-native services. The goal is to create a local, understandable, extensible security tool that shows how these signals can be analyzed together.

---

## Core features

### IAM analysis

The scanner reviews IAM policies and trust policies for common risk patterns, including:

- Wildcard actions
- Wildcard resources
- Sensitive IAM permissions
- `iam:PassRole` exposure
- Privilege escalation paths
- Broad trust relationships
- Missing MFA conditions
- Over-permissive access patterns

### CloudTrail analysis

CloudTrail events are analyzed for suspicious or high-risk behavior, such as:

- Root account usage
- Console login without MFA
- IAM policy changes
- Access key creation
- Failed authorization attempts
- CloudTrail tampering attempts
- GuardDuty disabling attempts
- Suspicious user agents
- Activity from unusual regions

### GuardDuty analysis

GuardDuty findings are normalized and enriched with:

- Severity normalization
- Principal extraction
- Resource extraction
- MITRE ATT&CK mapping
- Response guidance
- Cross-source correlation

### Access Analyzer support

The tool can ingest IAM Access Analyzer-style findings and convert them into reviewable security findings.

Optional AWS API integration is also included for environments where read-only Access Analyzer access is available.

### Correlation engine

Findings from IAM, CloudTrail, GuardDuty, and Access Analyzer can be correlated by identity or resource.

This helps build a clearer story around risk instead of showing isolated alerts.

### Suppression and severity overrides

A YAML config file can be used to:

- Suppress known accepted findings
- Override severity for business-specific context
- Adjust trusted principals
- Tune regions and behavior

This is useful because real security tools need false-positive handling, not just detection logic.

### Finding state

The scanner can store finding fingerprints in SQLite to support simple deduplication and state tracking across runs.

---

## Quick start

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it:

```bash
# macOS/Linux
source .venv/bin/activate

# Windows
.venv\\Scripts\\activate
```

Install the project:

```bash
pip install -e .[dev]
```

Run the demo:

```bash
./scripts/run_demo.sh
```

On Windows, run the CLI directly:

```bash
aws-cloud-security-scanner analyze ^
  --iam samples/iam_policies ^
  --cloudtrail samples/cloudtrail/cloudtrail_events.json ^
  --guardduty samples/guardduty/guardduty_findings.json ^
  --access-analyzer samples/access_analyzer/findings.json ^
  --config config/example.yml ^
  --out reports/demo_report.md ^
  --json-out reports/demo_report.json ^
  --sarif-out reports/demo_report.sarif.json ^
  --asff-out reports/demo_report.asff.json ^
  --ocsf-out reports/demo_report.ocsf.json ^
  --state-db reports/finding_state.sqlite ^
  --ai-summary-out reports/ai_summary.md
```

---

## Example outputs

After running the demo, reports are generated under `reports/`.

Common outputs:

```text
reports/demo_report.md
reports/demo_report.json
reports/demo_report.sarif.json
reports/demo_report.asff.json
reports/demo_report.ocsf.json
reports/ai_summary.md
reports/finding_state.sqlite
```

The Markdown report includes:

- Executive summary
- Top findings
- Severity-ranked risk list
- IAM findings
- CloudTrail findings
- GuardDuty findings
- Access Analyzer findings
- Correlated identity-risk storylines
- Least-privilege review drafts
- Remediation notes

---

## Architecture

The project is organized around small, separate components:

```text
src/cloudsec_aws_lab/
  analyzers/        # IAM, CloudTrail, GuardDuty, Access Analyzer analysis
  reporting/        # Markdown, JSON, SARIF, ASFF, OCSF outputs
  correlation/      # Multi-source identity/resource correlation
  config/           # YAML config, suppressions, severity overrides
  state/            # SQLite finding state and deduplication
  remediation/      # Least-privilege and Terraform remediation helpers
  integrations/     # Optional AWS API integrations
  cli.py            # Main command-line interface
```

The basic flow is:

```text
Input files
  ↓
Validation and safe loading
  ↓
Source-specific analyzers
  ↓
Finding normalization
  ↓
Correlation and enrichment
  ↓
Suppression / severity override
  ↓
Reports and machine-readable exports
```

---

## Output formats

### Markdown

Human-readable report for review and discussion.

### JSON

Structured output for automation and further processing.

### SARIF

Useful for GitHub code scanning style workflows.

### ASFF-style output

Modeled after AWS Security Finding Format concepts for Security Hub-style workflows.

### OCSF-style output

Normalized output inspired by security data lake workflows.

---

## Configuration

Example config:

```yaml
trusted_principals:
  - arn:aws:iam::123456789012:role/SecurityAuditRole

allowed_regions:
  - us-east-1
  - us-west-2

severity_overrides:
  - match:
      finding_type: IAM_WILDCARD_ACTION
    severity: HIGH
    reason: Wildcard IAM access is considered high risk in this environment.

suppressions:
  - id: accepted-demo-risk
    match:
      finding_type: CLOUDTRAIL_UNUSUAL_REGION
    reason: Known test activity in sample data.
    expires: 2026-12-31
```

Suppression and override logic is intentionally config-driven so users can tune the scanner without changing Python code.

---

## Security and safety

This project is safe by default:

- Uses local sample data
- Does not require AWS credentials for the demo
- Does not modify AWS resources
- Does not perform exploitation
- Does not send data externally by default

If used with real AWS data:

- Use read-only IAM roles
- Avoid committing account IDs, keys, tokens, or production logs
- Review generated remediation before applying anything
- Treat AI-generated summaries as review assistance, not final decisions

---

## Optional AWS integrations

The project includes optional integration paths for production-style workflows:

- IAM Access Analyzer API ingestion
- S3/Athena workflow documentation
- EventBridge/Lambda deployment skeleton
- Bedrock summary path with local fallback

These are optional. The scanner can still run fully offline with sample data.

---

## Dashboard

A simple Streamlit dashboard is included for reviewing findings visually.

Run it with:

```bash
pip install streamlit pandas
streamlit run dashboard/app.py
```

The dashboard supports:

- Severity filtering
- MITRE ATT&CK filtering
- Finding search
- Basic charts
- Report exploration

---

## Terraform examples

Terraform examples are included for:

- Remediation review snippets
- EventBridge/Lambda deployment skeleton
- IaC security scanning examples

The CI workflow includes optional Checkov/tfsec scanning for Terraform files.

---

## Development

Run tests:

```bash
pytest --cov=src/cloudsec_aws_lab --cov-fail-under=85
```

Run linting:

```bash
ruff check src tests
```

Run type checks:

```bash
mypy src
```

Run security checks:

```bash
bandit -r src
pip-audit
```

---

## CI checks

The GitHub Actions workflow includes:

- Ruff
- Mypy
- Pytest with coverage
- Bandit
- pip-audit
- Checkov/tfsec for Terraform
- SARIF generation path
- Pre-commit support
- Dependabot configuration

---

## Adding a new rule

Rules should be small, testable, and explainable.

A good rule should include:

- Clear finding type
- Severity
- Evidence
- Affected principal or resource
- Remediation guidance
- MITRE mapping if applicable
- Unit test
- Sample input if useful

See:

```text
docs/rule-development.md
```

---

## Roadmap

Possible future improvements:

- Deeper AWS Organizations support
- SCP analysis
- IAM Identity Center analysis
- Permission boundary and session policy analysis
- More OCSF mappings
- Security Hub BatchImportFindings integration
- Athena query runner
- Better least-privilege policy generation
- More dashboard views
- More real-world test cases

---

## Repository topics

Suggested GitHub topics:

```text
aws
cloud-security
aws-security
iam
cloudtrail
guardduty
access-analyzer
security-engineering
security-automation
devsecops
mitre-attack
sarif
security-hub
ocsf
terraform
python
least-privilege
cloud-detection-response
```

---

## License

MIT License.
