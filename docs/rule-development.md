# Rule Development Guide

## Rule quality bar

A new rule should include:

1. Clear security behavior being detected.
2. Stable rule ID.
3. Severity rationale.
4. Evidence fields that help an analyst verify the alert.
5. Remediation that is specific enough for an engineer to act on.
6. Unit tests for positive, negative, malformed, and edge-case inputs.

## Preferred pattern

Rules should return `Finding` objects and avoid directly printing. Keep parsing, detection, correlation, and reporting separate.

## Input safety

All new ingestion paths should use `io_utils.load_json` or equivalent safe loaders with:

- file existence checks
- extension checks
- size limits
- malformed JSON handling
- schema validation through Pydantic models

## Severity guidance

- `CRITICAL`: root use, disabled logging/detection, active credential compromise, public admin access.
- `HIGH`: privilege escalation, no MFA login, sensitive IAM/KMS/S3 changes.
- `MEDIUM`: reconnaissance-like denied calls, suspicious user agents, risky configuration drift.
- `LOW`: hygiene issues or context-dependent signals.
