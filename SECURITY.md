# Security Policy

This repository is a defensive learning project. Do not upload real customer CloudTrail logs, account IDs, access keys, or production IAM policies.

Recommended safe usage:

- Use anonymized CloudTrail exports.
- Use read-only roles if extending the tool to call AWS APIs.
- Store credentials only in local environment variables or AWS profiles.
- Never commit `.env`, `~/.aws/credentials`, access keys, session tokens, or raw production logs.

If you find a security issue in this project, open a private report or contact the maintainer directly.
