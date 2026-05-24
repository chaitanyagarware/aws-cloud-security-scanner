"""Example Lambda wrapper for production-style deployment.

This skeleton expects object keys or local mounted files to be resolved by a pipeline step.
It is intentionally read-only and does not remediate automatically.
"""
from __future__ import annotations

from cloudsec_aws_lab.cli import build_parser


def handler(event, context):  # pragma: no cover - deployment skeleton
    args = ["analyze"] + event.get("args", [])
    parser = build_parser()
    parsed = parser.parse_args(args)
    exit_code = parsed.func(parsed)
    return {"statusCode": 200 if exit_code == 0 else 500, "exitCode": exit_code}
