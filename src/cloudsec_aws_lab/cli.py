from __future__ import annotations

import argparse
import logging
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .access_analyzer import analyze_access_analyzer
from .cloudtrail_analyzer import analyze_cloudtrail
from .config import load_config
from .correlation import correlate_findings
from .exceptions import CloudSecLabError, InputValidationError
from .guardduty_analyzer import analyze_guardduty
from .iam_analyzer import analyze_iam_path
from .io_utils import write_json
from .least_privilege import calculate_impact_metrics, recommend_from_cloudtrail
from .logging_utils import configure_logging
from .reporting.asff import build_asff
from .reporting.json_report import build_json
from .reporting.markdown import render_markdown
from .reporting.sarif import build_sarif
from .reporting.ocsf import build_ocsf
from .ai_summary import bedrock_summary, local_executive_summary
from .state import mark_seen
from .risk_model import sort_findings
from .suppressions import apply_suppressions_and_overrides
from .aws_ingestion import fetch_access_analyzer_findings

console = Console()
logger = logging.getLogger(__name__)


def run_analyze(args: argparse.Namespace) -> int:
    configure_logging(verbose=args.verbose, json_logs=args.json_logs)
    logger.info("starting analysis")
    cfg = load_config(args.config)
    findings = []
    cloudtrail_context = {"actions_by_principal": {}}

    try:
        if args.iam:
            findings.extend(analyze_iam_path(args.iam))
        if args.cloudtrail:
            ct_findings, cloudtrail_context = analyze_cloudtrail(args.cloudtrail, approved_regions=cfg.approved_regions)
            findings.extend(ct_findings)
        if args.guardduty:
            findings.extend(analyze_guardduty(args.guardduty))
        if args.access_analyzer:
            findings.extend(analyze_access_analyzer(args.access_analyzer))
        if args.access_analyzer_api:
            api_path = fetch_access_analyzer_findings(args.access_analyzer_api, args.region)
            findings.extend(analyze_access_analyzer(api_path))
    except ValueError as exc:
        raise InputValidationError(str(exc)) from exc

    if not args.no_correlation:
        findings.extend(correlate_findings(findings))

    findings, suppression_metrics = apply_suppressions_and_overrides(findings, cfg)
    least_privilege = recommend_from_cloudtrail(cloudtrail_context)
    ordered = sort_findings(findings)
    metrics = calculate_impact_metrics(ordered, least_privilege)
    metrics.update(suppression_metrics)

    if args.state_db:
        metrics.update(mark_seen(args.state_db, ordered))

    table = Table(title="AWS Cloud Security Scanner Findings")
    table.add_column("Severity")
    table.add_column("Source")
    table.add_column("Rule")
    table.add_column("Title")
    table.add_column("Principal")
    for f in ordered[:15]:
        table.add_row(f.severity, f.source, f.rule_id, f.title, f.principal)
    console.print(table)

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(render_markdown(ordered, least_privilege, metrics), encoding="utf-8")
        console.print(f"[green]Markdown report written to {out_path}[/green]")

    if args.json_out:
        write_json(args.json_out, build_json(ordered, least_privilege, metrics))
        console.print(f"[green]JSON report written to {args.json_out}[/green]")

    if args.sarif_out:
        write_json(args.sarif_out, build_sarif(ordered))
        console.print(f"[green]SARIF report written to {args.sarif_out}[/green]")

    if args.asff_out:
        write_json(args.asff_out, build_asff(ordered, account_id=args.account_id, region=args.region))
        console.print(f"[green]ASFF report written to {args.asff_out}[/green]")

    if args.ocsf_out:
        write_json(args.ocsf_out, build_ocsf(ordered))
        console.print(f"[green]OCSF report written to {args.ocsf_out}[/green]")

    if args.ai_summary_out:
        summary = bedrock_summary(ordered) if args.bedrock else local_executive_summary(ordered)
        out_ai = Path(args.ai_summary_out)
        out_ai.parent.mkdir(parents=True, exist_ok=True)
        out_ai.write_text(summary, encoding="utf-8")
        console.print(f"[green]AI/executive summary written to {out_ai}[/green]")

    if args.fail_on_high and any(f.severity in {"CRITICAL", "HIGH"} for f in ordered):
        return 2
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AWS cloud security scanner for IAM, CloudTrail, GuardDuty, Access Analyzer, SARIF, ASFF, and OCSF")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Analyze IAM policies, CloudTrail logs, GuardDuty findings, and Access Analyzer exports")
    analyze.add_argument("--iam", help="Path to IAM policy JSON file or directory")
    analyze.add_argument("--cloudtrail", help="Path to CloudTrail JSON file")
    analyze.add_argument("--guardduty", help="Path to GuardDuty findings JSON file")
    analyze.add_argument("--access-analyzer", help="Path to IAM Access Analyzer findings/policy validation JSON")
    analyze.add_argument("--access-analyzer-api", help="Optional AWS IAM Access Analyzer analyzer ARN/name to fetch findings via boto3")
    analyze.add_argument("--config", help="YAML config for trusted principals, approved regions, and allowlists")
    analyze.add_argument("--out", default="reports/demo_report.md", help="Markdown report output path")
    analyze.add_argument("--json-out", default="reports/demo_report.json", help="JSON report output path")
    analyze.add_argument("--sarif-out", default="reports/demo_report.sarif.json", help="SARIF output path for GitHub code scanning")
    analyze.add_argument("--asff-out", default="reports/demo_report.asff.json", help="ASFF output path for Security Hub style ingestion")
    analyze.add_argument("--ocsf-out", default="reports/demo_report.ocsf.json", help="OCSF-like output path for normalized security data lakes")
    analyze.add_argument("--state-db", default="reports/finding_state.sqlite", help="SQLite state database for finding deduplication over time")
    analyze.add_argument("--ai-summary-out", default="reports/ai_summary.md", help="Executive summary output path")
    analyze.add_argument("--bedrock", action="store_true", help="Use Amazon Bedrock for optional AI summary; falls back to local summary")
    analyze.add_argument("--account-id", default="000000000000", help="Account ID used in ASFF output")
    analyze.add_argument("--region", default="us-east-1", help="Region used in ASFF output")
    analyze.add_argument("--no-correlation", action="store_true", help="Disable multi-source correlation findings")
    analyze.add_argument("--fail-on-high", action="store_true", help="Return non-zero if HIGH/CRITICAL findings exist")
    analyze.add_argument("--verbose", action="store_true", help="Enable debug logging")
    analyze.add_argument("--json-logs", action="store_true", help="Emit structured JSON logs to stderr")
    analyze.set_defaults(func=run_analyze)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except CloudSecLabError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        logger.error("analysis failed", exc_info=True)
        return 1
    except KeyboardInterrupt:
        console.print("[yellow]Interrupted by user[/yellow]")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
