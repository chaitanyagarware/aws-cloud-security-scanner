from __future__ import annotations

from pathlib import Path

def parse_s3_uri(uri: str) -> tuple[str, str]:
    if not uri.startswith("s3://") or "/" not in uri[5:]:
        raise ValueError("Expected s3://bucket/key")
    bucket, key = uri[5:].split("/", 1)
    return bucket, key

def athena_cloudtrail_query(database: str, table: str, days: int = 7) -> str:
    return f"""SELECT eventtime, eventsource, eventname, awsregion, sourceipaddress, useridentity
FROM {database}.{table}
WHERE from_iso8601_timestamp(eventtime) > current_timestamp - interval '{days}' day
  AND (errorcode IS NOT NULL OR eventname IN ('CreateAccessKey','AttachUserPolicy','PassRole','StopLogging','DeleteTrail'))
ORDER BY eventtime DESC;"""

def write_athena_template(path: str | Path, database: str, table: str, days: int = 7) -> None:
    Path(path).write_text(athena_cloudtrail_query(database, table, days), encoding="utf-8")


def fetch_access_analyzer_findings(analyzer_arn_or_name: str, region: str, output_path: str | Path = "reports/access_analyzer_api_findings.json") -> Path:
    """Fetch IAM Access Analyzer findings with boto3 into a local JSON file.

    Requires optional install: pip install -e .[aws]
    Uses the caller's AWS credentials. Recommended policy: access-analyzer:ListFindings only.
    """
    try:
        import boto3  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError("Install optional AWS dependencies with: pip install -e .[aws]") from exc
    client = boto3.client("accessanalyzer", region_name=region)
    paginator = client.get_paginator("list_findings")
    items = []
    for page in paginator.paginate(analyzerArn=analyzer_arn_or_name):
        items.extend(page.get("findings", []))
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    import json
    path.write_text(json.dumps({"findings": items}, indent=2, default=str), encoding="utf-8")
    return path
