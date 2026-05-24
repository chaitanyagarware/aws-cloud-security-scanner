from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Iterator

from .exceptions import InputValidationError

DEFAULT_MAX_JSON_BYTES = 10 * 1024 * 1024
DEFAULT_MAX_RECORDS = 250_000


def safe_resolve(path: str | Path, *, must_exist: bool = True) -> Path:
    text = str(path)
    if text.startswith("s3://"):
        raise InputValidationError("s3:// paths are handled by the optional AWS ingestion module, not local file loading")
    p = Path(path).expanduser()
    try:
        resolved = p.resolve(strict=must_exist)
    except FileNotFoundError as exc:
        raise InputValidationError(f"Input path does not exist: {p}") from exc
    except OSError as exc:
        raise InputValidationError(f"Invalid path: {p}") from exc
    return resolved


def _enforce_size(path: Path, max_bytes: int) -> None:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise InputValidationError(f"Cannot stat input file: {path}") from exc
    if size > max_bytes:
        raise InputValidationError(
            f"Input file too large: {path} is {size} bytes; limit is {max_bytes} bytes. "
            "Use JSONL streaming or S3/Athena ingestion for production-scale CloudTrail."
        )


def load_json(path: str | Path, *, max_bytes: int = DEFAULT_MAX_JSON_BYTES) -> Any:
    p = safe_resolve(path)
    if not p.is_file():
        raise InputValidationError(f"Expected JSON file but got directory: {p}")
    if p.suffix.lower() != ".json":
        raise InputValidationError(f"Expected .json file: {p}")
    _enforce_size(p, max_bytes)
    try:
        with p.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError as exc:
        raise InputValidationError(f"Malformed JSON in {p}: {exc.msg} at line {exc.lineno}, column {exc.colno}") from exc
    except UnicodeDecodeError as exc:
        raise InputValidationError(f"Input file is not valid UTF-8 JSON: {p}") from exc
    except OSError as exc:
        raise InputValidationError(f"Unable to read input file: {p}") from exc


def iter_json_records(path: str | Path, *, max_bytes: int = DEFAULT_MAX_JSON_BYTES, max_records: int = DEFAULT_MAX_RECORDS) -> Iterator[dict[str, Any]]:
    """Yield records from JSON, CloudTrail Records JSON, list JSON, or newline-delimited JSON.

    This is intentionally simple but gives the project a scalable production path:
    small JSON files are fully validated, while .jsonl/.ndjson can be processed line by line.
    """
    p = safe_resolve(path)
    if not p.is_file():
        raise InputValidationError(f"Expected event file but got directory: {p}")
    suffix = p.suffix.lower()
    if suffix in {".jsonl", ".ndjson"}:
        count = 0
        try:
            with p.open("r", encoding="utf-8") as fh:
                for lineno, line in enumerate(fh, 1):
                    if not line.strip():
                        continue
                    count += 1
                    if count > max_records:
                        raise InputValidationError(f"Too many records in {p}; limit is {max_records}")
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise InputValidationError(f"Malformed JSONL in {p} at line {lineno}: {exc.msg}") from exc
                    if not isinstance(item, dict):
                        raise InputValidationError(f"JSONL record at line {lineno} must be an object")
                    yield item
        except OSError as exc:
            raise InputValidationError(f"Unable to read input file: {p}") from exc
        return
    raw = load_json(p, max_bytes=max_bytes)
    if isinstance(raw, dict) and isinstance(raw.get("Records"), list):
        for item in raw["Records"]:
            if isinstance(item, dict):
                yield item
        return
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                yield item
        return
    if isinstance(raw, dict):
        yield raw
        return
    raise InputValidationError(f"Unsupported JSON structure in {p}")


def iter_json_files(path: str | Path, *, max_files: int = 500) -> Iterable[Path]:
    p = safe_resolve(path)
    if p.is_file():
        if p.suffix.lower() != ".json":
            raise InputValidationError(f"Expected .json file: {p}")
        yield p
        return
    if not p.is_dir():
        raise InputValidationError(f"Expected file or directory: {p}")
    files = sorted(item for item in p.glob("*.json") if item.is_file())
    if len(files) > max_files:
        raise InputValidationError(f"Too many JSON files in {p}: {len(files)} found; limit is {max_files}")
    for item in files:
        yield item


def write_json(path: str | Path, data: Any) -> None:
    p = Path(path).expanduser()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
    except OSError as exc:
        raise InputValidationError(f"Unable to write JSON output {p}: {exc}") from exc
