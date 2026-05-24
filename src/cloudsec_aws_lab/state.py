from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Iterable

from .models import Finding


def fingerprint(f: Finding) -> str:
    payload = {"rule_id": f.rule_id, "principal": f.principal, "resource": f.resource, "title": f.title}
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:24]

def mark_seen(db_path: str | Path, findings: Iterable[Finding]) -> dict[str, int]:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        conn.execute("create table if not exists findings (fingerprint text primary key, first_seen text default current_timestamp, last_seen text default current_timestamp, count integer default 0)")
        new = repeat = 0
        for f in findings:
            fp = fingerprint(f)
            cur = conn.execute("select count from findings where fingerprint=?", (fp,)).fetchone()
            if cur:
                repeat += 1
                conn.execute("update findings set last_seen=current_timestamp, count=count+1 where fingerprint=?", (fp,))
            else:
                new += 1
                conn.execute("insert into findings(fingerprint, count) values (?, 1)", (fp,))
        conn.commit()
        return {"new_findings": new, "repeat_findings": repeat}
    finally:
        conn.close()
