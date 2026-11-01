"""Scan history: compact summaries in a local SQLite file, plus diffs between scans.

Stored in ``$XDG_DATA_HOME/osint/history.db`` (default ``~/.local/share/osint``).
Only summaries are kept (account names, breach names, short fact lines), never
raw page content, and never anything from the password check.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path

from .models import FOUND, ScanResult

NEVER_RECORDED = {"password"}
MAX_FACTS = 200
SKIP_SECTION_PREFIXES = ("Username scan:",)

enabled = True  # --no-history turns this off for the process


def db_path() -> Path:
    base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "osint" / "history.db"


def connect(path: Path | None = None) -> sqlite3.Connection:
    path = path or db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS scans ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, kind TEXT NOT NULL, "
        "target TEXT NOT NULL, summary TEXT NOT NULL)")
    conn.execute("CREATE INDEX IF NOT EXISTS scans_target ON scans(kind, target)")
    return conn


# ---------------------------------------------------------------- summaries

def _section_facts(body: dict) -> list[str]:
    kind = body.get("type")
    if kind == "kv":
        return [f"{k}: {v}" for k, v in body["items"].items()]
    if kind == "table":
        return [" | ".join(row) for row in body["rows"]]
    if kind == "list":
        return list(body["items"])
    return []


def summarize(result: ScanResult) -> dict:
    """The compact, comparable form of a result."""
    accounts = sorted({h.name for h in result.hits if h.status == FOUND}, key=str.lower)
    accounts += [a for a in result.meta.get("accounts", []) if a not in accounts]
    breaches: list[str] = list(result.meta.get("breaches", []))
    body = result.sections.get("Breaches")
    if body and body.get("type") == "table":
        breaches += [row[0] for row in body["rows"] if row and row[0] not in breaches]
    facts = {}
    for title, sec in result.sections.items():
        if title == "Breaches" or title.startswith(SKIP_SECTION_PREFIXES):
            continue
        lines = _section_facts(sec)[:MAX_FACTS]
        if lines:
            facts[title] = lines
    out = {"counts": result.counts() if result.hits else {}, "accounts": accounts, "breaches": sorted(breaches),
           "facts": facts}
    if "score" in result.meta:
        out["score"] = result.meta["score"]
    return out


def record(result: ScanResult, path: Path | None = None) -> int | None:
    """Store a summary. Returns the new id, or None (nothing stored: password, cancelled, history off, DB error)."""
    if not enabled or result.kind in NEVER_RECORDED or result.cancelled:
        return None
    try:
        with connect(path) as conn:
            cur = conn.execute(
                "INSERT INTO scans(ts, kind, target, summary) VALUES (?,?,?,?)",
                (datetime.now().isoformat(timespec="seconds"), result.kind, result.target,
                 json.dumps(summarize(result), ensure_ascii=False)))
            return cur.lastrowid
    except (sqlite3.Error, OSError):
        return None


def _row(r) -> dict:
    return {"id": r[0], "ts": r[1], "kind": r[2], "target": r[3], "summary": json.loads(r[4])}


def list_scans(limit: int = 30, path: Path | None = None) -> list[dict]:
    with connect(path) as conn:
        rows = conn.execute("SELECT id, ts, kind, target, summary FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [_row(r) for r in rows]


def get(scan_id: int, path: Path | None = None) -> dict | None:
    with connect(path) as conn:
        r = conn.execute("SELECT id, ts, kind, target, summary FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return _row(r) if r else None


def latest(kind: str, target: str, path: Path | None = None) -> dict | None:
    """Most recent stored scan of the same kind and target (case-insensitive target)."""
    with connect(path) as conn:
        r = conn.execute(
            "SELECT id, ts, kind, target, summary FROM scans WHERE kind = ? AND lower(target) = lower(?) "
            "ORDER BY id DESC LIMIT 1", (kind, target)).fetchone()
    return _row(r) if r else None


def clear(path: Path | None = None) -> int:
    """Delete every stored scan; returns how many there were."""
    with connect(path) as conn:
        n = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        conn.execute("DELETE FROM scans")
    return n
