"""Markdown report generation and saving."""

from __future__ import annotations

import os
import re
from datetime import datetime
from pathlib import Path

from .models import FOUND, MISSING, UNKNOWN, ScanResult

DEFAULT_DIR = Path("reports")

LEGAL_NOTE = (
    "> This report is meant for auditing your own digital footprint, CTFs and "
    "authorized research only. Collecting data about other people without a lawful "
    "basis may violate privacy laws (GDPR, KVKK, CFAA and similar)."
)

KIND_TITLES = {"username": "Username report", "email": "Email report", "domain": "Domain / IP report"}


def reports_dir() -> Path:
    """Default output directory; ``OSINT_REPORT_DIR`` overrides it (used by tests)."""
    env = os.environ.get("OSINT_REPORT_DIR")
    return Path(env) if env else DEFAULT_DIR


def safe_name(target: str) -> str:
    """Turn a target into a safe file name fragment (blocks path traversal)."""
    cleaned = re.sub(r"[^A-Za-z0-9._@-]+", "_", target.strip()).strip("._")
    return cleaned[:80] or "target"


def _cell(value: str) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _section_md(body: dict) -> list[str]:
    kind = body.get("type")
    if kind == "kv":
        return [f"- **{k}:** {v}" for k, v in body["items"].items()] or ["None."]
    if kind == "table":
        if not body["rows"]:
            return ["None."]
        lines = ["| " + " | ".join(body["headers"]) + " |", "|" + "---|" * len(body["headers"])]
        lines += ["| " + " | ".join(_cell(c) for c in row) + " |" for row in body["rows"]]
        return lines
    if kind == "list":
        return [f"- `{i}`" for i in body["items"]] or ["None."]
    return [body.get("text", "")]


def to_markdown(result: ScanResult, now: datetime | None = None) -> str:
    now = now or datetime.now()
    lines = [
        f"# {KIND_TITLES.get(result.kind, 'Report')}: {result.target}",
        "",
        f"- Date: {now:%Y-%m-%d %H:%M}",
        f"- Target: `{result.target}`",
        "",
        LEGAL_NOTE,
        "",
    ]
    if result.cancelled:
        lines += ["> The scan was cancelled before it finished; results are partial.", ""]

    if result.hits:
        counts = result.counts()
        found = sorted((h for h in result.hits if h.status == FOUND), key=lambda h: h.name.lower())
        unknown = sorted((h for h in result.hits if h.status == UNKNOWN), key=lambda h: h.name.lower())
        lines += [
            f"Checked: {len(result.hits)} · Found: {counts[FOUND]} · "
            f"Not found: {counts[MISSING]} · Unknown: {counts[UNKNOWN]}",
            "",
            "## Found accounts",
            "",
        ]
        if found:
            lines += ["| Site | URL |", "|---|---|"]
            lines += [f"| {_cell(h.name)} | {_cell(h.url)} |" for h in found]
        else:
            lines.append("No accounts found.")
        lines += ["", "## Unknown (check manually)", ""]
        if unknown:
            lines += ["| Site | Reason |", "|---|---|"]
            lines += [f"| {_cell(h.name)} | {_cell(h.detail)} |" for h in unknown]
        else:
            lines.append("None.")
        lines.append("")

    for title, body in result.sections.items():
        lines += [f"## {title}", ""] + _section_md(body) + [""]

    if result.notes:
        lines += ["## Notes", ""] + [f"- {n}" for n in result.notes] + [""]
    return "\n".join(lines).rstrip() + "\n"


def save_report(
    result: ScanResult,
    path: Path | str | None = None,
    now: datetime | None = None,
) -> Path:
    """Write the report as Markdown and return its path.

    ``path`` may be a file (``.md``) or a directory; with none, ``./reports/`` is used.
    An existing file is never overwritten: a time suffix and then a counter are added.
    """
    now = now or datetime.now()
    content = to_markdown(result, now)
    target = Path(path) if path else reports_dir()
    if target.suffix.lower() == ".md":
        folder, stem = target.parent, target.stem
    else:
        folder, stem = target, f"{result.kind}-{safe_name(result.target)}-{now:%Y-%m-%d}"
    folder.mkdir(parents=True, exist_ok=True)
    out = folder / f"{stem}.md"
    if out.exists():
        out = folder / f"{stem}-{now:%H%M%S}.md"
    n = 2
    while out.exists():
        out = folder / f"{stem}-{now:%H%M%S}-{n}.md"
        n += 1
    out.write_text(content, encoding="utf-8")
    return out
