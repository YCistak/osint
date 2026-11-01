"""Markdown report generation and saving."""

from __future__ import annotations

import os
import re
from datetime import datetime
from pathlib import Path

from .html_report import to_html
from .models import FOUND, MISSING, UNKNOWN, ScanResult

DEFAULT_DIR = Path("reports")

LEGAL_NOTE = (
    "> This report is meant for auditing your own digital footprint, CTFs and "
    "authorized research only. Collecting data about other people without a lawful "
    "basis may violate privacy laws (GDPR, KVKK, CFAA and similar)."
)

KIND_TITLES = {"phone": "Phone report", "image": "Image report", "username": "Username report", "email": "Email report", "domain": "Domain / IP report",
                "github": "GitHub report", "me": "Privacy self-audit", "password": "Password check"}


class ReportRefused(ValueError):
    """The result must never be written to disk (password checks)."""


NEVER_SAVED = {"password"}


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
        lines = [f"- **{k}:** {v}" for k, v in body.get("summary", {}).items()]
        if lines:
            lines.append("")
        if not body["rows"]:
            lines.append("None.")
        else:
            lines += ["| " + " | ".join(body["headers"]) + " |", "|" + "---|" * len(body["headers"])]
            lines += ["| " + " | ".join(_cell(c) for c in row) + " |" for row in body["rows"]]
        if body.get("footer"):
            lines += ["", body["footer"]]
        return lines
    if kind == "list":
        return [f"- `{i}`" for i in body["items"]] or ["None."]
    if kind == "steps":
        return [f"{n}. {i}" for n, i in enumerate(body["items"], 1)] or ["None."]
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
            detailed = [h for h in found if h.profile]
            if detailed:
                lines += ["", "### Profile details", ""]
                for h in detailed:
                    lines.append(f"- **{h.name}**")
                    lines += [f"  - {k}: {_cell(v)}" for k, v in h.profile.items()]
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


def resolve_format(path: Path | str | None, fmt: str | None) -> str:
    """"html" or "md": explicit ``fmt`` wins, then the file extension, then Markdown."""
    if fmt in ("html", "md"):
        return fmt
    suffix = Path(path).suffix.lower() if path else ""
    return "html" if suffix in (".html", ".htm") else "md"


def save_report(
    result: ScanResult,
    path: Path | str | None = None,
    now: datetime | None = None,
    fmt: str | None = None,
) -> Path:
    """Write the report (Markdown by default, HTML for ``.html`` or ``fmt="html"``).

    ``path`` may be a file or a directory; with none, ``./reports/`` is used.
    An existing file is never overwritten: a time suffix and then a counter are added.
    """
    if result.kind in NEVER_SAVED:
        raise ReportRefused("password checks are never saved")
    now = now or datetime.now()
    fmt = resolve_format(path, fmt)
    ext = ".html" if fmt == "html" else ".md"
    content = to_html(result, now) if fmt == "html" else to_markdown(result, now)
    target = Path(path).expanduser() if path else reports_dir()
    if target.suffix.lower() in (".md", ".html", ".htm"):
        folder, stem = target.parent, target.stem
    else:
        folder, stem = target, f"{result.kind}-{safe_name(result.target)}-{now:%Y-%m-%d}"
    folder.mkdir(parents=True, exist_ok=True)
    out = folder / f"{stem}{ext}"
    if out.exists():
        out = folder / f"{stem}-{now:%H%M%S}{ext}"
    n = 2
    while out.exists():
        out = folder / f"{stem}-{now:%H%M%S}-{n}{ext}"
        n += 1
    out.write_text(content, encoding="utf-8")
    return out
