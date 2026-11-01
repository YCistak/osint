"""Single-file HTML report: inline CSS, dark theme, no scripts.

Every value that came from outside (site names, profile text, URLs, breach
data ...) goes through :func:`esc`; links and images only accept http(s) URLs.
"""

from __future__ import annotations

import html
from datetime import datetime

from .models import FOUND, MISSING, UNKNOWN, ScanResult

LEGAL = (
    "This report is meant for auditing your own digital footprint, CTFs and authorized "
    "research only. Collecting data about other people without a lawful basis may violate "
    "privacy laws (GDPR, KVKK, CFAA and similar)."
)
TITLES = {"phone": "Phone report", "image": "Image report", "username": "Username report",
          "email": "Email report", "domain": "Domain / IP report",
          "github": "GitHub report", "me": "Privacy self-audit", "password": "Password check"}

CSS = """
:root{color-scheme:dark;--bg:#0d1117;--card:#161b22;--line:#30363d;--fg:#e6edf3;--dim:#8b949e;--acc:#58a6ff;--ok:#3fb950;--warn:#d29922}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
main{max-width:960px;margin:0 auto;padding:24px 16px 64px}h1{font-size:1.6rem;margin:0 0 4px}
h2{font-size:1.1rem;margin:0 0 12px;color:var(--acc)}.meta{color:var(--dim);margin:0 0 16px}
.legal{border-left:3px solid var(--warn);padding:8px 12px;color:var(--dim);margin:0 0 24px;background:var(--card)}
section{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px;margin:0 0 16px}
a{color:var(--acc);word-break:break-all}table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}
th{color:var(--dim);font-weight:600}dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:0}
dt{color:var(--dim)}dd{margin:0;overflow-wrap:anywhere}.hit{display:flex;gap:12px;padding:10px 0;border-bottom:1px solid var(--line)}
.hit:last-child{border:0}.hit img{width:48px;height:48px;border-radius:50%;object-fit:cover;background:var(--line);flex:none}
.hit h3{margin:0;font-size:1rem}.hit dl{margin-top:4px;font-size:.9rem}.ok{color:var(--ok)}.warn{color:var(--warn)}
.stats{color:var(--dim);margin:0 0 12px}ul,ol{margin:0;padding-left:22px}li{margin:4px 0}code{background:var(--bg);padding:1px 5px;border-radius:4px}
"""


def esc(value) -> str:
    return html.escape(str(value), quote=True)


def safe_url(value) -> str:
    """The URL if it is plain http(s), else an empty string."""
    s = str(value).strip()
    return s if s.lower().startswith(("http://", "https://")) and not any(c in s for c in "\n\r\t <>\"'") else ""


def link(url, label=None) -> str:
    u = safe_url(url)
    text = esc(label if label is not None else url)
    return f'<a href="{esc(u)}" rel="noopener noreferrer nofollow" target="_blank">{text}</a>' if u else text


def cell(value) -> str:
    """Plain text, with bare http(s) values turned into links."""
    s = str(value)
    return link(s) if safe_url(s) == s.strip() and s.strip() else esc(s)


def _kv(items: dict) -> str:
    if not items:
        return "<p>None.</p>"
    rows = "".join(f"<dt>{esc(k)}</dt><dd>{cell(v)}</dd>" for k, v in items.items())
    return f"<dl>{rows}</dl>"


def _body(body: dict) -> str:
    kind = body.get("type")
    if kind == "kv":
        return _kv(body["items"])
    if kind == "table":
        parts = []
        if body.get("summary"):
            parts.append(_kv(body["summary"]))
        if not body["rows"]:
            parts.append("<p>None.</p>")
        else:
            head = "".join(f"<th>{esc(h)}</th>" for h in body["headers"])
            rows = "".join("<tr>" + "".join(f"<td>{cell(c)}</td>" for c in r) + "</tr>" for r in body["rows"])
            parts.append(f"<table><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table>")
        if body.get("footer"):
            parts.append(f'<p class="stats">{esc(body["footer"])}</p>')
        return "".join(parts)
    if kind == "list":
        return "<ul>" + "".join(f"<li><code>{esc(i)}</code></li>" for i in body["items"]) + "</ul>" if body["items"] else "<p>None.</p>"
    if kind == "steps":
        return "<ol>" + "".join(f"<li>{esc(i)}</li>" for i in body["items"]) + "</ol>" if body["items"] else "<p>None.</p>"
    return f"<p>{esc(body.get('text', ''))}</p>"


def _hit(h) -> str:
    avatar = safe_url(h.profile.get("Avatar", "")) if h.profile else ""
    img = (f'<img src="{esc(avatar)}" alt="" loading="lazy" referrerpolicy="no-referrer">' if avatar
           else '<img alt="" src="data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==">')
    details = {k: v for k, v in (h.profile or {}).items() if k != "Avatar"}
    return (f'<div class="hit">{img}<div><h3>{esc(h.name)}</h3><div>{link(h.url)}</div>'
            f'{_kv(details) if details else ""}</div></div>')


def to_html(result: ScanResult, now: datetime | None = None) -> str:
    now = now or datetime.now()
    title = f"{TITLES.get(result.kind, 'Report')}: {result.target}"
    out = [
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        '<meta name="referrer" content="no-referrer">',
        f"<title>{esc(title)}</title><style>{CSS}</style></head><body><main>",
        f"<h1>{esc(title)}</h1>",
        f'<p class="meta">{now:%Y-%m-%d %H:%M} &middot; target <code>{esc(result.target)}</code></p>',
        f'<p class="legal">{esc(LEGAL)}</p>',
    ]
    if result.cancelled:
        out.append('<p class="warn">The scan was cancelled before it finished; results are partial.</p>')
    if result.hits:
        counts = result.counts()
        found = sorted((h for h in result.hits if h.status == FOUND), key=lambda h: h.name.lower())
        unknown = sorted((h for h in result.hits if h.status == UNKNOWN), key=lambda h: h.name.lower())
        stats = (f'{len(result.hits)} checked &middot; <span class="ok">{counts[FOUND]} found</span> &middot; '
                 f'{counts[MISSING]} not found &middot; <span class="warn">{counts[UNKNOWN]} unknown</span>')
        out.append(f'<section><h2>Found accounts</h2><p class="stats">{stats}</p>')
        out.append("".join(_hit(h) for h in found) or "<p>No accounts found.</p>")
        out.append("</section>")
        out.append("<section><h2>Unknown (check manually)</h2>")
        if unknown:
            rows = "".join(f"<tr><td>{esc(h.name)}</td><td>{esc(h.detail)}</td></tr>" for h in unknown)
            out.append(f"<table><thead><tr><th>Site</th><th>Reason</th></tr></thead><tbody>{rows}</tbody></table>")
        else:
            out.append("<p>None.</p>")
        out.append("</section>")
    for name, body in result.sections.items():
        out.append(f"<section><h2>{esc(name)}</h2>{_body(body)}</section>")
    if result.notes:
        out.append("<section><h2>Notes</h2><ul>" + "".join(f"<li>{esc(n)}</li>" for n in result.notes) + "</ul></section>")
    out.append("</main></body></html>\n")
    return "".join(out)
