"""Deep GitHub profile analysis through the public REST API.

No key needed; an optional ``GITHUB_TOKEN`` environment variable raises the
rate limit from 60 to 5000 requests per hour (it is only sent to api.github.com).
Besides the profile, repositories and activity, it looks for e-mail addresses
that public commits expose, and flags real addresses versus GitHub noreply ones.
"""

from __future__ import annotations

import os
from collections import Counter
from datetime import datetime

import httpx

from . import net
from .models import ScanResult, kv, table, text
from .username import username_valid

API = "https://api.github.com"
USER_AGENT = "osint-cli (+https://github.com/YCistak/osint)"
MAX_COMMIT_REPOS = 5
COMMITS_PER_REPO = 30


class GitHubError(RuntimeError):
    """The API could not answer (not found, rate limit, network)."""


class RateLimited(GitHubError):
    pass


def token() -> str:
    return os.environ.get("GITHUB_TOKEN", "").strip()


def new_client() -> httpx.Client:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT,
               "X-GitHub-Api-Version": "2022-11-28"}
    if token():
        headers["Authorization"] = f"Bearer {token()}"
    return net.sync_client(timeout=15.0, headers=headers)


def rate_limit_message(resp: httpx.Response) -> str:
    reset = resp.headers.get("x-ratelimit-reset", "")
    when = ""
    if reset.isdigit():
        when = " It resets at " + datetime.fromtimestamp(int(reset)).strftime("%H:%M") + "."
    hint = "" if token() else " Set the GITHUB_TOKEN environment variable (a token with no scopes is enough) for 5000 requests per hour."
    return f"GitHub API rate limit reached.{when}{hint}"


class Api:
    """Thin wrapper that raises readable errors and remembers the remaining quota."""

    def __init__(self, client: httpx.Client) -> None:
        self.client = client
        self.remaining: str = ""
        self.calls = 0

    def get(self, path: str, **params):
        self.calls += 1
        try:
            resp = self.client.get(API + path, params=params or None)
        except httpx.HTTPError as e:
            raise GitHubError(f"could not reach api.github.com ({type(e).__name__})") from None
        self.remaining = resp.headers.get("x-ratelimit-remaining", self.remaining)
        if resp.status_code == 404:
            raise GitHubError("not found")
        if resp.status_code in (403, 429) and (self.remaining == "0" or resp.status_code == 429
                                                or "rate limit" in resp.text.lower()):
            raise RateLimited(rate_limit_message(resp))
        if resp.status_code != 200:
            raise GitHubError(f"GitHub answered HTTP {resp.status_code}")
        try:
            return resp.json()
        except ValueError:
            raise GitHubError("GitHub returned an invalid answer")


# ---------------------------------------------------------------- pure helpers

def is_noreply(email: str) -> bool:
    e = email.lower()
    return e.endswith("@users.noreply.github.com") or e.endswith("@noreply.github.com")


def collect_event_emails(events: list) -> list[tuple[str, str, str]]:
    """``(email, author name, source)`` from PushEvent commits."""
    out = []
    for ev in events or []:
        if not isinstance(ev, dict) or ev.get("type") != "PushEvent":
            continue
        repo = (ev.get("repo") or {}).get("name", "")
        for c in (ev.get("payload") or {}).get("commits") or []:
            a = c.get("author") or {}
            if a.get("email"):
                out.append((a["email"], a.get("name", ""), f"push event in {repo}"))
    return out


def collect_commit_emails(commits: list, repo: str) -> list[tuple[str, str, str]]:
    out = []
    for c in commits or []:
        a = ((c or {}).get("commit") or {}).get("author") or {}
        if a.get("email"):
            out.append((a["email"], a.get("name", ""), f"commit in {repo}"))
    return out


def summarize_emails(found: list[tuple[str, str, str]]) -> list[dict]:
    """Group by address (case-insensitive): kind, names, number of sightings, sources."""
    groups: dict[str, dict] = {}
    for email, name, source in found:
        g = groups.setdefault(email.lower(), {"email": email, "names": set(), "count": 0, "sources": set()})
        g["count"] += 1
        if name:
            g["names"].add(name)
        g["sources"].add(source)
    rows = []
    for g in groups.values():
        rows.append({"email": g["email"], "kind": "noreply" if is_noreply(g["email"]) else "REAL ADDRESS",
                     "names": sorted(g["names"]), "count": g["count"], "sources": sorted(g["sources"])})
    rows.sort(key=lambda r: (r["kind"] == "noreply", -r["count"], r["email"].lower()))
    return rows


def summarize_repos(repos: list) -> dict:
    repos = [r for r in repos if isinstance(r, dict)]
    own = [r for r in repos if not r.get("fork")]
    langs = Counter(r["language"] for r in own if r.get("language"))
    stars = sum(int(r.get("stargazers_count") or 0) for r in own)
    top = sorted(own, key=lambda r: (-int(r.get("stargazers_count") or 0), r.get("name", "")))[:5]
    return {"total": len(repos), "own": len(own), "forks": len(repos) - len(own), "stars": stars,
            "languages": langs.most_common(8), "top": top}


def summarize_events(events: list) -> dict:
    events = [e for e in events if isinstance(e, dict)]
    kinds = Counter(e.get("type", "?").replace("Event", "") for e in events)
    dates = sorted(e.get("created_at", "") for e in events if e.get("created_at"))
    return {"count": len(events), "kinds": kinds.most_common(), "first": dates[0] if dates else "",
            "last": dates[-1] if dates else ""}
