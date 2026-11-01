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


# ---------------------------------------------------------------- analysis

def _date(value: str) -> str:
    return value[:10] if value else ""


def profile_fields(user: dict) -> dict[str, str]:
    fields = {
        "Login": user.get("login"), "Name": user.get("name"), "Type": user.get("type"),
        "Bio": user.get("bio"), "Company": user.get("company"), "Location": user.get("location"),
        "Public email": user.get("email"), "Website": user.get("blog"),
        "Twitter / X": user.get("twitter_username"), "Followers": user.get("followers"),
        "Following": user.get("following"), "Public repositories": user.get("public_repos"),
        "Public gists": user.get("public_gists"), "Joined": _date(user.get("created_at") or ""),
        "Profile": user.get("html_url"),
    }
    return {k: str(v) for k, v in fields.items() if v not in (None, "", 0) or k in ("Followers", "Public repositories")}


def analyze(name: str, client: httpx.Client | None = None) -> ScanResult:
    """Run the deep scan. Raises :class:`GitHubError` only when the profile itself cannot be read;
    problems in later steps become notes so partial results are kept."""
    if not username_valid(name):
        raise GitHubError("invalid username")
    own = client is None
    client = client or new_client()
    api = Api(client)
    result = ScanResult("github", name)
    try:
        try:
            user = api.get(f"/users/{name}")
        except GitHubError as e:
            if str(e) == "not found":
                raise GitHubError(f"GitHub user '{name}' does not exist") from None
            raise
        result.sections["Profile"] = kv(profile_fields(user))
        emails: list[tuple[str, str, str]] = []
        if user.get("email"):
            emails.append((user["email"], user.get("name") or "", "public profile"))

        def step(title: str, fn) -> None:
            try:
                fn()
            except RateLimited as e:
                result.notes.append(f"{title}: {e}")
                raise
            except GitHubError as e:
                result.sections[title] = text(f"Unavailable: {e}")

        repos: list = []
        try:
            step("Repositories", lambda: _repositories(api, name, result, repos))
            step("Organizations", lambda: _orgs(api, name, result))
            step("Recent activity", lambda: _activity(api, name, result, emails))
            step("Emails in public commits", lambda: _commit_emails(api, name, repos, result, emails))
        except RateLimited:
            result.notes.append("The scan stopped early because of the rate limit; the sections above are partial.")
        result.meta["emails"] = [r["email"] for r in summarize_emails(emails) if r["kind"] != "noreply"]
        result.meta["profile"] = profile_fields(user)
        if api.remaining:
            result.notes.append(f"GitHub API calls left this hour: {api.remaining}"
                                + ("" if token() else " (set GITHUB_TOKEN for a higher limit)"))
    finally:
        if own:
            client.close()
    return result


def _repositories(api: Api, name: str, result: ScanResult, sink: list) -> None:
    repos = api.get(f"/users/{name}/repos", per_page=100, sort="pushed", type="owner")
    sink.extend(repos)
    s = summarize_repos(repos)
    info = {"Repositories": f"{s['total']} ({s['own']} own, {s['forks']} forks)", "Stars on own repos": str(s["stars"])}
    if s["total"] >= 100:
        info["Note"] = "only the 100 most recently pushed repositories were read"
    body = table(["Repository", "Stars", "Language", "Last push"],
                 [[r.get("name", ""), str(r.get("stargazers_count", 0)), r.get("language") or "-",
                   _date(r.get("pushed_at") or "")] for r in s["top"]])
    body["summary"] = info
    result.sections["Repositories"] = body
    if s["languages"]:
        total = sum(c for _, c in s["languages"])
        result.sections["Top languages"] = table(
            ["Language", "Repositories", "Share"],
            [[lang, str(c), f"{100 * c // total}%"] for lang, c in s["languages"]])


def _orgs(api: Api, name: str, result: ScanResult) -> None:
    orgs = api.get(f"/users/{name}/orgs")
    names = [o.get("login", "") for o in orgs if isinstance(o, dict)]
    result.sections["Organizations"] = (
        table(["Organization", "URL"], [[n, f"https://github.com/{n}"] for n in names]) if names
        else text("No public organization memberships."))


def _activity(api: Api, name: str, result: ScanResult, emails: list) -> None:
    events = api.get(f"/users/{name}/events/public", per_page=100)
    s = summarize_events(events)
    emails.extend(collect_event_emails(events))
    if not s["count"]:
        result.sections["Recent activity"] = text("No public activity in the last 90 days.")
        return
    body = table(["Event", "Count"], [[k, str(c)] for k, c in s["kinds"]])
    body["summary"] = {"Public events read": str(s["count"]), "Newest": s["last"][:16].replace("T", " "),
                       "Oldest": s["first"][:16].replace("T", " ")}
    result.sections["Recent activity"] = body


def _commit_emails(api: Api, name: str, repos: list, result: ScanResult, emails: list) -> None:
    own = [r for r in repos if isinstance(r, dict) and not r.get("fork") and r.get("name")]
    for r in own[:MAX_COMMIT_REPOS]:
        try:
            commits = api.get(f"/repos/{name}/{r['name']}/commits", author=name, per_page=COMMITS_PER_REPO)
        except RateLimited:
            raise
        except GitHubError:
            continue  # empty or disabled repository
        emails.extend(collect_commit_emails(commits, r["name"]))
    rows = summarize_emails(emails)
    if not rows:
        result.sections["Emails in public commits"] = text("No e-mail addresses found in recent public activity.")
        return
    body = table(["Address", "Kind", "Seen", "Names", "Where"],
                 [[r["email"], r["kind"], str(r["count"]), ", ".join(r["names"]) or "-",
                   "; ".join(r["sources"][:3])] for r in rows])
    real = [r for r in rows if r["kind"] != "noreply"]
    body["footer"] = (
        f"{len(real)} real address(es) exposed in public commits: anyone can read them from the git history. "
        "Fix: GitHub Settings > Emails > 'Keep my email addresses private' and 'Block command line pushes that expose my email'."
        if real else "Only GitHub noreply addresses are exposed (good).")
    result.sections["Emails in public commits"] = body
