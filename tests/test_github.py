"""GitHub deep analysis with a mocked API."""

import io
import json

import httpx
import pytest
from rich.console import Console

from osint import cli, github, repl
from osint.sites import Site

USER = {"login": "jane", "name": "Jane Doe", "type": "User", "bio": "hacker", "company": "ACME",
        "location": "Istanbul", "email": None, "blog": "https://jane.test", "twitter_username": "janed",
        "followers": 10, "following": 2, "public_repos": 3, "public_gists": 0,
        "created_at": "2015-03-04T10:00:00Z", "html_url": "https://github.com/jane"}
REPOS = [
    {"name": "tool", "fork": False, "stargazers_count": 50, "language": "Python", "pushed_at": "2025-01-02T00:00:00Z"},
    {"name": "lib", "fork": False, "stargazers_count": 5, "language": "Python", "pushed_at": "2024-01-02T00:00:00Z"},
    {"name": "cfg", "fork": False, "stargazers_count": 0, "language": "Shell", "pushed_at": "2023-01-02T00:00:00Z"},
    {"name": "forked", "fork": True, "stargazers_count": 999, "language": "C", "pushed_at": "2025-01-02T00:00:00Z"},
]
EVENTS = [
    {"type": "PushEvent", "repo": {"name": "jane/tool"}, "created_at": "2025-05-02T10:00:00Z",
     "payload": {"commits": [{"author": {"name": "Jane", "email": "12345+jane@users.noreply.github.com"}},
                             {"author": {"name": "Jane D", "email": "Jane@Home.Test"}}]}},
    {"type": "WatchEvent", "repo": {"name": "x/y"}, "created_at": "2025-05-01T10:00:00Z", "payload": {}},
]
COMMITS = [{"commit": {"author": {"name": "Jane Doe", "email": "jane@home.test"}}},
           {"commit": {"author": {"name": "Jane Doe", "email": "jane@work.test"}}}]


def make_client(routes=None, rate_limited=False, headers=None):
    routes = {
        "/users/jane": USER, "/users/jane/repos": REPOS, "/users/jane/orgs": [{"login": "acme"}],
        "/users/jane/events/public": EVENTS, "/repos/jane/tool/commits": COMMITS,
        "/repos/jane/lib/commits": COMMITS[:1], "/repos/jane/cfg/commits": [],
        **(routes or {}),
    }
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        h = {"x-ratelimit-remaining": "42", **(headers or {})}
        if rate_limited and request.url.path != "/users/jane":
            return httpx.Response(403, json={"message": "API rate limit exceeded"},
                                  headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1893456000"})
        body = routes.get(request.url.path)
        if body is None:
            return httpx.Response(404, json={"message": "Not Found"}, headers=h)
        return httpx.Response(200, json=body, headers=h)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    client.seen = seen
    return client


def test_is_noreply():
    assert github.is_noreply("1+a@users.noreply.github.com") and github.is_noreply("noreply@github.com")
    assert github.is_noreply("a@users.noreply.github.com")
    assert not github.is_noreply("a@gmail.com")


def test_summarize_emails_groups_case_insensitively_and_orders_real_first():
    rows = github.summarize_emails([
        ("1+a@users.noreply.github.com", "A", "s1"), ("A@x.test", "A", "s2"), ("a@x.test", "Alice", "s3")])
    assert [r["email"] for r in rows] == ["A@x.test", "1+a@users.noreply.github.com"]
    assert rows[0]["kind"] == "REAL ADDRESS" and rows[0]["count"] == 2 and rows[0]["names"] == ["A", "Alice"]
    assert rows[1]["kind"] == "noreply"


def test_summarize_repos_ignores_forks():
    s = github.summarize_repos(REPOS)
    assert (s["total"], s["own"], s["forks"], s["stars"]) == (4, 3, 1, 55)
    assert s["languages"][0] == ("Python", 2)
    assert s["top"][0]["name"] == "tool"


def test_collect_event_emails_only_push_events():
    got = github.collect_event_emails(EVENTS)
    assert [g[0] for g in got] == ["12345+jane@users.noreply.github.com", "Jane@Home.Test"]
    assert github.collect_event_emails(None) == []


def test_full_analysis_sections():
    client = make_client()
    r = github.analyze("jane", client)
    assert list(r.sections) == ["Profile", "Repositories", "Top languages", "Organizations",
                                "Recent activity", "Emails in public commits"]
    assert r.sections["Profile"]["items"]["Location"] == "Istanbul"
    assert "3 own, 1 forks" in r.sections["Repositories"]["summary"]["Repositories"]
    assert r.sections["Top languages"]["rows"][0][:2] == ["Python", "2"]
    assert r.sections["Organizations"]["rows"][0][0] == "acme"
    assert r.sections["Recent activity"]["summary"]["Public events read"] == "2"
    rows = {row[0].lower(): row for row in r.sections["Emails in public commits"]["rows"]}
    assert rows["jane@home.test"][1] == "REAL ADDRESS" and rows["jane@home.test"][2] == "3"
    assert rows["jane@work.test"][1] == "REAL ADDRESS"
    assert rows["12345+jane@users.noreply.github.com"][1] == "noreply"
    assert "2 real address" in r.sections["Emails in public commits"]["footer"]
    assert sorted(e.lower() for e in r.meta["emails"]) == ["jane@home.test", "jane@work.test"]
    assert any("calls left" in n and "42" in n for n in r.notes)


def test_commit_scan_limited_to_own_non_fork_repos_and_filters_by_author():
    client = make_client()
    github.analyze("jane", client)
    paths = [r.url.path for r in client.seen]
    assert "/repos/jane/forked/commits" not in paths
    assert sum(p.endswith("/commits") for p in paths) == 3
    commit_req = next(r for r in client.seen if r.url.path == "/repos/jane/tool/commits")
    assert commit_req.url.params["author"] == "jane"


def test_public_profile_email_is_reported():
    client = make_client({"/users/jane": {**USER, "email": "pub@jane.test"}})
    r = github.analyze("jane", client)
    rows = {row[0]: row for row in r.sections["Emails in public commits"]["rows"]}
    assert rows["pub@jane.test"][4] == "public profile"


def test_user_not_found_and_invalid():
    with pytest.raises(github.GitHubError, match="does not exist"):
        github.analyze("ghost", make_client())
    with pytest.raises(github.GitHubError, match="invalid"):
        github.analyze("bad name!", make_client())


def test_rate_limit_is_clear_and_keeps_partial_result(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    r = github.analyze("jane", make_client(rate_limited=True))
    assert "Profile" in r.sections
    notes = " ".join(r.notes)
    assert "rate limit reached" in notes and "GITHUB_TOKEN" in notes and "partial" in notes


def test_rate_limit_on_the_profile_itself_raises_clear_error(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    def handler(request):
        return httpx.Response(403, json={"message": "API rate limit exceeded"},
                              headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1893456000"})

    with pytest.raises(github.RateLimited, match="GITHUB_TOKEN"):
        github.analyze("jane", httpx.Client(transport=httpx.MockTransport(handler)))


def test_network_error_is_github_error():
    def boom(request):
        raise httpx.ConnectError("down")

    with pytest.raises(github.GitHubError, match="could not reach"):
        github.analyze("jane", httpx.Client(transport=httpx.MockTransport(boom)))


def test_token_is_sent_as_bearer_only_when_set(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "tok123")
    assert github.new_client().headers["authorization"] == "Bearer tok123"
    monkeypatch.delenv("GITHUB_TOKEN")
    assert "authorization" not in github.new_client().headers


def test_cli_and_repl_use_analyze(monkeypatch, capsys):
    from osint.models import ScanResult

    monkeypatch.setattr(github, "analyze", lambda name: ScanResult("github", name))
    assert cli.main(["github", "jane", "--json", "--no-banner"]) == 0
    assert json.loads(capsys.readouterr().out)["kind"] == "github"

    def fail(name):
        raise github.GitHubError("GitHub API rate limit reached.")

    monkeypatch.setattr(github, "analyze", fail)
    assert cli.main(["github", "jane", "--no-banner"]) == 2
    buf = io.StringIO()
    s = repl.Session(Console(file=buf, width=120, highlight=False), [Site("D", "https://d.test/{username}")])
    repl.execute(s, "github jane")
    assert "rate limit reached" in buf.getvalue()
    repl.execute(s, "github a b")
    assert "usage: github" in buf.getvalue()
