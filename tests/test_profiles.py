"""Profile detail extraction with mocked responses (no network)."""

import asyncio
import io

import httpx
from rich.console import Console

from osint import profiles, ui, username
from osint.models import FOUND, Hit
from osint.sites import Site

GITHUB = {
    "login": "octo", "name": "Octo Cat", "bio": "Builds\n things", "location": "SF",
    "company": "@gh", "blog": "octo.example", "followers": 1234, "created_at": "2011-01-25T18:44:36Z",
    "avatar_url": "https://avatars.githubusercontent.com/u/1",
}


def run(site, handler, name="octo"):
    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await username.check_site(c, site, name)

    return asyncio.run(go())


def test_github_parser_normalizes_fields():
    p = profiles.parse_github(GITHUB)
    assert p["Name"] == "Octo Cat" and p["Bio"] == "Builds things"
    assert p["Website"] == "https://octo.example" and p["Followers"] == "1,234"
    assert p["Joined"] == "2011-01-25" and p["Avatar"].startswith("https://")
    assert list(p)[:2] == ["Name", "Bio"]  # stable order


def test_inline_json_probe_gives_profile_without_extra_request():
    calls = []

    def handler(req):
        calls.append(str(req.url))
        return httpx.Response(200, json=GITHUB)

    s = Site("GitHub", "https://github.com/{username}", url_probe="https://api.github.com/users/{username}")
    hit = run(s, handler)
    assert hit.status == FOUND and hit.profile["Name"] == "Octo Cat"
    assert calls == ["https://api.github.com/users/octo"]


def test_gitlab_bluesky_keybase_parsers():
    assert profiles.parse_gitlab([{"name": "G", "bio": "b", "location": "L", "avatar_url": "https://x/a.png"}])["Name"] == "G"
    assert profiles.parse_gitlab([]) == {}
    bs = profiles.parse_bluesky({"displayName": "B", "description": "hi", "followersCount": 5,
                                 "createdAt": "2023-05-01T00:00:00Z", "avatar": "https://cdn/a.jpg"})
    assert bs["Name"] == "B" and bs["Joined"] == "2023-05-01"
    kb = profiles.parse_keybase({"them": [{"profile": {"full_name": "K", "bio": "x", "location": "NYC"},
                                          "pictures": {"primary": {"url": "https://kb/p.jpg"}}}]})
    assert kb == {"Name": "K", "Bio": "x", "Location": "NYC", "Avatar": "https://kb/p.jpg"}
    assert profiles.parse_keybase({"them": [None]}) == {}


def test_reddit_hackernews_devto_parsers():
    r = profiles.parse_reddit({"data": {"subreddit": {"title": "T", "public_description": "bio"},
                                        "total_karma": 4200, "created_utc": 1300000000,
                                        "icon_img": "https://styles/a.png?width=256"}})
    assert r["Name"] == "T" and r["Followers"] == "4,200 karma" and r["Avatar"] == "https://styles/a.png"
    hn = profiles.parse_hackernews({"about": "I &lt;3 C<p>second", "created": 1300000000, "karma": 9})
    assert "second" in hn["Bio"] and "<p>" not in hn["Bio"]
    d = profiles.parse_devto({"name": "D", "summary": "s", "profile_image": "https://dev/i.png"})
    assert d["Name"] == "D"


def test_extra_request_for_reddit_like_sites():
    seen = []

    def handler(req):
        seen.append(str(req.url))
        if "about.json" in str(req.url):
            return httpx.Response(200, json={"data": {"subreddit": {"title": "Rd"}, "total_karma": 1}})
        return httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})

    hit = run(Site("Reddit", "https://www.reddit.com/user/{username}"), handler)
    assert hit.profile["Name"] == "Rd"
    assert seen == ["https://www.reddit.com/user/octo", "https://www.reddit.com/user/octo/about.json"]


def test_extra_request_failure_does_not_break_hit():
    def handler(req):
        if "about.json" in str(req.url):
            raise httpx.ConnectError("boom")
        return httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})

    hit = run(Site("Reddit", "https://www.reddit.com/user/{username}"), handler)
    assert hit.status == FOUND and hit.profile == {}


PAGE = """<html><head>
<meta property="og:title" content="Jane &amp; Co - Designer">
<meta property="og:description" content="Designs   things.">
<meta property="og:image" content="https://img.test/jane.jpg">
<meta property="og:site_name" content="Demo"></head><body></body></html>"""


def test_generic_meta_fallback_reuses_fetched_body():
    calls = []

    def handler(req):
        calls.append(1)
        return httpx.Response(200, text=PAGE, headers={"content-type": "text/html; charset=utf-8"})

    hit = run(Site("Demo", "https://demo.test/{username}"), handler, name="jane")
    assert hit.profile == {"Name": "Jane & Co - Designer", "Bio": "Designs things.",
                           "Avatar": "https://img.test/jane.jpg"}
    assert len(calls) == 1  # no refetch


def test_meta_ignores_title_that_is_just_the_site_name_and_bad_urls():
    page = ('<meta property="og:title" content="Demo"><meta property="og:image" content="javascript:alert(1)">'
            '<meta name="description" content="hello">')
    assert profiles.parse_meta(page, "Demo") == {"Bio": "hello"}


def test_meta_boilerplate_without_the_username_is_dropped():
    page = ('<meta property="og:title" content="GIFs on GIPHY"><meta property="og:description" content="Find GIFs">')
    assert profiles.parse_meta(page, "Giphy", "torvalds") == {}
    assert profiles.parse_meta(page.replace("Find GIFs", "torvalds channel"), "Giphy", "torvalds")["Bio"] == "torvalds channel"


def test_non_html_non_json_gives_nothing():
    assert profiles.from_response("Demo", "image/png", "<meta>") == {}
    assert profiles.from_response("GitHub", "application/json", "not json") == {}


def test_text_is_cleaned_and_capped():
    assert profiles.clean_text("a\x00b\x1b[31m  c") == "ab[31m c"
    assert len(profiles.clean_text("x" * 1000)) == profiles.MAX_TEXT


def test_profile_lines_render_under_hit_and_in_json():
    hit = Hit("GitHub", "https://github.com/octo", FOUND, profile={"Name": "Octo", "Location": "SF"})
    buf = io.StringIO()
    c = Console(file=buf, width=100, highlight=False)
    for line in ui.profile_lines(hit):
        c.print(line)
    out = buf.getvalue()
    assert "      Name: Octo" in out and "      Location: SF" in out
    assert hit.to_dict()["profile"] == {"Name": "Octo", "Location": "SF"}
    assert "profile" not in Hit("X", "u", FOUND).to_dict()


def test_markdown_report_lists_profile_details():
    from osint import report
    from osint.models import ScanResult

    r = ScanResult("username", "octo")
    r.hits = [Hit("GitHub", "https://github.com/octo", FOUND, profile={"Name": "Octo", "Bio": "a|b"})]
    md = report.to_markdown(r)
    assert "### Profile details" in md and "  - Name: Octo" in md and "a\\|b" in md
