"""Profile details (name, bio, location, avatar ...) for found username hits.

Three layers, cheapest first, all bounded in time:

1. Site-specific parsers for JSON the scan already fetched (GitHub, GitLab,
   Bluesky and Keybase use an API URL as their probe, so the body is JSON).
2. A few public JSON APIs fetched with one extra request (Reddit, Hacker News,
   DEV Community), only when the hit is on one of those sites.
3. A generic fallback that reads ``og:`` / ``description`` meta tags from the
   HTML body that was already downloaded (no refetch).

Everything here treats remote content as untrusted data: text is length-capped,
control characters are removed and only http(s) URLs are kept.
"""

from __future__ import annotations

import asyncio
import html
import json
import re
from collections.abc import Callable
from datetime import datetime, timezone

import httpx

ENRICH_TIMEOUT = 8.0  # hard cap for the extra request of one profile
MAX_TEXT = 200
FIELD_ORDER = ("Name", "Bio", "Location", "Company", "Website", "Followers", "Joined", "Avatar")

_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_WS = re.compile(r"\s+")


def clean_text(value, limit: int = MAX_TEXT) -> str:
    if value is None or isinstance(value, (dict, list)):
        return ""
    s = _WS.sub(" ", _CTRL.sub("", str(value))).strip()
    return s if len(s) <= limit else s[: limit - 1] + "…"


def clean_url(value) -> str:
    s = clean_text(value, 500)
    return s if s.lower().startswith(("http://", "https://")) else ""


def _date(value) -> str:
    """Year-month-day from an ISO string or a unix timestamp; '' if unusable."""
    try:
        if isinstance(value, (int, float)) and value > 0:
            return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%d")
        if isinstance(value, str) and re.match(r"\d{4}-\d{2}-\d{2}", value):
            return value[:10]
    except (OverflowError, OSError, ValueError):
        pass
    return ""


def _finish(fields: dict) -> dict[str, str]:
    """Drop empty values and keep a stable, display-friendly order."""
    ordered = {k: fields[k] for k in FIELD_ORDER if fields.get(k)}
    return ordered


def _num(v) -> str:
    return f"{v:,}" if isinstance(v, int) and not isinstance(v, bool) else ""


# --------------------------------------------------------------- JSON parsers

def _with_scheme(value) -> str:
    s = clean_text(value, 500)
    return s if not s or s.lower().startswith(("http://", "https://")) else "https://" + s


def parse_github(p) -> dict:
    if not isinstance(p, dict):
        return {}
    return _finish({
        "Name": clean_text(p.get("name")), "Bio": clean_text(p.get("bio")),
        "Location": clean_text(p.get("location")), "Company": clean_text(p.get("company")),
        "Website": clean_url(_with_scheme(p.get("blog"))),
        "Followers": _num(p.get("followers")), "Joined": _date(p.get("created_at")),
        "Avatar": clean_url(p.get("avatar_url")),
    })


def parse_gitlab(p) -> dict:
    if isinstance(p, list):  # users?username= returns a list
        p = p[0] if p else None
    if not isinstance(p, dict):
        return {}
    return _finish({
        "Name": clean_text(p.get("name")), "Bio": clean_text(p.get("bio")),
        "Location": clean_text(p.get("location")), "Company": clean_text(p.get("organization")),
        "Website": clean_url(p.get("website_url")), "Avatar": clean_url(p.get("avatar_url")),
        "Joined": _date(p.get("created_at")),
    })


def parse_bluesky(p) -> dict:
    if not isinstance(p, dict):
        return {}
    return _finish({
        "Name": clean_text(p.get("displayName")), "Bio": clean_text(p.get("description")),
        "Followers": _num(p.get("followersCount")), "Joined": _date(p.get("createdAt")),
        "Avatar": clean_url(p.get("avatar")),
    })


def parse_keybase(p) -> dict:
    try:
        them = p["them"][0]
        prof = them.get("profile") or {}
    except (KeyError, IndexError, TypeError, AttributeError):
        return {}
    return _finish({
        "Name": clean_text(prof.get("full_name")), "Bio": clean_text(prof.get("bio")),
        "Location": clean_text(prof.get("location")),
        "Avatar": clean_url(((them.get("pictures") or {}).get("primary") or {}).get("url")),
    })


def parse_reddit(p) -> dict:
    data = p.get("data") if isinstance(p, dict) else None
    if not isinstance(data, dict):
        return {}
    sub = data.get("subreddit") if isinstance(data.get("subreddit"), dict) else {}
    avatar = (data.get("icon_img") or sub.get("icon_img") or "").split("?")[0]
    karma = data.get("total_karma")
    return _finish({
        "Name": clean_text(sub.get("title")), "Bio": clean_text(sub.get("public_description")),
        "Followers": _num(karma) and f"{_num(karma)} karma",
        "Joined": _date(data.get("created_utc")), "Avatar": clean_url(avatar),
    })


def parse_hackernews(p) -> dict:
    if not isinstance(p, dict):
        return {}
    about = re.sub(r"<[^>]+>", " ", html.unescape(str(p.get("about") or "")))
    return _finish({
        "Bio": clean_text(about), "Joined": _date(p.get("created")),
        "Followers": _num(p.get("karma")) and f"{_num(p.get('karma'))} karma",
    })


def parse_devto(p) -> dict:
    if not isinstance(p, dict):
        return {}
    return _finish({
        "Name": clean_text(p.get("name")), "Bio": clean_text(p.get("summary")),
        "Location": clean_text(p.get("location")), "Joined": clean_text(p.get("joined_at"), 40),
        "Website": clean_url(p.get("website_url")), "Avatar": clean_url(p.get("profile_image")),
    })


# parsers for the JSON that the scan already downloaded, keyed by site name
INLINE: dict[str, Callable] = {
    "github": parse_github, "gitlab": parse_gitlab, "bluesky": parse_bluesky, "keybase": parse_keybase,
}
# sites whose profile needs one extra request: name -> (url template, parser)
EXTRA: dict[str, tuple[str, Callable]] = {
    "reddit": ("https://www.reddit.com/user/{u}/about.json", parse_reddit),
    "hackernews": ("https://hacker-news.firebaseio.com/v0/user/{u}.json", parse_hackernews),
    "hacker news": ("https://hacker-news.firebaseio.com/v0/user/{u}.json", parse_hackernews),
    "dev community": ("https://dev.to/api/users/by_username?url={u}", parse_devto),
    "dev.to": ("https://dev.to/api/users/by_username?url={u}", parse_devto),
}

# --------------------------------------------------------------- generic fallback

_META_TAG = re.compile(r"<meta\b[^>]*>", re.I)
_ATTR = re.compile(r"""([a-zA-Z:_-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')""")


def parse_meta(body: str, site_name: str = "", username: str = "") -> dict:
    """Name/Bio/Avatar from og: and description meta tags of an HTML page.

    With ``username`` given, the tags are kept only when they mention it: that filters
    out site-wide boilerplate that every page of the site shares.
    """
    metas: dict[str, str] = {}
    for tag in _META_TAG.findall(body[:200_000]):
        attrs = {m[0].lower(): html.unescape(m[1] or m[2]) for m in _ATTR.findall(tag)}
        key = (attrs.get("property") or attrs.get("name") or "").lower()
        if key and attrs.get("content") and key not in metas:
            metas[key] = attrs["content"]
    title = clean_text(metas.get("og:title") or metas.get("twitter:title"), 120)
    generic = {site_name.lower(), ""}
    if title.lower() in generic or all(w in site_name.lower() for w in title.lower().split() if len(w) > 2):
        title = ""
    desc = clean_text(metas.get("og:description") or metas.get("description")
                      or metas.get("twitter:description"))
    image = clean_url(metas.get("og:image") or metas.get("twitter:image"))
    if username and username.lower() not in f"{title} {desc}".lower():
        return {}
    return _finish({"Name": title, "Bio": desc, "Avatar": image})


# --------------------------------------------------------------- entry points

def _json(text: str):
    try:
        return json.loads(text)
    except ValueError:
        return None


def from_response(site_name: str, content_type: str, body: str, username: str = "") -> dict:
    """Profile fields from a response that was already downloaded (no network)."""
    key = site_name.lower()
    if key in INLINE:
        data = _json(body)
        if data is not None:
            return INLINE[key](data)
    if "html" in content_type.lower() and "<" in body:
        return parse_meta(body, site_name, username)
    return {}


async def fetch_extra(client: httpx.AsyncClient, site_name: str, username: str) -> dict:
    """One extra bounded request for sites that only have the profile in an API."""
    entry = EXTRA.get(site_name.lower())
    if not entry:
        return {}
    url, parser = entry
    from urllib.parse import quote

    try:
        r = await asyncio.wait_for(
            client.get(url.replace("{u}", quote(username, safe="")), follow_redirects=True),
            ENRICH_TIMEOUT,
        )
        if r.status_code != 200:
            return {}
        data = _json(r.text[:300_000])
        return parser(data) if data is not None else {}
    except Exception:  # profile details are best effort; never fail the scan
        return {}


async def get_profile(client: httpx.AsyncClient, site_name: str, username: str,
                      content_type: str, body: str) -> dict:
    """Best available profile for a found hit. Never raises."""
    try:
        extra = await fetch_extra(client, site_name, username)
        if extra:
            return extra
        return from_response(site_name, content_type, body, username)
    except Exception:
        return {}
