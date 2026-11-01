"""Username search engine implementing maigret's check types.

Supported ``check_type`` values (same semantics as maigret):

* ``status_code``  - any 2xx answer means the profile exists.
* ``message``      - body must not contain any ``absence`` string and, when
  ``presence`` strings are given, must contain at least one of them.
* ``response_url`` - redirects are NOT followed; a 2xx answer means it exists
  (a redirect to a "not found" page means it does not).
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable

import httpx

from . import net, profiles
from .models import FOUND, MISSING, UNKNOWN, Hit
from .sites import Site

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36"
)
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,40}$")
MAX_BODY = 300_000
DEFAULT_CONCURRENCY = 50
DEFAULT_TIMEOUT = 10.0

# Strings that mean "we were blocked", regardless of the site.
GENERIC_BLOCK_MARKERS = (
    "Attention Required! | Cloudflare",
    "cf-browser-verification",
    "Just a moment...",
    "Access denied | ",
    "Checking your browser before accessing",
)


def username_valid(username: str) -> bool:
    return bool(USERNAME_RE.match(username))


def classify(site: Site, status: int, body: str) -> tuple[str, str]:
    """Turn an HTTP answer into ``(status, detail)``. Unsure answers are UNKNOWN."""
    if status == 429:
        return UNKNOWN, "rate limited (429)"
    if status >= 500:
        return UNKNOWN, f"server error (HTTP {status})"
    if status in (401, 403) and not site.ignore403:
        return UNKNOWN, f"blocked (HTTP {status})"

    if site.check_type in ("status_code", "response_url"):
        if 200 <= status < 300:
            return FOUND, f"HTTP {status}"
        return MISSING, f"HTTP {status}"

    # message
    for marker, label in site.errors.items():
        if marker and marker in body:
            return UNKNOWN, f"site error: {label}"
    for marker in GENERIC_BLOCK_MARKERS:
        if marker in body:
            return UNKNOWN, "bot protection page"
    if any(s in body for s in site.absence):
        return MISSING, "absence marker present"
    if site.presence:
        if any(s in body for s in site.presence):
            return FOUND, "presence marker found"
        return MISSING, "presence marker missing"
    return FOUND, "no absence marker"


async def check_site(
    client: httpx.AsyncClient, site: Site, username: str, retries: int = 1,
    fetch_profiles: bool = True,
) -> Hit:
    """Check one site. Never raises."""
    profile = site.profile_url(username)
    if not site.accepts(username):
        return Hit(site.name, profile, MISSING, "username format not valid for this site")
    follow = site.check_type != "response_url"
    attempt = 0
    while True:
        try:
            resp = await client.get(
                site.request_url(username),
                headers={**site.headers} or None,
                follow_redirects=follow,
            )
            body = resp.text[:MAX_BODY]
            status, detail = classify(site, resp.status_code, body)
            details = {}
            if status == FOUND and fetch_profiles:
                details = await profiles.get_profile(
                    client, site.name, username, resp.headers.get("content-type", ""), body)
            return Hit(site.name, profile, status, detail, details)
        except httpx.TimeoutException:
            if attempt < retries:
                attempt += 1
                continue
            return Hit(site.name, profile, UNKNOWN, "timeout")
        except httpx.TransportError as e:
            if attempt < retries:
                attempt += 1
                continue
            return Hit(site.name, profile, UNKNOWN, f"connection error ({type(e).__name__})")
        except Exception as e:  # never let one site crash the scan
            return Hit(site.name, profile, UNKNOWN, f"error ({type(e).__name__})")


def new_client(timeout: float = DEFAULT_TIMEOUT, concurrency: int = DEFAULT_CONCURRENCY) -> httpx.AsyncClient:
    return net.async_client(
        timeout=timeout,
        headers={"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.9"},
        limits=httpx.Limits(max_connections=concurrency * 2, max_keepalive_connections=concurrency),
        verify=True,
    )


async def scan(
    username: str,
    sites: list[Site],
    results: list[Hit] | None = None,
    on_hit: Callable[[Hit, int, int], None] | None = None,
    *,
    concurrency: int = DEFAULT_CONCURRENCY,
    timeout: float = DEFAULT_TIMEOUT,
    client: httpx.AsyncClient | None = None,
) -> list[Hit]:
    """Search ``username`` on every site concurrently.

    ``results`` is appended to as answers arrive, so a cancelled scan (Ctrl-C)
    still leaves the partial results with the caller. ``on_hit(hit, done, total)``
    is called after each site.
    """
    results = results if results is not None else []
    sem = asyncio.Semaphore(concurrency)
    own_client = client is None
    client = client or new_client(timeout, concurrency)
    total = len(sites)

    async def run(site: Site) -> None:
        async with sem:
            hit = await check_site(client, site, username)
        results.append(hit)
        if on_hit:
            on_hit(hit, len(results), total)

    tasks = [asyncio.ensure_future(run(s)) for s in sites]
    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise
    finally:
        if own_client:
            await client.aclose()
    return results
