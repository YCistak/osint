"""Username engine: maigret check types against httpx MockTransport."""

import asyncio

import httpx
import pytest

from osint import username
from osint.models import FOUND, MISSING, UNKNOWN
from osint.sites import Site


def site(**kw) -> Site:
    base = dict(name="Demo", url="https://demo.test/{username}")
    base.update(kw)
    return Site(**base)


def client_for(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def check(s: Site, handler, name="alice", **kw):
    async def go():
        async with client_for(handler) as c:
            return await username.check_site(c, s, name, **kw)

    return asyncio.run(go())


# ---- classify ---------------------------------------------------------

@pytest.mark.parametrize("status,expected", [
    (200, FOUND), (204, FOUND), (404, MISSING), (410, MISSING), (302, MISSING),
    (429, UNKNOWN), (403, UNKNOWN), (401, UNKNOWN), (500, UNKNOWN), (503, UNKNOWN),
])
def test_status_code(status, expected):
    assert username.classify(site(check_type="status_code"), status, "")[0] == expected


def test_ignore403_treats_403_as_normal_answer():
    s = site(check_type="status_code", ignore403=True)
    assert username.classify(s, 403, "")[0] == MISSING


def test_message_absence_string_means_missing():
    s = site(check_type="message", absence=("User not found",))
    assert username.classify(s, 200, "<p>User not found</p>")[0] == MISSING
    assert username.classify(s, 200, "<h1>alice</h1>")[0] == FOUND


def test_message_presence_string_required_when_given():
    s = site(check_type="message", presence=("og:title",), absence=("nope",))
    assert username.classify(s, 200, '<meta property="og:title">')[0] == FOUND
    assert username.classify(s, 200, "empty page")[0] == MISSING


def test_message_absence_wins_over_presence():
    s = site(check_type="message", presence=("profile",), absence=("deleted",))
    assert username.classify(s, 200, "profile deleted")[0] == MISSING


def test_message_site_specific_error_is_unknown():
    s = site(check_type="message", absence=("x",), errors={"captcha": "Captcha required"})
    status, detail = username.classify(s, 200, "please solve the captcha")
    assert status == UNKNOWN and "Captcha" in detail


def test_message_generic_bot_wall_is_unknown():
    s = site(check_type="message", absence=("x",))
    assert username.classify(s, 200, "<title>Just a moment...</title>")[0] == UNKNOWN


def test_message_works_on_404_pages_too():
    s = site(check_type="message", presence=("profile",))
    assert username.classify(s, 404, "profile")[0] == FOUND


# ---- check_site -------------------------------------------------------

def test_check_site_status_code_found_and_url():
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(200)

    hit = check(site(), handler)
    assert hit.status == FOUND and hit.url == "https://demo.test/alice"
    assert seen == ["https://demo.test/alice"]


def test_check_site_uses_url_probe_but_reports_profile_url():
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(200, json={"id": 1})

    s = site(url_probe="https://api.demo.test/users/{username}")
    hit = check(s, handler)
    assert seen == ["https://api.demo.test/users/alice"]
    assert hit.url == "https://demo.test/alice"


def test_check_site_sends_custom_headers():
    def handler(request):
        assert request.headers["x-token"] == "abc"
        return httpx.Response(200)

    assert check(site(headers={"x-token": "abc"}), handler).status == FOUND


def test_response_url_does_not_follow_redirects():
    def handler(request):
        if request.url.path == "/alice":
            return httpx.Response(302, headers={"location": "https://demo.test/404"})
        return httpx.Response(200)

    hit = check(site(check_type="response_url"), handler)
    assert hit.status == MISSING  # a redirect means "no such user"


def test_status_code_follows_redirects():
    def handler(request):
        if request.url.path == "/alice":
            return httpx.Response(301, headers={"location": "https://demo.test/Alice"})
        return httpx.Response(200)

    assert check(site(), handler).status == FOUND


def test_regex_check_skips_request_for_invalid_name():
    def handler(request):  # pragma: no cover - must not be called
        raise AssertionError("request should not be sent")

    s = site(regex_check=r"^[a-z]{3,}$")
    hit = check(s, handler, name="a1")
    assert hit.status == MISSING and "not valid" in hit.detail


def test_retry_once_on_connection_error_then_success():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ConnectError("boom", request=request)
        return httpx.Response(200)

    hit = check(site(), handler)
    assert hit.status == FOUND and calls["n"] == 2


def test_connection_error_twice_is_unknown():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        raise httpx.ConnectError("boom", request=request)

    hit = check(site(), handler)
    assert hit.status == UNKNOWN and calls["n"] == 2 and "ConnectError" in hit.detail


def test_timeout_is_unknown():
    def handler(request):
        raise httpx.ReadTimeout("slow", request=request)

    assert check(site(), handler).detail == "timeout"


def test_username_is_url_encoded():
    seen = []

    def handler(request):
        seen.append(request.url.raw_path.decode())
        return httpx.Response(404)

    check(site(), handler, name="a b/c")
    assert seen == ["/a%20b%2Fc"]


# ---- scan -------------------------------------------------------------

def test_scan_collects_results_and_reports_progress():
    sites = [site(name=f"S{i}", url=f"https://s{i}.test/{{username}}") for i in range(6)]

    def handler(request):
        return httpx.Response(200 if request.url.host in ("s1.test", "s3.test") else 404)

    progress = []

    async def go():
        async with client_for(handler) as c:
            return await username.scan("alice", sites, None, lambda h, d, t: progress.append((d, t)),
                                       concurrency=3, client=c)

    hits = asyncio.run(go())
    assert sorted(h.name for h in hits if h.status == FOUND) == ["S1", "S3"]
    assert [d for d, _ in progress] == [1, 2, 3, 4, 5, 6] and progress[-1] == (6, 6)


def test_scan_keeps_partial_results_when_cancelled():
    sites = [site(name=f"S{i}", url=f"https://s{i}.test/{{username}}") for i in range(4)]

    async def handler(request):
        if request.url.host == "s0.test":
            return httpx.Response(200)
        await asyncio.sleep(30)
        return httpx.Response(200)

    async def go():
        results = []
        async with client_for(handler) as c:
            task = asyncio.ensure_future(username.scan("alice", sites, results, client=c))
            await asyncio.sleep(0.3)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        return results

    results = asyncio.run(go())
    assert [h.name for h in results] == ["S0"]


def test_username_valid():
    assert username.username_valid("torvalds") and username.username_valid("a.b_c-d")
    assert not username.username_valid("") and not username.username_valid("a b")
    assert not username.username_valid("x" * 41) and not username.username_valid("../etc")
