"""Email recon: source parsers with canned responses, state -> sections, module selection."""

import asyncio
import hashlib

import httpx
import pytest

from osint import emailscan as es
from osint.models import FOUND, MISSING, UNKNOWN, Hit


def client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


# ---- validation / helpers -----------------------------------------------

def test_email_valid_and_local_part():
    assert es.email_valid("jane.doe+tag@example.co.uk")
    for bad in ["", "no-at.com", "a@b", "a b@c.com", "@x.com"]:
        assert not es.email_valid(bad)
    assert es.local_part("jane.doe@example.com") == "jane.doe"


# ---- XposedOrNot --------------------------------------------------------

def test_parse_xposed_check_flattens_groups():
    assert es.parse_xposed_check(200, {"breaches": [["Adobe", "LinkedIn"]], "email": "x"}) == ["Adobe", "LinkedIn"]


def test_parse_xposed_check_404_means_clean():
    assert es.parse_xposed_check(404, {"Error": "Not found"}) == []


@pytest.mark.parametrize("status,payload", [(429, None), (500, None), (200, "garbage")])
def test_parse_xposed_check_unknown(status, payload):
    assert es.parse_xposed_check(status, payload) is None


def test_parse_xposed_analytics():
    payload = {
        "BreachMetrics": {"risk": [{"risk_label": "High", "risk_score": 80}],
                          "passwords_strength": [{"EasyToCrack": 2, "PlainText": 0, "StrongHash": 5}]},
        "ExposedBreaches": {"breaches_details": [
            {"breach": "Adobe", "xposed_date": "2013", "xposed_records": 152000000,
             "xposed_data": "Email addresses;Passwords", "domain": "adobe.com"}]},
    }
    out = es.parse_xposed_analytics(payload)
    assert out["risk"] == "High" and out["score"] == 80
    assert out["passwords"] == {"EasyToCrack": 2, "StrongHash": 5}  # zero counts dropped
    assert out["details"][0] == {"breach": "Adobe", "date": "2013", "records": 152000000,
                                 "data": "Email addresses, Passwords", "domain": "adobe.com"}


def test_parse_xposed_analytics_tolerates_garbage():
    assert es.parse_xposed_analytics(None)["details"] == []
    assert es.parse_xposed_analytics({"BreachMetrics": {"risk": "x"}})["risk"] == ""


def test_fetch_xposed_with_mock_transport():
    seen = []

    def handler(request):
        seen.append(request.url.path)
        if request.url.path.startswith("/v1/check-email/"):
            return httpx.Response(200, json={"breaches": [["Adobe"]]})
        return httpx.Response(200, json={"BreachMetrics": {"risk": [{"risk_label": "Low", "risk_score": 10}]}})

    state = es.EmailState("a@b.com")

    async def go():
        async with client(handler) as c:
            await es.fetch_xposed(c, state)

    asyncio.run(go())
    assert state.breaches == ["Adobe"] and state.analytics["risk"] == "Low"
    assert seen[0] == "/v1/check-email/a@b.com" and seen[1] == "/v1/breach-analytics"


def test_fetch_xposed_network_error_leaves_unknown():
    def handler(request):
        raise httpx.ConnectError("down", request=request)

    state = es.EmailState("a@b.com")

    async def go():
        async with client(handler) as c:
            await es.fetch_xposed(c, state)

    asyncio.run(go())
    assert state.breaches is None


# ---- Gravatar -----------------------------------------------------------

def test_parse_gravatar():
    payload = {"entry": [{"displayName": "Jane", "preferredUsername": "jane",
                          "profileUrl": "https://gravatar.com/jane", "currentLocation": "Paris",
                          "aboutMe": "hi", "accounts": [{"shortname": "github", "url": "https://github.com/jane"}]}]}
    p = es.parse_gravatar(payload)
    assert p["Name"] == "Jane" and p["Profile"] == "https://gravatar.com/jane"
    assert p["Linked accounts"] == "github: https://github.com/jane"
    assert es.parse_gravatar("User not found") is None
    assert es.parse_gravatar({"entry": []}) is None


def test_fetch_gravatar_hashes_lowercased_email_with_sha256():
    seen = []

    def handler(request):
        seen.append(request.url.path)
        return httpx.Response(404, text="User not found")

    state = es.EmailState("Jane.Doe@Example.com")

    async def go():
        async with client(handler) as c:
            await es.fetch_gravatar(c, state)

    asyncio.run(go())
    expected = hashlib.sha256(b"jane.doe@example.com").hexdigest()
    assert seen == [f"/{expected}.json"] and state.gravatar is None and state.gravatar_checked


# ---- GitHub -------------------------------------------------------------

def test_parse_github_search_users():
    payload = {"total_count": 1, "items": [{"login": "jane", "html_url": "https://github.com/jane", "type": "User"}]}
    users, note = es.parse_github_search(200, payload, "5")
    assert users == [{"login": "jane", "url": "https://github.com/jane", "type": "User"}] and note == ""


def test_parse_github_search_empty_is_not_unknown():
    users, _ = es.parse_github_search(200, {"total_count": 0, "items": []}, "9")
    assert users == []


@pytest.mark.parametrize("status,remaining", [(403, "0"), (429, None), (200, "0")])
def test_parse_github_search_rate_limit(status, remaining):
    users, note = es.parse_github_search(status, {"items": []}, remaining)
    assert users is None and "rate limit" in note


def test_fetch_github_query_uses_in_email():
    seen = []

    def handler(request):
        seen.append(request.url.params["q"])
        return httpx.Response(200, json={"items": []}, headers={"x-ratelimit-remaining": "3"})

    state = es.EmailState("jane@example.com")

    async def go():
        async with client(handler) as c:
            await es.fetch_github(c, state)

    asyncio.run(go())
    assert seen == ["jane@example.com in:email"] and state.github == []


# ---- MX -----------------------------------------------------------------

def test_parse_mx_sorts_by_priority():
    assert es.parse_mx(["20 b.example.com.", "10 A.example.com.", "junk"]) == [
        (10, "a.example.com"), (20, "b.example.com")]


@pytest.mark.parametrize("hosts,expected", [
    (["aspmx.l.google.com"], "Google Workspace / Gmail"),
    (["example-com.mail.protection.outlook.com"], "Microsoft 365 / Outlook"),
    (["mail.protonmail.ch"], "Proton Mail"),
    (["mx.selfhosted.net"], ""),
    (["evilgoogle.com"], ""),  # suffix must match on a label boundary
])
def test_detect_provider(hosts, expected):
    assert es.detect_provider(hosts) == expected


def test_lookup_mx_with_fake_resolver(monkeypatch):
    import dns.resolver

    class FakeResolver:
        lifetime = 0

        def resolve(self, name, rtype):
            if name == "gone.test":
                raise dns.resolver.NXDOMAIN()
            return [type("R", (), {"to_text": lambda s: "10 aspmx.l.google.com."})()]

    monkeypatch.setattr(dns.resolver, "Resolver", FakeResolver)
    assert es.lookup_mx("example.test") == ([(10, "aspmx.l.google.com")], "")
    records, note = es.lookup_mx("gone.test")
    assert records == [] and "NXDOMAIN" in note


# ---- holehe -------------------------------------------------------------

def test_holehe_to_hit_statuses():
    assert es.holehe_to_hit({"name": "a", "domain": "a.com", "exists": True}).status == FOUND
    assert es.holehe_to_hit({"name": "a", "domain": "a.com", "exists": False}).status == MISSING
    hit = es.holehe_to_hit({"name": "a", "domain": "a.com", "exists": False, "rateLimit": True})
    assert hit.status == UNKNOWN  # rateLimit trumps "exists"


def test_holehe_to_hit_carries_recovery_details():
    hit = es.holehe_to_hit({"name": "a", "domain": "a.com", "exists": True,
                            "emailrecovery": "j***@x.com", "phoneNumber": "0612"})
    assert "j***@x.com" in hit.detail and "0612" in hit.detail


def test_load_modules_filters():
    default, skipped = es.load_modules()
    names = {m.__name__ for m in default}
    assert not names & es.PASSWORD_RESET_MODULES
    assert not names & {"pornhub", "redtube", "xnxx", "xvideos"}
    assert skipped > 0
    unsafe, _ = es.load_modules(unsafe=True)
    assert {m.__name__ for m in unsafe} >= es.PASSWORD_RESET_MODULES
    assert len(unsafe) == len(default) + len(es.PASSWORD_RESET_MODULES)


def test_run_holehe_marks_crashing_and_silent_modules_unknown():
    async def good(email, client, out):
        out.append({"name": "good", "domain": "good.com", "exists": True})

    async def silent(email, client, out):
        pass

    async def crashing(email, client, out):
        raise RuntimeError("boom")

    state = es.EmailState("a@b.com")
    seen = []
    es.scan("a@b.com", state, lambda h, d, t: seen.append((h.name, d, t)),
            modules=[good, silent, crashing], module_timeout=2.0)
    by_name = {h.name: h.status for h in state.accounts}
    assert by_name == {"good": FOUND, "silent": UNKNOWN, "crashing": UNKNOWN}
    assert len(seen) == 3 and all(t == 3 for _, _, t in seen)


# ---- state -> sections ----------------------------------------------------

def full_state() -> es.EmailState:
    st = es.EmailState("jane@example.com")
    st.accounts = [Hit("Spotify", "spotify.com", FOUND, "recovery email: j***@x.com"),
                   Hit("Imgur", "imgur.com", MISSING), Hit("Nike", "nike.com", UNKNOWN, "rate limited")]
    st.breaches = ["Adobe", "LinkedIn"]
    st.analytics = {"risk": "High", "score": 80, "passwords": {"PlainText": 1},
                    "details": [{"breach": "Adobe", "date": "2013", "records": 5, "data": "Passwords", "domain": ""}]}
    st.gravatar = {"Name": "Jane", "Profile": "https://gravatar.com/jane"}
    st.github = [{"login": "jane", "url": "https://github.com/jane", "type": "User"}]
    st.mx = [(10, "aspmx.l.google.com")]
    return st


def test_state_builds_grouped_sections_in_order():
    res = full_state().to_result()
    assert list(res.sections) == ["Breaches", "Registered accounts", "Profiles", "Mail server"]
    breaches = res.sections["Breaches"]
    assert breaches["summary"]["Risk"] == "High (80/100)" and len(breaches["rows"]) == 2
    assert breaches["rows"][0][:2] == ["Adobe", "2013"]
    accounts = res.sections["Registered accounts"]
    assert [r[0] for r in accounts["rows"]] == ["Spotify"]  # only found ones listed
    assert "3 services checked, 1 registered, 1 unknown" in accounts["footer"]
    assert res.sections["Profiles"]["items"]["GitHub"].startswith("jane")
    assert res.sections["Mail server"]["items"]["Provider"] == "Google Workspace / Gmail"


def test_state_adds_username_tip():
    res = full_state().to_result()
    assert any("username jane" in n for n in res.notes)


def test_state_handles_nothing_found():
    st = es.EmailState("x@example.com")
    st.breaches = []
    st.github = []
    st.mx_note = ""
    res = st.to_result()
    assert "No known breaches" in res.sections["Breaches"]["text"]
    assert "No public profile" in res.sections["Profiles"]["text"]
    assert "cannot receive mail" in res.sections["Mail server"]["text"]


def test_state_breach_check_failed_is_stated():
    st = es.EmailState("x@example.com")
    assert "Could not check" in st.to_result().sections["Breaches"]["text"]
