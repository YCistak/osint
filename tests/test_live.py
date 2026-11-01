"""Smoke tests that touch the real internet. Run with: python -m pytest -m live"""

import asyncio

import pytest

from osint import domainscan, username
from osint.models import FOUND, MISSING
from osint.sites import load_sites

pytestmark = pytest.mark.live

NONSENSE = "zq8xkv3pp91wwq7"


def _scan(name, names):
    sites = [s for s in load_sites() if s.name in names]
    assert sites, "expected sites missing from sites.json"
    return {h.name: h for h in asyncio.run(username.scan(name, sites))}


def test_github_torvalds_found():
    hits = _scan("torvalds", {"GitHub"})
    assert hits["GitHub"].status == FOUND, hits["GitHub"]


def test_nonsense_name_not_found_on_github():
    hits = _scan(NONSENSE, {"GitHub"})
    assert hits["GitHub"].status == MISSING


def test_full_list_has_no_false_positives_for_nonsense_name():
    hits = asyncio.run(username.scan(NONSENSE, load_sites()))
    assert [h.name for h in hits if h.status == FOUND] == []


def test_example_com_dns():
    records = domainscan.dns_lookup("example.com")
    assert records["A"], records


# ---- 0.4 features ------------------------------------------------------------------

def test_pwned_passwords_known_password():
    from osint import password

    assert password.check("password123") > 1000


def test_internetdb_cloudflare_dns():
    from osint import domainsec, net

    client = net.sync_client(timeout=15.0)
    data = domainsec.internetdb_lookup("1.1.1.1", client)
    assert data and 443 in data["ports"]


def test_tls_certificate_example_com():
    from osint import domainsec

    body = domainsec.tls_certificate("example.com")
    assert "Issuer" in body["items"] and "day(s)" in body["items"]["Time left"]


def test_wayback_example_com():
    from osint import domainsec

    items = domainsec.wayback_summary("example.com")["items"]
    assert items["First snapshot"] < items["Last snapshot"]


def test_email_security_google():
    from osint import domainsec

    rows = {r[0]: r for r in domainsec.email_security("google.com")["rows"]}
    assert rows["SPF"][1] != "-" and rows["DMARC"][1] != "-"


def test_github_deep_torvalds():
    from osint import github

    res = github.analyze("torvalds")
    assert "Repositories" in res.sections and "Emails in public commits" in res.sections
    assert res.sections["Profile"]["items"]["Login"] == "torvalds"


def test_variations_generation():
    from osint import variations

    assert "torvalds1" in variations.generate("torvalds")
