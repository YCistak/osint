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
