"""Site loading and the maigret pruning rules in scripts/update_sites.py."""

import json
import sys
from pathlib import Path

import pytest

from osint import sites as sites_mod
from osint.sites import SiteListError, load_sites, site_from_dict

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import update_sites  # noqa: E402


# ---- loader -------------------------------------------------------------

def write(tmp_path, payload) -> Path:
    p = tmp_path / "sites.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


def test_bundled_list_loads_and_is_large():
    sites = load_sites()
    assert len(sites) >= 400
    assert len({s.name for s in sites}) == len(sites)
    assert all("{username}" in s.url for s in sites)
    assert {s.check_type for s in sites} <= sites_mod.CHECK_TYPES


def test_load_minimal(tmp_path):
    p = write(tmp_path, {"sites": [{"name": "A", "url": "https://a.test/{username}"}]})
    (site,) = load_sites(p)
    assert site.check_type == "status_code" and site.profile_url("bob") == "https://a.test/bob"


@pytest.mark.parametrize("payload,fragment", [
    ({"sites": []}, "no 'sites'"),
    ({}, "no 'sites'"),
    ({"sites": ["x"]}, "not an object"),
    ({"sites": [{"name": "A", "url": "https://a.test/"}]}, "required"),
    ({"sites": [{"name": "A", "url": "https://a.test/{username}", "check_type": "magic"}]}, "unsupported"),
    ({"sites": [{"name": "A", "url": "https://a.test/{username}", "check_type": "message"}]}, "presence or absence"),
    ({"sites": [{"name": "A", "url": "https://a/{username}"}, {"name": "A", "url": "https://b/{username}"}]}, "twice"),
])
def test_load_rejects_bad_entries(tmp_path, payload, fragment):
    with pytest.raises(SiteListError, match=fragment):
        load_sites(write(tmp_path, payload))


def test_load_missing_and_invalid_json(tmp_path):
    with pytest.raises(SiteListError, match="not found"):
        load_sites(tmp_path / "nope.json")
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(SiteListError, match="valid JSON"):
        load_sites(bad)


def test_site_accepts_uses_regex_check():
    s = site_from_dict({"name": "A", "url": "https://a/{username}", "regex_check": "^[a-z]+$"})
    assert s.accepts("abc") and not s.accepts("ab1")


def test_bundled_list_has_no_adult_sites():
    names = " ".join(s.name.lower() for s in load_sites())
    for word in ("porn", "xvideos", "xnxx", "onlyfans", "chaturbate"):
        assert word not in names


# ---- pruning rules ------------------------------------------------------

def maigret(**kw) -> dict:
    base = {"url": "https://x.test/{username}", "checkType": "status_code", "alexaRank": 100,
            "usernameClaimed": "blue", "usernameUnclaimed": "zzz", "tags": ["social"]}
    base.update(kw)
    return base


@pytest.mark.parametrize("overrides", [
    {"disabled": True},
    {"tags": ["porn"]},
    {"tags": ["dating"]},
    {"protection": ["cf_js_challenge"]},
    {"requestMethod": "POST"},
    {"requestPayload": {"a": 1}},
    {"activation": {"method": "x"}},
    {"type": "steam_id"},
    {"checkType": None},
    {"checkType": "message"},  # message without any marker strings
    {"url": "https://x.test/profile"},  # no {username}
])
def test_usable_rejects(overrides):
    site = maigret(**overrides)
    if overrides.get("checkType", 1) is None:
        site.pop("checkType")
    assert not update_sites.usable("X", site)


def test_usable_accepts_plain_and_message_with_markers():
    assert update_sites.usable("X", maigret())
    assert update_sites.usable("X", maigret(checkType="message", absenceStrs=["not found"]))
    assert update_sites.usable("X", maigret(checkType="response_url"))


def test_convert_expands_placeholders_and_renames_keys():
    raw = maigret(url="{urlMain}{urlSubpath}/u/{username}", urlMain="https://x.test", urlSubpath="/forum",
                  urlProbe="{urlMain}/api/{username}", presenseStrs=["ok"], regexCheck="^a+$",
                  headers={"h": "v"}, ignore403=True)
    out = update_sites.convert("X", raw)
    assert out["url"] == "https://x.test/forum/u/{username}"
    assert out["url_probe"] == "https://x.test/api/{username}"
    assert out["presence"] == ["ok"] and out["regex_check"] == "^a+$"
    assert out["headers"] == {"h": "v"} and out["ignore403"] is True
    assert out["claimed"] == "blue" and out["rank"] == 100


def test_build_orders_by_rank_applies_limit_and_blocklist():
    data = {"engines": {}, "sites": {
        "C": maigret(alexaRank=300), "A": maigret(alexaRank=10), "B": maigret(alexaRank=20),
        "D": maigret(alexaRank=5, disabled=True),
    }}
    assert [s["name"] for s in update_sites.build(data, 10, set())] == ["A", "B", "C"]
    assert [s["name"] for s in update_sites.build(data, 2, set())] == ["A", "B"]
    assert [s["name"] for s in update_sites.build(data, 10, {"B"})] == ["A", "C"]


def test_build_expands_engine_templates():
    data = {
        "engines": {"Forum": {"site": {"checkType": "message", "absenceStrs": ["gone"],
                                       "url": "{urlMain}/u/{username}"}}},
        "sites": {"F": {"engine": "Forum", "urlMain": "https://f.test", "alexaRank": 50,
                        "usernameClaimed": "a", "usernameUnclaimed": "b", "tags": ["forum"]}},
    }
    (out,) = update_sites.build(data, 10, set())
    assert out["url"] == "https://f.test/u/{username}" and out["absence"] == ["gone"]


def test_build_tops_up_with_unranked_standalone_sites():
    unranked = maigret()
    unranked.pop("alexaRank")
    data = {"engines": {}, "sites": {"R": maigret(alexaRank=9), "U": unranked, "T": {**unranked, "tags": ["porn"]}}}
    names = [s["name"] for s in update_sites.build(data, 10, set())]
    assert names == ["R", "U"]
    assert [s["name"] for s in update_sites.build(data, 10, set(), fill_unranked=False)] == ["R"]


def test_blocklist_parsing(tmp_path):
    p = tmp_path / "bl.txt"
    p.write_text("Foo  # false positive\n\n# comment only\nBar\n")
    assert update_sites.load_blocklist(p) == {"Foo", "Bar"}
    assert update_sites.load_blocklist(tmp_path / "none.txt") == set()


def test_bundled_list_respects_blocklist():
    blocked = update_sites.load_blocklist()
    assert blocked  # validation produced a blocklist
    assert not blocked & {s.name for s in load_sites()}
