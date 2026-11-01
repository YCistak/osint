"""Username variations: generation rules, merging of hits, CLI flag and REPL toggle."""

import io

import pytest
from rich.console import Console

from osint import cli, repl, runner, variations
from osint.models import FOUND, MISSING, Hit, ScanResult
from osint.sites import Site


def test_split_tokens():
    assert variations.split_tokens("john.doe") == ["john", "doe"]
    assert variations.split_tokens("JaneDoe_99") == ["jane", "doe", "99"]
    assert variations.split_tokens("torvalds") == ["torvalds"]
    assert variations.split_tokens("..--") == []


def test_generate_single_word():
    out = variations.generate("torvalds", year=2026)
    assert out == ["torvalds_", "_torvalds", "torvalds.", "torvalds1", "torvalds123", "torvalds2026", "torvalds_26"]


def test_generate_two_words_is_capped_and_unique():
    out = variations.generate("john.doe", year=2026)
    assert len(out) == variations.MAX_VARIANTS
    assert out[:4] == ["johndoe", "john_doe", "john-doe", "jdoe"]
    assert "john.doe" not in out
    assert len({v.lower() for v in out}) == len(out)


def test_generate_limit_and_validity():
    assert len(variations.generate("john.doe", limit=3)) == 3
    for v in variations.generate("a_b-c", year=2026):
        from osint.username import username_valid

        assert username_valid(v)
    assert variations.generate("--") == []


def test_generate_uses_current_year_by_default():
    from datetime import datetime

    assert any(str(datetime.now().year) in v for v in variations.generate("zed"))


def test_merge_dedupes_by_url_and_keeps_only_found():
    base = [Hit("GitHub", "https://github.com/Jane", FOUND), Hit("Reddit", "https://reddit.com/u/jane", MISSING)]
    extra = [
        ("jane1", [Hit("GitHub", "https://github.com/jane", FOUND),      # same URL, different case
                   Hit("Reddit", "https://reddit.com/u/jane1", FOUND),
                   Hit("Twitter", "https://x.com/jane1", MISSING)]),
        ("jane_", [Hit("Reddit", "https://reddit.com/u/jane1", FOUND)]),  # already merged
    ]
    merged = runner.merge_variation_hits(base, extra)
    assert [(h.name, h.url) for h in merged] == [
        ("GitHub", "https://github.com/Jane"), ("Reddit", "https://reddit.com/u/jane"),
        ("Reddit", "https://reddit.com/u/jane1")]
    assert merged[-1].detail == "variant: jane1" and merged[-1].status == FOUND


def test_run_variations_lists_variants_first_and_merges(monkeypatch):
    calls = []

    def fake(name, sites, console, **kw):
        calls.append(name)
        r = ScanResult("username", name)
        r.hits = [Hit("Demo", f"https://demo.test/{name}", FOUND if name in ("jane", "jane1") else MISSING)]
        return r

    monkeypatch.setattr(runner, "run_username", fake)
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, width=120, highlight=False)
    res = runner.run_username_variations("jane", [], console, names=["jane1", "jane_"])
    assert calls == ["jane", "jane1", "jane_"]
    assert buf.getvalue().startswith("[*] variations (2): jane1, jane_")
    assert sorted(h.url for h in res.hits if h.status == FOUND) == ["https://demo.test/jane", "https://demo.test/jane1"]
    assert "Variations scanned: jane1, jane_" in res.notes[0]


def test_run_variations_stops_when_cancelled(monkeypatch):
    calls = []

    def fake(name, sites, console, **kw):
        calls.append(name)
        r = ScanResult("username", name)
        r.cancelled = name == "jane"
        return r

    monkeypatch.setattr(runner, "run_username", fake)
    res = runner.run_username_variations("jane", [], Console(file=io.StringIO()), names=["a1", "b1"])
    assert calls == ["jane"] and res.cancelled


def test_cli_variations_flag_uses_variation_runner(monkeypatch, capsys):
    used = []

    def fake(name, sites, console, **kw):
        used.append(name)
        return ScanResult("username", name)

    monkeypatch.setattr(runner, "run_username_variations", fake)
    assert cli.build_parser().parse_args(["username", "x", "--variations"]).variations is True
    assert cli.main(["username", "jane", "--variations", "--json"]) == 0
    assert used == ["jane"]


def make_session():
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, width=120, highlight=False)
    return repl.Session(console, [Site("Demo", "https://demo.test/{username}")]), buf


def test_repl_toggle_and_dash_v(monkeypatch):
    used = []
    monkeypatch.setattr(runner, "run_username_variations",
                        lambda name, *a, **k: used.append(("var", name)) or ScanResult("username", name))
    monkeypatch.setattr(runner, "run_username",
                        lambda name, *a, **k: used.append(("plain", name)) or ScanResult("username", name))
    s, buf = make_session()
    repl.execute(s, "username jane")
    repl.execute(s, "username jane -v")
    repl.execute(s, "variations on")
    repl.execute(s, "username jane")
    repl.execute(s, "variations off")
    repl.execute(s, "variations")
    repl.execute(s, "variations maybe")
    assert used == [("plain", "jane"), ("var", "jane"), ("var", "jane")]
    assert "variations: off" in buf.getvalue() and "usage: variations on|off" in buf.getvalue()


def test_completion_for_variations_and_username_flag():
    s, _ = make_session()
    assert repl.completion_candidates(s, "variations o") == ["on", "off"]
    assert "--variations" in repl.completion_candidates(s, "username jane --v")
    assert "variations" in repl.completion_candidates(s, "var")
