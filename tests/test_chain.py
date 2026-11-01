"""Chained username scans from email results."""

import io

from rich.console import Console

from osint import cli, emailscan, repl, runner
from osint.models import FOUND, MISSING, Hit, ScanResult
from osint.sites import Site


def state(**kw):
    st = emailscan.EmailState("Jane.Doe@example.com")
    for k, v in kw.items():
        setattr(st, k, v)
    return st


def test_discovered_usernames_ordered_deduped_and_validated():
    st = state(github=[{"login": "janedoe", "url": "u", "type": "User"}],
               gravatar={"Username": "JaneDoe"})
    assert st.discovered_usernames() == ["janedoe", "Jane.Doe"]  # gravatar dup (case-insensitive) dropped
    assert state().discovered_usernames() == ["Jane.Doe"]
    assert state(email="a+tag@x.com").discovered_usernames() == []  # '+' is not a valid username char
    assert state(github=[{"login": "bad name", "url": "u"}]).to_result().usernames == ["Jane.Doe"]


def fake_username(name, sites, console, **kw):
    r = ScanResult("username", name)
    r.hits = [Hit("GitHub", f"https://github.com/{name}", FOUND), Hit("X", "u", MISSING)]
    return r


def test_run_chain_adds_sections_and_chained(monkeypatch):
    monkeypatch.setattr(runner, "run_username", fake_username)
    parent = ScanResult("email", "a@b.com", usernames=["a", "b"])
    res = runner.run_chain(parent, [], Console(file=io.StringIO()))
    assert [r.target for r in res] == ["a", "b"] and parent.chained == res
    assert "Username scan: a" in parent.sections
    d = parent.to_dict()
    assert d["discovered_usernames"] == ["a", "b"] and len(d["chained"]) == 2


def make_session():
    buf = io.StringIO()
    s = repl.Session(Console(file=buf, force_terminal=False, width=120, highlight=False), [Site("D", "https://d.test/{username}")])
    return s, buf


def email_result():
    return ScanResult("email", "a@b.com", usernames=["alice", "a"])


def test_repl_prompt_yes_runs_chain_and_prints_summary(monkeypatch):
    s, buf = make_session()
    asked = []
    s.ask = lambda p: (asked.append(p), "y")[1]
    monkeypatch.setattr(runner, "run_email", lambda *a, **k: email_result())
    monkeypatch.setattr(runner, "run_username", fake_username)
    repl.execute(s, "email a@b.com")
    out = buf.getvalue()
    assert asked == ["Scan these usernames? [y/N] "]
    assert "usernames discovered: alice, a" in out and "Combined summary" in out
    assert "2 accounts found across 2 usernames" in out


def test_repl_prompt_default_is_no(monkeypatch):
    s, buf = make_session()
    for answer in ("", "n", "maybe"):
        s.ask = lambda p, a=answer: a
        monkeypatch.setattr(runner, "run_email", lambda *a, **k: email_result())
        monkeypatch.setattr(runner, "run_chain", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not run")))
        repl.execute(s, "email a@b.com")
    assert "Combined summary" not in buf.getvalue()


def test_ask_yes_no_is_no_without_a_terminal(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("y\n"))
    assert repl.ask_yes_no("? ") == "n"


def test_no_prompt_when_nothing_discovered(monkeypatch):
    s, buf = make_session()
    s.ask = lambda p: (_ for _ in ()).throw(AssertionError("must not ask"))
    monkeypatch.setattr(runner, "run_email", lambda *a, **k: ScanResult("email", "a@b.com"))
    repl.execute(s, "email a@b.com")


def test_cli_chain_flag_runs_automatically_and_json_includes_chained(monkeypatch, capsys):
    monkeypatch.setattr(runner, "run_email", lambda *a, **k: email_result())
    monkeypatch.setattr(runner, "run_username", fake_username)
    monkeypatch.setattr(cli, "load_sites", lambda *a: [Site("D", "https://d.test/{username}")])
    assert cli.main(["email", "a@b.com", "--chain", "--json"]) == 0
    import json
    data = json.loads(capsys.readouterr().out)
    assert [c["target"] for c in data["chained"]] == ["alice", "a"]
    assert cli.main(["email", "a@b.com", "--chain", "--no-banner"]) == 0
    assert "Combined summary" in capsys.readouterr().out
    assert cli.main(["email", "a@b.com", "--no-banner"]) == 0
    assert "Combined summary" not in capsys.readouterr().out
