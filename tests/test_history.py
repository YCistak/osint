"""SQLite history: recording, privacy, diffs, change line, commands, --no-history."""

import io
import json
import sqlite3

import pytest
from rich.console import Console

from osint import cli, history, historycmd, password, repl
from osint.models import FOUND, MISSING, Hit, ScanResult, table, text
from osint.sites import Site


def username_result(name="jane", found=("GitHub", "Reddit")):
    r = ScanResult("username", name)
    r.hits = [Hit(n, f"https://{n.lower()}.test/{name}", FOUND) for n in found] + [Hit("Gone", "https://g.test", MISSING)]
    return r


def email_result(addr="a@b.test", breaches=("Adobe",), found=("Spotify",)):
    r = ScanResult("email", addr)
    r.hits = [Hit(n, "x.test", FOUND) for n in found]
    if breaches:
        r.sections["Breaches"] = table(["Breach", "Year"], [[b, "2013"] for b in breaches])
    return r


def test_db_path_respects_xdg(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    assert history.db_path() == tmp_path / "data" / "osint" / "history.db"
    assert history.record(username_result()) == 1
    assert (tmp_path / "data" / "osint" / "history.db").is_file()


def test_summarize_username_and_email():
    s = history.summarize(username_result())
    assert s["accounts"] == ["GitHub", "Reddit"] and s["counts"]["found"] == 2
    e = history.summarize(email_result(breaches=("Adobe", "LinkedIn")))
    assert e["breaches"] == ["Adobe", "LinkedIn"] and e["accounts"] == ["Spotify"]


def test_record_list_get_latest():
    a = history.record(username_result("jane"))
    b = history.record(username_result("JANE", found=("GitHub",)))
    assert (a, b) == (1, 2)
    assert [r["id"] for r in history.list_scans()] == [2, 1]
    assert history.get(1)["summary"]["accounts"] == ["GitHub", "Reddit"]
    assert history.get(99) is None
    assert history.latest("username", "jane")["id"] == 2  # case-insensitive
    assert history.latest("email", "jane") is None


def test_password_cancelled_and_disabled_are_never_recorded(monkeypatch):
    assert history.record(password.build_result(3, "weak")) is None
    c = username_result()
    c.cancelled = True
    assert history.record(c) is None
    monkeypatch.setattr(history, "enabled", False)
    assert history.record(username_result()) is None
    assert history.after_scan(username_result()) is None
    monkeypatch.setattr(history, "enabled", True)
    assert history.list_scans() == []


def test_diff_and_change_line():
    first = history.record(email_result(breaches=("Adobe",), found=("Spotify", "Old")))
    old = history.get(first)
    new_res = email_result(breaches=("Adobe", "LinkedIn"), found=("Spotify", "Dropbox"))
    new = {"summary": history.summarize(new_res)}
    d = history.diff(old, new)
    assert d["new_accounts"] == ["Dropbox"] and d["removed_accounts"] == ["Old"]
    assert d["new_breaches"] == ["LinkedIn"] and d["removed_breaches"] == []
    line = history.change_line(d, old["ts"])
    assert "1 new account(s): Dropbox" in line and "1 new breach(es): LinkedIn" in line and "gone: Old" in line


def test_diff_detects_fact_changes():
    a = ScanResult("domain", "x.test")
    a.sections["DNS records"] = table(["Type", "Values"], [["A", "1.1.1.1"]])
    b = ScanResult("domain", "x.test")
    b.sections["DNS records"] = table(["Type", "Values"], [["A", "2.2.2.2"]])
    i = history.record(a)
    d = history.diff(history.get(i), {"summary": history.summarize(b)})
    assert d["facts"]["DNS records"] == {"added": ["A | 2.2.2.2"], "removed": ["A | 1.1.1.1"]}
    assert "DNS records" in history.change_line(d, "2026-01-01T00:00:00")


def test_after_scan_adds_note_only_when_there_is_a_previous_scan():
    first = username_result()
    assert history.after_scan(first) is None and first.notes == []
    second = username_result(found=("GitHub", "Reddit", "Twitch"))
    line = history.after_scan(second)
    assert "1 new account(s): Twitch" in line and second.notes == [line]
    third = username_result(found=("GitHub", "Reddit", "Twitch"))
    assert history.after_scan(third).startswith("No changes since the last scan")


def test_database_errors_do_not_break_scans(tmp_path, monkeypatch):
    blocker = tmp_path / "blocked"
    blocker.write_text("not a directory")
    monkeypatch.setenv("XDG_DATA_HOME", str(blocker))
    r = username_result()
    assert history.after_scan(r) is None
    assert r.notes == []


def test_clear():
    history.record(username_result())
    history.record(username_result("bob"))
    assert history.clear() == 2 and history.list_scans() == []


# ---- history command ---------------------------------------------------------------

def run_cmd(args, answer="n", assume_yes=False):
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, width=140, highlight=False)
    code = historycmd.handle(args, console, lambda p: answer, assume_yes=assume_yes)
    return code, buf.getvalue()


def test_command_list_show_diff():
    history.record(email_result(breaches=("Adobe",), found=("Spotify",)))
    history.record(email_result(breaches=("Adobe", "LinkedIn"), found=("Spotify", "Dropbox")))
    code, out = run_cmd([])
    assert code == 0 and "a@b.test" in out and "email" in out
    code, out = run_cmd(["show", "2"])
    assert "Dropbox" in out and "LinkedIn" in out
    code, out = run_cmd(["diff", "1", "2"])
    assert "New accounts: Dropbox" in out and "New breaches: LinkedIn" in out
    code, out = run_cmd(["diff", "1", "1"])
    assert "no differences" in out


def test_command_errors_and_empty():
    assert "history is empty" in run_cmd([])[1]
    code, out = run_cmd(["show", "7"])
    assert code == 2 and "no scan with id" in out
    assert run_cmd(["show", "x"])[0] == 2
    assert run_cmd(["diff", "1", "2"])[0] == 2
    code, out = run_cmd(["bogus"])
    assert code == 2 and "usage: history" in out


def test_clear_asks_first():
    history.record(username_result())
    code, out = run_cmd(["clear"], answer="n")
    assert code == 1 and "nothing deleted" in out and len(history.list_scans()) == 1
    code, out = run_cmd(["clear"], answer="y")
    assert code == 0 and "deleted 1" in out and history.list_scans() == []
    history.record(username_result())
    assert run_cmd(["clear"], assume_yes=True)[0] == 0 and history.list_scans() == []


# ---- CLI / REPL integration ----------------------------------------------------------

def test_cli_phone_scan_is_recorded_and_no_history_skips(capsys):
    assert cli.main(["phone", "+905551112233", "--no-banner", "--json"]) == 0
    assert len(history.list_scans()) == 1
    assert cli.main(["phone", "+905551112233", "--no-banner", "--json", "--no-history"]) == 0
    assert len(history.list_scans()) == 1


def test_cli_second_scan_reports_changes_in_json(capsys):
    cli.main(["phone", "+905551112233", "--no-banner", "--json"])
    capsys.readouterr()
    cli.main(["phone", "+905551112233", "--no-banner", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert any("last scan" in n for n in data["notes"])


def test_cli_history_subcommand(capsys):
    cli.main(["phone", "+905551112233", "--no-banner", "--json"])
    capsys.readouterr()
    assert cli.main(["history"]) == 0
    assert "phone" in capsys.readouterr().out
    assert cli.main(["history", "clear", "--yes"]) == 0
    assert history.list_scans() == []


def test_repl_scan_records_and_history_command():
    buf = io.StringIO()
    s = repl.Session(Console(file=buf, width=140, highlight=False), [Site("D", "https://d.test/{username}")])
    s.ask = lambda p: "y"
    repl.execute(s, "phone +905551112233")
    assert len(history.list_scans()) == 1
    repl.execute(s, "history")
    repl.execute(s, "history show 1")
    repl.execute(s, "history clear")
    assert history.list_scans() == []
    assert "+905551112233" in buf.getvalue().replace(" ", "") or "905551112233" in buf.getvalue()


def test_repl_password_check_leaves_database_untouched(monkeypatch):
    import httpx

    secret = "canary-Pw-4821"
    monkeypatch.setattr(password.net, "sync_client",
                        lambda **kw: httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, text="AAAA:1"))))
    buf = io.StringIO()
    s = repl.Session(Console(file=buf, width=140), [])
    repl.execute(s, "password")
    repl.execute(s, secret)
    assert history.list_scans() == []
    raw = history.db_path().read_bytes() if history.db_path().exists() else b""
    assert secret.encode() not in raw and secret not in buf.getvalue()
