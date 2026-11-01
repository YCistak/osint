"""REPL: command parsing, dispatch, saving, completion list, plain-stdin loop."""

import io

import pytest
from rich.console import Console

from osint import repl
from osint.models import FOUND, MISSING, Hit, ScanResult
from osint.sites import Site


def make_session():
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, width=120, highlight=False)
    sites = [Site("Demo", "https://demo.test/{username}")]
    return repl.Session(console, sites), buf


def fake_username_result(name="jane"):
    r = ScanResult("username", name)
    r.hits = [Hit("GitHub", f"https://github.com/{name}", FOUND), Hit("Reddit", "https://r.test", MISSING, "HTTP 404")]
    return r


# ---- parsing --------------------------------------------------------------

def test_parse_line():
    assert repl.parse_line("username torvalds") == ("username", ["torvalds"])
    assert repl.parse_line("  EMAIL   a@b.com --unsafe ") == ("email", ["a@b.com", "--unsafe"])
    assert repl.parse_line("save 'my reports/x.md'") == ("save", ["my reports/x.md"])
    assert repl.parse_line("   ") == ("", [])
    with pytest.raises(ValueError):
        repl.parse_line('username "unterminated')


def test_split_flags():
    assert repl.split_flags(["a@b.com", "--unsafe"]) == (["a@b.com"], {"--unsafe"})


def test_completion_list_contains_all_commands():
    s, _ = make_session()
    words = repl.completion_candidates(s, "")
    for cmd in ["username", "email", "domain", "phone", "image", "save", "show", "help", "clear", "exit", "quit"]:
        assert cmd in words


# ---- dispatch -------------------------------------------------------------

def test_unknown_command_and_bad_quote_do_not_raise():
    s, buf = make_session()
    repl.execute(s, "frobnicate")
    repl.execute(s, 'username "oops')
    out = buf.getvalue()
    assert "unknown command 'frobnicate'" in out and "cannot parse input" in out
    assert s.running


def test_help_mentions_every_command_and_site_count():
    s, buf = make_session()
    repl.execute(s, "help")
    out = buf.getvalue()
    for word in ["username <name>", "email <address>", "domain <domain|ip>", "phone <number>", "image <path>",
                 "save [path] [--html]", "show all|found", "clear", "exit", "Ctrl-C"]:
        assert word in out
    assert "1 sites" in out


@pytest.mark.parametrize("line", ["exit", "quit", "EXIT"])
def test_exit_commands(line):
    s, _ = make_session()
    repl.execute(s, line)
    assert s.running is False


def test_username_validation_message():
    s, buf = make_session()
    repl.execute(s, "username ../etc")
    assert buf.getvalue().count("[!]") == 1 and s.last is None
    repl.execute(s, "username")  # a bare category name enters the category instead
    assert s.category.key == "username"


def test_username_runs_scan_and_stores_last(monkeypatch):
    s, buf = make_session()
    calls = []

    def fake(name, sites, console, **kw):
        calls.append((name, len(sites)))
        return fake_username_result(name)

    monkeypatch.setattr(repl.runner, "run_username", fake)
    repl.execute(s, "username jane")
    assert calls == [("jane", 1)] and s.last.target == "jane"
    out = buf.getvalue()
    assert "[+] GitHub" in out and "Reddit" not in out  # not-found hidden by default
    assert "2 sites checked" in out


def test_show_all_and_found(monkeypatch):
    s, buf = make_session()
    s.last = fake_username_result()
    repl.execute(s, "show all")
    assert "[-] Reddit" in buf.getvalue()
    buf.truncate(0); buf.seek(0)
    repl.execute(s, "show found")
    assert "Reddit" not in buf.getvalue() and "[+] GitHub" in buf.getvalue()
    repl.execute(s, "show everything")
    assert "usage: show all|found" in buf.getvalue()


def test_show_without_result():
    s, buf = make_session()
    repl.execute(s, "show all")
    assert "no result to show" in buf.getvalue()


def test_email_requires_valid_address_and_passes_flags(monkeypatch):
    s, buf = make_session()
    repl.execute(s, "email not-an-email")
    assert "usage: email" in buf.getvalue()
    seen = {}

    def fake(address, console, **kw):
        seen.update(address=address, **kw)
        return ScanResult("email", address)

    monkeypatch.setattr(repl.runner, "run_email", fake)
    repl.execute(s, "email a@b.com --unsafe")
    assert seen == {"address": "a@b.com", "unsafe": True, "all_modules": False}
    repl.execute(s, "email a@b.com --bogus")
    assert "unknown flag" in buf.getvalue()


def test_domain_cleans_target(monkeypatch):
    s, buf = make_session()
    seen = []
    monkeypatch.setattr(repl.runner, "run_domain", lambda t, c, **kw: (seen.append(t), ScanResult("domain", t))[1])
    repl.execute(s, "domain https://Example.com/path")
    assert seen == ["example.com"]
    repl.execute(s, "domain not a domain")
    repl.execute(s, "domain ???")
    assert buf.getvalue().count("[!]") == 2


def test_save_without_result_and_with_result(tmp_path, monkeypatch):
    s, buf = make_session()
    repl.execute(s, "save")
    assert "nothing to save" in buf.getvalue()
    monkeypatch.chdir(tmp_path)
    s.last = fake_username_result()
    repl.execute(s, "save")
    saved = list((tmp_path / "reports").glob("username-jane-*.md"))
    assert len(saved) == 1 and "report saved" in buf.getvalue()
    repl.execute(s, f"save {tmp_path}/custom.md")
    assert (tmp_path / "custom.md").exists()


def test_ctrl_c_inside_command_does_not_exit(monkeypatch):
    s, buf = make_session()

    def boom(*a, **kw):
        raise KeyboardInterrupt

    monkeypatch.setattr(repl.runner, "run_domain", boom)
    repl.execute(s, "domain example.com")
    assert s.running and "cancelled" in buf.getvalue()


# ---- loop over non-tty stdin ---------------------------------------------

def test_plain_stdin_loop_processes_lines_until_eof(monkeypatch):
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, width=100, highlight=False)
    monkeypatch.setattr("sys.stdin", io.StringIO("help\nfrobnicate\n"))
    code = repl.run(console, [Site("Demo", "https://demo.test/{username}")], banner=True)
    out = buf.getvalue()
    assert code == 0
    assert "██████╗" in out and "v0.3 · 1 sites · type 'help'" in out
    assert "osint ❯ help" in out and "unknown command 'frobnicate'" in out


def test_history_path_env_and_xdg(monkeypatch, tmp_path):
    monkeypatch.setenv("OSINT_HISTORY_FILE", str(tmp_path / "h"))
    assert repl.history_path() == tmp_path / "h"
    monkeypatch.delenv("OSINT_HISTORY_FILE")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert repl.history_path() == tmp_path / "osint" / "history"


# ---- start screen: clear + command list ----------------------------------

def tty_console(buf):
    return Console(file=buf, force_terminal=True, color_system=None, width=100, highlight=False)


def test_command_list_shown_under_banner_and_in_help_share_rows():
    buf = io.StringIO()
    repl.print_menu(Console(file=buf, force_terminal=False, width=100), 500)
    out = buf.getvalue()
    for word in ["[1]", "Username", "search a username on 500 sites", "[2]", "Email",
                 "[3]", "Domain/IP", "[4]", "Phone", "[5]", "Image", "EXIF metadata & GPS", "[0]", "Exit"]:
        assert word in out
    assert "│" not in out and "─" not in out  # borderless


def test_clear_command_redraws_banner_and_commands_on_tty():
    buf = io.StringIO()
    s = repl.Session(tty_console(buf), [Site("Demo", "https://demo.test/{username}")])
    repl.execute(s, "clear")
    out = buf.getvalue()
    assert out.startswith("\x1b[H\x1b[2J\x1b[3J")
    assert "██████╗" in out and "[1]" in out and "Username" in out


def test_run_clears_on_tty_but_not_when_banner_off_or_not_tty(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    sites = [Site("Demo", "https://demo.test/{username}")]
    buf = io.StringIO()
    repl.run(tty_console(buf), sites, banner=True)
    assert buf.getvalue().startswith("\x1b[H\x1b[2J\x1b[3J") and "[1]" in buf.getvalue()
    buf = io.StringIO()
    repl.run(tty_console(buf), sites, banner=False)
    assert "\x1b[3J" not in buf.getvalue() and "[1]" not in buf.getvalue()
    buf = io.StringIO()
    repl.run(Console(file=buf, force_terminal=False), sites, banner=True)
    assert "\x1b[3J" not in buf.getvalue() and "[1]" in buf.getvalue()
