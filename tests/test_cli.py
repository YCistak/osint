"""One-shot CLI: argparse wiring, --json, --no-banner, --save, exit codes."""

import json
import re
import subprocess
import sys

import pytest

from osint import cli
from osint.models import FOUND, MISSING, Hit, ScanResult, kv


def result_with_hits():
    r = ScanResult("username", "jane")
    r.hits = [Hit("GitHub", "https://github.com/jane", FOUND), Hit("Reddit", "https://r.test", MISSING)]
    return r


@pytest.fixture
def fake_runs(monkeypatch):
    calls = {}

    def user(name, sites, console, **kw):
        calls["username"] = (name, kw)
        return result_with_hits()

    def mail(address, console, **kw):
        calls["email"] = (address, kw)
        r = ScanResult("email", address)
        r.sections["Mail server"] = kv({"Provider": "Google"})
        return r

    def dom(target, console, **kw):
        calls["domain"] = (target, kw)
        r = ScanResult("domain", target)
        r.sections["Reverse DNS"] = kv({"PTR": "one.one.one.one"})
        return r

    monkeypatch.setattr(cli.runner, "run_username", user)
    monkeypatch.setattr(cli.runner, "run_email", mail)
    monkeypatch.setattr(cli.runner, "run_domain", dom)
    return calls


def test_parser_subcommands_and_flags():
    p = cli.build_parser()
    a = p.parse_args(["username", "bob", "--show-all", "--json", "--no-banner"])
    assert (a.command, a.target, a.show_all, a.json, a.no_banner) == ("username", "bob", True, True, True)
    a = p.parse_args(["email", "a@b.com", "--unsafe", "--all-modules", "--save", "out.md"])
    assert a.unsafe and a.all_modules and a.save == "out.md"
    assert p.parse_args(["--no-banner"]).command is None


def test_json_output_is_pure_json(fake_runs, capsys):
    code = cli.main(["username", "jane", "--json"])
    out = capsys.readouterr().out
    data = json.loads(out)  # nothing but JSON on stdout
    assert code == 0 and data["kind"] == "username" and data["counts"]["found"] == 1
    assert data["hits"][0]["name"] == "GitHub"
    assert fake_runs["username"][1]["progress"] is False


def test_json_for_email_and_domain(fake_runs, capsys):
    cli.main(["email", "a@b.com", "--json"])
    assert json.loads(capsys.readouterr().out)["sections"]["Mail server"]["items"]["Provider"] == "Google"
    cli.main(["domain", "https://1.1.1.1/", "--json"])
    assert json.loads(capsys.readouterr().out)["target"] == "1.1.1.1"
    assert fake_runs["domain"][0] == "1.1.1.1"


def test_banner_printed_by_default_and_hidden_with_flag(fake_runs, capsys):
    cli.main(["domain", "example.com"])
    assert "██████╗" in capsys.readouterr().out
    cli.main(["domain", "example.com", "--no-banner"])
    assert "██████╗" not in capsys.readouterr().out


def test_email_flags_forwarded(fake_runs, capsys):
    cli.main(["email", "a@b.com", "--unsafe", "--no-banner"])
    assert fake_runs["email"][1]["unsafe"] is True and fake_runs["email"][1]["all_modules"] is False


@pytest.mark.parametrize("argv", [
    ["username", "../etc"], ["email", "nope"], ["domain", "not a domain"],
])
def test_invalid_targets_exit_2(argv, capsys, fake_runs):
    assert cli.main(argv + ["--no-banner"]) == 2
    assert "[!]" in capsys.readouterr().err
    assert not fake_runs


def test_save_writes_report(fake_runs, tmp_path, capsys):
    target = tmp_path / "r.md"
    assert cli.main(["username", "jane", "--no-banner", "--save", str(target)]) == 0
    assert target.exists() and "# Username report: jane" in target.read_text(encoding="utf-8")
    assert "report saved" in capsys.readouterr().out


def test_cancelled_scan_returns_130(monkeypatch, capsys):
    def user(name, sites, console, **kw):
        r = result_with_hits()
        r.cancelled = True
        return r

    monkeypatch.setattr(cli.runner, "run_username", user)
    assert cli.main(["username", "jane", "--no-banner"]) == 130


def test_no_command_starts_repl(monkeypatch):
    started = {}
    monkeypatch.setattr(cli.repl, "run", lambda console, sites, banner: started.update(banner=banner, n=len(sites)) or 0)
    assert cli.main(["--no-banner"]) == 0
    assert started["banner"] is False and started["n"] >= 400


# ---- the real installed entry point -----------------------------------------

def run_cli(*args, stdin=None):
    return subprocess.run([sys.executable, "-m", "osint.cli", *args], input=stdin,
                          capture_output=True, text=True, timeout=60)


def test_help_and_version_via_subprocess():
    h = run_cli("--help")
    assert h.returncode == 0 and "username" in h.stdout and "--no-banner" in h.stdout and "--json" in h.stdout
    v = run_cli("--version")
    assert v.stdout.strip() == "osint 0.3.0"


def test_repl_via_piped_stdin():
    r = run_cli(stdin="help\nexit\n")
    assert r.returncode == 0
    assert "██████╗" in r.stdout and "osint ❯" in r.stdout and "username <name>" in r.stdout


def test_repl_eof_exits_cleanly():
    r = run_cli("--no-banner", stdin="")
    assert r.returncode == 0 and "██████╗" not in r.stdout


def pty_start_output() -> str:
    """Run the interactive shell on a real pty (stdlib only), return what it printed before exiting."""
    import os
    import pty
    import select
    import time

    pid, fd = pty.fork()
    if pid == 0:
        os.environ["TERM"] = "xterm"
        os.execv(sys.executable, [sys.executable, "-m", "osint.cli"])
    buf, deadline, sent = b"", time.time() + 20, False
    while time.time() < deadline:
        if select.select([fd], [], [], 0.3)[0]:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
        if not sent and "❯".encode() in buf:
            os.write(fd, b"exit\r")
            sent = True
    os.waitpid(pid, 0)
    return buf.decode(errors="replace")


def test_pty_start_clears_and_lists_commands_but_one_shot_does_not():
    out = pty_start_output()
    assert out.startswith("\x1b[H\x1b[2J\x1b[3J")
    plain = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", out)
    assert "██████╗" in plain and "[1]" in plain and "Username" in plain and "[3]" in plain and "Domain/IP" in plain
    one = run_cli("--help")  # one-shot paths never reach repl.run; no network needed
    assert "\x1b[3J" not in one.stdout and "[1]" not in one.stdout
