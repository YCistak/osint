"""Category menu: registry, navigation, context completion, phone/image/save commands."""

import io
import os
import re
import select
import sys
import time

import pytest
from PIL import Image
from rich.console import Console

from osint import categories, repl
from osint.categories import Category
from osint.models import FOUND, Hit, ScanResult
from osint.sites import Site


def make_session():
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, width=110, highlight=False)
    return repl.Session(console, [Site("Demo", "https://demo.test/{username}")]), buf


def last_screen(buf):
    return buf.getvalue()


# ---- registry ---------------------------------------------------------------

def test_registry_order_and_menu_rows():
    keys = [c.key for c in categories.REGISTRY]
    assert keys == ["username", "email", "domain", "phone", "image", "github", "me", "password"]
    rows = categories.menu_rows(500)
    assert rows[0] == ("1", "Username", "search a username on 500 sites")
    assert rows[-1] == ("0", "Exit", "")
    assert [r[0] for r in rows] == [str(i) for i in range(1, len(keys) + 1)] + ["0"]


def test_find_by_number_name_label_alias():
    assert categories.find("1").key == "username"
    assert categories.find("Email").key == "email"
    assert categories.find("domain/ip").key == "domain" and categories.find("ip").key == "domain"
    assert categories.find("0") is None and categories.find("9") is None and categories.find("") is None


def test_new_category_appears_in_menu_help_and_completion_without_menu_code(monkeypatch):
    monkeypatch.setattr(categories, "REGISTRY", list(categories.REGISTRY))
    seen = []
    categories.register(Category("crypto", "Crypto", "wallet lookup", "<address>", "bc1q...",
                                 run=lambda s, a: seen.append(a), flags=("--chain",)))
    s, buf = make_session()
    n = len(categories.REGISTRY)
    repl.print_menu(s.console, 1)
    assert f"[{n}]" in buf.getvalue() and "Crypto" in buf.getvalue() and "wallet lookup" in buf.getvalue()
    repl.execute(s, str(n))
    assert s.category.key == "crypto" and "crypto" in repl.prompt_text(s)
    repl.execute(s, "bc1qxyz")
    assert seen == [["bc1qxyz"]]
    assert "crypto" in repl.completion_candidates(make_session()[0], "cr")
    assert "crypto" in repl.help_text(1)
    with pytest.raises(ValueError):
        categories.register(Category("crypto", "X", "x", "x", "x", run=lambda s, a: None))


# ---- navigation ---------------------------------------------------------------

def test_number_and_name_enter_category_and_back_returns():
    s, buf = make_session()
    assert repl.prompt_text(s) == "osint ❯ "
    repl.execute(s, "1")
    assert s.category.key == "username" and repl.prompt_text(s) == "osint/username ❯ "
    out = buf.getvalue()
    assert "just type it to scan, e.g. torvalds" in out and "back | 0" in out
    repl.execute(s, "back")
    assert s.category is None and "[1]" in buf.getvalue().split("back | 0")[-1]
    repl.execute(s, "Email")
    assert s.category.key == "email"
    repl.execute(s, "0")  # inside a category 0 means back, not exit
    assert s.category is None and s.running
    repl.execute(s, "0")  # at the main menu 0 exits
    assert not s.running


def test_exit_works_inside_category_and_help_is_global():
    s, buf = make_session()
    repl.execute(s, "3")
    repl.execute(s, "help")
    assert "Menu:" in buf.getvalue()
    repl.execute(s, "exit")
    assert not s.running


def test_category_screens_have_banner_and_own_help_for_each_category():
    for cat in categories.REGISTRY:
        s, buf = make_session()
        repl.execute(s, cat.key)
        out = buf.getvalue()
        assert "OSINT" in out and cat.label in out and cat.target in out and cat.example in out
    s, buf = make_session()
    repl.execute(s, "phone")
    assert "--region XX" in buf.getvalue()


def test_bare_target_inside_category_runs_scan(monkeypatch):
    s, buf = make_session()
    seen = []
    monkeypatch.setattr(repl.runner, "run_username", lambda n, sites, c, **k: (seen.append(n), ScanResult("username", n))[1])
    repl.execute(s, "1")
    repl.execute(s, "torvalds")
    assert seen == ["torvalds"] and s.last.target == "torvalds"
    assert s.category.key == "username"  # stays in the category for the next target


def test_global_commands_still_work_from_main_and_from_other_category(monkeypatch):
    s, _ = make_session()
    seen = []
    monkeypatch.setattr(repl.runner, "run_username", lambda n, sites, c, **k: (seen.append(n), ScanResult("username", n))[1])
    repl.execute(s, "username alice")
    assert seen == ["alice"] and s.category is None
    repl.execute(s, "4")
    repl.execute(s, "username bob")  # global form inside phone
    assert seen == ["alice", "bob"] and s.category.key == "phone"


def test_reserved_words_are_not_treated_as_targets(monkeypatch):
    s, buf = make_session()
    monkeypatch.setattr(repl.runner, "run_username", lambda *a, **k: pytest.fail("must not scan"))
    repl.execute(s, "1")
    repl.execute(s, "show")
    assert "usage: show all|found" in buf.getvalue()


def test_back_at_main_and_unknown_command():
    s, buf = make_session()
    repl.execute(s, "back")
    repl.execute(s, "9")
    out = buf.getvalue()
    assert "already at the main menu" in out and "unknown command '9'" in out


def test_clear_redraws_current_screen():
    s, buf = make_session()
    repl.execute(s, "2")
    n = buf.getvalue().count("Email")
    repl.execute(s, "clear")
    assert buf.getvalue().count("Email") > n
    repl.execute(s, "back")
    repl.execute(s, "clear")
    assert buf.getvalue().rstrip().endswith("Type a number or a name. 'help' lists every command.")


# ---- context completion ---------------------------------------------------------

def test_completion_depends_on_context():
    s, _ = make_session()
    assert repl.completion_candidates(s, "us") == ["username"]
    assert "1" in repl.completion_candidates(s, "") and "back" not in repl.completion_candidates(s, "")
    assert repl.completion_candidates(s, "save ") == ["--html"]
    assert repl.completion_candidates(s, "show a") == ["all"]
    assert repl.completion_candidates(s, "email a@b.com --u") == ["--unsafe"]
    assert repl.completion_candidates(s, "email a@b.com --unsafe --") == ["--all-modules"]
    repl.execute(s, "email")
    assert "back" in repl.completion_candidates(s, "b")
    assert repl.completion_candidates(s, "a@b.com --a") == ["--all-modules"]
    repl.execute(s, "back")
    repl.execute(s, "phone")
    assert repl.completion_candidates(s, "+90 --r") == ["--region"]
    assert repl.completion_candidates(s, "+90 --u") == []


def test_path_completion_only_for_image_target():
    s, _ = make_session()
    assert repl.wants_path(s, "image ~/Pic") and repl.wants_path(s, "image ")
    assert not repl.wants_path(s, "username ./x") and not repl.wants_path(s, "image --x")
    repl.execute(s, "image")
    assert repl.wants_path(s, "~/Pic") and repl.wants_path(s, "./a b") and not repl.wants_path(s, "ba")
    repl.execute(s, "back")
    repl.execute(s, "phone")
    assert not repl.wants_path(s, "~/Pic")


# ---- phone / image / save commands ----------------------------------------------

def test_phone_command_in_category_with_spaces_and_region():
    s, buf = make_session()
    repl.execute(s, "phone")
    repl.execute(s, "0555 111 22 33")
    assert "+905551112233" in buf.getvalue() and s.last.kind == "phone"
    repl.execute(s, "650 253 0000 --region US")
    assert s.last.target == "+16502530000"
    repl.execute(s, "123 --region ZZ")
    repl.execute(s, "123 --bogus")
    repl.execute(s, "abc")
    assert buf.getvalue().count("[!]") == 3


def test_image_command_handles_path_with_spaces_and_errors(tmp_path):
    folder = tmp_path / "my pics"
    folder.mkdir()
    Image.new("RGB", (4, 4)).save(folder / "a b.png")
    s, buf = make_session()
    repl.execute(s, "image")
    repl.execute(s, f"'{folder}/a b.png'")
    assert "Format: PNG" in buf.getvalue() and s.last.kind == "image"
    repl.execute(s, str(folder / "missing.jpg"))
    assert "file not found" in buf.getvalue()


def test_save_html_by_flag_and_extension(tmp_path, monkeypatch):
    s, buf = make_session()
    monkeypatch.chdir(tmp_path)
    s.last = ScanResult("username", "jane", hits=[Hit("GitHub", "https://github.com/jane", FOUND)])
    repl.execute(s, "save --html")
    repl.execute(s, f"save {tmp_path}/r.html")
    repl.execute(s, "save")
    assert len(list((tmp_path / "reports").glob("*.html"))) == 1
    assert (tmp_path / "r.html").read_text().startswith("<!doctype html>")
    assert len(list((tmp_path / "reports").glob("*.md"))) == 1
    repl.execute(s, "save --pdf")
    assert "usage: save [path] [--html]" in buf.getvalue()


# ---- one-shot CLI ---------------------------------------------------------------

def run_cli(*args):
    import subprocess

    return subprocess.run([sys.executable, "-m", "osint.cli", *args], capture_output=True, text=True, timeout=60)


def test_cli_phone_and_image_one_shot(tmp_path):
    r = run_cli("phone", "+905551112233", "--no-banner")
    assert r.returncode == 0 and "E.164: +905551112233" in r.stdout
    import json
    j = json.loads(run_cli("phone", "0555 111 22 33", "--json").stdout)
    assert j["kind"] == "phone" and j["target"] == "+905551112233"
    assert run_cli("phone", "abc").returncode == 2 and run_cli("phone", "1", "--region", "ZZ").returncode == 2
    p = tmp_path / "x.png"
    Image.new("RGB", (4, 4)).save(p)
    assert "Format: PNG" in run_cli("image", str(p), "--no-banner").stdout
    assert run_cli("image", str(tmp_path / "nope.jpg")).returncode == 2


def test_cli_save_html(tmp_path):
    out = tmp_path / "p.html"
    r = run_cli("phone", "+905551112233", "--no-banner", "--save", str(out))
    assert r.returncode == 0 and out.read_text().startswith("<!doctype html>")
    r = run_cli("phone", "+905551112233", "--no-banner", "--save", str(tmp_path), "--html")
    assert list(tmp_path.glob("phone-*.html"))


# ---- real pty: start -> 1 -> category prompt -> back -> menu -----------------------

def pty_run(steps, timeout=25):
    """Run the shell on a pty. ``steps`` are lines sent one by one, each after the next prompt appears."""
    import pty
    import tempfile

    history_dir = tempfile.mkdtemp()
    pid, fd = pty.fork()
    if pid == 0:
        os.environ["TERM"] = "xterm"
        os.environ["OSINT_HISTORY_FILE"] = os.path.join(history_dir, "history")
        os.execv(sys.executable, [sys.executable, "-m", "osint.cli"])
    buf, deadline, sent = b"", time.time() + timeout, 0
    while time.time() < deadline:
        if select.select([fd], [], [], 0.3)[0]:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
        if sent < len(steps) and buf.count("❯".encode()) > sent:
            time.sleep(0.2)
            os.write(fd, (steps[sent] + "\r").encode())
            sent += 1
    os.waitpid(pid, 0)
    return buf.decode(errors="replace")


def test_pty_menu_navigation():
    out = pty_run(["1", "back", "exit"])
    plain = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", out)
    assert out.startswith("\x1b[H\x1b[2J\x1b[3J")
    assert "██████╗" in plain and "[1]" in plain and "[0]" in plain
    assert "osint/username" in plain and "just type it to scan" in plain
    # after "back" the main menu is drawn again (second full clear sequence)
    assert out.count("\x1b[2J") >= 3
    assert plain.rstrip().endswith("exit")
