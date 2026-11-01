"""Pwned Passwords check: hashing, parsing, API call, and the guarantee that the password is never stored."""

import hashlib
import io
import json
import sys

import httpx
import pytest
from rich.console import Console

from osint import cli, password, repl, report
from osint.sites import Site

SECRET = "Tr0ub4dor&3-unique-canary-9137"


def mock_client(suffix_counts, seen=None):
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        body = "\r\n".join(f"{k}:{v}" for k, v in suffix_counts.items())
        return httpx.Response(200, text=body)

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_split_hash_matches_known_sha1():
    prefix, suffix = password.split_hash("password")
    assert prefix == "5BAA6" and suffix == "1E4C9B93F3F0682250B6CF8331B7EE68FD8"


def test_parse_range_counts_and_padding():
    body = "AAAA:3\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:9,545,824\r\nBBBB:0\r\n"
    assert password.parse_range(body, "1e4c9b93f3f0682250b6cf8331b7ee68fd8") == 9545824
    assert password.parse_range(body, "BBBB") == 0
    assert password.parse_range(body, "CCCC") == 0
    assert password.parse_range("garbage", "X") == 0


def test_check_sends_only_prefix_with_padding_header():
    seen = []
    prefix, suffix = password.split_hash(SECRET)
    count = password.check(SECRET, mock_client({suffix: 42}, seen))
    assert count == 42
    req = seen[0]
    assert str(req.url) == f"https://api.pwnedpasswords.com/range/{prefix}"
    assert req.headers["Add-Padding"] == "true"
    full = hashlib.sha1(SECRET.encode()).hexdigest()
    sent = str(req.url) + str(req.headers) + req.content.decode()
    assert SECRET not in sent and full not in sent.lower() and suffix.lower() not in sent.lower()


def test_check_errors():
    bad = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(503)))
    with pytest.raises(password.PasswordError, match="503"):
        password.check("x", bad)

    def boom(request):
        raise httpx.ConnectError("down")

    with pytest.raises(password.PasswordError, match="could not reach"):
        password.check("x", httpx.Client(transport=httpx.MockTransport(boom)))
    with pytest.raises(password.PasswordError):
        password.analyze("")


@pytest.mark.parametrize("pw,word", [("password1", "weak"), ("abc", "weak"), ("aaaaaaaaaaaa", "weak"),
                                     ("Gx7!kq2#Lm9z", "strong"), ("correct-horse-battery-staple", "strong")])
def test_strength_hint(pw, word):
    assert password.strength_hint(pw).startswith(word)


def test_result_contains_no_password_or_hash():
    prefix, suffix = password.split_hash(SECRET)
    result = password.analyze(SECRET, mock_client({suffix: 7}))
    blob = json.dumps(result.to_dict()).lower()
    assert SECRET.lower() not in blob and suffix.lower() not in blob and prefix.lower() not in blob
    assert result.target == "(hidden)"
    assert result.sections["Pwned Passwords"]["items"]["Times seen in breaches"] == "7"


def test_report_refuses_password_results(tmp_path):
    result = password.build_result(5, "weak")
    with pytest.raises(report.ReportRefused):
        report.save_report(result, tmp_path)
    assert list(tmp_path.iterdir()) == []


# ---- CLI -----------------------------------------------------------------------

@pytest.fixture
def api(monkeypatch):
    """Route the password client to a mock and record that no real network is used."""
    prefix, suffix = password.split_hash(SECRET)
    monkeypatch.setattr(password.net, "sync_client",
                        lambda **kw: mock_client({suffix: 1234}))


def test_cli_stdin_json_has_count_and_no_secret(api, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO(SECRET + "\n"))
    assert cli.main(["password", "--stdin", "--json"]) == 0
    out = capsys.readouterr()
    data = json.loads(out.out)
    assert data["kind"] == "password" and "1,234" in json.dumps(data)
    assert SECRET not in out.out + out.err


def test_cli_argv_password_warns_but_never_echoes(api, capsys):
    assert cli.main(["password", SECRET, "--no-banner"]) == 0
    out = capsys.readouterr()
    assert "shell history" in out.err
    assert SECRET not in out.out + out.err


def test_cli_without_input_in_pipe_fails(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    assert cli.main(["password", "--no-banner"]) == 2
    assert cli.main(["password", "--stdin", "--no-banner"]) == 2  # empty line


def test_cli_save_is_refused(api, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO(SECRET + "\n"))
    assert cli.main(["password", "--stdin", "--save", str(tmp_path)]) == 2
    assert "never saved" in capsys.readouterr().err
    assert list(tmp_path.iterdir()) == []


# ---- REPL ----------------------------------------------------------------------

def make_session(secrets):
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, width=120, highlight=False)
    s = repl.Session(console, [Site("Demo", "https://demo.test/{username}")])
    answers = iter(secrets)
    s.secret = lambda prompt: next(answers, "")
    return s, buf


def test_repl_command_line_password_is_rejected_and_not_checked(api):
    s, buf = make_session([])
    repl.execute(s, f"password {SECRET}")
    out = buf.getvalue()
    assert "never type a password" in out
    assert SECRET not in out


def test_repl_category_line_is_the_secret_and_never_echoed(api):
    s, buf = make_session([])
    repl.execute(s, "password")
    assert s.category.key == "password"
    repl.execute(s, SECRET)
    out = buf.getvalue()
    assert "1,234" in out and SECRET not in out
    assert s.last is None  # nothing to save
    repl.execute(s, "save")  # inside a secret category "save" is itself a (weak) password, but still no file
    repl.execute(s, "")
    assert s.category is None


def test_history_excludes_secret_category_with_arguments():
    assert repl.history_excluded(f"password {SECRET}")
    assert repl.history_excluded("password   x")
    assert not repl.history_excluded("password")
    assert not repl.history_excluded("username torvalds")


def test_history_file_never_receives_password(tmp_path, monkeypatch):
    from prompt_toolkit.history import FileHistory

    monkeypatch.setenv("OSINT_HISTORY_FILE", str(tmp_path / "h"))
    ps = repl._make_prompt_session(repl.Session(Console(file=io.StringIO()), []))
    ps.history.append_string("username torvalds")
    ps.history.append_string(f"password {SECRET}")
    ps.history.append_string("password")
    content = (tmp_path / "h").read_text()
    assert "torvalds" in content and SECRET not in content
    assert isinstance(ps.history, FileHistory)


def test_plain_stdin_loop_does_not_echo_password(api, monkeypatch):
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, width=120, highlight=False)
    monkeypatch.setattr(sys, "stdin", io.StringIO(f"password\n{SECRET}\n\nexit\n"))
    repl.run(console, [Site("Demo", "https://demo.test/{username}")], banner=False)
    out = buf.getvalue()
    assert "1,234" in out and SECRET not in out
