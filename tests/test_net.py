"""Proxy state, client factories, Tor check, CLI flags and the REPL proxy command."""

import io

import httpx
import pytest
from rich.console import Console

from osint import cli, net, repl
from osint.sites import Site


@pytest.fixture(autouse=True)
def clean_proxy(monkeypatch):
    monkeypatch.delenv("OSINT_PROXY", raising=False)
    net.set_proxy(None)
    yield
    net.set_proxy(None)


def test_validate_accepts_supported_schemes():
    for url in ["http://127.0.0.1:8080", "https://p.test:443", "socks5://127.0.0.1:1080", "socks5h://127.0.0.1:9050"]:
        net.set_proxy(url)
        assert net.get_proxy() == url


@pytest.mark.parametrize("bad", ["ftp://x:1", "127.0.0.1:8080", "socks5://nohost", "http://host:notaport", ""])
def test_validate_rejects_bad_urls(bad):
    if bad == "":
        net.set_proxy(bad)  # empty clears instead of failing
        assert net.get_proxy() is None
        return
    with pytest.raises(net.ProxyError):
        net.set_proxy(bad)


def test_redact_hides_password():
    assert net.redact("http://u:secret@h.test:80") == "http://u:***@h.test:80"
    net.set_proxy("http://u:secret@h.test:80")
    assert "secret" not in net.describe()


def test_describe_and_warning():
    assert net.describe() == "" and net.bypass_warning() == ""
    net.set_proxy(net.TOR_PROXY)
    assert net.describe() == "tor"
    assert "do not go through the proxy" in net.bypass_warning()


def test_factories_pass_proxy_only_when_set(monkeypatch):
    seen = []
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: seen.append(("async", kw)))
    monkeypatch.setattr(httpx, "Client", lambda **kw: seen.append(("sync", kw)))
    net.async_client(timeout=1)
    net.sync_client(timeout=1)
    assert all("proxy" not in kw for _, kw in seen)
    net.set_proxy("socks5h://127.0.0.1:9050")
    net.async_client(timeout=1)
    net.sync_client(timeout=1)
    assert [kw["proxy"] for _, kw in seen[2:]] == ["socks5h://127.0.0.1:9050"] * 2


def test_real_clients_build_with_socks_proxy():
    net.set_proxy("socks5h://127.0.0.1:9050")
    c = net.sync_client()
    c.close()
    net.set_proxy("http://127.0.0.1:8080")
    net.sync_client().close()


def _client(payload):
    return httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=payload)))


def test_check_tor_reports_tor_and_non_tor():
    ok, msg = net.check_tor(_client({"IsTor": True, "IP": "1.2.3.4"}))
    assert ok and "1.2.3.4" in msg
    ok, msg = net.check_tor(_client({"IsTor": False, "IP": "5.6.7.8"}))
    assert not ok and "NOT using Tor" in msg


def test_check_tor_network_error():
    def boom(request):
        raise httpx.ConnectError("refused")

    ok, msg = net.check_tor(httpx.Client(transport=httpx.MockTransport(boom)))
    assert not ok and "9050" in msg


# ---- CLI ---------------------------------------------------------------------

def test_cli_flags_parse_before_and_after_command():
    p = cli.build_parser()
    assert p.parse_args(["--proxy", "http://h:1", "phone", "+9055"]).proxy == "http://h:1"
    assert p.parse_args(["phone", "+9055", "--tor"]).tor is True
    assert not hasattr(p.parse_args(["phone", "+9055"]), "proxy")


def test_cli_bad_proxy_exits_2(capsys):
    assert cli.main(["--proxy", "ftp://x:1", "--no-banner", "phone", "+905551112233"]) == 2
    assert "unsupported proxy scheme" in capsys.readouterr().err


def test_cli_tor_not_running_exits_2(monkeypatch, capsys):
    monkeypatch.setattr(net, "check_tor", lambda: (False, "could not reach the Tor check service"))
    assert cli.main(["--tor", "--no-banner", "phone", "+905551112233"]) == 2
    assert "Tor check" in capsys.readouterr().err


def test_cli_env_proxy(monkeypatch):
    monkeypatch.setenv("OSINT_PROXY", "http://127.0.0.1:3128")
    assert cli.main(["--no-banner", "--json", "phone", "+905551112233"]) == 0
    assert net.get_proxy() == "http://127.0.0.1:3128"


# ---- REPL --------------------------------------------------------------------

def make_session():
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, width=120, highlight=False)
    return repl.Session(console, [Site("Demo", "https://demo.test/{username}")]), buf


def test_repl_proxy_set_show_off():
    s, buf = make_session()
    repl.execute(s, "proxy http://127.0.0.1:8080")
    assert net.get_proxy() == "http://127.0.0.1:8080"
    repl.execute(s, "proxy")
    repl.execute(s, "proxy off")
    assert net.get_proxy() is None
    out = buf.getvalue()
    assert "proxy set" in out and "do not go through the proxy" in out and "proxy off" in out


def test_repl_proxy_tor_requires_working_tor(monkeypatch):
    s, buf = make_session()
    monkeypatch.setattr(net, "check_tor", lambda: (False, "no tor here"))
    repl.execute(s, "proxy tor")
    assert net.get_proxy() is None and "no tor here" in buf.getvalue()
    monkeypatch.setattr(net, "check_tor", lambda: (True, "traffic leaves through Tor (exit IP 9.9.9.9)"))
    repl.execute(s, "proxy tor")
    assert net.get_proxy() == net.TOR_PROXY


def test_repl_proxy_rejects_bad_url():
    s, buf = make_session()
    repl.execute(s, "proxy nonsense")
    assert net.get_proxy() is None and "[!]" in buf.getvalue()


def test_banner_shows_proxy():
    from osint.banner import subtitle

    assert "proxy" not in subtitle(500).plain
    net.set_proxy(net.TOR_PROXY)
    assert "proxy: tor" in subtitle(500).plain
