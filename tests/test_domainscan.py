"""Domain / IP module: parsing, target kind, mocked network and mocked DNS."""

import dns.resolver
import httpx
import pytest

from osint import domainscan
from osint.models import ScanResult


def test_target_kind():
    assert domainscan.target_kind("1.1.1.1") == "ip"
    assert domainscan.target_kind("2606:4700:4700::1111") == "ip"
    assert domainscan.target_kind("example.com") == "domain"
    assert domainscan.target_kind("sub.domain.example.co.uk") == "domain"
    assert domainscan.target_kind("türkiye.gov.tr") == "domain"
    for bad in ["", "localhost", "a b.com", "-x.com", "http://x"]:
        assert domainscan.target_kind(bad) == "invalid"


def test_clean_target():
    assert domainscan.clean_target("  https://Example.COM/path?x=1 ") == "example.com"
    assert domainscan.clean_target("example.com.") == "example.com"
    assert domainscan.clean_target("example.com:8080") == "example.com"
    assert domainscan.clean_target("1.1.1.1") == "1.1.1.1"


def test_extract_subdomains_dedupes_and_filters():
    records = [
        {"name_value": "example.com\nwww.example.com", "common_name": "example.com"},
        {"name_value": "*.example.com", "common_name": "*.example.com"},
        {"name_value": "WWW.example.com", "common_name": "www.example.com"},
        {"name_value": "mail.example.com\nother.org", "common_name": "mail.example.com"},
        {"name_value": "user@example.com", "common_name": "x"},  # email certificate
        {"name_value": "evil-example.com", "common_name": "evil-example.com"},  # not a subdomain
        "garbage",
        {},
    ]
    assert domainscan.extract_subdomains(records, "example.com") == [
        "example.com", "mail.example.com", "www.example.com",
    ]


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_crtsh_success():
    def handler(request):
        assert "crt.sh" in request.url.host and "output=json" in str(request.url)
        return httpx.Response(200, json=[{"name_value": "a.example.com\nb.example.com"}])

    assert domainscan.crtsh_lookup("example.com", _client(handler)) == ["a.example.com", "b.example.com"]


@pytest.mark.parametrize("response,fragment", [
    (httpx.Response(502), "502"),
    (httpx.Response(200, text="<html>not json</html>"), "JSON"),
])
def test_crtsh_errors(response, fragment):
    with pytest.raises(RuntimeError, match=fragment):
        domainscan.crtsh_lookup("example.com", _client(lambda r: response))


def test_crtsh_timeout_retries_once():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        raise httpx.ReadTimeout("slow", request=request)

    with pytest.raises(RuntimeError, match="timed out"):
        domainscan.crtsh_lookup("example.com", _client(handler))
    assert calls["n"] == 2


def test_ip_location():
    def handler(request):
        return httpx.Response(200, json={
            "status": "success", "country": "Turkey", "city": "Ankara", "lat": 39.9, "lon": 32.8,
            "isp": "X", "query": "1.2.3.4"})

    info = domainscan.ip_location("1.2.3.4", _client(handler))
    assert info["Country"] == "Turkey" and info["Coordinates"] == "39.9, 32.8"


def test_ip_location_error():
    failing = lambda r: httpx.Response(200, json={"status": "fail", "message": "private range"})
    with pytest.raises(RuntimeError, match="private range"):
        domainscan.ip_location("10.0.0.1", _client(failing))


class FakeResolver:
    """Stands in for dns.resolver.Resolver."""

    def __init__(self):
        self.lifetime = 0

    def resolve(self, name, rtype):
        if str(name) == "missing.test":
            raise dns.resolver.NXDOMAIN()
        if rtype == "A":
            return [type("R", (), {"to_text": lambda s: "9.9.9.9"})(),
                    type("R", (), {"to_text": lambda s: "1.1.1.1"})()]
        raise dns.resolver.NoAnswer()


def test_dns_lookup_with_fake_resolver(monkeypatch):
    monkeypatch.setattr(domainscan.dns.resolver, "Resolver", FakeResolver)
    out = domainscan.dns_lookup("example.test")
    assert out["A"] == ["1.1.1.1", "9.9.9.9"]  # sorted
    assert out["MX"] == [] and set(out) == set(domainscan.DNS_TYPES)
    with pytest.raises(ValueError, match="NXDOMAIN"):
        domainscan.dns_lookup("missing.test")


@pytest.fixture(autouse=True)
def stub_security(monkeypatch):
    """Keep these tests offline: the security sections have their own tests in test_domainsec.py."""
    from osint import domainsec

    monkeypatch.setattr(domainsec, "email_security", lambda d: {"type": "text", "text": "stub"})
    monkeypatch.setattr(domainsec, "resolve_a", lambda d: ["93.184.216.34"])
    monkeypatch.setattr(domainsec, "exposure", lambda ips: {"type": "text", "text": "stub " + ",".join(ips)})
    monkeypatch.setattr(domainsec, "tls_certificate", lambda d: {"type": "text", "text": "stub"})
    monkeypatch.setattr(domainsec, "wayback_summary", lambda d: {"type": "text", "text": "stub"})


def test_scan_ip_builds_sections(monkeypatch):
    monkeypatch.setattr(domainscan, "reverse_dns", lambda ip: ["host.example.net"])
    monkeypatch.setattr(domainscan, "ip_location", lambda ip: {"Country": "Turkey"})
    steps = []
    result = domainscan.scan("8.8.8.8", on_step=steps.append)
    assert list(result.sections) == ["Reverse DNS", "Geolocation", "Exposure (Shodan InternetDB)"]
    assert result.sections["Reverse DNS"]["items"] == ["host.example.net"]
    assert result.sections["Exposure (Shodan InternetDB)"]["text"] == "stub 8.8.8.8"
    assert steps == ["Reverse DNS", "Geolocation", "Exposure (Shodan InternetDB)"]


def test_scan_failed_step_becomes_text_and_others_still_run(monkeypatch):
    def broken(domain):
        raise RuntimeError("whois down")

    monkeypatch.setattr(domainscan, "whois_lookup", broken)
    monkeypatch.setattr(domainscan, "dns_lookup", lambda d: {"A": ["1.2.3.4"]})
    monkeypatch.setattr(domainscan, "crtsh_lookup", lambda d: ["www.example.com"])
    result = domainscan.scan("https://Example.com/x")
    assert result.target == "example.com"
    assert "whois down" in result.sections["Whois"]["text"]
    assert result.sections["DNS records"]["type"] == "table"
    assert result.sections["Subdomains (crt.sh)"]["items"] == ["www.example.com"]
    assert list(result.sections)[3:] == [
        "Email security (SPF / DMARC / DKIM)", "Exposure (Shodan InternetDB)",
        "TLS certificate", "Wayback Machine"]


def test_scan_security_sections_fail_independently(monkeypatch):
    from osint import domainsec

    def tls_down(d):
        raise RuntimeError("connection timed out")

    monkeypatch.setattr(domainsec, "tls_certificate", tls_down)
    monkeypatch.setattr(domainscan, "whois_lookup", lambda d: {"Domain": d})
    monkeypatch.setattr(domainscan, "dns_lookup", lambda d: {"A": []})
    monkeypatch.setattr(domainscan, "crtsh_lookup", lambda d: [])
    result = domainscan.scan("example.com")
    assert "connection timed out" in result.sections["TLS certificate"]["text"]
    assert result.sections["Wayback Machine"]["text"] == "stub"


def test_scan_warns_when_proxy_is_active(monkeypatch):
    from osint import net

    monkeypatch.setattr(domainscan, "whois_lookup", lambda d: {"Domain": d})
    monkeypatch.setattr(domainscan, "dns_lookup", lambda d: {"A": []})
    monkeypatch.setattr(domainscan, "crtsh_lookup", lambda d: [])
    net.set_proxy("socks5h://127.0.0.1:9050")
    try:
        result = domainscan.scan("example.com")
    finally:
        net.set_proxy(None)
    assert any("do not go through the proxy" in n for n in result.notes)


def test_scan_rejects_invalid_target():
    with pytest.raises(ValueError):
        domainscan.scan("not a domain")
