"""SPF/DMARC/DKIM assessment, InternetDB, TLS certificate parsing and Wayback summary (all offline)."""

import httpx
import pytest

from osint import domainsec


# ---- SPF / DMARC / DKIM --------------------------------------------------------

@pytest.mark.parametrize("records,word", [
    ([], "Missing"),
    (["v=spf1 include:_spf.google.com -all"], "Good"),
    (["v=spf1 mx ~all"], "soft fail"),
    (["v=spf1 ?all"], "Weak"),
    (["v=spf1 +all"], "Dangerous"),
    (["v=spf1 ip4:1.2.3.4"], "Incomplete"),
    (["v=spf1 redirect=_spf.example.com"], "redirect"),
    (["v=spf1 -all", "v=spf1 ~all"], "more than one"),
    (["google-site-verification=abc"], "Missing"),
])
def test_assess_spf(records, word):
    assert word in domainsec.assess_spf(records)[1]


def test_spf_lookup_limit_warning():
    rec = "v=spf1 " + " ".join(f"include:s{i}.example.com" for i in range(11)) + " -all"
    assert "limit is 10" in domainsec.assess_spf([rec])[1]


@pytest.mark.parametrize("rec,word", [
    ("v=DMARC1; p=reject; rua=mailto:a@b.c", "Good"),
    ("v=DMARC1; p=quarantine; rua=mailto:a@b.c", "p=quarantine"),
    ("v=DMARC1; p=none", "Weak"),
    ("v=DMARC1; rua=mailto:a@b.c", "Invalid"),
])
def test_assess_dmarc(rec, word):
    assert word in domainsec.assess_dmarc([rec])[1]


def test_dmarc_extras_and_missing():
    assert "rua" in domainsec.assess_dmarc(["v=DMARC1; p=reject"])[1]
    assert "50%" in domainsec.assess_dmarc(["v=DMARC1; p=reject; pct=50; rua=mailto:x@y.z"])[1]
    assert "Missing" in domainsec.assess_dmarc([])[1]


def test_assess_dkim():
    assert domainsec.assess_dkim("default", [])[1] == "Not found"
    assert domainsec.assess_dkim("k1", ["v=DKIM1; k=rsa; p=MIGf"])[1] == "Key published"
    assert "Revoked" in domainsec.assess_dkim("k1", ["v=DKIM1; p="])[1]


def test_email_security_table(monkeypatch):
    answers = {
        "example.com": ["v=spf1 -all"],
        "_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:r@example.com"],
        "google._domainkey.example.com": ["v=DKIM1; k=rsa; p=ABC"],
    }
    monkeypatch.setattr(domainsec, "txt_records", lambda name, resolver=None: answers.get(name, []))
    body = domainsec.email_security("example.com")
    rows = {r[0]: r for r in body["rows"]}
    assert "Good" in rows["SPF"][2] and "Good" in rows["DMARC"][2]
    assert rows["DKIM (google)"][2] == "Key published" and rows["DKIM (default)"][2] == "Not found"
    assert [r[0] for r in body["rows"]][2:] == [f"DKIM ({s})" for s in domainsec.DKIM_SELECTORS]
    assert "1 found" in body["footer"]


# ---- InternetDB ----------------------------------------------------------------

def db_client(status=200, payload=None, boom=False):
    def handler(request):
        if boom:
            raise httpx.ConnectError("x")
        return httpx.Response(status, json=payload or {})

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_exposure_rows():
    payload = {"ip": "1.1.1.1", "ports": [443, 80], "hostnames": ["one.one.one.one"],
               "vulns": [f"CVE-2020-{i}" for i in range(10)], "tags": ["cdn"]}
    body = domainsec.exposure(["1.1.1.1"], db_client(200, payload))
    row = body["rows"][0]
    assert row[:3] == ["1.1.1.1", "80, 443", "one.one.one.one"]
    assert "(+2 more)" in row[3] and row[4] == "cdn"


def test_exposure_no_data_and_errors():
    assert "No data" in domainsec.exposure(["9.9.9.9"], db_client(404))["rows"][0][4]
    with pytest.raises(RuntimeError, match="HTTP 500"):
        domainsec.exposure(["9.9.9.9"], db_client(500))
    with pytest.raises(RuntimeError, match="could not reach"):
        domainsec.exposure(["9.9.9.9"], db_client(boom=True))
    with pytest.raises(ValueError):
        domainsec.exposure([])


# ---- TLS -----------------------------------------------------------------------

CERT = {
    "subject": ((("commonName", "example.com"),),),
    "issuer": ((("countryName", "US"),), (("organizationName", "Let's Encrypt"),), (("commonName", "R11"),)),
    "notBefore": "Jan  1 00:00:00 2026 GMT",
    "notAfter": "Apr  1 00:00:00 2026 GMT",
    "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com"), ("IP Address", "1.2.3.4")),
    "serialNumber": "ABC123",
}


def test_parse_cert_days_left_and_fields():
    import ssl

    now = ssl.cert_time_to_seconds("Mar 20 00:00:00 2026 GMT")
    out = domainsec.parse_cert(CERT, now=now)
    assert out["Subject"] == "commonName=example.com"
    assert "Let's Encrypt" in out["Issuer"]
    assert out["Valid until"] == "2026-04-01 00:00 UTC"
    assert out["Time left"] == "12 day(s) left (renew soon)"
    assert out["Alternative names"] == "example.com, www.example.com"


def test_parse_cert_expired():
    import ssl

    now = ssl.cert_time_to_seconds("Apr 11 00:00:00 2026 GMT")
    assert domainsec.parse_cert(CERT, now=now)["Time left"] == "EXPIRED 10 day(s) ago"


def test_tls_certificate_uses_fetcher_and_propagates_errors():
    body = domainsec.tls_certificate("example.com", fetch=lambda host: CERT)
    assert body["items"]["Serial number"] == "ABC123"

    def bad(host):
        raise RuntimeError("certificate did not validate: self-signed")

    with pytest.raises(RuntimeError, match="self-signed"):
        domainsec.tls_certificate("example.com", fetch=bad)


def test_fetch_cert_connection_refused_is_runtime_error():
    with pytest.raises(RuntimeError, match="could not connect"):
        domainsec.fetch_cert("127.0.0.1", port=1, timeout=1.0)


# ---- Wayback -------------------------------------------------------------------

def cdx_client(payload, status=200, text=None):
    def handler(request):
        if text is not None:
            return httpx.Response(status, text=text)
        return httpx.Response(status, json=payload)

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_parse_cdx_skips_header():
    assert domainsec.parse_cdx([["timestamp"], ["20020120142510"], ["20250101000000"]]) == [
        "20020120142510", "20250101000000"]
    with pytest.raises(ValueError):
        domainsec.parse_cdx({"x": 1})


def test_wayback_summary():
    body = domainsec.wayback_summary(
        "example.com", cdx_client([["timestamp"], ["20020120142510"], ["20100101000000"], ["20250601000000"]]))
    items = body["items"]
    assert items["First snapshot"] == "2002-01-20" and items["Last snapshot"] == "2025-06-01"
    assert items["Months with snapshots"] == "3"
    assert items["First snapshot link"] == "https://web.archive.org/web/20020120142510/example.com"


def test_wayback_empty_and_errors():
    assert domainsec.wayback_summary("x.test", cdx_client(None, text=""))["items"]["Snapshots"] == "none archived"
    assert domainsec.wayback_summary("x.test", cdx_client([["timestamp"]]))["items"]["Snapshots"] == "none archived"
    with pytest.raises(RuntimeError, match="HTTP 503"):
        domainsec.wayback_summary("x.test", cdx_client(None, status=503, text="busy"))
    with pytest.raises(RuntimeError, match="invalid"):
        domainsec.wayback_summary("x.test", cdx_client(None, text="not json"))
