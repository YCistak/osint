import re
from datetime import datetime

from osint import report
from osint.html_report import safe_url, to_html
from osint.models import FOUND, UNKNOWN, Hit, ScanResult, kv, table, text

XSS = '<script>alert(1)</script>'


def evil_result():
    r = ScanResult("username", f'x"{XSS}')
    r.hits = [
        Hit(XSS, 'https://ok.test/a"onmouseover="x', FOUND,
            profile={"Name": XSS, "Bio": "<img src=x onerror=alert(1)>", "Avatar": "javascript:alert(1)"}),
        Hit("Good", "https://good.test/u", FOUND, profile={"Name": "N", "Avatar": "https://img.test/a.png"}),
        Hit("Odd", "javascript:alert(2)", FOUND),
        Hit("Blocked", "https://b.test", UNKNOWN, XSS),
    ]
    r.sections["Evil " + XSS] = kv({XSS: XSS, "Link": "https://x.test/?a=1&b=2"})
    r.sections["T"] = table(["h" + XSS], [[XSS, "javascript:alert(3)"]])
    r.sections["Msg"] = text(XSS)
    r.notes.append(XSS)
    return r


def test_no_raw_html_from_external_data_survives():
    out = to_html(evil_result(), datetime(2026, 1, 2, 3, 4))
    assert XSS not in out and "<img src=x" not in out
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in out
    # exactly the tags we write ourselves: no <script> element anywhere
    assert not re.search(r"<script", out, re.I)
    # no event-handler attribute could be injected into a tag
    assert not re.search(r"<[^>]+\sonmouseover=", out) and not re.search(r"<[^>]+\sonerror=", out)


def test_only_http_urls_become_links_or_images():
    out = to_html(evil_result())
    assert 'href="javascript' not in out and 'src="javascript' not in out
    assert 'href="https://good.test/u"' in out and 'src="https://img.test/a.png"' in out
    assert 'rel="noopener noreferrer nofollow"' in out
    assert safe_url("https://a.test/x") and not safe_url("javascript:1") and not safe_url("//a.test")
    assert not safe_url('https://a.test/" onclick="x')


def test_self_contained_dark_page_with_sections():
    out = to_html(evil_result())
    assert out.startswith("<!doctype html>") and "<style>" in out and "color-scheme:dark" in out
    assert not re.search(r'<link[^>]+rel="stylesheet"', out)
    for h in ("Found accounts", "Unknown (check manually)", "Notes", "T"):
        assert f"<h2>{h}</h2>" in out
    assert "a=1&amp;b=2" in out


def test_save_format_detection_and_never_overwrites(tmp_path):
    r = ScanResult("phone", "+90555")
    r.sections["Number"] = kv({"Valid": "yes"})
    now = datetime(2026, 1, 2, 3, 4, 5)
    a = report.save_report(r, tmp_path / "r.html", now)
    assert a.suffix == ".html" and a.read_text().startswith("<!doctype html>")
    b = report.save_report(r, tmp_path / "r.html", now)
    assert b != a and b.suffix == ".html"
    c = report.save_report(r, tmp_path, now, fmt="html")
    assert c.suffix == ".html" and c.parent == tmp_path
    d = report.save_report(r, tmp_path, now)
    assert d.suffix == ".md"
    assert report.resolve_format("x.HTM", None) == "html" and report.resolve_format("x", "md") == "md"
