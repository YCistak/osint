"""Markdown report generation and saving."""

from datetime import datetime

from osint import report
from osint.models import FOUND, MISSING, UNKNOWN, Hit, ScanResult, bullets, kv, table, text

NOW = datetime(2026, 11, 1, 14, 30, 5)


def username_result() -> ScanResult:
    r = ScanResult("username", "jane")
    r.hits = [
        Hit("GitHub", "https://github.com/jane", FOUND, "HTTP 200"),
        Hit("Reddit", "https://reddit.com/user/jane", MISSING, "HTTP 404"),
        Hit("Weird|Site", "https://w.test/jane", UNKNOWN, "blocked (HTTP 403)"),
        Hit("Atlassian", "https://a.test/jane", FOUND),
    ]
    return r


def test_safe_name():
    assert report.safe_name("a@example.com") == "a@example.com"
    assert "/" not in report.safe_name("../../etc/passwd")
    assert report.safe_name("   ") == "target"
    assert len(report.safe_name("a" * 500)) <= 80


def test_username_markdown_lists_found_sorted_and_unknown():
    md = report.to_markdown(username_result(), NOW)
    assert md.startswith("# Username report: jane")
    assert "Checked: 4 · Found: 2 · Not found: 1 · Unknown: 1" in md
    assert md.index("| Atlassian |") < md.index("| GitHub |")  # sorted by name
    assert "Reddit" not in md  # not-found sites are not listed
    assert "Weird\\|Site" in md  # pipes are escaped in table cells
    assert "authorized research" in md  # legal note present
    assert "2026-11-01 14:30" in md


def test_markdown_for_no_hits_and_cancelled():
    r = ScanResult("username", "ghost", cancelled=True)
    r.hits = [Hit("GitHub", "u", MISSING)]
    md = report.to_markdown(r, NOW)
    assert "No accounts found." in md and "cancelled" in md


def test_section_rendering_kv_table_list_text_notes():
    r = ScanResult("email", "jane@example.com")
    r.sections["Info"] = kv({"Provider": "Google"})
    body = table(["Service", "Domain"], [["Spotify", "spotify.com"]])
    body["summary"] = {"Risk": "High"}
    body["footer"] = "1 of 3 registered"
    r.sections["Accounts"] = body
    r.sections["Subdomains"] = bullets(["a.example.com"])
    r.sections["Empty"] = text("Nothing here.")
    r.notes = ["Tip: run 'username jane'"]
    md = report.to_markdown(r, NOW)
    for expected in ["# Email report: jane@example.com", "- **Provider:** Google", "- **Risk:** High",
                     "| Service | Domain |", "| Spotify | spotify.com |", "1 of 3 registered",
                     "- `a.example.com`", "Nothing here.", "- Tip: run 'username jane'"]:
        assert expected in md


def test_save_default_name_in_given_dir_and_no_overwrite(tmp_path):
    r = username_result()
    p1 = report.save_report(r, tmp_path, NOW)
    assert p1.name == "username-jane-2026-11-01.md"
    assert p1.read_text(encoding="utf-8") == report.to_markdown(r, NOW)
    p2 = report.save_report(r, tmp_path, NOW)
    p3 = report.save_report(r, tmp_path, NOW)
    assert len({p1, p2, p3}) == 3 and p1.exists() and p2.exists() and p3.exists()


def test_save_to_explicit_file_path(tmp_path):
    p = report.save_report(username_result(), tmp_path / "out" / "mine.md", NOW)
    assert p == tmp_path / "out" / "mine.md" and p.exists()
    again = report.save_report(username_result(), tmp_path / "out" / "mine.md", NOW)
    assert again != p  # existing file is never overwritten


def test_save_default_dir_is_reports_and_env_override(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("OSINT_REPORT_DIR", raising=False)
    p = report.save_report(username_result(), None, NOW)
    assert p.parent.name == "reports" and (tmp_path / "reports").is_dir()
    monkeypatch.setenv("OSINT_REPORT_DIR", str(tmp_path / "elsewhere"))
    assert report.save_report(username_result(), None, NOW).parent == tmp_path / "elsewhere"


def test_hostile_target_cannot_escape_folder(tmp_path):
    r = ScanResult("domain", "../../evil")
    p = report.save_report(r, tmp_path, NOW)
    assert p.parent == tmp_path
