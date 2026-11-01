"""Privacy self-audit: score formula, recommendations, result layout, CLI, REPL and reports."""

import io
import json
import sys
from datetime import datetime

import httpx
import pytest
from rich.console import Console

from osint import cli, github, me, password, phone, repl, report, runner
from osint.models import FOUND, MISSING, Hit, ScanResult, kv, table, text
from osint.sites import Site

NOW = datetime(2026, 6, 1)


def breach(name, year, data="Email addresses"):
    return {"name": name, "year": str(year), "data": data}


def test_label_bands():
    assert [me.label_for(s) for s in (100, 80, 79, 50, 49, 0)] == ["good", "good", "fair", "fair", "poor", "poor"]


def test_score_with_nothing_found_is_100():
    f = me.Facts(username="x", email="a@b.test")
    score, rows = me.compute_score(f, NOW)
    assert score == 100 and all(r[2] == "0" for r in rows)


def test_each_factor_points_and_caps():
    f = me.Facts(username="x", username_accounts=[f"S{i}" for i in range(40)])
    assert me.compute_score(f, NOW)[0] == 85  # 40 // 2 = 20, capped at 15
    f = me.Facts(email="a@b.test", email_accounts=[f"S{i}" for i in range(30)])
    assert me.compute_score(f, NOW)[0] == 90  # 30 // 3 = 10, cap 10
    f = me.Facts(email="a@b.test", breaches=[breach(f"B{i}", 2015) for i in range(9)])
    assert me.compute_score(f, NOW)[0] == 72  # 9 * 4 = 36, cap 28
    f = me.Facts(email="a@b.test", breaches=[breach("A", 2015, "Passwords, Email addresses")])
    assert me.compute_score(f, NOW)[0] == 100 - 4 - 8
    f = me.Facts(email="a@b.test", breaches=[breach("A", 2025)])
    assert me.compute_score(f, NOW)[0] == 100 - 4 - 4  # breach + recent
    f = me.Facts(email="a@b.test", breaches=[breach("A", 2024)])  # 2024 >= 2026 - 2
    assert me.compute_score(f, NOW)[0] == 92
    f = me.Facts(email="a@b.test", breaches=[breach("A", 2023)])
    assert me.compute_score(f, NOW)[0] == 96


def test_profile_phone_git_password_factors():
    f = me.Facts(username="x", exposed_fields={"GitHub": ["Location", "Company"], "Reddit": ["Name"]})
    assert me.compute_score(f, NOW)[0] == 100 - 9
    f = me.Facts(username="x", exposed_fields={"A": ["Location"] * 6})
    assert me.compute_score(f, NOW)[0] == 88  # cap 12
    f = me.Facts(email="a@b.test", email_profiles=["Gravatar"], phone_hints=["Amazon"])
    assert me.compute_score(f, NOW)[0] == 90
    f = me.Facts(username="x", git_emails=["me@home.test"])
    assert me.compute_score(f, NOW)[0] == 94
    assert me.compute_score(me.Facts(password_count=5), NOW)[0] == 90
    assert me.compute_score(me.Facts(password_count=0), NOW)[0] == 100


def test_score_never_below_zero():
    f = me.Facts(username="x", email="a@b.test", username_accounts=["s"] * 100, email_accounts=["s"] * 100,
                 breaches=[breach(f"B{i}", 2026, "Passwords") for i in range(20)],
                 exposed_fields={"A": ["Location", "Company", "Email", "Name"]}, email_profiles=["GitHub"],
                 phone_hints=["x"], git_emails=["a@b"], password_count=3)
    score, rows = me.compute_score(f, NOW)
    assert score == 0
    assert sum(int(r[2].lstrip("-")) for r in rows) > 100


def test_rows_only_for_given_inputs():
    _, rows = me.compute_score(me.Facts(phone="+90555"), NOW)
    assert rows == []
    _, rows = me.compute_score(me.Facts(username="x"), NOW)
    assert [r[0] for r in rows] == ["Username accounts", "Sensitive profile fields", "Real email in public git commits"]


def test_recommendations_are_concrete():
    f = me.Facts(username="x", email="a@b.test", username_accounts=["GitHub"] * 6, email_accounts=["a"] * 6,
                 breaches=[breach("Adobe", 2013, "Passwords, Email addresses"), breach("Dubsmash", 2018, "Phone numbers")],
                 exposed_fields={"GitHub": ["Location", "Email"]}, git_emails=["me@home.test"],
                 email_profiles=["Gravatar"], phone_hints=["Amazon"], password_count=7)
    recs = me.recommendations(f, NOW)
    text_ = "\n".join(recs)
    assert recs[0].startswith("The password you checked")
    assert "Change passwords for services in these breaches: Dubsmash, Adobe (newest: Dubsmash, 2018)." in text_
    assert "Remove location from your GitHub profile." in text_
    assert "Remove public email from your GitHub profile." in text_
    assert "Keep my email addresses private" in text_
    assert "Phone numbers were leaked" in text_ and "Amazon" in text_
    assert "Enable two-factor authentication (2FA)" in text_ and "password manager" in text_
    assert len(recs) == len(set(recs))


def test_recommendations_minimal_still_has_basics():
    recs = me.recommendations(me.Facts(username="x"), NOW)
    assert len(recs) == 2 and "2FA" in recs[0]


def test_classify_identifier():
    assert me.classify_identifier("jane@example.com") == "email"
    assert me.classify_identifier("+905551112233") == "phone"
    assert me.classify_identifier("0555 111 22 33") == "phone"
    assert me.classify_identifier("torvalds") == "username"
    assert me.classify_identifier("not an@email") == "invalid"
    assert me.classify_identifier("bad name!") == "invalid"


def test_parse_args():
    ids, flags, problem = me.parse_args(["torvalds", "a@b.test", "+905551112233", "--password"])
    assert ids == {"username": "torvalds", "email": "a@b.test", "phone": "+905551112233"} and flags == {"password"}
    assert me.parse_args(["--username", "x", "--region", "DE"])[0] == {"username": "x", "region": "DE"}
    assert "needs a value" in me.parse_args(["--email"])[2]
    assert "unknown flag" in me.parse_args(["--bogus"])[2]
    assert "more than one username" in me.parse_args(["a", "b"])[2]
    assert "not a valid" in me.parse_args(["bad name!"])[2]


# ---- facts from scan results ------------------------------------------------------

def sample_results():
    user = ScanResult("username", "jane")
    user.hits = [Hit("GitHub", "https://github.com/jane", FOUND, profile={"Name": "Jane Doe", "Location": "Istanbul", "Company": "ACME"}),
                 Hit("Reddit", "https://reddit.com/u/jane", FOUND, profile={"Name": "jane"}),
                 Hit("Gone", "https://g.test", MISSING)]
    mail = ScanResult("email", "jane@example.com")
    mail.hits = [Hit("Spotify", "spotify.com", FOUND), Hit("Amazon", "amazon.com", FOUND, "phone: ***1234"),
                 Hit("Nope", "n.test", MISSING)]
    mail.sections["Breaches"] = table(["Breach", "Year", "Records", "Exposed data"],
                                      [["Adobe", "2013", "1", "Passwords, Email addresses"], ["Dubsmash", "2018", "2", "Phone numbers"]])
    mail.sections["Profiles"] = kv({"Gravatar name": "Jane", "Gravatar location": "Izmir", "GitHub": "jane (https://github.com/jane)"})
    return user, mail


def test_facts_from_results():
    user, mail = sample_results()
    f = me.Facts(username="jane", email="jane@example.com")
    me.facts_from_username(user, f)
    me.facts_from_email(mail, f)
    assert f.username_accounts == ["GitHub", "Reddit"]
    assert f.exposed_fields["GitHub"] == ["Location", "Company", "Name"]
    assert "Reddit" not in f.exposed_fields  # a bare handle is not a real name
    assert f.exposed_fields["Gravatar"] == ["Location"]
    assert f.email_accounts == ["Amazon", "Spotify"] and f.phone_hints == ["Amazon"]
    assert [b["name"] for b in f.breaches] == ["Adobe", "Dubsmash"]
    assert f.email_profiles == ["Gravatar", "GitHub"]


def test_build_result_layout_and_meta():
    user, mail = sample_results()
    f = me.Facts(username="jane", email="jane@example.com", phone="+905551112233", password_count=0)
    me.facts_from_username(user, f)
    me.facts_from_email(mail, f)
    ph = phone.analyze("+905551112233")
    res = me.build_result(f, {"username": user, "email": mail, "phone": ph}, NOW)
    titles = list(res.sections)
    assert titles[:3] == ["Summary", "Privacy score", "Recommendations"]
    assert "Accounts for username 'jane'" in titles and "Email: Breaches" in titles and "Phone: Number" in titles
    summary = res.sections["Summary"]["items"]
    assert summary["Breaches"] == "2; newest: Dubsmash (2018)"
    assert "Passwords" in summary["Exposed data classes"]
    assert "GitHub: Location, Company, Name" in summary["Exposed profile fields"]
    assert "revealed by: Amazon" in summary["Phone"] and "Turkey" in summary["Phone"]
    assert summary["Password check"] == "not found in known breaches"
    score = res.meta["score"]
    assert res.sections["Privacy score"]["summary"]["Privacy score"] == f"{score}/100 ({me.label_for(score)})"
    assert res.target == "jane + jane@example.com + +905551112233"
    assert res.meta["breaches"] == ["Adobe", "Dubsmash"] and "username:GitHub" in res.meta["accounts"]
    assert {b["factor"] for b in res.meta["breakdown"]} >= {"Data breaches", "Username accounts"}


def test_build_result_unchecked_breaches_not_called_clean():
    mail = ScanResult("email", "a@b.test")
    mail.sections["Breaches"] = text("Could not check XposedOrNot (service unavailable or rate limited).")
    f = me.Facts(email="a@b.test")
    me.facts_from_email(mail, f)
    res = me.build_result(f, {"email": mail}, NOW)
    assert "could not be checked" in res.sections["Summary"]["items"]["Breaches"]


# ---- run() -----------------------------------------------------------------------

@pytest.fixture
def fake_scans(monkeypatch):
    user, mail = sample_results()
    calls = []
    monkeypatch.setattr(runner, "run_username", lambda name, *a, **k: calls.append(("user", name)) or user)
    monkeypatch.setattr(runner, "run_email", lambda addr, *a, **k: calls.append(("email", addr)) or mail)
    monkeypatch.setattr(password, "check", lambda pw: calls.append(("pw", len(pw))) or 12)
    return calls


def gh_result(*a):
    r = ScanResult("github", "jane")
    r.sections["Profile"] = kv({"Login": "jane"})
    r.sections["Emails in public commits"] = table(["Address"], [["jane@home.test"]])
    r.meta["emails"] = ["jane@home.test"]
    return r


def test_run_all_inputs(fake_scans):
    console = Console(file=io.StringIO())
    res = me.run(username="jane", email="jane@example.com", phone="+905551112233", pw="secret-pw",
                 sites=[], console=console, progress=False, github_lookup=gh_result)
    assert [c[0] for c in fake_scans] == ["user", "email", "pw"]
    assert "GitHub: Emails in public commits" in res.sections
    f_summary = res.sections["Summary"]["items"]
    assert f_summary["Password check"] == "found 12 time(s) in breaches"
    assert "jane@home.test" in f_summary["Emails in public git commits"]
    assert "secret-pw" not in json.dumps(res.to_dict())


def test_run_skips_blank_inputs(fake_scans):
    res = me.run(email="a@b.test", sites=[], console=Console(file=io.StringIO()), progress=False,
                 github_lookup=gh_result)
    assert [c[0] for c in fake_scans] == ["email"]
    assert "Accounts for username" not in " ".join(res.sections)


def test_run_survives_failing_steps(fake_scans, monkeypatch):
    monkeypatch.setattr(password, "check", lambda pw: (_ for _ in ()).throw(password.PasswordError("down")))

    def gh_down(login):
        raise github.GitHubError("rate limit reached")

    res = me.run(username="jane", email="jane@example.com", phone="nonsense", pw="x", sites=[],
                 console=Console(file=io.StringIO()), progress=False, github_lookup=gh_down)
    notes = " ".join(res.notes)
    assert "Phone not analyzed" in notes and "Password not checked: down" in notes and "rate limit reached" in notes
    assert "Password check" not in res.sections["Summary"]["items"]
    assert 0 <= res.meta["score"] <= 100


# ---- CLI ------------------------------------------------------------------------------

def test_cli_requires_input_and_validates(capsys):
    assert cli.main(["me", "--no-banner"]) == 2
    assert cli.main(["me", "--username", "bad name!", "--no-banner"]) == 2
    assert cli.main(["me", "--email", "nope", "--no-banner"]) == 2
    assert cli.main(["me", "--phone", "123", "--region", "ZZ", "--no-banner"]) == 2


def test_cli_json_has_score_and_no_password(fake_scans, monkeypatch, capsys):
    monkeypatch.setattr(github, "analyze", gh_result)
    monkeypatch.setattr(sys, "stdin", io.StringIO("hunter2-secret\n"))
    code = cli.main(["me", "--username", "jane", "--email", "jane@example.com", "--check-password", "--json", "--no-banner"])
    out = capsys.readouterr()
    assert code == 0
    data = json.loads(out.out)
    assert data["kind"] == "me" and 0 <= data["meta"]["score"] <= 100
    assert "Recommendations" in data["sections"]
    assert "hunter2-secret" not in out.out + out.err
    assert ("pw", len("hunter2-secret")) in fake_scans


def test_cli_save_markdown_and_html(fake_scans, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(github, "analyze", gh_result)
    assert cli.main(["me", "--username", "jane", "--no-banner", "--save", str(tmp_path)]) == 0
    assert cli.main(["me", "--username", "jane", "--no-banner", "--save", str(tmp_path), "--html"]) == 0
    md = next(tmp_path.glob("*.md")).read_text()
    html = next(tmp_path.glob("*.html")).read_text()
    assert "# Privacy self-audit: jane" in md and "## Privacy score" in md and "| Factor | Found | Points |" in md
    assert "1. " in md.split("## Recommendations")[1]
    assert "<ol><li>" in html and "Privacy score" in html and "<title>Privacy self-audit: jane</title>" in html


# ---- REPL -------------------------------------------------------------------------------

def make_session(lines=(), secrets=(), yes=False):
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, width=140, highlight=False)
    s = repl.Session(console, [Site("Demo", "https://demo.test/{username}")])
    answers, sec = iter(lines), iter(secrets)
    s.line = lambda p: next(answers, "")
    s.secret = lambda p: next(sec, "")
    s.ask = lambda p: "y" if yes else "n"
    return s, buf


def test_repl_free_form_line(fake_scans, monkeypatch):
    monkeypatch.setattr(github, "analyze", gh_result)
    s, buf = make_session()
    repl.execute(s, "me jane jane@example.com")
    assert [c[0] for c in fake_scans] == ["user", "email"]
    out = buf.getvalue()
    assert "Privacy score" in out and "Recommendations" in out and "1. " in out
    assert s.last.kind == "me"


def test_repl_ask_mode_skips_blanks_and_hides_password(fake_scans, monkeypatch):
    monkeypatch.setattr(github, "analyze", gh_result)
    s, buf = make_session(lines=["jane", "", ""], secrets=["topsecret-pw"], yes=True)
    repl.execute(s, "me")  # enters the category
    repl.execute(s, "ask")
    assert [c[0] for c in fake_scans] == ["user", "pw"]
    assert "topsecret-pw" not in buf.getvalue()


def test_repl_errors(fake_scans):
    s, buf = make_session()
    repl.execute(s, "me bad name!")
    repl.execute(s, "me --bogus")
    repl.execute(s, "me --region DE")
    out = buf.getvalue()
    assert out.count("[!]") >= 3 and fake_scans == []


def test_repl_ask_with_nothing(fake_scans):
    s, buf = make_session(lines=["", "", ""])
    repl.execute(s, "me")
    repl.execute(s, "ask")
    assert "nothing to check" in buf.getvalue() and fake_scans == []
