"""Privacy self-audit: combine username, email, phone and password checks into one score.

The score is deliberately simple and fully explained: it starts at 100 and
every finding subtracts a fixed number of points (see :data:`FORMULA` and the
README). The table in the result lists each factor, what was found and the
points taken, so nothing about the number is hidden.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

# (factor, rule) rows documented in the README and printed with `--help`-style output.
FORMULA = [
    ("Accounts found for the username", "1 point per 2 accounts, max 15"),
    ("Services registered with the email", "1 point per 3 services, max 10"),
    ("Data breaches", "4 points per breach, max 28"),
    ("Passwords exposed in a breach", "8 points if any breach leaked passwords"),
    ("Recent breach (last 2 years)", "4 points"),
    ("Sensitive profile fields", "3 points per exposed field (location, company, public email, real name), max 12"),
    ("Email linked to a public profile", "5 points (Gravatar or GitHub profile found for the address)"),
    ("Phone number in recovery hints", "5 points if a service reveals a (masked) phone number"),
    ("Real email in public git commits", "6 points"),
    ("Your password found in breaches", "10 points"),
]
SENSITIVE_FIELDS = ("Location", "Company", "Email", "Name")
RECENT_YEARS = 2
BANDS = ((80, "good"), (50, "fair"), (0, "poor"))


def label_for(score: int) -> str:
    return next(name for floor, name in BANDS if score >= floor)


@dataclass
class Facts:
    """Everything the score and the recommendations are computed from."""

    username: str = ""
    email: str = ""
    phone: str = ""
    username_accounts: list[str] = field(default_factory=list)  # site names
    email_accounts: list[str] = field(default_factory=list)  # service names
    breaches: list[dict] = field(default_factory=list)  # {"name", "year", "data"}
    exposed_fields: dict[str, list[str]] = field(default_factory=dict)  # site -> sensitive fields
    email_profiles: list[str] = field(default_factory=list)  # "Gravatar", "GitHub"
    phone_hints: list[str] = field(default_factory=list)  # services that reveal a phone number
    git_emails: list[str] = field(default_factory=list)  # real addresses in public commits
    password_count: int | None = None  # None = not checked


def breach_year(breach: dict) -> int | None:
    y = str(breach.get("year", ""))[:4]
    return int(y) if y.isdigit() else None


def compute_score(f: Facts, now: datetime | None = None) -> tuple[int, list[list[str]]]:
    """Return ``(score, rows)`` where rows are ``[factor, what was found, points]``."""
    year = (now or datetime.now()).year
    rows: list[list[str]] = []

    def add(factor: str, found: str, points: int) -> None:
        rows.append([factor, found, f"-{points}" if points else "0"])

    if f.username:
        n = len(f.username_accounts)
        add("Username accounts", f"{n} found", min(15, n // 2))
    if f.email:
        n = len(f.email_accounts)
        add("Email-registered services", f"{n} found", min(10, n // 3))
        b = len(f.breaches)
        add("Data breaches", f"{b} found", min(28, 4 * b))
        leaked = [x for x in f.breaches if "password" in str(x.get("data", "")).lower()]
        add("Passwords exposed in breaches", f"{len(leaked)} breach(es)", 8 if leaked else 0)
        years = [y for y in (breach_year(x) for x in f.breaches) if y]
        recent = [y for y in years if y >= year - RECENT_YEARS]
        add("Recent breach (last 2 years)", "yes" if recent else "no", 4 if recent else 0)
        add("Email linked to a public profile", ", ".join(f.email_profiles) or "no", 5 if f.email_profiles else 0)
        add("Phone number in recovery hints", ", ".join(f.phone_hints[:3]) or "no", 5 if f.phone_hints else 0)
    fields = sum(len(v) for v in f.exposed_fields.values())
    if f.username or f.email:
        add("Sensitive profile fields", f"{fields} exposed", min(12, 3 * fields))
    if f.username or f.email:
        add("Real email in public git commits", ", ".join(f.git_emails[:2]) or "no", 6 if f.git_emails else 0)
    if f.password_count is not None:
        add("Your password in breaches", f"{f.password_count:,} time(s)" if f.password_count else "not found",
            10 if f.password_count else 0)
    total = sum(int(r[2].lstrip("-")) for r in rows)
    return max(0, 100 - total), rows


def recommendations(f: Facts, now: datetime | None = None) -> list[str]:
    """Concrete English advice, most important first."""
    year = (now or datetime.now()).year
    recs: list[str] = []
    if f.password_count:
        recs.append("The password you checked appears in known breaches: stop using it everywhere and "
                    "replace it with a unique one.")
    if f.breaches:
        dated = sorted((b for b in f.breaches if breach_year(b)), key=lambda b: breach_year(b), reverse=True)
        names = ", ".join(b["name"] for b in (dated or f.breaches)[:5])
        recs.append(f"Change passwords for services in these breaches: {names}"
                    + (f" (newest: {dated[0]['name']}, {breach_year(dated[0])})" if dated else "") + ".")
        classes = sorted({c.strip() for b in f.breaches for c in str(b.get("data", "")).split(",") if c.strip()})
        if any("password" in c.lower() for c in classes):
            recs.append("Passwords were exposed: change them everywhere you reused them, starting with email and banking.")
        if any(c.lower().startswith("phone") for c in classes):
            recs.append("Phone numbers were leaked: expect SMS phishing and do not use SMS as your only 2FA.")
    if f.git_emails:
        recs.append("Your real email address is visible in public git commits: enable 'Keep my email addresses "
                    "private' and 'Block command line pushes that expose my email' in GitHub settings, then use "
                    "your noreply address in git (git config user.email).")
    for site, fields in sorted(f.exposed_fields.items(), key=lambda kv: kv[0].lower()):
        for fld in fields:
            what = {"Email": "public email", "Name": "real name"}.get(fld, fld.lower())
            recs.append(f"Remove {what} from your {site} profile.")
    if f.phone_hints:
        recs.append(f"Services reveal a hint of your phone number ({', '.join(f.phone_hints[:3])}): remove it from "
                    "account recovery and use an authenticator app instead.")
    if f.email_profiles:
        recs.append(f"Your email address is tied to a public profile ({', '.join(f.email_profiles)}): use a "
                    "separate address for public profiles, or clear the details on that profile.")
    total_accounts = len(f.username_accounts) + len(f.email_accounts)
    if total_accounts >= 10:
        recs.append(f"Delete accounts you no longer use ({total_accounts} found): every account is one more "
                    "place that can be breached.")
    if f.username and len(f.username_accounts) >= 5:
        recs.append("The same username appears on many sites, which makes you easy to link: use different "
                    "usernames for unrelated services.")
    recs.append("Enable two-factor authentication (2FA) on email, banking, social and developer accounts; "
                "prefer an authenticator app over SMS.")
    recs.append("Use a password manager with a unique, random password for every service.")
    seen: set[str] = set()
    return [r for r in recs if not (r in seen or seen.add(r))]


# ---------------------------------------------------------------- facts from scan results

def exposed_profile_fields(result) -> dict[str, list[str]]:
    """Sensitive fields found in the profiles of a username scan, per site."""
    from .models import FOUND

    out: dict[str, list[str]] = {}
    for h in result.hits:
        if h.status != FOUND or not h.profile:
            continue
        got = []
        for fld in SENSITIVE_FIELDS:
            val = h.profile.get(fld, "")
            if not val:
                continue
            if fld == "Name" and (" " not in val.strip() or val.strip().lower() == result.target.lower()):
                continue  # a bare handle is not a real name
            got.append(fld)
        if got:
            out[h.name] = got
    return out


def facts_from_username(result, f: Facts) -> None:
    from .models import FOUND

    f.username_accounts = sorted({h.name for h in result.hits if h.status == FOUND}, key=str.lower)
    f.exposed_fields.update(exposed_profile_fields(result))


def facts_from_email(result, f: Facts) -> None:
    from .models import FOUND

    f.email_accounts = sorted({h.name for h in result.hits if h.status == FOUND}, key=str.lower)
    body = result.sections.get("Breaches") or {}
    if body.get("type") == "table":
        for row in body["rows"]:
            f.breaches.append({"name": row[0], "year": row[1] if len(row) > 1 else "",
                               "data": row[3] if len(row) > 3 else ""})
    profiles = (result.sections.get("Profiles") or {}).get("items", {})
    if any(k.startswith("Gravatar") for k in profiles):
        f.email_profiles.append("Gravatar")
    if "GitHub" in profiles:
        f.email_profiles.append("GitHub")
    f.phone_hints = sorted({h.name for h in result.hits if h.status == FOUND and "phone:" in h.detail}, key=str.lower)
    gravatar_loc = profiles.get("Gravatar location")
    if gravatar_loc:
        f.exposed_fields.setdefault("Gravatar", []).append("Location")


# ---------------------------------------------------------------- result

def _count_text(n: int, word: str) -> str:
    return f"{n} {word}"


def build_result(f: Facts, parts: dict, now: datetime | None = None) -> "ScanResult":
    """The final audit result. ``parts`` holds the sub-scan results:
    ``username``, ``email``, ``phone`` and ``github`` (any may be missing)."""
    from .models import ScanResult, FOUND, kv, steps, table, text

    label = " + ".join(x for x in (f.username, f.email, f.phone) if x) or "(nothing)"
    res = ScanResult("me", label)
    score, rows = compute_score(f, now)
    verdict = label_for(score)

    summary: dict[str, str] = {}
    if f.username:
        summary["Accounts (username)"] = f"{len(f.username_accounts)} found for '{f.username}'"
    if f.email:
        summary["Services (email)"] = f"{len(f.email_accounts)} registered with {f.email}"
        if f.breaches:
            dated = sorted((b for b in f.breaches if breach_year(b)), key=breach_year, reverse=True)
            newest = f"{dated[0]['name']} ({breach_year(dated[0])})" if dated else "unknown date"
            classes = sorted({c.strip() for b in f.breaches for c in str(b.get('data', '')).split(',') if c.strip()})
            summary["Breaches"] = f"{len(f.breaches)}; newest: {newest}"
            summary["Exposed data classes"] = ", ".join(classes[:12]) or "unknown"
        elif "email" in parts and parts["email"].sections.get("Breaches", {}).get("type") == "text" \
                and "Could not" in parts["email"].sections["Breaches"].get("text", ""):
            summary["Breaches"] = "could not be checked (service unavailable)"
        else:
            summary["Breaches"] = "none known"
    exposed = [f"{site}: {', '.join(flds)}" for site, flds in sorted(f.exposed_fields.items(), key=lambda kv: kv[0].lower())]
    if f.username or f.email:
        summary["Exposed profile fields"] = "; ".join(exposed) or "none found"
    if f.git_emails:
        summary["Emails in public git commits"] = ", ".join(f.git_emails[:3])
    if f.phone:
        ph = parts.get("phone")
        info = (ph.sections.get("Number", {}).get("items", {}) if ph else {})
        desc = ", ".join(x for x in (info.get("Country"), info.get("Carrier"), info.get("Line type")) if x)
        hint = ("revealed by: " + ", ".join(f.phone_hints[:3])) if f.phone_hints else "no recovery hint found"
        summary["Phone"] = f"{info.get('E.164', f.phone)} ({desc or 'unknown'}); {hint}"
    if f.password_count is not None:
        summary["Password check"] = (f"found {f.password_count:,} time(s) in breaches" if f.password_count
                                     else "not found in known breaches")
    res.sections["Summary"] = kv(summary)

    body = table(["Factor", "Found", "Points"], rows)
    body["summary"] = {"Privacy score": f"{score}/100 ({verdict})"}
    body["footer"] = ("Start at 100 and subtract the points above (never below 0). 80-100 good, 50-79 fair, "
                      "0-49 poor. Factors without input are not counted. The formula is in the README.")
    res.sections["Privacy score"] = body
    res.sections["Recommendations"] = steps(recommendations(f, now))

    if "username" in parts:
        found = [h for h in parts["username"].hits if h.status == FOUND]
        t = table(["Site", "URL", "Exposed fields"],
                  [[h.name, h.url, ", ".join(f.exposed_fields.get(h.name, [])) or "-"]
                   for h in sorted(found, key=lambda h: h.name.lower())])
        t["footer"] = f"{len(parts['username'].hits)} sites checked."
        res.sections[f"Accounts for username '{f.username}'"] = t
    if "email" in parts:
        for title in ("Breaches", "Registered accounts", "Profiles", "Mail server"):
            if title in parts["email"].sections:
                res.sections[f"Email: {title}"] = parts["email"].sections[title]
    if "phone" in parts:
        res.sections["Phone: Number"] = parts["phone"].sections["Number"]
    if "github" in parts:
        for title in ("Profile", "Emails in public commits"):
            if title in parts["github"].sections:
                res.sections[f"GitHub: {title}"] = parts["github"].sections[title]
    if not (f.username or f.email or f.phone):
        res.sections["Summary"] = text("Nothing to check: give a username, an email address or a phone number.")

    res.meta.update({
        "score": score, "verdict": verdict,
        "accounts": [f"username:{a}" for a in f.username_accounts] + [f"email:{a}" for a in f.email_accounts],
        "breaches": [b["name"] for b in f.breaches],
        "breakdown": [{"factor": r[0], "found": r[1], "points": int(r[2])} for r in rows],
    })
    for part in parts.values():
        res.cancelled = res.cancelled or part.cancelled
    return res


def classify_identifier(token: str) -> str:
    """'email', 'phone' or 'username' for a free-form token."""
    from .emailscan import email_valid

    t = token.strip()
    if "@" in t:
        return "email" if email_valid(t) else "invalid"
    digits = t.replace(" ", "").replace("-", "").replace("(", "").replace(")", "")
    if t.startswith("+") and digits[1:].isdigit() or (digits.isdigit() and len(digits) >= 7):
        return "phone"
    from .username import username_valid

    return "username" if username_valid(t) else "invalid"


def run(
    *,
    username: str = "",
    email: str = "",
    phone: str = "",
    region: str = "TR",
    pw: str | None = None,
    sites=None,
    console=None,
    progress: bool = True,
    github_lookup=None,
) -> "ScanResult":
    """Run every relevant scan for the given identifiers and build the audit.

    ``pw`` (optional) is checked against Pwned Passwords and then dropped; only the
    count is kept. Failures of single steps are noted, not fatal.
    """
    from . import github, password, phone as phone_mod, runner
    from .ui import info

    f = Facts(username=username, email=email, phone=phone)
    parts: dict = {}
    notes: list[str] = []

    if username:
        parts["username"] = runner.run_username(username, sites, console, progress=progress, print_hits=progress)
        facts_from_username(parts["username"], f)
    if email and not (parts.get("username") and parts["username"].cancelled):
        parts["email"] = runner.run_email(email, console, progress=progress)
        facts_from_email(parts["email"], f)
    if phone:
        try:
            parts["phone"] = phone_mod.analyze(phone, region.upper())
        except phone_mod.PhoneError as e:
            notes.append(f"Phone not analyzed: {e}")
            f.phone = ""
    if pw:
        if progress:
            info(console, "checking the password (only 5 hash characters leave this machine) ...")
        try:
            f.password_count = password.check(pw)
        except password.PasswordError as e:
            notes.append(f"Password not checked: {e}")
        pw = None

    login = ""
    if "GitHub" in f.username_accounts:
        login = username
    elif "email" in parts:
        gh = parts["email"].sections.get("Profiles", {}).get("items", {}).get("GitHub", "")
        login = gh.split(" ")[0] if gh else ""
    if login:
        if progress:
            info(console, f"reading public GitHub activity of {login} for exposed commit emails ...")
        try:
            parts["github"] = (github_lookup or github.analyze)(login)
            f.git_emails = list(parts["github"].meta.get("emails", []))
        except github.GitHubError as e:
            notes.append(f"GitHub commit emails not checked: {e}")

    result = build_result(f, parts)
    result.notes.extend(notes)
    return result


def parse_args(args: list[str]) -> tuple[dict[str, str], set[str], str]:
    """Parse REPL arguments: ``--username X --email Y --phone Z --region XX --password`` and free
    tokens (classified by shape). Returns ``(identifiers, flags, problem)``."""
    ids: dict[str, str] = {}
    flags: set[str] = set()
    it = iter(args)
    for a in it:
        if a in ("--username", "--email", "--phone", "--region"):
            value = next(it, "")
            if not value:
                return ids, flags, f"{a} needs a value"
            ids[a[2:]] = value
        elif a in ("--password", "--check-password"):
            flags.add("password")
        elif a.startswith("--"):
            return ids, flags, f"unknown flag: {a}"
        else:
            kind = classify_identifier(a)
            if kind == "invalid":
                return ids, flags, f"'{a}' is not a valid username, email address or phone number"
            if kind in ids:
                return ids, flags, f"more than one {kind} given"
            ids[kind] = a
    return ids, flags, ""
