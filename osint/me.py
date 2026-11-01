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
