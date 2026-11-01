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
