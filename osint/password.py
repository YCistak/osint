"""Password exposure check with the Have I Been Pwned "Pwned Passwords" range API.

k-anonymity: only the first 5 hex characters of the password's SHA-1 are sent;
the service answers with every known suffix for that prefix and the match is
done locally. The password and its full hash live only inside :func:`check`
and are never stored, logged, returned or written to a report.
"""

from __future__ import annotations

import hashlib
import re

import httpx

from . import net
from .models import ScanResult, kv, text

RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
HIDDEN_TARGET = "(hidden)"
USER_AGENT = "osint-cli (+https://github.com/YCistak/osint)"

COMMON_PATTERNS = ("password", "qwerty", "123456", "abcdef", "letmein", "iloveyou", "admin", "welcome")


class PasswordError(Exception):
    """The range API could not be queried."""


def split_hash(password: str) -> tuple[str, str]:
    """``(prefix, suffix)`` of the upper-case SHA-1 hex digest (5 + 35 characters)."""
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()  # noqa: S324 - required by the API
    return digest[:5], digest[5:]


def parse_range(body: str, suffix: str) -> int:
    """Count for ``suffix`` in a range answer (``SUFFIX:COUNT`` lines); padding rows have count 0."""
    suffix = suffix.upper()
    for line in body.splitlines():
        name, _, count = line.strip().partition(":")
        if name.upper() == suffix:
            try:
                return int(count.replace(",", "").strip() or 0)
            except ValueError:
                return 0
    return 0


def check(password: str, client: httpx.Client | None = None) -> int:
    """How many times the password appears in known breaches (0 = not found).

    Raises :class:`PasswordError` if the service cannot be reached.
    """
    prefix, suffix = split_hash(password)
    own = client is None
    client = client or net.sync_client(timeout=15.0)
    try:
        resp = client.get(RANGE_URL.format(prefix=prefix),
                          headers={"Add-Padding": "true", "User-Agent": USER_AGENT})
    except httpx.HTTPError as e:
        raise PasswordError(f"could not reach api.pwnedpasswords.com ({type(e).__name__})") from None
    finally:
        if own:
            client.close()
    if resp.status_code != 200:
        raise PasswordError(f"the Pwned Passwords service answered HTTP {resp.status_code}")
    return parse_range(resp.text, suffix)


def strength_hint(password: str) -> str:
    """Rough local strength note from length and character variety (not a guarantee)."""
    classes = sum(bool(re.search(p, password)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    lowered = password.lower()
    if any(p in lowered for p in COMMON_PATTERNS):
        return "weak: contains a very common pattern"
    if len(set(password)) <= 2 and password:
        return "weak: almost no variety"
    if len(password) < 8:
        return "weak: shorter than 8 characters"
    if len(password) >= 16 or (len(password) >= 12 and classes >= 3):
        return "strong: long and varied"
    if len(password) >= 10 and classes >= 2:
        return "fair: reasonable length, longer is better"
    return "weak: add length (12+ characters) and variety"


def build_result(count: int, hint: str) -> ScanResult:
    """The result for a finished check. Contains only the count and the hint."""
    result = ScanResult("password", HIDDEN_TARGET)
    if count > 0:
        verdict = f"Found in known breaches {count:,} time(s). Do not use it anywhere; change it where it is in use."
    else:
        verdict = "Not found in the Pwned Passwords data set (this is not proof that it is strong)."
    result.sections["Pwned Passwords"] = kv({"Times seen in breaches": f"{count:,}", "Verdict": verdict})
    result.sections["Local strength hint"] = text(hint.capitalize() + ".")
    result.notes.append(
        "Privacy: only the first 5 characters of the SHA-1 hash were sent (k-anonymity). "
        "The password is never stored, logged or saved in a report.")
    return result


def analyze(password: str, client: httpx.Client | None = None) -> ScanResult:
    """Check a password and return a result that carries no trace of it."""
    if not password:
        raise PasswordError("empty password")
    return build_result(check(password, client), strength_hint(password))
