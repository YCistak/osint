"""Domain security checks: SPF/DMARC/DKIM, Shodan InternetDB, TLS certificate, Wayback Machine.

Every function returns a section body (see ``models``) or raises
``RuntimeError``/``ValueError`` with a short reason; ``domainscan.scan`` turns
that into a per-section "Unavailable" note.
"""

from __future__ import annotations

import re

import dns.exception
import dns.resolver

from .models import table

DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1")
SPF_LOOKUP_MECHANISMS = ("include:", "a", "mx", "ptr", "exists:", "redirect=")


# ---------------------------------------------------------------- SPF / DMARC / DKIM

def txt_records(name: str, resolver: dns.resolver.Resolver | None = None) -> list[str]:
    """TXT strings of ``name`` (chunks joined). Missing names give an empty list."""
    if resolver is None:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5.0
    try:
        answer = resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.Timeout:
        raise RuntimeError(f"DNS timeout while asking for {name}")
    return ["".join(part.decode("utf-8", "replace") for part in rdata.strings) for rdata in answer]


def assess_spf(records: list[str]) -> tuple[str, str]:
    """``(record, assessment)`` for the TXT records of a domain."""
    spf = [r for r in records if r.lower().startswith("v=spf1")]
    if not spf:
        return "", "Missing: anyone can send mail that claims to come from this domain."
    if len(spf) > 1:
        return spf[0], "Invalid: more than one SPF record (receivers may reject all of them)."
    rec = spf[0]
    tokens = rec.lower().split()
    lookups = sum(1 for t in tokens[1:] if t.lstrip("+-~?").startswith(SPF_LOOKUP_MECHANISMS))
    notes = []
    if "-all" in tokens:
        verdict = "Good: strict policy (-all)."
    elif "~all" in tokens:
        verdict = "OK: soft fail (~all); -all is stricter."
    elif "?all" in tokens:
        verdict = "Weak: neutral (?all) gives no protection."
    elif "+all" in tokens or "all" in tokens:
        verdict = "Dangerous: +all allows any server to send."
    elif any(t.startswith("redirect=") for t in tokens):
        verdict = "Delegates to another domain (redirect=)."
    else:
        verdict = "Incomplete: no 'all' mechanism at the end."
    if lookups > 10:
        notes.append(f"{lookups} DNS-lookup mechanisms (the limit is 10; receivers may return permerror)")
    return rec, " ".join([verdict] + [n + "." for n in notes])


def parse_tags(record: str) -> dict[str, str]:
    """``'v=DMARC1; p=none'`` -> ``{'v': 'DMARC1', 'p': 'none'}``."""
    tags = {}
    for part in record.split(";"):
        key, sep, value = part.strip().partition("=")
        if sep:
            tags[key.strip().lower()] = value.strip()
    return tags


def assess_dmarc(records: list[str]) -> tuple[str, str]:
    dmarc = [r for r in records if r.lower().startswith("v=dmarc1")]
    if not dmarc:
        return "", "Missing: no policy against spoofed mail from this domain."
    rec = dmarc[0]
    tags = parse_tags(rec)
    policy = tags.get("p", "").lower()
    verdicts = {
        "reject": "Good: p=reject.",
        "quarantine": "OK: p=quarantine; p=reject is stricter.",
        "none": "Weak: p=none only monitors, spoofed mail is still delivered.",
    }
    verdict = verdicts.get(policy, "Invalid: missing or unknown p= policy.")
    extras = []
    if "rua" not in tags:
        extras.append("no rua= address for aggregate reports")
    pct = tags.get("pct")
    if pct and pct.isdigit() and int(pct) < 100:
        extras.append(f"policy applies to only {pct}% of mail")
    return rec, " ".join([verdict] + [e[0].upper() + e[1:] + "." for e in extras])


def assess_dkim(selector: str, records: list[str]) -> tuple[str, str]:
    keys = [r for r in records if "p=" in r.lower() or r.lower().startswith("v=dkim1")]
    if not keys:
        return "", "Not found"
    tags = parse_tags(keys[0])
    if not tags.get("p"):
        return keys[0], "Revoked key (empty p=)"
    return keys[0], "Key published"


def email_security(domain: str) -> dict:
    """SPF, DMARC and common DKIM selectors as one table."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    rows = []
    spf, verdict = assess_spf(txt_records(domain, resolver))
    rows.append(["SPF", _short(spf) or "-", verdict])
    dmarc, verdict = assess_dmarc(txt_records(f"_dmarc.{domain}", resolver))
    rows.append(["DMARC", _short(dmarc) or "-", verdict])
    found = 0
    for sel in DKIM_SELECTORS:
        try:
            rec, verdict = assess_dkim(sel, txt_records(f"{sel}._domainkey.{domain}", resolver))
        except RuntimeError:
            rec, verdict = "", "Lookup timed out"
        found += rec != ""
        rows.append([f"DKIM ({sel})", _short(rec) or "-", verdict])
    body = table(["Check", "Record", "Assessment"], rows)
    body["footer"] = ("DKIM selectors are guessed (default, google, selector1, selector2, k1); "
                      f"{'a missing one does not mean DKIM is off' if not found else str(found) + ' found'}.")
    return body


def _short(value: str, limit: int = 90) -> str:
    return value if len(value) <= limit else value[: limit - 3] + "..."
