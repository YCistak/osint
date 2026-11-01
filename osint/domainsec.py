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


# ---------------------------------------------------------------- Shodan InternetDB

INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"


def resolve_a(domain: str) -> list[str]:
    """IPv4 addresses of ``domain`` (empty when there is no A record)."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    try:
        return sorted(r.to_text() for r in resolver.resolve(domain, "A"))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.Timeout:
        raise RuntimeError("DNS timeout while resolving A records")


def internetdb_lookup(ip: str, client) -> dict | None:
    """The InternetDB record for ``ip``, or ``None`` when Shodan has no data (HTTP 404)."""
    import httpx

    try:
        resp = client.get(INTERNETDB_URL.format(ip=ip))
    except httpx.HTTPError as e:
        raise RuntimeError(f"could not reach internetdb.shodan.io ({type(e).__name__})")
    if resp.status_code == 404:
        return None
    if resp.status_code != 200:
        raise RuntimeError(f"InternetDB answered HTTP {resp.status_code}")
    try:
        data = resp.json()
    except ValueError:
        raise RuntimeError("InternetDB returned an invalid answer")
    return data if isinstance(data, dict) else None


def internetdb_rows(ip: str, data: dict | None) -> list[str]:
    if not data:
        return [ip, "-", "-", "-", "No data in Shodan InternetDB"]
    ports = ", ".join(str(p) for p in sorted(data.get("ports") or []))
    names = ", ".join(sorted(data.get("hostnames") or []))
    vulns = sorted(data.get("vulns") or [])
    shown = ", ".join(vulns[:8]) + (f" (+{len(vulns) - 8} more)" if len(vulns) > 8 else "")
    return [ip, ports or "-", names or "-", shown or "none listed", ", ".join(data.get("tags") or []) or "-"]


def exposure(ips: list[str], client=None) -> dict:
    """Open ports, hostnames and known CVEs per IP (passive: Shodan's data, no scanning from here)."""
    from . import net

    if not ips:
        raise ValueError("no A record to look up")
    own = client is None
    client = client or net.sync_client(timeout=10.0)
    try:
        rows = [internetdb_rows(ip, internetdb_lookup(ip, client)) for ip in ips[:10]]
    finally:
        if own:
            client.close()
    body = table(["IP", "Open ports", "Hostnames", "Vulnerabilities (CVE)", "Tags"], rows)
    body["footer"] = "Passive data from Shodan InternetDB; nothing was scanned from this machine. Listed CVEs are candidates, not confirmed."
    return body


# ---------------------------------------------------------------- TLS certificate

def _name_text(rdns) -> str:
    return ", ".join(f"{k}={v}" for rdn in rdns for k, v in rdn)


def parse_cert(cert: dict, now: float | None = None) -> dict[str, str]:
    """Readable fields of an ``ssl.getpeercert()`` dict."""
    import ssl
    import time

    now = now if now is not None else time.time()
    not_before = ssl.cert_time_to_seconds(cert["notBefore"])
    not_after = ssl.cert_time_to_seconds(cert["notAfter"])
    days_left = int((not_after - now) // 86400)
    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    if days_left < 0:
        status = f"EXPIRED {-days_left} day(s) ago"
    elif days_left < 14:
        status = f"{days_left} day(s) left (renew soon)"
    else:
        status = f"{days_left} day(s) left"
    out = {
        "Subject": _name_text(cert.get("subject", ())),
        "Issuer": _name_text(cert.get("issuer", ())),
        "Valid from": _fmt_time(not_before),
        "Valid until": _fmt_time(not_after),
        "Time left": status,
        "Alternative names": ", ".join(sans[:15]) + (f" (+{len(sans) - 15} more)" if len(sans) > 15 else ""),
        "Serial number": str(cert.get("serialNumber", "")),
    }
    return {k: v for k, v in out.items() if v}


def _fmt_time(ts: float) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def fetch_cert(host: str, port: int = 443, timeout: float = 6.0) -> dict:
    """Connect, validate against the system trust store and return the peer certificate."""
    import socket
    import ssl

    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                return tls.getpeercert()
    except ssl.SSLCertVerificationError as e:
        raise RuntimeError(f"certificate did not validate: {e.verify_message or e}")
    except ssl.SSLError as e:
        raise RuntimeError(f"TLS handshake failed ({e.reason or type(e).__name__})")
    except socket.timeout:
        raise RuntimeError(f"connection to {host}:{port} timed out")
    except OSError as e:
        raise RuntimeError(f"could not connect to {host}:{port} ({type(e).__name__})")


def tls_certificate(domain: str, fetch=fetch_cert) -> dict:
    from .models import kv

    cert = fetch(domain)
    return kv(parse_cert(cert))


# ---------------------------------------------------------------- Wayback Machine

CDX_URL = "https://web.archive.org/cdx/search/cdx"


def parse_cdx(payload) -> list[str]:
    """Timestamps from a CDX ``output=json`` answer (the first row is the header)."""
    if not isinstance(payload, list):
        raise ValueError("unexpected CDX answer")
    return [row[0] for row in payload[1:] if isinstance(row, list) and row and str(row[0]).isdigit()]


def _stamp(ts: str) -> str:
    return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}" if len(ts) >= 8 else ts


def wayback_summary(domain: str, client=None) -> dict:
    """First and last archived capture and how many distinct months have captures."""
    import httpx

    from . import net
    from .models import kv

    own = client is None
    client = client or net.sync_client(timeout=25.0, follow_redirects=True)
    try:
        resp = client.get(CDX_URL, params={"url": domain, "output": "json", "fl": "timestamp",
                                           "collapse": "timestamp:6", "limit": 2000})
    except httpx.TimeoutException:
        raise RuntimeError("the Wayback Machine timed out")
    except httpx.HTTPError as e:
        raise RuntimeError(f"could not reach web.archive.org ({type(e).__name__})")
    finally:
        if own:
            client.close()
    if resp.status_code != 200:
        raise RuntimeError(f"the Wayback Machine answered HTTP {resp.status_code}")
    text_body = resp.text.strip()
    if not text_body:
        return kv({"Snapshots": "none archived"})
    try:
        stamps = parse_cdx(resp.json())
    except ValueError:
        raise RuntimeError("the Wayback Machine returned an invalid answer")
    if not stamps:
        return kv({"Snapshots": "none archived"})
    first, last = stamps[0], stamps[-1]
    items = {
        "First snapshot": _stamp(first),
        "First snapshot link": f"https://web.archive.org/web/{first}/{domain}",
        "Last snapshot": _stamp(last),
        "Last snapshot link": f"https://web.archive.org/web/{last}/{domain}",
        "Months with snapshots": f"{len(stamps)}" + (" (list capped at 2000)" if len(stamps) >= 2000 else ""),
    }
    return kv(items)
