"""Domain / IP reconnaissance: whois, DNS, crt.sh subdomains, reverse DNS, geolocation."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from datetime import date, datetime

import dns.exception
import dns.resolver
import dns.reversename
import httpx

from .models import ScanResult, bullets, kv, table, text

DNS_TYPES = ["A", "AAAA", "MX", "NS", "TXT"]
CRT_URL = "https://crt.sh/?q=%25.{domain}&output=json"
IPAPI_URL = (
    "http://ip-api.com/json/{ip}"
    "?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
)
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$", re.I
)


def target_kind(target: str) -> str:
    """Return 'ip', 'domain' or 'invalid'."""
    target = target.strip()
    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        pass
    try:  # internationalized names are checked in punycode form
        ascii_target = target.encode("idna").decode("ascii")
    except UnicodeError:
        return "invalid"
    return "domain" if DOMAIN_RE.match(ascii_target) else "invalid"


def clean_target(raw: str) -> str:
    """Strip scheme, path, port and trailing dot (https://a.com/x -> a.com)."""
    t = raw.strip()
    t = re.sub(r"^[a-z][a-z0-9+.-]*://", "", t, flags=re.I)
    t = t.split("/")[0].split("?")[0]
    if t.count(":") == 1:  # host:port
        t = t.split(":")[0]
    return t.rstrip(".").lower()


# ---------------------------------------------------------------- whois

def _date_str(v) -> str:
    if isinstance(v, list):
        v = v[0] if v else None
    if isinstance(v, (datetime, date)):
        return v.strftime("%Y-%m-%d")
    return str(v) if v else ""


def _list_str(v) -> str:
    if not v:
        return ""
    if isinstance(v, (list, tuple, set)):
        return ", ".join(sorted({str(x).lower() for x in v}))
    return str(v)


def whois_lookup(domain: str) -> dict[str, str]:
    """Query whois (blocking). Raises ValueError if nothing is registered."""
    import whois

    w = whois.whois(domain)
    fields = {
        "Domain": _list_str(w.get("domain_name")),
        "Registrar": _list_str(w.get("registrar")),
        "Created": _date_str(w.get("creation_date")),
        "Updated": _date_str(w.get("updated_date")),
        "Expires": _date_str(w.get("expiration_date")),
        "Name servers": _list_str(w.get("name_servers")),
        "Status": _list_str(w.get("status")),
        "Organization": _list_str(w.get("org")),
        "Country": _list_str(w.get("country")),
        "Email": _list_str(w.get("emails")),
    }
    filled = {k: v for k, v in fields.items() if v}
    if not filled:
        raise ValueError("no whois record found (the domain may be unregistered)")
    return filled


# ---------------------------------------------------------------- DNS

def dns_lookup(domain: str, types: list[str] | None = None) -> dict[str, list[str]]:
    """Values per record type; missing types give an empty list."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 6.0
    out: dict[str, list[str]] = {}
    for rtype in types or DNS_TYPES:
        try:
            answer = resolver.resolve(domain, rtype)
            out[rtype] = sorted(r.to_text() for r in answer)
        except dns.resolver.NXDOMAIN:
            raise ValueError(f"'{domain}' does not exist in DNS (NXDOMAIN)")
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            out[rtype] = []
        except dns.exception.Timeout:
            out[rtype] = []
    return out


# ---------------------------------------------------------------- crt.sh

def extract_subdomains(records: list[dict], domain: str) -> list[str]:
    """Unique, sorted subdomains from crt.sh JSON records.

    ``name_value`` may hold several names separated by newlines; ``*.`` prefixes
    are dropped and names outside ``domain`` are ignored.
    """
    domain = domain.lower().rstrip(".")
    found: set[str] = set()
    for rec in records:
        if not isinstance(rec, dict):
            continue
        for key in ("name_value", "common_name"):
            for name in str(rec.get(key, "")).splitlines():
                name = name.strip().lower().lstrip("*.").rstrip(".")
                if not name or "@" in name or " " in name:
                    continue
                if name == domain or name.endswith("." + domain):
                    found.add(name)
    return sorted(found)


def crtsh_lookup(domain: str, client: httpx.Client | None = None) -> list[str]:
    own = client is None
    client = client or httpx.Client(timeout=30.0, follow_redirects=True)
    try:
        try:
            resp = client.get(CRT_URL.format(domain=domain))
        except httpx.TimeoutException:  # crt.sh is often busy: retry once
            resp = client.get(CRT_URL.format(domain=domain))
        if resp.status_code != 200:
            raise RuntimeError(f"crt.sh did not answer (HTTP {resp.status_code}); try again later")
        try:
            records = resp.json()
        except ValueError:
            raise RuntimeError("crt.sh returned an invalid answer (not JSON)")
        return extract_subdomains(records, domain)
    except httpx.TimeoutException:
        raise RuntimeError("crt.sh timed out (the service is often busy)")
    except httpx.HTTPError as e:
        raise RuntimeError(f"could not reach crt.sh: {type(e).__name__}")
    finally:
        if own:
            client.close()


# ---------------------------------------------------------------- IP

def reverse_dns(ip: str) -> list[str]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 6.0
    try:
        answer = resolver.resolve(dns.reversename.from_address(ip), "PTR")
        return sorted(r.to_text().rstrip(".") for r in answer)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.Timeout:
        raise RuntimeError("reverse DNS lookup timed out")


def ip_location(ip: str, client: httpx.Client | None = None) -> dict[str, str]:
    """Basic geolocation from ip-api.com (free, no key, HTTP only)."""
    own = client is None
    client = client or httpx.Client(timeout=10.0)
    try:
        resp = client.get(IPAPI_URL.format(ip=ip))
        data = resp.json()
    except httpx.HTTPError as e:
        raise RuntimeError(f"could not reach ip-api.com: {type(e).__name__}")
    except ValueError:
        raise RuntimeError("ip-api.com returned an invalid answer")
    finally:
        if own:
            client.close()
    if data.get("status") != "success":
        raise RuntimeError(f"location not found: {data.get('message', 'unknown reason')}")
    mapping = {
        "Country": "country", "Region": "regionName", "City": "city", "Postal code": "zip",
        "Time zone": "timezone", "ISP": "isp", "Organization": "org", "AS": "as",
    }
    out = {k: str(data[v]) for k, v in mapping.items() if data.get(v)}
    if "lat" in data and "lon" in data:
        out["Coordinates"] = f"{data['lat']}, {data['lon']}"
    return out


# ---------------------------------------------------------------- orchestration

def dns_table(records: dict[str, list[str]]) -> dict:
    return table(["Type", "Values"], [[t, "; ".join(records.get(t, [])) or "-"] for t in DNS_TYPES])


def scan(
    target: str,
    result: ScanResult | None = None,
    on_step: Callable[[str], None] | None = None,
) -> ScanResult:
    """Run all lookups for a domain or IP. Each step fails on its own: a failed
    step becomes a note and the rest still run. Partial output stays in ``result``
    if the caller interrupts with Ctrl-C."""
    target = clean_target(target)
    kind = target_kind(target)
    if kind == "invalid":
        raise ValueError(f"'{target}' is not a valid domain or IP address")
    result = result or ScanResult("domain", target)

    def step(title: str, fn: Callable[[], dict]) -> None:
        if on_step:
            on_step(title)
        try:
            result.sections[title] = fn()
        except (ValueError, RuntimeError) as e:
            result.sections[title] = text(f"Unavailable: {e}")
        except Exception as e:  # a broken step must not kill the rest
            result.sections[title] = text(f"Unavailable: {type(e).__name__}: {e}")

    if kind == "ip":
        step("Reverse DNS", lambda: _ptr_body(target))
        step("Geolocation", lambda: kv(ip_location(target)))
    else:
        step("Whois", lambda: kv(whois_lookup(target)))
        step("DNS records", lambda: dns_table(dns_lookup(target)))
        step("Subdomains (crt.sh)", lambda: _subdomain_body(crtsh_lookup(target)))
    return result


def _ptr_body(ip: str) -> dict:
    names = reverse_dns(ip)
    return bullets(names) if names else text("No PTR record.")


def _subdomain_body(names: list[str]) -> dict:
    if not names:
        return text("No certificates found for subdomains.")
    body = bullets(names[:200])
    if len(names) > 200:
        body["items"].append(f"... and {len(names) - 200} more")
    return body
