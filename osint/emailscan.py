"""Email reconnaissance.

Sources (all free, no API key):

* holehe      - checks which services have an account for the address
* XposedOrNot - public breach list and breach analytics
* Gravatar    - public profile attached to the address hash
* GitHub      - user search by public commit/profile email
* DNS         - MX records and mail provider detection
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass, field

import httpx

from .models import FOUND, MISSING, UNKNOWN, Hit, ScanResult, bullets, kv, table, text

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

XPOSED_CHECK = "https://api.xposedornot.com/v1/check-email/{email}"
XPOSED_ANALYTICS = "https://api.xposedornot.com/v1/breach-analytics"
GRAVATAR_URL = "https://gravatar.com/{hash}.json"
GITHUB_SEARCH = "https://api.github.com/search/users"
USER_AGENT = "osint-cli (+https://github.com/YCistak/osint)"

# holehe modules that trigger a "forgot password" flow and may send a real
# email to the target. Skipped unless --unsafe is given.
PASSWORD_RESET_MODULES = {"adobe", "mail_ru", "odnoklassniki", "samsung"}
# holehe module categories we never run (adult sites).
ADULT_CATEGORIES = {"porn"}
# Modules that returned "unknown" for every probe in our measurements (stale
# endpoints, bot walls). Skipped by default; --all-modules runs them anyway.
# Measured with scripts/measure_email_modules.py (3 rounds, 65 of 113 modules never answered).
DEAD_MODULES: set[str] = {
    "aboutme", "amocrm", "atlassian", "babeshows", "badeggsonline", "bitmoji",
    "blablacar", "blackworldforum", "bluegrassrivals", "buymeacoffee", "cambridgemt",
    "chinaphonearena", "codecademy", "codeigniter", "cpaelites", "cpahero",
    "cracked_to", "crevado", "deliveroo", "demonforums", "discord", "dominosfr", "ebay",
    "ello", "evernote", "firefox", "freelancer", "freiberg", "garmin", "github",
    "google", "hubspot", "imgur", "instagram", "issuu", "komoot", "lastfm",
    "nattyornot", "ndemiccreations", "nike", "nimble", "nocrm", "nutshell",
    "onlinesequencer", "patreon", "pinterest", "pipedrive", "rocketreach", "sevencups",
    "snapchat", "soundcloud", "spotify", "strava", "teamleader", "therianguide",
    "thevapingforum", "tumblr", "tunefind", "venmo", "vivino", "voxmedia", "vrbo",
    "vsco", "xing", "yahoo",
}

MX_PROVIDERS = {
    "google.com": "Google Workspace / Gmail",
    "googlemail.com": "Google Workspace / Gmail",
    "outlook.com": "Microsoft 365 / Outlook",
    "protection.outlook.com": "Microsoft 365 / Outlook",
    "hotmail.com": "Microsoft Outlook / Hotmail",
    "yahoodns.net": "Yahoo Mail",
    "protonmail.ch": "Proton Mail",
    "proton.me": "Proton Mail",
    "icloud.com": "Apple iCloud Mail",
    "me.com": "Apple iCloud Mail",
    "zoho.com": "Zoho Mail",
    "zoho.eu": "Zoho Mail",
    "fastmail.com": "Fastmail",
    "messagingengine.com": "Fastmail",
    "yandex.net": "Yandex Mail",
    "yandex.ru": "Yandex Mail",
    "mail.ru": "Mail.ru",
    "mimecast.com": "Mimecast (filtering gateway)",
    "pphosted.com": "Proofpoint (filtering gateway)",
    "secureserver.net": "GoDaddy",
    "ovh.net": "OVH",
    "mailgun.org": "Mailgun",
    "improvmx.com": "ImprovMX (forwarding)",
    "forwardemail.net": "Forward Email (forwarding)",
}


def email_valid(email: str) -> bool:
    return bool(EMAIL_RE.match(email))


def local_part(email: str) -> str:
    return email.split("@", 1)[0]


# --------------------------------------------------------------- parsers

def parse_xposed_check(status: int, payload) -> list[str] | None:
    """Breach names from /check-email. ``[]`` = clean, ``None`` = could not tell."""
    if status == 404:
        return []
    if status != 200 or not isinstance(payload, dict):
        return None
    groups = payload.get("breaches") or []
    names: list[str] = []
    for group in groups:
        if isinstance(group, list):
            names += [str(n) for n in group]
        elif isinstance(group, str):
            names.append(group)
    return names


def parse_xposed_analytics(payload) -> dict:
    """Pull risk, password-strength and per-breach details from breach-analytics."""
    out: dict = {"risk": "", "score": None, "passwords": {}, "details": []}
    if not isinstance(payload, dict):
        return out
    metrics = payload.get("BreachMetrics") or {}
    risk = (metrics.get("risk") or [{}])[0] if isinstance(metrics.get("risk"), list) else {}
    out["risk"] = risk.get("risk_label", "")
    out["score"] = risk.get("risk_score")
    strengths = metrics.get("passwords_strength") or [{}]
    if isinstance(strengths, list) and strengths and isinstance(strengths[0], dict):
        out["passwords"] = {k: v for k, v in strengths[0].items() if v}
    exposed = (payload.get("ExposedBreaches") or {}).get("breaches_details") or []
    for item in exposed:
        if isinstance(item, dict):
            out["details"].append(
                {
                    "breach": str(item.get("breach", "")),
                    "date": str(item.get("xposed_date", "")),
                    "records": item.get("xposed_records") or 0,
                    "data": str(item.get("xposed_data", "")).replace(";", ", "),
                    "domain": str(item.get("domain", "")),
                }
            )
    return out


def parse_gravatar(payload) -> dict | None:
    """Profile fields from a gravatar ``<hash>.json`` answer, or None."""
    if not isinstance(payload, dict):
        return None
    entries = payload.get("entry")
    if not isinstance(entries, list) or not entries or not isinstance(entries[0], dict):
        return None
    e = entries[0]
    accounts = []
    for acc in e.get("accounts") or []:
        if isinstance(acc, dict) and acc.get("url"):
            accounts.append(f"{acc.get('shortname') or acc.get('domain') or 'account'}: {acc['url']}")
    profile = {
        "Name": e.get("displayName") or "",
        "Username": e.get("preferredUsername") or "",
        "Profile": e.get("profileUrl") or "",
        "Location": e.get("currentLocation") or "",
        "About": (e.get("aboutMe") or "")[:200],
        "Linked accounts": "; ".join(accounts),
    }
    return {k: v for k, v in profile.items() if v}


def parse_github_search(status: int, payload, remaining: str | None = None) -> tuple[list[dict] | None, str]:
    """Users from the GitHub search API. Returns ``(users|None, note)``."""
    if status in (403, 429) or remaining == "0":
        return None, "GitHub API rate limit reached (unauthenticated: 10 searches/min)"
    if status != 200 or not isinstance(payload, dict):
        return None, f"GitHub API answered HTTP {status}"
    users = [
        {"login": i.get("login", ""), "url": i.get("html_url", ""), "type": i.get("type", "")}
        for i in payload.get("items", [])
        if isinstance(i, dict)
    ]
    return users, ""


def detect_provider(mx_hosts: list[str]) -> str:
    """Name the mail provider from MX host names, or ''."""
    for host in mx_hosts:
        h = host.lower().rstrip(".")
        for suffix, name in MX_PROVIDERS.items():
            if h == suffix or h.endswith("." + suffix):
                return name
    return ""


def parse_mx(records: list[str]) -> list[tuple[int, str]]:
    """``['10 mx.example.com.']`` -> sorted ``[(10, 'mx.example.com')]``."""
    out = []
    for rec in records:
        parts = rec.split()
        if len(parts) == 2 and parts[0].isdigit():
            out.append((int(parts[0]), parts[1].rstrip(".").lower()))
    return sorted(out)


# --------------------------------------------------------------- holehe

def holehe_to_hit(raw: dict) -> Hit:
    """Convert a holehe result dict into a Hit.

    holehe also flags request failures with ``rateLimit=True``; such answers are
    not trustworthy and count as UNKNOWN.
    """
    extra = []
    if raw.get("emailrecovery"):
        extra.append(f"recovery email: {raw['emailrecovery']}")
    if raw.get("phoneNumber"):
        extra.append(f"phone: {raw['phoneNumber']}")
    if raw.get("others"):
        extra.append(str(raw["others"]))
    if raw.get("rateLimit"):
        status = UNKNOWN
        extra.insert(0, "rate limited or no usable answer")
    elif raw.get("exists"):
        status = FOUND
    else:
        status = MISSING
    return Hit(str(raw.get("name", "?")), str(raw.get("domain", "")), status, "; ".join(extra))


def discover_holehe_functions() -> list:
    """Import every holehe module and return its check function.

    holehe's own ``core.import_submodules`` walks packages without a name prefix,
    which breaks here: holehe has a module category called ``osint`` and Python
    would import *our* ``osint`` package instead. A prefixed walk avoids that.
    """
    import importlib
    import pkgutil

    import holehe.modules as root

    functions = []
    for info in pkgutil.walk_packages(root.__path__, root.__name__ + "."):
        if info.ispkg:
            continue
        module = importlib.import_module(info.name)
        fn = getattr(module, info.name.rsplit(".", 1)[1], None)
        if callable(fn):
            functions.append(fn)
    return functions


def load_modules(unsafe: bool = False, all_modules: bool = False) -> tuple[list, int]:
    """holehe module functions, minus adult, password-reset and known-dead ones.

    Returns ``(modules, skipped_count)``."""
    functions = discover_holehe_functions()
    keep = []
    for fn in functions:
        category = fn.__module__.split(".")[2] if fn.__module__.count(".") >= 3 else ""
        if category in ADULT_CATEGORIES:
            continue
        if not unsafe and fn.__name__ in PASSWORD_RESET_MODULES:
            continue
        if not all_modules and fn.__name__ in DEAD_MODULES:
            continue
        keep.append(fn)
    return keep, len(functions) - len(keep)


# --------------------------------------------------------------- state

@dataclass
class EmailState:
    """Mutable bag the async scan fills in; survives cancellation."""

    email: str
    accounts: list[Hit] = field(default_factory=list)
    breaches: list[str] | None = None  # None = could not check
    analytics: dict = field(default_factory=dict)
    gravatar: dict | None = None
    gravatar_checked: bool = False
    github: list[dict] | None = None
    github_note: str = ""
    mx: list[tuple[int, str]] = field(default_factory=list)
    mx_note: str = ""
    skipped_modules: int = 0
    cancelled: bool = False

    def to_result(self) -> ScanResult:
        res = ScanResult("email", self.email, cancelled=self.cancelled)
        res.hits = list(self.accounts)

        # Breaches
        if self.breaches is None:
            res.sections["Breaches"] = text("Could not check XposedOrNot (service unavailable or rate limited).")
        elif not self.breaches:
            res.sections["Breaches"] = text("No known breaches for this address.")
        else:
            info = {"Breaches": str(len(self.breaches))}
            if self.analytics.get("risk"):
                info["Risk"] = f"{self.analytics['risk']} ({self.analytics.get('score')}/100)"
            if self.analytics.get("passwords"):
                info["Password exposure"] = ", ".join(f"{k}: {v}" for k, v in self.analytics["passwords"].items())
            details = {d["breach"]: d for d in self.analytics.get("details", [])}
            rows = []
            for name in self.breaches:
                d = details.get(name, {})
                records = d.get("records") or 0
                rows.append([name, d.get("date", ""), f"{records:,}" if records else "", d.get("data", "")])
            rows.sort(key=lambda r: r[1], reverse=True)  # newest first, unknown years last
            body = table(["Breach", "Year", "Records", "Exposed data"], rows)
            body["summary"] = info
            body["display_limit"] = 15  # terminal shows the newest; reports/JSON keep all
            res.sections["Breaches"] = body

        # Registered accounts
        found = sorted((h for h in self.accounts if h.status == FOUND), key=lambda h: h.name.lower())
        unknown = [h for h in self.accounts if h.status == UNKNOWN]
        if self.accounts:
            body = table(
                ["Service", "Domain", "Extra"],
                [[h.name, h.url, h.detail] for h in found],
            )
            body["footer"] = (
                f"{len(self.accounts)} services checked, {len(found)} registered, "
                f"{len(unknown)} unknown (blocked or rate limited)."
            )
            res.sections["Registered accounts"] = body
        else:
            res.sections["Registered accounts"] = text("Account check did not run.")

        # Profiles
        profiles: dict[str, str] = {}
        if self.gravatar:
            for k, v in self.gravatar.items():
                profiles[f"Gravatar {k.lower()}"] = v
        if self.github:
            for u in self.github:
                profiles["GitHub"] = f"{u['login']} ({u['url']})"
        if profiles:
            res.sections["Profiles"] = kv(profiles)
        else:
            msg = ["No public profile found"]
            if self.github is None and self.github_note:
                msg.append(self.github_note)
            res.sections["Profiles"] = text(". ".join(msg) + ".")

        # Mail server
        if self.mx:
            info = {"MX": ", ".join(f"{p} {h}" for p, h in self.mx)}
            prov = detect_provider([h for _, h in self.mx])
            info["Provider"] = prov or "unrecognized (custom or self-hosted)"
            res.sections["Mail server"] = kv(info)
        else:
            res.sections["Mail server"] = text(self.mx_note or "No MX records found; the domain cannot receive mail.")

        res.notes.append(f"Tip: run 'username {local_part(self.email)}' to search the local part as a username.")
        if self.skipped_modules:
            res.notes.append(f"{self.skipped_modules} holehe modules were skipped (password-reset, adult or known-dead).")
        return res


# --------------------------------------------------------------- async sources

async def fetch_xposed(client: httpx.AsyncClient, state: EmailState) -> None:
    try:
        r = await client.get(XPOSED_CHECK.format(email=state.email))
        payload = r.json() if r.status_code in (200, 404) else None
    except (httpx.HTTPError, ValueError):
        return
    state.breaches = parse_xposed_check(r.status_code, payload)
    if state.breaches:
        try:
            a = await client.get(XPOSED_ANALYTICS, params={"email": state.email})
            if a.status_code == 200:
                state.analytics = parse_xposed_analytics(a.json())
        except (httpx.HTTPError, ValueError):
            pass


async def fetch_gravatar(client: httpx.AsyncClient, state: EmailState) -> None:
    digest = hashlib.sha256(state.email.strip().lower().encode()).hexdigest()
    try:
        r = await client.get(GRAVATAR_URL.format(hash=digest))
        state.gravatar_checked = True
        if r.status_code == 200:
            state.gravatar = parse_gravatar(r.json())
    except (httpx.HTTPError, ValueError):
        pass


async def fetch_github(client: httpx.AsyncClient, state: EmailState) -> None:
    try:
        r = await client.get(
            GITHUB_SEARCH,
            params={"q": f"{state.email} in:email"},
            headers={"Accept": "application/vnd.github+json"},
        )
        payload = r.json() if r.status_code == 200 else None
    except (httpx.HTTPError, ValueError):
        state.github_note = "GitHub API unreachable"
        return
    state.github, state.github_note = parse_github_search(
        r.status_code, payload, r.headers.get("x-ratelimit-remaining")
    )


def lookup_mx(domain: str) -> tuple[list[tuple[int, str]], str]:
    """Blocking DNS lookup, run in a worker thread."""
    import dns.exception
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 6.0
    try:
        answer = resolver.resolve(domain, "MX")
        return parse_mx([r.to_text() for r in answer]), ""
    except dns.resolver.NXDOMAIN:
        return [], f"Domain {domain} does not exist (NXDOMAIN)."
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return [], ""
    except dns.exception.Timeout:
        return [], "MX lookup timed out."


async def fetch_mx(state: EmailState) -> None:
    import trio

    domain = state.email.rsplit("@", 1)[1]
    state.mx, state.mx_note = await trio.to_thread.run_sync(lookup_mx, domain)


async def run_holehe(
    client: httpx.AsyncClient,
    state: EmailState,
    modules: list,
    on_progress: Callable[[Hit, int, int], None] | None,
    *,
    module_timeout: float,
    concurrency: int,
) -> None:
    import trio

    sem = trio.Semaphore(concurrency)
    total = len(modules)

    async def one(module) -> None:
        async with sem:
            out: list[dict] = []
            with trio.move_on_after(module_timeout) as scope:
                try:
                    await module(state.email, client, out)
                except Exception:
                    out = []
            if scope.cancelled_caught or not out:
                out = [{"name": module.__name__, "domain": "", "rateLimit": True}]
        for raw in out:
            hit = holehe_to_hit(raw)
            state.accounts.append(hit)
            if on_progress:
                on_progress(hit, len(state.accounts), total)

    async with trio.open_nursery() as nursery:
        for m in modules:
            nursery.start_soon(one, m)


def scan(
    email: str,
    state: EmailState | None = None,
    on_progress: Callable[[Hit, int, int], None] | None = None,
    *,
    unsafe: bool = False,
    all_modules: bool = False,
    module_timeout: float = 12.0,
    concurrency: int = 20,
    modules: list | None = None,
) -> EmailState:
    """Run every source. Blocking (uses trio); call from the main thread so
    Ctrl-C can interrupt it. ``state`` keeps partial results if that happens."""
    import trio

    state = state or EmailState(email)
    if modules is None:
        modules, state.skipped_modules = load_modules(unsafe, all_modules)

    async def main() -> None:
        headers = {"User-Agent": USER_AGENT}
        async with httpx.AsyncClient(timeout=15.0, headers=headers, follow_redirects=True) as api:
            async with httpx.AsyncClient(timeout=module_timeout, follow_redirects=True) as probe:
                async with trio.open_nursery() as nursery:
                    nursery.start_soon(fetch_xposed, api, state)
                    nursery.start_soon(fetch_gravatar, api, state)
                    nursery.start_soon(fetch_github, api, state)
                    nursery.start_soon(fetch_mx, state)

                    async def accounts() -> None:
                        await run_holehe(
                            probe, state, modules, on_progress,
                            module_timeout=module_timeout, concurrency=concurrency,
                        )

                    nursery.start_soon(accounts)

    try:
        trio.run(main)
    except KeyboardInterrupt:
        state.cancelled = True
    return state
