"""Site definitions for the username search.

The bundled ``sites.json`` is generated from the maigret project's ``data.json``
(MIT licensed, https://github.com/soxoj/maigret) by ``scripts/update_sites.py``.
We only read it as data; nothing in it is ever executed.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

SITES_FILE = Path(__file__).parent / "sites.json"
CHECK_TYPES = {"status_code", "message", "response_url"}


class SiteListError(Exception):
    """Raised when the site list is missing or malformed."""


@dataclass(frozen=True)
class Site:
    name: str
    url: str  # profile URL template containing {username}
    check_type: str = "status_code"
    url_probe: str = ""  # optional alternative URL (e.g. an API) used for the request
    presence: tuple[str, ...] = ()  # maigret "presenseStrs"
    absence: tuple[str, ...] = ()  # maigret "absenceStrs"
    headers: dict = field(default_factory=dict, hash=False, compare=False)
    regex_check: str = ""
    errors: dict = field(default_factory=dict, hash=False, compare=False)
    ignore403: bool = False
    rank: int = 0
    claimed: str = ""  # a username known to exist (self-check)

    def request_url(self, username: str) -> str:
        return (self.url_probe or self.url).replace("{username}", quote(username, safe=""))

    def profile_url(self, username: str) -> str:
        return self.url.replace("{username}", quote(username, safe=""))

    def accepts(self, username: str) -> bool:
        """False if the site's own username rule rejects this name."""
        if not self.regex_check:
            return True
        try:
            return re.match(self.regex_check, username) is not None
        except re.error:
            return True


def site_from_dict(raw: dict) -> Site:
    name = raw.get("name")
    url = raw.get("url")
    check_type = raw.get("check_type", "status_code")
    if not name or not url or "{username}" not in url:
        raise SiteListError(f"site {name!r}: 'name' and a 'url' with {{username}} are required")
    if check_type not in CHECK_TYPES:
        raise SiteListError(f"{name}: unsupported check_type '{check_type}'")
    if check_type == "message" and not (raw.get("presence") or raw.get("absence")):
        raise SiteListError(f"{name}: 'message' check needs presence or absence strings")
    return Site(
        name=name,
        url=url,
        check_type=check_type,
        url_probe=raw.get("url_probe", ""),
        presence=tuple(raw.get("presence", ())),
        absence=tuple(raw.get("absence", ())),
        headers=dict(raw.get("headers", {})),
        regex_check=raw.get("regex_check", ""),
        errors=dict(raw.get("errors", {})),
        ignore403=bool(raw.get("ignore403", False)),
        rank=int(raw.get("rank", 0)),
        claimed=raw.get("claimed", ""),
    )


def load_sites(path: Path | str | None = None) -> list[Site]:
    """Load and validate the site list."""
    path = Path(path) if path else SITES_FILE
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise SiteListError(f"site list not found: {path}") from e
    except json.JSONDecodeError as e:
        raise SiteListError(f"site list is not valid JSON: {e}") from e
    raw = data.get("sites") if isinstance(data, dict) else None
    if not isinstance(raw, list) or not raw:
        raise SiteListError("site list has no 'sites' array")
    sites: list[Site] = []
    seen: set[str] = set()
    for i, entry in enumerate(raw, 1):
        if not isinstance(entry, dict):
            raise SiteListError(f"entry {i} is not an object")
        site = site_from_dict(entry)
        if site.name in seen:
            raise SiteListError(f"{site.name}: defined twice")
        seen.add(site.name)
        sites.append(site)
    return sites
