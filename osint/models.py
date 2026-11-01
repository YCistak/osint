"""Shared result types used by every scanner, the REPL and the report writer."""

from __future__ import annotations

from dataclasses import dataclass, field

FOUND = "found"
MISSING = "missing"
UNKNOWN = "unknown"

STATUSES = (FOUND, MISSING, UNKNOWN)


@dataclass(frozen=True)
class Hit:
    """One checked service/site and what we learned about it."""

    name: str
    url: str
    status: str  # FOUND | MISSING | UNKNOWN
    detail: str = ""
    profile: dict = field(default_factory=dict, hash=False, compare=False)

    def to_dict(self) -> dict:
        d = {"name": self.name, "url": self.url, "status": self.status, "detail": self.detail}
        if self.profile:
            d["profile"] = dict(self.profile)
        return d


@dataclass
class ScanResult:
    """Everything a command produced, in a form the REPL, CLI and reports share.

    ``kind`` is "username", "email" or "domain". ``hits`` holds per-site results
    (username scans). ``sections`` holds named groups of lines/tables for the
    email and domain commands: ``{title: SectionBody}``.
    """

    kind: str
    target: str
    hits: list[Hit] = field(default_factory=list)
    sections: dict[str, dict] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    cancelled: bool = False
    usernames: list[str] = field(default_factory=list)  # usernames discovered (email scans)
    chained: list["ScanResult"] = field(default_factory=list)  # follow-up username scans
    meta: dict = field(default_factory=dict)  # structured facts for scoring and history (not shown)

    def counts(self) -> dict[str, int]:
        out = {s: 0 for s in STATUSES}
        for h in self.hits:
            out[h.status] = out.get(h.status, 0) + 1
        return out

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "target": self.target,
            "cancelled": self.cancelled,
            "counts": self.counts() if self.hits else {},
            "hits": [h.to_dict() for h in self.hits],
            "sections": self.sections,
            "notes": self.notes,
            **({"discovered_usernames": self.usernames} if self.usernames else {}),
            **({"chained": [c.to_dict() for c in self.chained]} if self.chained else {}),
            **({"meta": self.meta} if self.meta else {}),
        }


# --- section bodies for email/domain results -------------------------------
# Each body is a plain dict so it serialises straight to JSON.


def kv(items: dict[str, str]) -> dict:
    """Key/value lines."""
    return {"type": "kv", "items": {str(k): str(v) for k, v in items.items()}}


def table(headers: list[str], rows: list[list[str]]) -> dict:
    return {"type": "table", "headers": list(headers), "rows": [[str(c) for c in r] for r in rows]}


def bullets(items: list[str]) -> dict:
    return {"type": "list", "items": [str(i) for i in items]}


def text(message: str) -> dict:
    return {"type": "text", "text": message}
