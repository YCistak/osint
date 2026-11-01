"""Username variations: a small, predictable set of likely alternative handles."""

from __future__ import annotations

import re
from datetime import datetime

from .username import username_valid

MAX_VARIANTS = 10
SEPARATORS = ("", ".", "_", "-")
COMMON_SUFFIXES = ("1", "123")


def split_tokens(name: str) -> list[str]:
    """Words of a handle: split on ``. _ -`` and camelCase boundaries, lower-cased."""
    parts = re.split(r"[._-]+", name.strip())
    tokens: list[str] = []
    for part in parts:
        spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", part)
        tokens += [t.lower() for t in spaced.split() if t]
    return tokens


def generate(name: str, *, year: int | None = None, limit: int = MAX_VARIANTS) -> list[str]:
    """Up to ``limit`` variants of ``name`` (never ``name`` itself), most likely first.

    Order: separator combinations, first-initial forms, then suffixes
    (``1``, ``123``, current year). Every result passes ``username_valid``.
    """
    year = year if year is not None else datetime.now().year
    tokens = split_tokens(name)
    if not tokens:
        return []
    candidates: list[str] = []
    if len(tokens) >= 2:
        candidates += [sep.join(tokens) for sep in SEPARATORS]
        first, last = tokens[0], tokens[-1]
        candidates += [first[0] + last, first[0] + "." + last, first + last[0], last + first]
        base = "".join(tokens)
    else:
        base = tokens[0]
        candidates += [base + "_", "_" + base, base + "."]
    candidates += [base + s for s in (*COMMON_SUFFIXES, str(year))]
    candidates += [base + "_" + str(year % 100).zfill(2)] if len(tokens) == 1 else []

    seen = {name.lower()}
    out: list[str] = []
    for c in candidates:
        key = c.lower()
        if key in seen or not username_valid(c):
            continue
        seen.add(key)
        out.append(c)
        if len(out) >= limit:
            break
    return out
