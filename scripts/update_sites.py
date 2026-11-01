#!/usr/bin/env python3
"""Regenerate osint/sites.json from maigret's data.json.

maigret (https://github.com/soxoj/maigret, MIT) maintains a large database of
sites. We download it as plain JSON, never execute it, keep the top-N sites by
Alexa rank that our checker can handle, and write a compact file.

Usage:
    python scripts/update_sites.py                # download and write
    python scripts/update_sites.py --input data.json --limit 500
Engine-based sites (Discourse, XenForo, ...) are expanded from their engine template.
Sites listed in scripts/blocklist.txt (false positives found by
scripts/validate_sites.py) are always left out.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from datetime import date
from pathlib import Path

DATA_URL = "https://raw.githubusercontent.com/soxoj/maigret/main/maigret/resources/data.json"
ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "osint" / "sites.json"
BLOCKLIST = Path(__file__).resolve().parent / "blocklist.txt"

SUPPORTED_CHECKS = {"status_code", "message", "response_url"}
# Tags we never include (adult content, hidden-network or criminal communities).
EXCLUDED_TAGS = {"porn", "erotic", "dating", "webcam", "tor", "i2p", "cybercriminal"}


def load_blocklist(path: Path = BLOCKLIST) -> set[str]:
    if not path.exists():
        return set()
    names = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            names.add(line)
    return names


def usable(name: str, site: dict) -> bool:
    """True if our checker can evaluate this maigret entry."""
    if site.get("disabled"):
        return False
    if "alexaRank" not in site or "url" not in site:
        return False
    if set(site.get("tags", [])) & EXCLUDED_TAGS:
        return False
    if site.get("checkType") not in SUPPORTED_CHECKS:
        return False
    # Features we do not implement: bot protection, non-GET, payloads, token activation.
    if site.get("protection") or site.get("activation"):
        return False
    if site.get("requestMethod") not in (None, "GET") or site.get("requestPayload"):
        return False
    if site.get("requestHeadOnly") or site.get("type"):
        return False
    if "{username}" not in site["url"]:
        return False
    if site["checkType"] == "message" and not (site.get("presenseStrs") or site.get("absenceStrs")):
        return False
    return True


def expand(template: str, site: dict) -> str:
    return (
        template.replace("{urlMain}", site.get("urlMain", ""))
        .replace("{urlSubpath}", site.get("urlSubpath", ""))
    )


def convert(name: str, site: dict) -> dict:
    out: dict = {
        "name": name,
        "url": expand(site["url"], site),
        "check_type": site["checkType"],
        "rank": site["alexaRank"],
    }
    if site.get("urlProbe"):
        out["url_probe"] = expand(site["urlProbe"], site)
    if site.get("presenseStrs"):
        out["presence"] = site["presenseStrs"]
    if site.get("absenceStrs"):
        out["absence"] = site["absenceStrs"]
    if site.get("headers"):
        out["headers"] = site["headers"]
    if site.get("regexCheck"):
        out["regex_check"] = site["regexCheck"]
    if site.get("errors"):
        out["errors"] = site["errors"]
    if site.get("ignore403"):
        out["ignore403"] = True
    if site.get("usernameClaimed"):
        out["claimed"] = site["usernameClaimed"]
    return out


def with_engine(site: dict, engines: dict) -> dict:
    """Apply a maigret engine template (e.g. Discourse, XenForo) under the site's own keys."""
    name = site.get("engine")
    if not name:
        return site
    template = engines.get(name, {}).get("site")
    if not isinstance(template, dict):
        return {**site, "disabled": True}  # unknown engine: cannot be checked
    return {**template, **site}


def build(data: dict, limit: int, blocked: set[str], fill_unranked: bool = True) -> list[dict]:
    """Ranked sites first (best Alexa rank first); if that is fewer than ``limit``
    and ``fill_unranked`` is set, top up with unranked stand-alone (non-engine)
    sites in name order. Rank 0 in the output means "unranked"."""
    engines = data.get("engines", {})
    ranked, unranked = [], []
    for name, raw in data["sites"].items():
        if name in blocked:
            continue
        merged = with_engine(raw, engines)
        if usable(name, merged):
            ranked.append((merged["alexaRank"], name, merged))
        elif fill_unranked and not raw.get("alexaRank") and not raw.get("engine"):
            probe = {**merged, "alexaRank": 1}
            if usable(name, probe):
                unranked.append((0, name, {**merged, "alexaRank": 0}))
    ranked.sort(key=lambda t: (t[0], t[1].lower()))
    unranked.sort(key=lambda t: t[1].lower())
    return [convert(name, s) for _, name, s in (ranked + unranked)[:limit]]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--input", help="read a local maigret data.json instead of downloading")
    ap.add_argument("--limit", type=int, default=500, help="max sites to keep (default 500)")
    ap.add_argument("--no-fill", action="store_true", help="do not top up with unranked sites")
    ap.add_argument("--output", default=str(OUTPUT))
    args = ap.parse_args(argv)

    if args.input:
        raw = Path(args.input).read_bytes()
    else:
        with urllib.request.urlopen(DATA_URL, timeout=60) as resp:
            raw = resp.read()
    data = json.loads(raw)  # data only, never executed
    sites = build(data, args.limit, load_blocklist(), not args.no_fill)
    payload = {
        "source": "maigret data.json (MIT) https://github.com/soxoj/maigret",
        "generated": date.today().isoformat(),
        "count": len(sites),
        "sites": sites,
    }
    Path(args.output).write_text(json.dumps(payload, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"[+] wrote {len(sites)} sites to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
