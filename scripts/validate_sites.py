#!/usr/bin/env python3
"""Validate osint/sites.json against the live internet.

Two checks per site:
  1. False positives: scan N random nonsense usernames; any site that reports
     "found" for a name nobody owns is broken and gets flagged.
  2. Self-check: scan each site's own known-existing ``claimed`` username; sites
     that cannot find it are flagged as "blind" (they would never report a hit).

With --write, flagged sites are appended to scripts/blocklist.txt and removed
from sites.json (so scripts/update_sites.py reproduces the pruned list).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import string
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from osint import username as engine  # noqa: E402
from osint.models import FOUND  # noqa: E402
from osint.sites import SITES_FILE, load_sites  # noqa: E402

BLOCKLIST = Path(__file__).resolve().parent / "blocklist.txt"


def nonsense(rng: random.Random) -> str:
    """A name that is valid for almost every site and owned by nobody."""
    return "zq" + "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(12))


async def claimed_check(sites, concurrency: int, timeout: float) -> dict[str, str]:
    sem = asyncio.Semaphore(concurrency)
    out: dict[str, str] = {}
    async with engine.new_client(timeout, concurrency) as client:

        async def one(site):
            if not site.claimed:
                return
            async with sem:
                hit = await engine.check_site(client, site, site.claimed)
            out[site.name] = hit.status

        await asyncio.gather(*(one(s) for s in sites))
    return out


async def main_async(args) -> int:
    sites = load_sites()
    rng = random.Random(args.seed)
    names = [nonsense(rng) for _ in range(args.names)]
    print(f"[*] {len(sites)} sites, nonsense usernames: {', '.join(names)}")

    flagged_fp: dict[str, list[str]] = {}
    for name in names:
        hits = await engine.scan(name, sites, concurrency=args.concurrency, timeout=args.timeout)
        for h in hits:
            if h.status == FOUND:
                flagged_fp.setdefault(h.name, []).append(name)
    print(f"[*] false positives: {len(flagged_fp)}")
    for n in sorted(flagged_fp):
        print(f"    - {n}")

    blind: list[str] = []
    if not args.skip_claimed:
        statuses = await claimed_check(sites, args.concurrency, args.timeout)
        # Retry the failures once so a flaky connection does not condemn a good site.
        retry = [s for s in sites if statuses.get(s.name, FOUND) != FOUND]
        if retry:
            statuses.update(await claimed_check(retry, args.concurrency, args.timeout))
        blind = sorted(n for n, st in statuses.items() if st != FOUND)
        print(f"[*] sites that miss their own claimed username: {len(blind)}")

    if args.write:
        drop = set(flagged_fp) | (set(blind) if args.drop_blind else set())
        if drop:
            with BLOCKLIST.open("a", encoding="utf-8") as fh:
                for n in sorted(drop):
                    reason = "false positive" if n in flagged_fp else "misses claimed username"
                    fh.write(f"{n}  # {reason}\n")
            data = json.loads(SITES_FILE.read_text(encoding="utf-8"))
            data["sites"] = [s for s in data["sites"] if s["name"] not in drop]
            data["count"] = len(data["sites"])
            SITES_FILE.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
            print(f"[+] removed {len(drop)} sites, {data['count']} remain")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--names", type=int, default=2, help="how many nonsense usernames to scan")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--concurrency", type=int, default=50)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--skip-claimed", action="store_true")
    ap.add_argument("--drop-blind", action="store_true", help="also remove sites that miss their claimed username")
    ap.add_argument("--write", action="store_true", help="apply changes to blocklist.txt and sites.json")
    return asyncio.run(main_async(ap.parse_args()))


if __name__ == "__main__":
    sys.exit(main())
