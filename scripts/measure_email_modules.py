#!/usr/bin/env python3
"""Find holehe modules that never give a usable answer.

Every module is run ROUNDS times against a throwaway address. A module that is
"unknown" (rate limited, blocked, endpoint gone) in every round is reported; the
output is meant to be pasted into DEAD_MODULES in osint/emailscan.py.

    python scripts/measure_email_modules.py [address] [rounds]
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx  # noqa: E402
import trio  # noqa: E402

from osint import emailscan  # noqa: E402
from osint.models import UNKNOWN  # noqa: E402


def main() -> int:
    address = sys.argv[1] if len(sys.argv) > 1 else "test@gmail.com"
    rounds = int(sys.argv[2]) if len(sys.argv) > 2 else 2
    modules, _ = emailscan.load_modules(unsafe=False, all_modules=True)
    unknown_rounds: dict[str, int] = {m.__name__: 0 for m in modules}

    async def one_round() -> None:
        sem = trio.Semaphore(20)
        async with httpx.AsyncClient(timeout=12.0, follow_redirects=True) as client:

            async def probe(module) -> None:
                async with sem:
                    out: list[dict] = []
                    with trio.move_on_after(12.0):
                        try:
                            await module(address, client, out)
                        except Exception:
                            out = []
                    hits = [emailscan.holehe_to_hit(r) for r in out]
                    if not hits or all(h.status == UNKNOWN for h in hits):
                        unknown_rounds[module.__name__] += 1

            async with trio.open_nursery() as nursery:
                for m in modules:
                    nursery.start_soon(probe, m)

    for i in range(rounds):
        print(f"[*] round {i + 1}/{rounds} ...", file=sys.stderr)
        trio.run(one_round)

    dead = sorted(n for n, c in unknown_rounds.items() if c == rounds)
    print(f"[+] {len(dead)} of {len(modules)} modules unknown in all {rounds} rounds")
    print("DEAD_MODULES = {" + ", ".join(f'"{n}"' for n in dead) + "}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
