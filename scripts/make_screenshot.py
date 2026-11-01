#!/usr/bin/env python3
"""Render docs/screenshot.svg: the banner plus a real username scan.

Uses rich's recording console, so the SVG shows exactly what the terminal prints.
    python scripts/make_screenshot.py [username]     (default: torvalds)
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

from rich.console import Console

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from osint import runner, ui  # noqa: E402
from osint.banner import print_banner  # noqa: E402
from osint.sites import load_sites  # noqa: E402
from osint.models import FOUND, MISSING, UNKNOWN  # noqa: E402

KEEP = 10


def main() -> int:
    name = sys.argv[1] if len(sys.argv) > 1 else "torvalds"
    sites = load_sites()
    console = Console(record=True, file=io.StringIO(), width=100, force_terminal=True, color_system="truecolor", highlight=False)
    print_banner(console, len(sites))
    console.print(f"[bold cyan]osint[/] [bold blue]❯[/] username {name}")
    # Scan quietly (no live progress in the recording), then print a trimmed list
    # of the real result: the first few hits, then the true totals.
    result = runner.run_username(name, sites, console, progress=False)
    counts = result.counts()
    found = sorted((h for h in result.hits if h.status == FOUND), key=lambda h: h.name.lower())
    ui.info(console, f"searching [bold]{name}[/] on {len(sites)} sites (Ctrl-C cancels)")
    for hit in found[:KEEP]:
        console.print(ui.hit_line(hit))
    if len(found) > KEEP:
        console.print(f"[dim]    ... {len(found) - KEEP} more found (trimmed for this screenshot)[/]")
    console.print()
    ui.info(console, f"{len(result.hits)} sites checked: [green]{counts[FOUND]} found[/], "
                     f"{counts[MISSING]} not found, [yellow]{counts[UNKNOWN]} unknown[/]")
    console.print("[bold cyan]osint[/] [bold blue]❯[/] ")
    out = ROOT / "docs" / "screenshot.svg"
    console.save_svg(str(out), title="osint")
    print(f"[+] wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
