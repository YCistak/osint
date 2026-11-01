#!/usr/bin/env python3
"""Render docs/screenshot.svg: the banner plus a real username scan.

Uses rich's recording console, so the SVG shows exactly what the terminal prints.
    python scripts/make_screenshot.py [username]     (default: torvalds)
"""

from __future__ import annotations

import sys
from pathlib import Path

from rich.console import Console

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from osint import runner  # noqa: E402
from osint.banner import print_banner  # noqa: E402
from osint.sites import load_sites  # noqa: E402
from osint.ui import render_result  # noqa: E402


def main() -> int:
    name = sys.argv[1] if len(sys.argv) > 1 else "torvalds"
    sites = load_sites()
    console = Console(record=True, width=100, force_terminal=True, color_system="truecolor", highlight=False)
    print_banner(console, len(sites))
    console.print(f"[bold cyan]osint[/] [bold blue]❯[/] username {name}")
    # Scan quietly (no live progress in the recording), then print the result.
    result = runner.run_username(name, sites, console, progress=False)
    from osint import ui
    ui.info(console, f"searched [bold]{name}[/] on {len(sites)} sites")
    render_result(console, result)
    console.print("[bold cyan]osint[/] [bold blue]❯[/] ")
    out = ROOT / "docs" / "screenshot.svg"
    console.save_svg(str(out), title="osint")
    print(f"[+] wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
