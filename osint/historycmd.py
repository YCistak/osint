"""The ``history`` command shared by the CLI and the interactive shell.

    history                  list recent scans
    history show <id>        what one stored scan contained
    history diff <id1> <id2> what changed between two scans
    history clear            delete everything (asks first)
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable

from rich.console import Console
from rich.table import Table
from rich.text import Text

from . import history
from .ui import error, info

USAGE = "usage: history [list] | show <id> | diff <id1> <id2> | clear"


def _table(headers: list[str]) -> Table:
    t = Table(show_header=True, header_style="bold", box=None, pad_edge=False, padding=(0, 2))
    for h in headers:
        t.add_column(h, overflow="fold")
    return t


def show_list(console: Console, rows: list[dict]) -> None:
    if not rows:
        info(console, "history is empty (scans are recorded automatically; disable with --no-history)")
        return
    t = _table(["ID", "Date", "Kind", "Target", "Accounts", "Breaches"])
    for r in rows:
        s = r["summary"]
        t.add_row(str(r["id"]), r["ts"].replace("T", " "), r["kind"], r["target"],
                  str(len(s.get("accounts", []))), str(len(s.get("breaches", []))))
    console.print(t)


def show_scan(console: Console, row: dict) -> None:
    s = row["summary"]
    info(console, f"scan #{row['id']}: {row['kind']} {row['target']} ({row['ts'].replace('T', ' ')})")
    if "score" in s:
        console.print(Text("    "), Text("Privacy score: ", style="dim"), Text(str(s["score"])), sep="")
    for label, items in (("Accounts", s.get("accounts", [])), ("Breaches", s.get("breaches", []))):
        console.print(Text(f"    {label} ({len(items)}): ", style="dim"), Text(", ".join(items) or "-"), sep="")
    for title, lines in s.get("facts", {}).items():
        console.print(Text(f"    {title}:", style="dim"))
        for line in lines[:12]:
            console.print(Text("      " + line))
        if len(lines) > 12:
            console.print(Text(f"      ... {len(lines) - 12} more", style="dim"))


def show_diff(console: Console, old: dict, new: dict) -> None:
    d = history.diff(old, new)
    info(console, f"#{old['id']} ({old['ts'][:16].replace('T', ' ')}) -> #{new['id']} ({new['ts'][:16].replace('T', ' ')})")
    if old["kind"] != new["kind"] or old["target"].lower() != new["target"].lower():
        info(console, "note: the two scans are for different targets, so the comparison may not mean much")
    if history.is_empty(d):
        info(console, "no differences")
        return
    for label, key, style in (("New accounts", "new_accounts", "green"), ("Removed accounts", "removed_accounts", "red"),
                              ("New breaches", "new_breaches", "green"), ("Removed breaches", "removed_breaches", "red")):
        if d[key]:
            console.print(Text(f"    {label}: ", style="dim"), Text(", ".join(d[key]), style=style), sep="")
    if "score" in d:
        console.print(Text("    Privacy score: ", style="dim"), Text(f"{d['score'][0]} -> {d['score'][1]}"), sep="")
    for title, ch in d["facts"].items():
        console.print(Text(f"    {title}:", style="dim"))
        for line in ch["added"][:10]:
            console.print(Text("      + " + line, style="green"))
        for line in ch["removed"][:10]:
            console.print(Text("      - " + line, style="red"))


def _id(value: str) -> int | None:
    return int(value.lstrip("#")) if value.lstrip("#").isdigit() else None


def handle(args: list[str], console: Console, ask: Callable[[str], str], *, assume_yes: bool = False) -> int:
    """Run one history command. Returns an exit code (0 = fine)."""
    action = args[0].lower() if args else "list"
    rest = args[1:]
    try:
        if action == "list" and not rest:
            show_list(console, history.list_scans())
        elif action == "show" and len(rest) == 1:
            i = _id(rest[0])
            row = history.get(i) if i is not None else None
            if row is None:
                error(console, f"no scan with id '{rest[0]}'")
                return 2
            show_scan(console, row)
        elif action == "diff" and len(rest) == 2:
            ids = [_id(r) for r in rest]
            rows = [history.get(i) if i is not None else None for i in ids]
            if None in rows:
                error(console, "unknown scan id (see 'history')")
                return 2
            show_diff(console, rows[0], rows[1])
        elif action == "clear" and not rest:
            count = len(history.list_scans(1_000_000))
            if count == 0:
                info(console, "history is already empty")
                return 0
            if not assume_yes and ask(f"Delete all {count} stored scan(s)? [y/N] ").strip().lower() not in ("y", "yes"):
                info(console, "cancelled, nothing deleted")
                return 1
            history.clear()
            info(console, f"deleted {count} stored scan(s)")
        else:
            error(console, USAGE)
            return 2
    except (sqlite3.Error, OSError) as e:
        error(console, f"history database problem: {e}")
        return 1
    return 0
