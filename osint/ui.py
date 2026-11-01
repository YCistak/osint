"""Terminal output helpers: status markers, live progress line and result rendering."""

from __future__ import annotations

from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn
from rich.table import Table
from rich.text import Text

from .models import FOUND, MISSING, UNKNOWN, Hit, ScanResult

MARKERS = {
    FOUND: ("[+]", "bold green"),
    MISSING: ("[-]", "bold red"),
    UNKNOWN: ("[?]", "bold yellow"),
}
INFO = ("[*]", "bold blue")


def make_console(*, stderr: bool = False, quiet: bool = False) -> Console:
    return Console(stderr=stderr, quiet=quiet, highlight=False)


def marker(kind: str) -> Text:
    sym, style = MARKERS.get(kind, INFO) if kind != "info" else INFO
    return Text(sym, style=style)


def info(console: Console, message: str) -> None:
    console.print(marker("info"), message)


def error(console: Console, message: str) -> None:
    console.print(Text("[!]", style="bold red"), message)


def hit_line(hit: Hit) -> Text:
    line = Text.assemble(marker(hit.status), " ")
    line.append(hit.name, style="bold")
    if hit.url:
        line.append(f"  {hit.url}", style="cyan" if hit.status == FOUND else "dim")
    if hit.detail and hit.status != FOUND:
        line.append(f"  ({hit.detail})", style="dim")
    return line


def profile_lines(hit: Hit) -> list[Text]:
    """Indented detail lines (name, bio, location ...) under a found hit."""
    return [Text.assemble(("      ", ""), (f"{k}: ", "dim"), (v, "")) for k, v in hit.profile.items()]


class ScanProgress:
    """One live progress line; found hits print above it as they arrive.

    Usage::

        with ScanProgress(console, total, show_missing=False) as p:
            scan(..., on_hit=p.update)
    """

    def __init__(self, console: Console, total: int, *, print_hits: bool = True,
                 show_missing: bool = False, show_unknown: bool = False, label: str = "checked") -> None:
        self.console = console
        self.total = total
        self.print_hits = print_hits
        self.show_missing = show_missing
        self.show_unknown = show_unknown
        self.found = 0
        self._progress = Progress(
            TextColumn("[bold blue][*][/]"),
            TextColumn("{task.completed}/{task.total} " + label),
            BarColumn(bar_width=24),
            TextColumn("[green]{task.fields[found]} found"),
            console=console,
            transient=True,
        )
        self._task = None

    def __enter__(self) -> "ScanProgress":
        self._progress.start()
        self._task = self._progress.add_task("scan", total=self.total, found=0)
        return self

    def __exit__(self, *exc) -> None:
        self._progress.stop()

    def update(self, hit: Hit, done: int, total: int) -> None:
        if hit.status == FOUND:
            self.found += 1
        visible = (
            (hit.status == FOUND and self.print_hits)
            or (hit.status == MISSING and self.show_missing)
            or (hit.status == UNKNOWN and self.show_unknown)
        )
        if visible:
            self._progress.console.print(hit_line(hit))
            for line in profile_lines(hit):
                self._progress.console.print(line)
        self._progress.update(self._task, completed=done, total=total, found=self.found)


def render_section(console: Console, title: str, body: dict) -> None:
    console.print()
    console.print(marker("info"), Text(title, style="bold"))
    kind = body.get("type")
    if kind == "kv":
        for k, v in body["items"].items():
            console.print(Text("    "), Text(f"{k}: ", style="dim"), Text(v), sep="")
    elif kind == "table":
        for k, v in body.get("summary", {}).items():
            console.print(Text("    "), Text(f"{k}: ", style="dim"), Text(v), sep="")
        if body["rows"]:
            limit = body.get("display_limit") or len(body["rows"])
            table = Table(show_header=True, header_style="bold", box=None, pad_edge=False, padding=(0, 2))
            for h in body["headers"]:
                table.add_column(h, overflow="fold")
            for row in body["rows"][:limit]:
                table.add_row(*row)
            console.print(table)
            if len(body["rows"]) > limit:
                console.print(Text(f"    ... showing {limit} of {len(body['rows'])}; "
                                   "'save' writes the full list to the report", style="dim"))
        if body.get("footer"):
            console.print(Text("    " + body["footer"], style="dim"))
    elif kind == "list":
        for item in body["items"]:
            console.print(Text("    "), Text(item, style="cyan"), sep="")
    else:
        console.print(Text("    " + body.get("text", ""), style="dim"))


def render_result(console: Console, result: ScanResult, show: str = "found",
                  *, streamed: bool = False) -> None:
    """Print a finished (or re-displayed) result.

    ``show`` is "found" (default) or "all" (also not-found and unknown sites).
    ``streamed`` means the site lines were already printed live, so only the
    totals are shown.
    """
    if result.hits and result.kind == "username":
        counts = result.counts()
        wanted = {FOUND} if show == "found" else {FOUND, MISSING, UNKNOWN}
        if not streamed:
            for hit in sorted(result.hits, key=lambda h: (h.status != FOUND, h.name.lower())):
                if hit.status in wanted:
                    console.print(hit_line(hit))
                    for line in profile_lines(hit):
                        console.print(line)
        console.print()
        info(
            console,
            f"{len(result.hits)} sites checked: "
            f"[green]{counts[FOUND]} found[/], {counts[MISSING]} not found, "
            f"[yellow]{counts[UNKNOWN]} unknown[/]"
            + ("  [dim](cancelled)[/]" if result.cancelled else ""),
        )
        if counts[UNKNOWN] and show == "found":
            console.print(marker(UNKNOWN), f"{counts[UNKNOWN]} sites could not be checked (blocked, rate limited or timeout); list them with --show-all or 'show all'.")
    for title, body in result.sections.items():
        render_section(console, title, body)
    if result.cancelled and not result.hits:
        console.print()
        info(console, "scan cancelled; partial results shown above")
    for note in result.notes:
        console.print()
        info(console, note)


def render_chain_summary(console: Console, results: list[ScanResult]) -> None:
    """Combined overview after several chained username scans."""
    console.print()
    console.print(marker("info"), Text("Combined summary", style="bold"))
    grid = Table(show_header=True, header_style="bold", box=None, pad_edge=False, padding=(0, 2))
    grid.add_column("Username")
    grid.add_column("Found", justify="right")
    grid.add_column("Sites", overflow="fold")
    total = 0
    for r in results:
        found = sorted((h.name for h in r.hits if h.status == FOUND), key=str.lower)
        total += len(found)
        grid.add_row(r.target, str(len(found)), ", ".join(found[:12]) + (" ..." if len(found) > 12 else ""))
    console.print(grid)
    info(console, f"{total} accounts found across {len(results)} usernames")
