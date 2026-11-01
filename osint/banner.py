"""Block-letter banner rendered with a cyan -> blue gradient."""

from __future__ import annotations

from rich.console import Console
from rich.text import Text

from . import __version__, net

# "ANSI Shadow" style block letters spelling OSINT.
LOGO = [
    " ██████╗ ███████╗██╗███╗   ██╗████████╗",
    "██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝",
    "██║   ██║███████╗██║██╔██╗ ██║   ██║   ",
    "██║   ██║╚════██║██║██║╚██╗██║   ██║   ",
    "╚██████╔╝███████║██║██║ ╚████║   ██║   ",
    " ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   ",
]

# Gradient endpoints (RGB): bright cyan -> deep blue.
START = (0, 229, 255)
END = (41, 98, 255)


def _lerp(a: tuple[int, int, int], b: tuple[int, int, int], t: float) -> str:
    r, g, bl = (round(x + (y - x) * t) for x, y in zip(a, b))
    return f"#{r:02x}{g:02x}{bl:02x}"


def logo_text() -> Text:
    """The logo as a rich Text, colored left-to-right along the gradient."""
    width = max(len(line) for line in LOGO)
    text = Text()
    for row, line in enumerate(LOGO):
        for col, ch in enumerate(line):
            if ch == " ":
                text.append(ch)
            else:
                # Mix horizontal position with a slight vertical shift for depth.
                t = min(1.0, (col / max(width - 1, 1)) * 0.85 + (row / len(LOGO)) * 0.15)
                text.append(ch, style=_lerp(START, END, t))
        text.append("\n")
    return text


def subtitle(site_count: int) -> Text:
    line = _subtitle(site_count)
    proxy = net.describe()
    if proxy:
        line.append(" · ", style="dim")
        line.append(f"proxy: {proxy}", style="bold magenta")
    return line


def _subtitle(site_count: int) -> Text:
    return Text.assemble(
        (f"v{'.'.join(__version__.split('.')[:2])}", "bold cyan"),
        (" · ", "dim"),
        (f"{site_count} sites", "bold"),
        (" · ", "dim"),
        ("type ", ""),
        ("'help'", "bold yellow"),
    )


def print_banner(console: Console, site_count: int) -> None:
    """Print the banner without clearing the screen."""
    console.print(logo_text(), end="")
    console.print(subtitle(site_count))
    console.print()


def print_compact_banner(console: Console, site_count: int) -> None:
    """One-line banner for the category screens."""
    width = 5
    word = Text()
    for i, ch in enumerate("OSINT"):
        word.append(ch, style="bold " + _lerp(START, END, i / (width - 1)))
    console.print(word, Text("  "), subtitle(site_count))
    console.print()


CLEAR_SEQUENCE = "\033[H\033[2J\033[3J"  # home, erase screen, erase scrollback


def clear_screen(console: Console) -> None:
    """Wipe screen and scrollback so the next output starts at the very top (TTY only)."""
    if console.is_terminal:
        console.file.write(CLEAR_SEQUENCE)
        console.file.flush()
