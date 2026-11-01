"""Category registry for the interactive menu.

To add a category, build a :class:`Category` and call :func:`register` once
(see the bottom of ``repl.py``). The main menu, the numbering, the category
screen, ``help`` and tab completion are all generated from this list, so no
menu code needs to change.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Category:
    key: str  # command and prompt name, e.g. "username"
    label: str  # menu label, e.g. "Username"
    summary: str  # one line; "{sites}" is replaced by the site count
    target: str  # what the user types inside the category, e.g. "<name>"
    example: str  # example target shown on the category screen
    run: Callable  # run(session, args: list[str]) -> None
    flags: tuple[str, ...] = ()  # flags accepted after the target (for completion and help)
    extra_help: tuple[tuple[str, str], ...] = ()  # (usage, description) rows for the category screen
    path_target: bool = False  # the target is a file path (enables path completion)
    aliases: tuple[str, ...] = ()
    cli_usage: str = ""  # usage shown by the global command; defaults to "key target"

    def usage(self) -> str:
        return self.cli_usage or f"{self.key} {self.target}"

    def describe(self, site_count: int) -> str:
        return self.summary.format(sites=site_count)


REGISTRY: list[Category] = []


def register(category: Category) -> Category:
    if any(c.key == category.key for c in REGISTRY):
        raise ValueError(f"category '{category.key}' is already registered")
    REGISTRY.append(category)
    return category


def find(token: str) -> Category | None:
    """Look a category up by menu number ("1"), key, label or alias (case-insensitive)."""
    token = token.strip().lower()
    if not token:
        return None
    if token.isdigit():
        n = int(token)
        return REGISTRY[n - 1] if 1 <= n <= len(REGISTRY) else None
    for c in REGISTRY:
        if token in (c.key, c.label.lower(), *c.aliases):
            return c
    return None


def menu_rows(site_count: int) -> list[tuple[str, str, str]]:
    """(number, label, description) for every category, then the exit row."""
    rows = [(str(i), c.label, c.describe(site_count)) for i, c in enumerate(REGISTRY, 1)]
    rows.append(("0", "Exit", ""))
    return rows
