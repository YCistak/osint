"""Interactive shell: ``osint ❯`` prompt with history and tab completion."""

from __future__ import annotations

import os
import shlex
import sys
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console
from rich.text import Text

from . import domainscan, emailscan, report, runner, username
from .banner import clear_screen, print_banner
from .models import ScanResult
from .sites import Site
from .ui import error, info, render_result

COMMANDS = ["username", "email", "domain", "save", "show", "help", "clear", "exit", "quit"]
PROMPT = "osint ❯ "

HELP = """\
Commands:
  username <name>          search a username on {sites} sites
  email <address>          breaches, registered accounts, profiles, mail server
                           flags: --unsafe (include password-reset checks),
                                  --all-modules (include known-dead checks)
  domain <domain|ip>       whois, DNS, subdomains (domain) or reverse DNS, geolocation (IP)
  save [path]              save the last result as Markdown (default: ./reports/)
  show all|found           re-display the last result (all = include not found / unknown)
  clear                    clear the screen
  help                     this text
  exit | quit | Ctrl-D     leave

Ctrl-C during a scan cancels the scan, not the program."""


def history_path() -> Path:
    env = os.environ.get("OSINT_HISTORY_FILE")
    if env:
        return Path(env)
    base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "osint" / "history"


@dataclass
class Session:
    console: Console
    sites: list[Site]
    last: ScanResult | None = None
    running: bool = True
    history: list[str] = field(default_factory=list)


def parse_line(line: str) -> tuple[str, list[str]]:
    """Split a prompt line into ``(command, args)``. Raises ValueError on bad quoting."""
    parts = shlex.split(line)
    if not parts:
        return "", []
    return parts[0].lower(), parts[1:]


def split_flags(args: list[str]) -> tuple[list[str], set[str]]:
    flags = {a for a in args if a.startswith("--")}
    return [a for a in args if not a.startswith("--")], flags


def cmd_username(s: Session, args: list[str]) -> None:
    args, _ = split_flags(args)
    if len(args) != 1:
        error(s.console, "usage: username <name>")
        return
    name = args[0]
    if not username.username_valid(name):
        error(s.console, "invalid username (allowed: letters, digits, '.', '_', '-', max 40 chars)")
        return
    result = runner.run_username(name, s.sites, s.console)
    s.last = result
    render_result(s.console, result)


def cmd_email(s: Session, args: list[str]) -> None:
    args, flags = split_flags(args)
    if len(args) != 1 or not emailscan.email_valid(args[0]):
        error(s.console, "usage: email <address>   (e.g. email jane@example.com)")
        return
    unknown_flags = flags - {"--unsafe", "--all-modules"}
    if unknown_flags:
        error(s.console, f"unknown flag: {', '.join(sorted(unknown_flags))}")
        return
    result = runner.run_email(args[0], s.console, unsafe="--unsafe" in flags,
                              all_modules="--all-modules" in flags)
    s.last = result
    render_result(s.console, result)


def cmd_domain(s: Session, args: list[str]) -> None:
    if len(args) != 1:
        error(s.console, "usage: domain <domain|ip>")
        return
    target = domainscan.clean_target(args[0])
    if domainscan.target_kind(target) == "invalid":
        error(s.console, f"'{args[0]}' is not a valid domain or IP address")
        return
    result = runner.run_domain(target, s.console)
    s.last = result
    render_result(s.console, result)


def cmd_save(s: Session, args: list[str]) -> None:
    if s.last is None:
        error(s.console, "nothing to save yet: run username, email or domain first")
        return
    if len(args) > 1:
        error(s.console, "usage: save [path]")
        return
    try:
        path = report.save_report(s.last, args[0] if args else None)
    except OSError as e:
        error(s.console, f"could not save report: {e}")
        return
    s.console.print(Text("[+]", style="bold green"), f"report saved: {path}")


def cmd_show(s: Session, args: list[str]) -> None:
    if len(args) != 1 or args[0] not in ("all", "found"):
        error(s.console, "usage: show all|found")
        return
    if s.last is None:
        error(s.console, "no result to show yet")
        return
    render_result(s.console, s.last, show=args[0])


def cmd_help(s: Session, args: list[str]) -> None:
    s.console.print(HELP.format(sites=len(s.sites)), markup=False)


def cmd_clear(s: Session, args: list[str]) -> None:
    s.console.clear()


def cmd_exit(s: Session, args: list[str]) -> None:
    s.running = False


HANDLERS = {
    "username": cmd_username,
    "email": cmd_email,
    "domain": cmd_domain,
    "save": cmd_save,
    "show": cmd_show,
    "help": cmd_help,
    "?": cmd_help,
    "clear": cmd_clear,
    "exit": cmd_exit,
    "quit": cmd_exit,
}


def execute(s: Session, line: str) -> None:
    """Run one prompt line. Never raises for user mistakes."""
    try:
        cmd, args = parse_line(line)
    except ValueError as e:
        error(s.console, f"cannot parse input: {e}")
        return
    if not cmd:
        return
    handler = HANDLERS.get(cmd)
    if handler is None:
        error(s.console, f"unknown command '{cmd}'. Type 'help'.")
        return
    try:
        handler(s, args)
    except KeyboardInterrupt:
        s.console.print()
        info(s.console, "cancelled")


def _read_line_plain(console: Console) -> str | None:
    """Fallback for non-interactive stdin (pipes, files)."""
    console.print(PROMPT, end="", markup=False)
    line = sys.stdin.readline()
    if line == "":
        return None
    console.print(line.rstrip("\n"), markup=False)  # echo so transcripts read naturally
    return line


def _make_prompt_session():
    from prompt_toolkit import PromptSession
    from prompt_toolkit.completion import WordCompleter
    from prompt_toolkit.history import FileHistory

    path = history_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        history = FileHistory(str(path))
    except OSError:
        from prompt_toolkit.history import InMemoryHistory

        history = InMemoryHistory()
    completer = WordCompleter(COMMANDS, ignore_case=True, sentence=True)
    return PromptSession(history=history, completer=completer, complete_while_typing=False)


def run(console: Console, sites: list[Site], *, banner: bool = True) -> int:
    """Start the interactive loop. Returns the process exit code."""
    if banner:
        clear_screen(console)
        print_banner(console, len(sites))
    session = Session(console, sites)
    interactive = sys.stdin.isatty() and sys.stdout.isatty()
    prompt_session = _make_prompt_session() if interactive else None

    from prompt_toolkit.formatted_text import ANSI

    ansi_prompt = ANSI("\x1b[1;36mosint\x1b[0m \x1b[1;34m❯\x1b[0m ")
    while session.running:
        try:
            if prompt_session is not None:
                line = prompt_session.prompt(ansi_prompt)
            else:
                line = _read_line_plain(console)
                if line is None:
                    break
        except KeyboardInterrupt:  # Ctrl-C at the prompt: discard the line
            console.print()
            continue
        except EOFError:  # Ctrl-D
            console.print()
            break
        execute(session, line)
    return 0
