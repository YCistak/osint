"""Interactive shell: category menu, ``osint ❯`` prompt, history and context-aware tab completion."""

from __future__ import annotations

import os
import shlex
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.text import Text

from . import (categories, domainscan, emailscan, github, history, historycmd, image, net, password, phone,
               report, runner, username)
from .banner import clear_screen, print_banner, print_compact_banner
from .categories import Category
from .models import ScanResult
from .sites import Site
from .ui import error, info, render_chain_summary, render_result

PROMPT_BASE = "osint"
# commands available everywhere (besides the category commands)
GLOBAL_COMMANDS = ["save", "show", "history", "variations", "proxy", "help", "clear", "exit", "quit"]
BACK_WORDS = ("back", "0", "..")

# (usage, description, extra detail lines) -- rows of `help` that are not categories.
COMMAND_ROWS = [
    ("save [path] [--html]", "save last result (Markdown; .html or --html for a web page)", []),
    ("show all|found", "toggle unknown/not-found rows", []),
    ("history [show|diff|clear]", "stored scans: list, show <id>, diff <id> <id>, clear", []),
    ("variations on|off", "also search likely variants of usernames (or add -v to one scan)", []),
    ("proxy <url>|tor|off", "route traffic through a proxy / Tor; no argument shows the state", []),
    ("clear", "clear screen and redraw the current menu", []),
    ("help", "this text", []),
    ("exit | quit | Ctrl-D", "leave", []),
]


# ------------------------------------------------------------------ session

def ask_yes_no(prompt: str) -> str:
    """Read an answer from a real terminal; anything else (pipes, EOF) counts as 'no'."""
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return "n"
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt):
        return "n"


def read_secret(prompt: str) -> str:
    """Read a secret without echo. Non-interactive stdin is read as a plain line (no echo either)."""
    import getpass

    try:
        if sys.stdin.isatty():
            return getpass.getpass(prompt)
        return sys.stdin.readline().rstrip("\r\n")
    except (EOFError, KeyboardInterrupt):
        return ""


@dataclass
class Session:
    console: Console
    sites: list[Site]
    last: ScanResult | None = None
    running: bool = True
    category: Category | None = None  # None = main menu
    history: list[str] = field(default_factory=list)
    ask: Callable[[str], str] = field(default=lambda prompt: ask_yes_no(prompt))
    secret: Callable[[str], str] = field(default=lambda prompt: read_secret(prompt))
    variations: bool = False


def set_last(s: Session, result: ScanResult) -> None:
    """Remember the result for `save`/`show` and record it in the history (adds a change note)."""
    history.after_scan(result)
    s.last = result


def prompt_name(s: Session) -> str:
    return f"{PROMPT_BASE}/{s.category.key}" if s.category else PROMPT_BASE


def prompt_text(s: Session) -> str:
    return f"{prompt_name(s)} ❯ "


def prompt_ansi(s: Session) -> str:
    name = PROMPT_BASE
    sub = f"\x1b[2m/{s.category.key}\x1b[0m" if s.category else ""
    return f"\x1b[1;36m{name}\x1b[0m{sub} \x1b[1;34m❯\x1b[0m "


# ------------------------------------------------------------------ screens

def _grid() -> Table:
    table = Table.grid(padding=(0, 3))
    table.add_column(style="bold cyan", no_wrap=True)
    table.add_column(style="bold", no_wrap=True)
    table.add_column(style="dim")
    return table


def print_menu(console: Console, site_count: int) -> None:
    """The numbered category menu (built from the registry)."""
    table = _grid()
    for num, label, desc in categories.menu_rows(site_count):
        table.add_row(Text(f"  [{num}]"), Text(label), Text(desc))
    console.print(table)
    console.print()
    console.print(Text("  Type a number or a name. 'help' lists every command.", style="dim"))
    console.print()


def print_category(console: Console, cat: Category, site_count: int) -> None:
    """Short help of one category, shown under the compact banner."""
    console.print(Text.assemble(("  ", ""), (cat.label, "bold cyan"), ("  ", ""), (cat.describe(site_count), "dim")))
    console.print()
    table = Table.grid(padding=(0, 3))
    table.add_column(style="bold cyan", no_wrap=True)
    table.add_column(style="dim")
    hint = cat.example if cat.secret else f"just type it to scan, e.g. {cat.example}"
    table.add_row(Text(f"  {cat.target}"), Text(hint))
    for usage, desc in cat.extra_help:
        table.add_row(Text("  " + usage), Text(desc))
    table.add_row(Text("  save [path] [--html]"), Text("save the last result"))
    table.add_row(Text("  show all|found"), Text("toggle unknown/not-found rows"))
    table.add_row(Text("  back | 0"), Text("main menu"))
    table.add_row(Text("  clear | help | exit"), Text(""))
    console.print(table)
    console.print()


def draw_screen(s: Session, *, clear: bool = True) -> None:
    """Clear (TTY only) and draw the main menu or the current category screen."""
    n = len(s.sites)
    if clear:
        clear_screen(s.console)
    if s.category is None:
        print_banner(s.console, n)
        print_menu(s.console, n)
    else:
        print_compact_banner(s.console, n)
        print_category(s.console, s.category, n)


def help_text(site_count: int) -> str:
    lines = ["Menu:  type a number or a name to enter a category, 0 to exit.", "", "Commands:"]
    for cat in categories.REGISTRY:
        lines.append(f"  {cat.usage():<24} {cat.describe(site_count)}")
        lines.extend(f"  {'':<24} {usage}  {desc}" for usage, desc in cat.extra_help)
    for usage, desc, extra in COMMAND_ROWS:
        lines.append(f"  {usage:<24} {desc}")
        lines.extend(f"  {'':<24} {e}" for e in extra)
    lines += ["",
              "Inside a category just type the target; 'back' (or 0) returns to the menu.",
              "Ctrl-C during a scan cancels the scan, not the program."]
    return "\n".join(lines)


def history_path() -> Path:
    env = os.environ.get("OSINT_HISTORY_FILE")
    if env:
        return Path(env)
    base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "osint" / "history"


# ------------------------------------------------------------------ parsing

def parse_line(line: str) -> tuple[str, list[str]]:
    """Split a prompt line into ``(command, args)``. Raises ValueError on bad quoting."""
    parts = shlex.split(line)
    if not parts:
        return "", []
    return parts[0].lower(), parts[1:]


def split_flags(args: list[str]) -> tuple[list[str], set[str]]:
    flags = {a for a in args if a.startswith("--")}
    return [a for a in args if not a.startswith("--")], flags


# ------------------------------------------------------------------ category commands

def cmd_username(s: Session, args: list[str]) -> None:
    short_v = "-v" in args
    args = [a for a in args if a != "-v"]
    args, flags = split_flags(args)
    if len(args) != 1 or flags - {"--variations"}:
        error(s.console, "usage: username <name> [-v]")
        return
    name = args[0]
    if not username.username_valid(name):
        error(s.console, "invalid username (allowed: letters, digits, '.', '_', '-', max 40 chars)")
        return
    if short_v or "--variations" in flags or s.variations:
        result = runner.run_username_variations(name, s.sites, s.console)
    else:
        result = runner.run_username(name, s.sites, s.console)
    set_last(s, result)
    render_result(s.console, result)


def cmd_variations(s: Session, args: list[str]) -> None:
    if not args:
        info(s.console, f"variations: {'on' if s.variations else 'off'}")
        return
    if len(args) != 1 or args[0].lower() not in ("on", "off"):
        error(s.console, "usage: variations on|off")
        return
    s.variations = args[0].lower() == "on"
    info(s.console, f"variations {'on: username scans also try likely variants of the name' if s.variations else 'off'}")


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
    set_last(s, result)
    render_result(s.console, result)
    offer_chain(s, result)


def offer_chain(s: Session, result: ScanResult) -> None:
    """After an email scan, offer to search the discovered usernames."""
    if not result.usernames or result.cancelled:
        return
    s.console.print()
    info(s.console, "usernames discovered: " + ", ".join(result.usernames))
    answer = s.ask("Scan these usernames? [y/N] ").strip().lower()
    if answer in ("y", "yes"):
        results = runner.run_chain(result, s.sites, s.console)
        if results:
            render_chain_summary(s.console, results)


def cmd_domain(s: Session, args: list[str]) -> None:
    if len(args) != 1:
        error(s.console, "usage: domain <domain|ip>")
        return
    target = domainscan.clean_target(args[0])
    if domainscan.target_kind(target) == "invalid":
        error(s.console, f"'{args[0]}' is not a valid domain or IP address")
        return
    result = runner.run_domain(target, s.console)
    set_last(s, result)
    render_result(s.console, result)


def cmd_github(s: Session, args: list[str]) -> None:
    args, _ = split_flags(args)
    if len(args) != 1 or not username.username_valid(args[0]):
        error(s.console, "usage: github <username>   (e.g. github torvalds)")
        return
    info(s.console, f"reading the public GitHub profile of [bold]{args[0]}[/]"
                    + ("" if github.token() else " (no GITHUB_TOKEN: 60 API calls per hour)"))
    try:
        result = github.analyze(args[0])
    except github.GitHubError as e:
        error(s.console, str(e))
        return
    set_last(s, result)
    render_result(s.console, result)


def parse_region(args: list[str]) -> tuple[list[str], str | None, str]:
    """Pull ``--region XX`` / ``--region=XX`` out of ``args``. Returns (rest, region, error)."""
    rest: list[str] = []
    region: str | None = None
    it = iter(args)
    for a in it:
        if a.startswith("--region="):
            region = a.split("=", 1)[1]
        elif a == "--region":
            region = next(it, "")
            if not region:
                return rest, None, "--region needs a country code, e.g. --region TR"
        elif a.startswith("--"):
            return rest, None, f"unknown flag: {a}"
        else:
            rest.append(a)
    return rest, region, ""


def cmd_phone(s: Session, args: list[str]) -> None:
    rest, region, problem = parse_region(args)
    if problem or not rest:
        error(s.console, problem or "usage: phone <number> [--region XX]   (e.g. phone +905551112233)")
        return
    region = (region or phone.DEFAULT_REGION).upper()
    try:
        if not phone.region_valid(region):
            error(s.console, f"unknown region '{region}' (use a 2-letter country code such as TR, US, DE)")
            return
        result = phone.analyze(" ".join(rest), region)
    except phone.PhoneError as e:
        error(s.console, str(e))
        return
    set_last(s, result)
    render_result(s.console, result)


def cmd_image(s: Session, args: list[str]) -> None:
    args, _ = split_flags(args)
    if not args:
        error(s.console, "usage: image <path|url>   (e.g. image ~/Pictures/photo.jpg)")
        return
    try:
        result = image.analyze_target(" ".join(args))
    except image.ImageError as e:
        error(s.console, str(e))
        return
    set_last(s, result)
    render_result(s.console, result)


def check_password(s: Session, pw: str) -> None:
    """Run one password check and print it. The result is not kept (no `save`, no history)."""
    try:
        result = password.analyze(pw)
    except password.PasswordError as e:
        error(s.console, str(e))
        return
    render_result(s.console, result)


def cmd_password(s: Session, args: list[str]) -> None:
    if s.category is not None and s.category.secret and args:
        # called by the hidden prompt of the category: args[0] is the password
        check_password(s, args[0])
        return
    if args:
        error(s.console, "never type a password on the command line (it would be kept in the shell "
                         "history); enter the category and use the hidden prompt instead")
        return
    check_password_prompt(s)


def check_password_prompt(s: Session) -> None:
    pw = s.secret("Password (hidden, empty line cancels): ")
    if pw:
        check_password(s, pw)


# ------------------------------------------------------------------ shared commands

def cmd_save(s: Session, args: list[str]) -> None:
    if s.last is None:
        error(s.console, "nothing to save yet: run a scan first")
        return
    args, flags = split_flags(args)
    if len(args) > 1 or flags - {"--html"}:
        error(s.console, "usage: save [path] [--html]")
        return
    try:
        path = report.save_report(s.last, args[0] if args else None,
                                  fmt="html" if "--html" in flags else None)
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


def cmd_proxy(s: Session, args: list[str]) -> None:
    if not args:
        info(s.console, f"proxy: {net.describe() or 'off'}")
        return
    if len(args) != 1:
        error(s.console, "usage: proxy <url>|tor|off   (e.g. proxy socks5h://127.0.0.1:9050)")
        return
    word = args[0].lower()
    try:
        if word in ("off", "none"):
            net.set_proxy(None)
            info(s.console, "proxy off (direct connections)")
            return
        net.set_proxy(net.TOR_PROXY if word == "tor" else args[0])
    except net.ProxyError as e:
        error(s.console, str(e))
        return
    if word == "tor":
        is_tor, message = net.check_tor()
        if not is_tor:
            net.set_proxy(None)
            error(s.console, message + " Proxy left off.")
            return
        info(s.console, message)
    else:
        info(s.console, f"proxy set: {net.describe()}")
    info(s.console, net.bypass_warning())


def cmd_history(s: Session, args: list[str]) -> None:
    historycmd.handle(args, s.console, s.ask)


def cmd_help(s: Session, args: list[str]) -> None:
    s.console.print(help_text(len(s.sites)), markup=False)


def cmd_clear(s: Session, args: list[str]) -> None:
    draw_screen(s)


def cmd_exit(s: Session, args: list[str]) -> None:
    s.running = False


def go_back(s: Session) -> None:
    if s.category is None:
        info(s.console, "already at the main menu")
        return
    s.category = None
    draw_screen(s)


def enter_category(s: Session, cat: Category) -> None:
    s.category = cat
    draw_screen(s)
    if cat.secret:
        info(s.console, "input is hidden and never saved; an empty line returns to the menu")


SHARED_HANDLERS = {
    "save": cmd_save,
    "show": cmd_show,
    "proxy": cmd_proxy,
    "history": cmd_history,
    "variations": cmd_variations,
    "help": cmd_help,
    "?": cmd_help,
    "clear": cmd_clear,
    "exit": cmd_exit,
    "quit": cmd_exit,
}


# ------------------------------------------------------------------ registry (one place to add a category)

categories.register(Category(
    key="username", label="Username", summary="search a username on {sites} sites",
    target="<name>", example="torvalds", run=cmd_username, flags=("--variations",),
    extra_help=(("<name> -v", "also try likely variants (or: variations on|off)"),)))
categories.register(Category(
    key="email", label="Email", summary="breaches, accounts, profiles, mail server",
    target="<address>", example="jane@example.com", run=cmd_email,
    flags=("--unsafe", "--all-modules"),
    extra_help=(("--unsafe", "include password-reset checks (may email the target)"),
                ("--all-modules", "include known-dead account checks"))))
categories.register(Category(
    key="domain", label="Domain/IP", summary="whois, DNS, subdomains, geolocation",
    target="<domain|ip>", example="example.com", run=cmd_domain, aliases=("ip", "domain/ip")))
categories.register(Category(
    key="phone", label="Phone", summary="country, carrier, line type",
    target="<number>", example="+905551112233", run=cmd_phone, flags=("--region",),
    extra_help=(("--region XX", "country for numbers without + (default TR)"),),
    cli_usage="phone <number> [--region XX]"))
categories.register(Category(
    key="image", label="Image", summary="EXIF, GPS, reverse image search",
    target="<path|url>", example="~/Pictures/photo.jpg", run=cmd_image, path_target=True))
categories.register(Category(
    key="github", label="GitHub", summary="profile, repos, activity, emails in commits",
    target="<username>", example="torvalds", run=cmd_github))
categories.register(Category(
    key="password", label="Password", summary="check a password against known breaches",
    target="(hidden prompt)", example="type it, nothing is echoed or saved", run=cmd_password,
    secret=True, cli_usage="password",
    extra_help=(("(hidden)", "only 5 characters of the SHA-1 hash leave this machine"),)))


# ------------------------------------------------------------------ dispatch

def execute(s: Session, line: str) -> None:
    """Run one prompt line. Never raises for user mistakes."""
    if s.category is not None and s.category.secret:
        # inside a secret category the whole line is the secret: no parsing, no echo, no history
        raw = line.rstrip("\r\n")
        if not raw.strip():
            go_back(s)
        else:
            try:
                s.category.run(s, [raw])
            except KeyboardInterrupt:
                s.console.print()
                info(s.console, "cancelled")
        return
    try:
        cmd, args = parse_line(line)
    except ValueError as e:
        error(s.console, f"cannot parse input: {e}")
        return
    if not cmd:
        return
    try:
        dispatch(s, line, cmd, args)
    except KeyboardInterrupt:
        s.console.print()
        info(s.console, "cancelled")


def dispatch(s: Session, line: str, cmd: str, args: list[str]) -> None:
    shared = SHARED_HANDLERS.get(cmd)
    if s.category is None:
        if cmd == "0" and not args:
            s.running = False
            return
        if cmd in BACK_WORDS and not args:
            go_back(s)
            return
        cat = categories.find(cmd)
        if cat is not None:
            if args:
                cat.run(s, args)  # power-user form: "username torvalds"
            else:
                enter_category(s, cat)
            return
        if shared is not None:
            shared(s, args)
            return
        error(s.console, f"unknown command '{cmd}'. Type 'help'.")
        return

    # inside a category
    if cmd in BACK_WORDS and not args:
        go_back(s)
        return
    if shared is not None:
        shared(s, args)
        return
    other = categories.find(cmd)
    if args and other is not None and not cmd.isdigit():
        other.run(s, args)  # "email a@b.com" still works from inside another category
        return
    # everything else is the target (re-split with the raw words so paths and numbers keep spaces)
    try:
        words = shlex.split(line)
    except ValueError:
        words = [cmd, *args]
    s.category.run(s, words)


# ------------------------------------------------------------------ completion

def _context_category(s: Session, head: str) -> Category | None:
    """The category a typed line belongs to: the current one, or the one named by its first word."""
    named = categories.find(head) if head and not head.isdigit() else None
    if named is not None:
        return named
    return s.category if head not in SHARED_HANDLERS else None


def completion_candidates(s: Session, text: str) -> list[str]:
    """Words that can complete the last (partial) word of ``text`` in the current context."""
    parts = text.split(" ")
    prefix = parts[-1].lower()
    keys = [c.key for c in categories.REGISTRY]
    if len(parts) == 1:  # completing the first word
        if s.category is None:
            words = keys + [str(i) for i in range(len(keys) + 1)] + GLOBAL_COMMANDS
        else:
            words = ["back"] + keys + GLOBAL_COMMANDS
        return sorted((w for w in words if w.startswith(prefix)), key=lambda w: (not w.isalpha(), w))
    head = parts[0].lower()
    if head == "save":
        words = ["--html"]
    elif head == "show":
        words = ["all", "found"]
    elif head == "variations":
        words = ["on", "off"]
    elif head == "history":
        words = ["list", "show", "diff", "clear"]
    elif head == "proxy":
        words = ["tor", "off"]
    else:
        cat = _context_category(s, head)
        words = list(cat.flags) if cat else []
    return [w for w in words if w.startswith(prefix) and w not in parts[:-1]]


def wants_path(s: Session, text: str) -> bool:
    """True when the word being typed is a file path (the image target)."""
    parts = text.split(" ")
    if parts[-1].startswith("--"):
        return False
    if len(parts) == 1:
        return bool(s.category and s.category.path_target and any(ch in text for ch in "/~."))
    cat = _context_category(s, parts[0].lower())
    return bool(cat and cat.path_target)


def history_excluded(line: str) -> bool:
    """True for lines that must never reach the history file: a secret category word with arguments."""
    parts = line.split(None, 1)
    if len(parts) < 2:
        return False
    cat = categories.find(parts[0])
    return bool(cat and cat.secret)


def _make_prompt_session(session: Session):
    from prompt_toolkit import PromptSession
    from prompt_toolkit.completion import Completer, Completion, PathCompleter
    from prompt_toolkit.history import FileHistory

    class SafeFileHistory(FileHistory):
        def store_string(self, string: str) -> None:
            if not history_excluded(string):
                super().store_string(string)

    class ContextCompleter(Completer):
        def __init__(self) -> None:
            self.paths = PathCompleter(expanduser=True)

        def get_completions(self, document, complete_event):
            text = document.text_before_cursor
            if wants_path(session, text):
                from prompt_toolkit.document import Document

                word = text.split(" ")[-1] if " " in text else text
                yield from self.paths.get_completions(Document(word, len(word)), complete_event)
                return
            last = text.split(" ")[-1]
            for w in completion_candidates(session, text):
                yield Completion(w, start_position=-len(last))

    path = history_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        history = SafeFileHistory(str(path))
    except OSError:
        from prompt_toolkit.history import InMemoryHistory

        history = InMemoryHistory()
    return PromptSession(history=history, completer=ContextCompleter(), complete_while_typing=False)


def _read_line_plain(console: Console, s: Session) -> str | None:
    """Fallback for non-interactive stdin (pipes, files)."""
    console.print(prompt_text(s), end="", markup=False)
    line = sys.stdin.readline()
    if line == "":
        return None
    if not (s.category and s.category.secret):  # never echo a secret
        console.print(line.rstrip("\n"), markup=False)  # echo so transcripts read naturally
    else:
        console.print()
    return line


def run(console: Console, sites: list[Site], *, banner: bool = True) -> int:
    """Start the interactive loop. Returns the process exit code."""
    session = Session(console, sites)
    if banner:
        draw_screen(session)
    interactive = sys.stdin.isatty() and sys.stdout.isatty()
    prompt_session = _make_prompt_session(session) if interactive else None

    from prompt_toolkit import PromptSession
    from prompt_toolkit.formatted_text import ANSI
    from prompt_toolkit.history import DummyHistory

    secret_session = PromptSession(history=DummyHistory(), enable_history_search=False)

    while session.running:
        try:
            if prompt_session is not None and session.category is not None and session.category.secret:
                line = secret_session.prompt(ANSI(prompt_ansi(session)), is_password=True)
            elif prompt_session is not None:
                line = prompt_session.prompt(ANSI(prompt_ansi(session)))
            else:
                line = _read_line_plain(console, session)
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
