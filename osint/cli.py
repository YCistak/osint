"""Command-line entry point: interactive shell by default, one-shot commands via argparse."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__, domainscan, emailscan, report, repl, runner, username
from .banner import print_banner
from .sites import SiteListError, load_sites
from .ui import error, info, make_console, render_result


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--no-banner", action="store_true", help="do not print the banner")
    common.add_argument("--json", action="store_true", help="print the result as JSON (no banner, no progress)")
    common.add_argument("--save", nargs="?", const="", metavar="PATH",
                        help="also save a Markdown report (default folder: ./reports/)")

    parser = argparse.ArgumentParser(
        prog="osint",
        description="Terminal OSINT toolkit. Run without a command for the interactive shell.",
        parents=[common],
        epilog="Use it only on yourself, in CTFs, or with authorization.",
    )
    parser.add_argument("--version", action="version", version=f"osint {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="{username,email,domain}")

    p = sub.add_parser("username", parents=[common], help="search a username on 500 sites")
    p.add_argument("target", metavar="NAME")
    p.add_argument("--show-all", action="store_true", help="also list not-found and unknown sites")
    p.add_argument("--concurrency", type=int, default=username.DEFAULT_CONCURRENCY)
    p.add_argument("--timeout", type=float, default=username.DEFAULT_TIMEOUT)

    p = sub.add_parser("email", parents=[common], help="breaches, accounts, profiles, mail server")
    p.add_argument("target", metavar="ADDRESS")
    p.add_argument("--unsafe", action="store_true",
                   help="include password-reset checks (may email the target)")
    p.add_argument("--all-modules", action="store_true", help="include known-dead holehe modules")

    p = sub.add_parser("domain", parents=[common], help="whois, DNS, subdomains / IP geolocation")
    p.add_argument("target", metavar="DOMAIN|IP")
    return parser


def one_shot(args: argparse.Namespace) -> int:
    quiet = args.json
    console = make_console(quiet=quiet)
    errors = make_console(stderr=True)

    if args.command == "username":
        if not username.username_valid(args.target):
            error(errors, "invalid username (allowed: letters, digits, '.', '_', '-', max 40 chars)")
            return 2
        sites = load_sites()
        if not args.no_banner and not quiet:
            print_banner(console, len(sites))
        result = runner.run_username(
            args.target, sites, console, progress=not quiet,
            show_missing=args.show_all, show_unknown=args.show_all, print_hits=True,
            concurrency=args.concurrency, timeout=args.timeout,
        )
        show = "all" if args.show_all else "found"
    elif args.command == "email":
        if not emailscan.email_valid(args.target):
            error(errors, "invalid email address")
            return 2
        if not args.no_banner and not quiet:
            print_banner(console, len(load_sites()))
        result = runner.run_email(args.target, console, progress=not quiet,
                                  unsafe=args.unsafe, all_modules=args.all_modules)
        show = "found"
    else:
        target = domainscan.clean_target(args.target)
        if domainscan.target_kind(target) == "invalid":
            error(errors, f"'{args.target}' is not a valid domain or IP address")
            return 2
        if not args.no_banner and not quiet:
            print_banner(console, len(load_sites()))
        result = runner.run_domain(target, console, progress=not quiet)
        show = "found"

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    else:
        # username hits were already printed live; show only the totals
        render_result(console, result, show, streamed=result.kind == "username")

    if args.save is not None:
        path = report.save_report(result, args.save or None)
        info(errors if args.json else console, f"report saved: {path}")
    return 130 if result.cancelled else 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command:
        try:
            return one_shot(args)
        except SiteListError as e:
            error(make_console(stderr=True), f"site list problem: {e}")
            return 1
    # no command: interactive shell
    console = make_console()
    try:
        sites = load_sites()
    except SiteListError as e:
        error(make_console(stderr=True), f"site list problem: {e}")
        return 1
    return repl.run(console, sites, banner=not args.no_banner)


if __name__ == "__main__":
    sys.exit(main())
