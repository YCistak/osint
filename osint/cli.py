"""Command-line entry point: interactive shell by default, one-shot commands via argparse."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__, domainscan, emailscan, image, phone, report, repl, runner, username
from .banner import print_banner
from .sites import SiteListError, load_sites
from .ui import error, info, make_console, render_chain_summary, render_result


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--no-banner", action="store_true", help="do not print the banner")
    common.add_argument("--json", action="store_true", help="print the result as JSON (no banner, no progress)")
    common.add_argument("--save", nargs="?", const="", metavar="PATH",
                        help="also save a report: Markdown, or HTML for a .html path (default folder: ./reports/)")
    common.add_argument("--html", action="store_true", help="with --save: write a single-file HTML report")

    parser = argparse.ArgumentParser(
        prog="osint",
        description="Terminal OSINT toolkit. Run without a command for the interactive shell.",
        parents=[common],
        epilog="Use it only on yourself, in CTFs, or with authorization.",
    )
    parser.add_argument("--version", action="version", version=f"osint {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="{username,email,domain,phone,image}")

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
    p.add_argument("--chain", action="store_true",
                   help="also search the usernames found in the email results (GitHub, Gravatar, local part)")

    p = sub.add_parser("domain", parents=[common], help="whois, DNS, subdomains / IP geolocation")
    p.add_argument("target", metavar="DOMAIN|IP")

    p = sub.add_parser("phone", parents=[common], help="country, carrier, line type (offline)")
    p.add_argument("target", metavar="NUMBER")
    p.add_argument("--region", default=phone.DEFAULT_REGION, metavar="XX",
                   help=f"country code for numbers without '+' (default {phone.DEFAULT_REGION})")

    p = sub.add_parser("image", parents=[common], help="EXIF metadata and GPS of a local image")
    p.add_argument("target", metavar="PATH")
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
    elif args.command == "phone":
        try:
            if not phone.region_valid(args.region):
                error(errors, f"unknown region '{args.region}' (use a 2-letter country code such as TR, US, DE)")
                return 2
            result = phone.analyze(args.target, args.region.upper())
        except phone.PhoneError as e:
            error(errors, str(e))
            return 2
        if not args.no_banner and not quiet:
            print_banner(console, len(load_sites()))
        show = "found"
    elif args.command == "image":
        try:
            result = image.analyze(args.target)
        except image.ImageError as e:
            error(errors, str(e))
            return 2
        if not args.no_banner and not quiet:
            print_banner(console, len(load_sites()))
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
        if getattr(args, "chain", False) and result.usernames and not result.cancelled:
            runner.run_chain(result, load_sites(), console, progress=False)
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    else:
        # username hits were already printed live; show only the totals
        render_result(console, result, show, streamed=result.kind == "username")
        if getattr(args, "chain", False) and result.usernames and not result.cancelled:
            info(console, "chaining username scans: " + ", ".join(result.usernames))
            results = runner.run_chain(result, load_sites(), console)
            if results:
                render_chain_summary(console, results)

    if args.save is not None:
        path = report.save_report(result, args.save or None, fmt="html" if args.html else None)
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
