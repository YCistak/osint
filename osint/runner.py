"""Run scans with progress output and clean Ctrl-C handling.

Shared by the interactive REPL and the one-shot CLI. A Ctrl-C during a scan
cancels only that scan; whatever was collected so far is returned with
``cancelled=True``.
"""

from __future__ import annotations

import asyncio

from rich.console import Console

from . import domainscan, emailscan, username
from .models import Hit, ScanResult
from .sites import Site
from .ui import ScanProgress, info


def run_username(
    name: str,
    sites: list[Site],
    console: Console,
    *,
    progress: bool = True,
    show_missing: bool = False,
    show_unknown: bool = False,
    print_hits: bool = True,
    concurrency: int = username.DEFAULT_CONCURRENCY,
    timeout: float = username.DEFAULT_TIMEOUT,
) -> ScanResult:
    result = ScanResult("username", name)
    hits: list[Hit] = []
    if progress:
        info(console, f"searching [bold]{name}[/] on {len(sites)} sites (Ctrl-C cancels)")
    try:
        if progress:
            with ScanProgress(console, len(sites), print_hits=print_hits,
                              show_missing=show_missing, show_unknown=show_unknown) as p:
                asyncio.run(username.scan(name, sites, hits, p.update,
                                          concurrency=concurrency, timeout=timeout))
        else:
            asyncio.run(username.scan(name, sites, hits, None,
                                      concurrency=concurrency, timeout=timeout))
    except KeyboardInterrupt:
        result.cancelled = True
    result.hits = list(hits)
    return result


def run_email(
    address: str,
    console: Console,
    *,
    progress: bool = True,
    unsafe: bool = False,
    all_modules: bool = False,
) -> ScanResult:
    state = emailscan.EmailState(address)
    modules, state.skipped_modules = emailscan.load_modules(unsafe, all_modules)
    if progress:
        info(console, f"checking [bold]{address}[/] with {len(modules)} account checks "
                      "+ breach, profile and mail-server lookups (Ctrl-C cancels)")
        with ScanProgress(console, len(modules), print_hits=False, label="services") as p:
            emailscan.scan(address, state, p.update, modules=modules)
    else:
        emailscan.scan(address, state, None, modules=modules)
    return state.to_result()


def run_domain(target: str, console: Console, *, progress: bool = True) -> ScanResult:
    cleaned = domainscan.clean_target(target)
    result = ScanResult("domain", cleaned)
    if progress:
        info(console, f"investigating [bold]{cleaned}[/] (Ctrl-C cancels)")

    def step(title: str) -> None:
        if progress:
            info(console, title.lower() + " ...")

    try:
        domainscan.scan(cleaned, result, step)
    except KeyboardInterrupt:
        result.cancelled = True
    return result
