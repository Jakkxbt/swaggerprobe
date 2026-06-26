#!/usr/bin/env python3
import argparse
import os
import sys
import time
import urllib.parse
from dataclasses import dataclass, field

from . import __version__
from . import baseline, report
from .request import build_request, parse_headers
from .spec import READ_METHODS, load_spec, paths_to_methods


CHECKS = {
    "auth": "swaggerprobe.checks.auth",
    "bola": "swaggerprobe.checks.bola",
    "injection": "swaggerprobe.checks.injection",
    "massassign": "swaggerprobe.checks.massassign",
    "method": "swaggerprobe.checks.method",
    "errors": "swaggerprobe.checks.errors",
}

DESTRUCTIVE = {"POST", "PUT", "PATCH", "DELETE"}


@dataclass
class Context:
    base_url: str
    auth: dict = field(default_factory=dict)
    auth_a: dict = field(default_factory=dict)
    auth_b: dict = field(default_factory=dict)
    allow_write: bool = False
    delay: float = 0.0
    time_based: bool = False
    timeout: int = 10
    path_methods: dict = field(default_factory=dict)
    requests_sent: int = 0


class Colours:
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    END = "\033[0m"


def print_banner(quiet=False):
    if quiet or not sys.stdout.isatty():
        return
    g, c, d, b, e = Colours.GREEN, Colours.CYAN, Colours.DIM, Colours.BOLD, Colours.END
    print(
        f"{g}╾━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╼{e}\n"
        f"{b}{c}  S W A G G E R P R O B E{e}   {g}▓▒░ CobraSEC ░▒▓{e}\n"
        f"{d}  OpenAPI attack surface tester · Attack to Defend{e}\n"
        f"{g}╾━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╼{e}"
    )


def main(argv=None):
    args = parser().parse_args(argv)
    print_banner(args.quiet)
    spec_data, ops, spec_base = load_spec(args.spec)
    base_url = args.base or spec_base
    if not base_url:
        raise SystemExit("--base is required when the spec does not define a server/host")
    selected = _selected_checks(args.checks)

    if not args.run:
        _dry_run(ops, base_url, args, selected)
        return 0

    _enforce_allow_host(base_url, args.allow_host)
    auth = parse_headers(args.auth)
    ctx = Context(
        base_url=base_url,
        auth=auth,
        auth_a=parse_headers(args.auth_a),
        auth_b=parse_headers(args.auth_b),
        allow_write=args.allow_write,
        delay=args.delay,
        time_based=args.time,
        path_methods=paths_to_methods(ops),
    )

    findings = []
    modules = {name: _import_check(name) for name in selected}
    runnable = [op for op in ops if _safe_op(op, args.allow_write)]
    for op in runnable:
        base = baseline.capture(op, ctx, auth)
        ctx.requests_sent += 1
        for name, mod in modules.items():
            findings.extend(mod.run(op, ctx, base))
            if ctx.delay:
                time.sleep(ctx.delay)

    clean = report.clean_findings(findings)
    summary = {
        "tool": "swaggerprobe",
        "version": __version__,
        "operations": len(runnable),
        "checks": selected,
        "requests_sent": ctx.requests_sent,
        "base_url": base_url,
    }
    if args.json:
        report.write_json(args.json, clean, summary)
    if args.md:
        report.write_markdown(args.md, clean, summary)
    report.console(clean, summary, verbose=not args.quiet)
    return 1 if clean else 0


def parser():
    p = argparse.ArgumentParser(prog="swaggerprobe", description="OpenAPI attack surface tester")
    p.add_argument("-s", "--spec", required=True, help="spec file or URL, JSON or YAML")
    p.add_argument("--base", help="base URL override")
    p.add_argument("--auth", action="append", default=[], help="header, repeatable: 'Name: value'")
    p.add_argument("--auth-a", action="append", default=[], help="BOLA auth context A header")
    p.add_argument("--auth-b", action="append", default=[], help="BOLA auth context B header")
    p.add_argument("--allow-host", action="append", default=[], help="host allowlist, repeatable")
    p.add_argument("--run", action="store_true", help="send requests; default is dry-run")
    p.add_argument("--allow-write", action="store_true", help="permit PUT/POST/DELETE/PATCH")
    p.add_argument("--checks", default="all", help="comma list or all")
    p.add_argument("--delay", type=float, default=0.0, help="seconds between requests")
    p.add_argument("--time", action="store_true", help="enable time-based blind injection probes")
    p.add_argument("-o", "--json", help="write JSON report")
    p.add_argument("--md", help="write Markdown report")
    p.add_argument("-q", "--quiet", action="store_true", help="suppress banner and console report")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _selected_checks(value):
    if value == "all":
        return list(CHECKS)
    selected = [part.strip() for part in value.split(",") if part.strip()]
    unknown = sorted(set(selected) - set(CHECKS))
    if unknown:
        raise SystemExit(f"Unknown checks: {', '.join(unknown)}")
    return selected


def _dry_run(ops, base_url, args, selected):
    print("DRY RUN: request plan only; no HTTP requests sent.")
    print(f"Base: {base_url}")
    print(f"Checks: {', '.join(selected)}")
    auth = parse_headers(args.auth)
    planned = 0
    for op in ops:
        status = "skip-write" if not _safe_op(op, args.allow_write) else "plan"
        req, meta = build_request(op, base_url, auth)
        print(f"{status:10} {op.method:<7} {meta['url']}")
        planned += 1 if status == "plan" else 0
    print(f"Planned baseline requests: {planned}")


def _enforce_allow_host(base_url, allowed):
    parsed = urllib.parse.urlparse(base_url)
    host = parsed.hostname
    if not host:
        raise SystemExit("Base URL must include a host for --run")
    if host not in set(allowed):
        raise SystemExit(f"--allow-host {host} is required before active testing")


def _safe_op(op, allow_write):
    if allow_write:
        return True
    return op.method in READ_METHODS and op.method not in DESTRUCTIVE


def _import_check(name):
    module = __import__(CHECKS[name], fromlist=["run"])
    return module


if __name__ == "__main__":
    raise SystemExit(main())
