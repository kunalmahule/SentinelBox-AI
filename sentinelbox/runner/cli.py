"""Command-line interface: ``python -m sentinelbox.runner``."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from .library import DEFAULT_LIBRARY_PATH, LibraryError, load_library
from .models import Category, TargetMode
from .report import build_report, default_report_name, format_summary, write_report
from .runner import DEFAULT_MAX_CONSECUTIVE_FAILURES, DEFAULT_TIMEOUT_SECONDS, run_suite
from .transport import TargetUrlError, Transport, UrllibTransport, validate_target_url

EXIT_OK = 0
EXIT_EXECUTION_PROBLEMS = 1  # some cases failed to execute, or the run stopped early
EXIT_USAGE = 2
EXIT_INTERRUPTED = 130


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m sentinelbox.runner",
        description="Run the SentinelBox adversarial prompt library against a local mock AI target.",
    )
    parser.add_argument("--url", default="http://127.0.0.1:8001", help="target origin, loopback only (default: %(default)s)")
    parser.add_argument("--mode", choices=["vulnerable", "hardened", "both"], default="both", help="target mode(s) to test (default: %(default)s)")
    parser.add_argument("--library", type=Path, default=DEFAULT_LIBRARY_PATH, help="prompt library JSON file (default: bundled library)")
    parser.add_argument("--category", action="append", choices=[c.value for c in Category], help="only run this category (repeatable)")
    parser.add_argument("--output", type=Path, default=None, help="report path (default: reports/sbx-run-<time>-<id>.json)")
    parser.add_argument("--overwrite", action="store_true", help="allow replacing an existing report file")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS, help="per-request timeout in seconds (default: %(default)s)")
    parser.add_argument("--max-consecutive-failures", type=int, default=DEFAULT_MAX_CONSECUTIVE_FAILURES, help="stop after this many timeouts/connection errors in a row (default: %(default)s)")
    parser.add_argument("--verbose", action="store_true", help="print one line per executed case")
    return parser


def main(argv: Sequence[str] | None = None, transport: Transport | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.timeout <= 0 or args.max_consecutive_failures < 1:
        print("error: --timeout must be positive and --max-consecutive-failures at least 1", file=sys.stderr)
        return EXIT_USAGE
    try:
        base_url = validate_target_url(args.url)
        library = load_library(args.library)
    except (TargetUrlError, LibraryError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if args.output is not None and args.output.exists() and not args.overwrite:
        print(f"error: {args.output} already exists (use --overwrite to replace it)", file=sys.stderr)
        return EXIT_USAGE

    cases = [c for c in library.cases if not args.category or c.category.value in args.category]
    if not cases:
        print("error: no test cases match the selected categories", file=sys.stderr)
        return EXIT_USAGE
    modes = [TargetMode.VULNERABLE, TargetMode.HARDENED] if args.mode == "both" else [TargetMode(args.mode)]

    on_result = None
    if args.verbose:
        def on_result(r):  # noqa: E306
            print(f"  {r.test_id:<9} {r.target_mode:<10} {r.outcome:<17} HTTP {r.http_status if r.http_status else '-'}")

    run = run_suite(
        cases, modes, base_url, transport or UrllibTransport(),
        timeout=args.timeout, max_consecutive_failures=args.max_consecutive_failures, on_result=on_result,
    )
    report = build_report(run, library, base_url, modes, args.timeout)

    output = args.output or Path("reports") / default_report_name(report)
    try:
        written = write_report(report, output, overwrite=args.overwrite)
    except (FileExistsError, OSError, ValueError) as exc:
        print(f"error: could not write report: {exc}", file=sys.stderr)
        print(format_summary(report))
        return EXIT_USAGE

    print(format_summary(report, written))
    if run.status.value == "interrupted":
        return EXIT_INTERRUPTED
    problems = run.status.value != "complete" or any(
        r.outcome not in ("completed",) for r in run.results
    )
    return EXIT_EXECUTION_PROBLEMS if problems else EXIT_OK
