"""Command-line interface: ``python -m sentinelbox.rule_engine``."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from .analysis import (
    ReportFormatError,
    analyze_report,
    default_output_path,
    format_summary,
    read_report,
    same_file,
    validate_analysis,
    write_analysis,
)
from .expectations import DEFAULT_EXPECTATIONS_PATH, ExpectationsError, load_expectations
from .rules import RULE_SET_VERSION, RULES

EXIT_OK = 0
EXIT_INPUT_PROBLEMS = 1  # analysis written, but some records could not be evaluated
EXIT_USAGE = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m sentinelbox.rule_engine",
        description="Analyse an existing SentinelBox runner report with the rule engine. "
                    "The report is read-only; results go to a separate file.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("analyze", help="analyse a runner report and write a separate analysis report")
    analyze.add_argument("--report", type=Path, required=True, help="runner report JSON (read-only)")
    analyze.add_argument("--output", type=Path, default=None, help="analysis path (default: <report>.analysis.json next to the report)")
    analyze.add_argument("--overwrite", action="store_true", help="allow replacing an existing analysis file (never the input report)")
    analyze.add_argument("--expectations", type=Path, default=DEFAULT_EXPECTATIONS_PATH, help="expectation labels (default: bundled mock labels)")
    analyze.add_argument("--no-expectations", action="store_true", help="skip scoring; verdicts only, correctness 'unknown'")
    rules = sub.add_parser("list-rules", help="print the rule set")
    rules.add_argument("--details", action="store_true", help="include rationale and known limitations for every rule")
    return parser


def _list_rules(details: bool) -> int:
    print(f"SentinelBox rule set v{RULE_SET_VERSION} ({len(RULES)} rules)")
    for rule in RULES:
        kind = "context only" if rule.context_only else "control only" if rule.control_only else "verdict"
        print(f"{rule.rule_id:<14} {rule.family:<9} severity={rule.severity.value:<6} confidence={rule.confidence.value:<7} [{kind}] {rule.title}")
        if details:
            print(f"    why:         {rule.rationale}")
            print(f"    limitations: {rule.limitations}")
    return EXIT_OK


def _analyze(args: argparse.Namespace) -> int:
    output = args.output or default_output_path(args.report)
    if same_file(output, args.report):
        print("error: refusing to write over the input report; choose a different --output", file=sys.stderr)
        return EXIT_USAGE
    if output.exists() and not args.overwrite:
        print(f"error: {output} already exists (use --overwrite to replace it)", file=sys.stderr)
        return EXIT_USAGE
    try:
        loaded = read_report(args.report)
        expectations = None if args.no_expectations else load_expectations(args.expectations)
    except ReportFormatError as exc:
        print(f"error: {exc}", file=sys.stderr)
        for problem in exc.problems[:5]:
            print(f"  - {problem}", file=sys.stderr)
        return EXIT_USAGE
    except ExpectationsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    analysis = analyze_report(loaded, expectations)
    problems = validate_analysis(analysis)
    if problems:  # an internal bug, never silently written
        print("error: internal consistency check failed: " + "; ".join(problems[:3]), file=sys.stderr)
        return EXIT_USAGE
    try:
        written = write_analysis(analysis, output, overwrite=args.overwrite, input_path=args.report)
    except (FileExistsError, OSError, ValueError) as exc:
        print(f"error: could not write analysis: {exc}", file=sys.stderr)
        return EXIT_USAGE
    print(format_summary(analysis, written))
    return EXIT_INPUT_PROBLEMS if analysis["input"]["records_with_input_problems"] else EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "list-rules":
        return _list_rules(args.details)
    return _analyze(args)
