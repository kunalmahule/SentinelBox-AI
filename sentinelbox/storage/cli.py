"""Command-line interface: ``python -m sentinelbox.storage``."""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from . import queries, schema
from .database import (DEFAULT_DB_PATH, StorageError, init_database, migrate_database, open_database)
from .documents import read_document
from .importer import (ALREADY_IMPORTED, import_analysis, import_report, import_report_and_analysis,
                       import_sandbox_record)
from .verify import verify_database

EXIT_OK = 0
EXIT_ERROR = 2  # usage error, rejected document, conflict, missing/old database
EXIT_VERIFY_FAILED = 3

SYNTHETIC_NOTE = "All stored data is synthetic mock-environment test data (fictional canary values only)."


def _safe(text: object) -> str:
    """Escape control characters so stored text cannot drive the terminal."""
    return "".join(ch if ch.isprintable() or ch == " " else f"\\x{ord(ch):02x}" for ch in str(text))


def _table(headers: list[str], rows: list[list[object]]) -> str:
    cells = [[_safe(c) for c in row] for row in rows]
    widths = [max(len(h), *(len(r[i]) for r in cells)) if cells else len(h) for i, h in enumerate(headers)]
    lines = ["  ".join(h.ljust(w) for h, w in zip(headers, widths)).rstrip()]
    lines += ["  ".join(c.ljust(w) for c, w in zip(row, widths)).rstrip() for row in cells]
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m sentinelbox.storage",
        description="SentinelBox audit database: import runner reports and rule-engine analyses, then query them.")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_db(p):
        p.add_argument("--db", type=Path, default=DEFAULT_DB_PATH, help="database file (default: %(default)s)")

    p = sub.add_parser("init", help="create a new, empty database (never replaces an existing file)")
    add_db(p)

    p = sub.add_parser("import", help="import a runner report, and optionally its analysis, in one transaction")
    add_db(p)
    p.add_argument("--report", type=Path, required=True, help="runner report JSON (read-only)")
    p.add_argument("--analysis", type=Path, help="rule-engine analysis JSON for that report (read-only)")

    p = sub.add_parser("import-analysis", help="import an analysis for a run that is already stored")
    add_db(p)
    p.add_argument("--analysis", type=Path, required=True, help="rule-engine analysis JSON (read-only)")

    p = sub.add_parser("import-sandbox", help="import a sandbox record (and, optionally, the report/analysis it references)")
    add_db(p)
    p.add_argument("--record", type=Path, required=True, help="sandbox record JSON (read-only)")
    p.add_argument("--report", type=Path, help="the referenced runner report, if it is not stored yet")
    p.add_argument("--analysis", type=Path, help="the referenced analysis, if it is not stored yet")

    p = sub.add_parser("sandbox-runs", help="list stored sandbox runs, newest first")
    add_db(p)
    p.add_argument("--outcome", choices=schema.SANDBOX_OUTCOMES)
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("show-sandbox", help="one sandbox run: policy, control checks, outcome, cleanup, references")
    add_db(p)
    p.add_argument("sandbox_run", help="sandbox run id or unique prefix (at least 4 characters)")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("runs", help="list stored runs, newest first")
    add_db(p)
    p.add_argument("--status", choices=schema.RUN_STATUSES)
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--json", action="store_true", help="machine-readable output")

    p = sub.add_parser("show-run", help="one run: outcomes, analyses, verdicts and rule hits")
    add_db(p)
    p.add_argument("run", help="run id or unique prefix (at least 4 characters)")
    p.add_argument("--analysis", help="analysis id or prefix (default: the newest analysis of the run)")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("findings", help="list findings (default: detected and inconclusive only)")
    add_db(p)
    p.add_argument("--run", help="run id or prefix")
    p.add_argument("--analysis", help="analysis id or prefix")
    p.add_argument("--mode", choices=schema.TARGET_MODES)
    p.add_argument("--category", choices=schema.CATEGORIES)
    p.add_argument("--verdict", action="append", choices=schema.VERDICTS, help="repeatable; overrides the default filter")
    p.add_argument("--all", action="store_true", help="include every verdict")
    p.add_argument("--rule", help="only findings where this rule id matched, e.g. R-CANARY-001")
    p.add_argument("--min-severity", choices=schema.SEVERITIES)
    p.add_argument("--test-id")
    p.add_argument("--correctness", choices=schema.CORRECTNESS)
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("show-finding", help="one finding with the stored (synthetic) response and rule evidence")
    add_db(p)
    p.add_argument("finding_id", help="as printed by the findings command, e.g. <analysis_id>:7")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("info", help="schema version, row counts and the data policy")
    add_db(p)
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("verify", help="check integrity, the audit hash chain and append-only triggers")
    add_db(p)
    p.add_argument("--reports-dir", type=Path, help="also compare stored SHA-256 values with the original JSON files here")

    p = sub.add_parser("migrate", help="upgrade an older database (makes a backup first)")
    add_db(p)
    return parser


def _print_json(value: object) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False))


def _read_conn(args):
    return contextlib.closing(open_database(args.db, readonly=True))


def _cmd_init(args) -> int:
    path = init_database(args.db)
    print(f"Created {path} (schema version {schema.LATEST_VERSION}).")
    print(SYNTHETIC_NOTE)
    return EXIT_OK


def _describe_run(r) -> str:
    verb = "already stored (unchanged)" if r.status == ALREADY_IMPORTED else "stored"
    return f"Run {r.run_id}: {verb}, {r.executions} executions."


def _describe_analysis(a) -> str:
    verb = "already stored (unchanged)" if a.status == ALREADY_IMPORTED else "stored"
    return f"Analysis {a.analysis_id}: {verb}, {a.findings} findings, {a.matches} rule hits."


def _cmd_import(args) -> int:
    report = read_document(args.report, "report")
    analysis = read_document(args.analysis, "analysis") if args.analysis else None
    with contextlib.closing(open_database(args.db)) as conn:
        if analysis is None:
            print(_describe_run(import_report(conn, report)))
        else:
            run, imported = import_report_and_analysis(conn, report, analysis)
            print(_describe_run(run))
            print(_describe_analysis(imported))
    print(SYNTHETIC_NOTE)
    return EXIT_OK


def _cmd_import_analysis(args) -> int:
    analysis = read_document(args.analysis, "analysis")
    with contextlib.closing(open_database(args.db)) as conn:
        print(_describe_analysis(import_analysis(conn, analysis)))
    print(SYNTHETIC_NOTE)
    return EXIT_OK


def _cmd_import_sandbox(args) -> int:
    record = read_document(args.record, "sandbox record")
    report = read_document(args.report, "report") if args.report else None
    analysis = read_document(args.analysis, "analysis") if args.analysis else None
    with contextlib.closing(open_database(args.db)) as conn:
        result = import_sandbox_record(conn, record, report=report, analysis=analysis)
    if result.run is not None:
        print(_describe_run(result.run))
    if result.analysis is not None:
        print(_describe_analysis(result.analysis))
    verb = "already stored (unchanged)" if result.status == ALREADY_IMPORTED else "stored"
    print(f"Sandbox run {result.sandbox_run_id}: {verb}, outcome {result.outcome}.")
    print(SYNTHETIC_NOTE)
    return EXIT_OK


def _cmd_sandbox_runs(args) -> int:
    with _read_conn(args) as conn:
        runs = queries.list_sandbox_runs(conn, outcome=args.outcome, limit=args.limit)
    if args.json:
        _print_json(runs)
        return EXIT_OK
    if not runs:
        print("No sandbox runs stored yet.")
        return EXIT_OK
    print(_table(["sandbox_run_id", "kind", "outcome", "controls_ok", "started_at", "cleanup", "run_id"],
                 [[r["sandbox_run_id"], r["kind"], r["outcome"], "yes" if r["controls_verified"] else "no",
                   r["started_at"][:19], r["cleanup_status"], (r["run_id"] or "-")[:12]] for r in runs]))
    return EXIT_OK


def _cmd_show_sandbox(args) -> int:
    with _read_conn(args) as conn:
        record = queries.get_sandbox_run(conn, queries.resolve_sandbox_run_id(conn, args.sandbox_run))
    if args.json:
        _print_json(record)
        return EXIT_OK
    print(f"Sandbox run {record['sandbox_run_id']}  kind={record['kind']}  outcome={record['outcome']}")
    print(f"Started {record['started_at']}  duration {record['duration_ms']} ms  exit code {record['exit_code']}  "
          f"timed out {record['timed_out']}")
    print(f"Policy {record['policy_version']}  image {record['image_ref'] or '-'} id {record['image_id'] or '-'}")
    print(f"Docker client {record['docker_client_version'] or '-'}  server {record['docker_server_version'] or '-'}")
    print(f"Controls verified before execution: {'yes' if record['controls_verified'] else 'NO'}")
    for item in record["controls"]["results"]:
        print(f"  [{'ok' if item['ok'] else 'FAIL'}] {_safe(item['name'])}: expected {_safe(item['expected'])}, found {_safe(item['actual'])}")
    print(f"Cleanup: {record['cleanup_status']}" + (f" ({_safe(record['cleanup_detail'])})" if record["cleanup_detail"] else ""))
    print(f"Cases requested {record['cases_requested']}, returned {record['cases_returned']}; "
          f"stdout truncated {record['stdout_truncated']}, stderr truncated {record['stderr_truncated']}")
    if record["stderr_summary"]:
        print(f"stderr (summary): {_safe(record['stderr_summary'])}")
    print(f"Linked run {record['run_id'] or '-'}  analysis {record['analysis_id'] or '-'}")
    print(f"Note: {_safe(record['note'])}")
    print(SYNTHETIC_NOTE)
    return EXIT_OK


def _cmd_runs(args) -> int:
    with _read_conn(args) as conn:
        runs = queries.list_runs(conn, status=args.status, limit=args.limit)
    if args.json:
        _print_json(runs)
        return EXIT_OK
    if not runs:
        print("No runs stored yet.")
        return EXIT_OK
    print(_table(["run_id", "status", "started_at", "planned", "attempted", "analyses", "report_file"],
                 [[r["run_id"][:12], r["status"], r["started_at"][:19], r["planned"], r["attempted"], r["analyses"],
                   r["report_file_name"]] for r in runs]))
    return EXIT_OK


def _cmd_show_run(args) -> int:
    with _read_conn(args) as conn:
        run_id = queries.resolve_run_id(conn, args.run)
        run = queries.get_run(conn, run_id)
        analysis_id = queries.resolve_analysis_id(conn, args.analysis) if args.analysis else queries.latest_analysis_id(conn, run_id)
        verdicts = queries.verdict_summary(conn, analysis_id) if analysis_id else []
        rules = queries.rule_summary(conn, analysis_id) if analysis_id else []
    if args.json:
        _print_json({"run": run, "analysis_id": analysis_id, "verdicts": verdicts, "rules": rules})
        return EXIT_OK
    print(f"Run {run['run_id']}  status={run['status']}  {run['started_at']} -> {run['finished_at']}")
    print(f"Target {run['target_base_url']}  library {run['library_name']} {run['library_version']}  report {run['report_file_name']}")
    print(f"Planned {run['planned']}, attempted {run['attempted']}.  Execution outcomes by mode:")
    for mode, counts in run["outcomes_by_mode"].items():
        print(f"  {mode}: " + ", ".join(f"{k}={v}" for k, v in counts.items()))
    print(f"Analyses stored: {len(run['analyses'])}")
    if analysis_id:
        print(f"\nAnalysis {analysis_id} (verdict vs expected detection):")
        print(_table(["mode", "verdict", "correctness", "count"],
                     [[v["target_mode"], v["verdict"], v["detection_correctness"], v["n"]] for v in verdicts]))
        if rules:
            print("\nRule hits:")
            print(_table(["rule", "severity", "effect", "hits", "findings"],
                         [[r["rule_id"], r["severity"], r["effect"], r["hits"], r["findings"]] for r in rules]))
    print("\n" + SYNTHETIC_NOTE)
    return EXIT_OK


def _cmd_findings(args) -> int:
    verdicts = tuple(args.verdict) if args.verdict else (None if args.all else ("detected", "inconclusive"))
    with _read_conn(args) as conn:
        run_id = queries.resolve_run_id(conn, args.run) if args.run else None
        analysis_id = queries.resolve_analysis_id(conn, args.analysis) if args.analysis else None
        findings = queries.list_findings(
            conn, run_id=run_id, analysis_id=analysis_id, target_mode=args.mode, category=args.category,
            verdicts=verdicts, rule_id=args.rule, min_severity=args.min_severity, test_id=args.test_id,
            correctness=args.correctness, limit=args.limit)
    if args.json:
        _print_json(findings)
        return EXIT_OK
    if not findings:
        print("No findings match.")
        return EXIT_OK
    print(_table(["finding_id", "test", "mode", "verdict", "severity", "correctness", "rules"],
                 [[f["finding_id"], f["test_id"], f["target_mode"], f["verdict"], f["max_severity"] or "-",
                   f["detection_correctness"], ",".join(dict.fromkeys(m["rule_id"] for m in f["rules"] if not m["is_context"])) or "-"]
                  for f in findings]))
    print(f"\n{len(findings)} shown (limit {args.limit}). {SYNTHETIC_NOTE}")
    return EXIT_OK


def _cmd_show_finding(args) -> int:
    with _read_conn(args) as conn:
        finding = queries.get_finding(conn, args.finding_id)
    if args.json:
        _print_json(finding)
        return EXIT_OK
    print(f"Finding {finding['finding_id']}  {finding['test_id']} / {finding['target_mode']} / {finding['category']}")
    print(f"Verdict {finding['verdict']}  expected {finding['expected_detection']}  correctness {finding['detection_correctness']}")
    print(f"Synthetic response text: {_safe(finding['response_text'])}")
    for m in finding["matches"]:
        tag = "context" if m["is_context"] else "match"
        print(f"  [{tag}] {m['rule_id']} {m['severity']} {m['effect']}: {_safe(m['evidence_text'])!r}")
        print(f"      why: {_safe(m['rationale'])}")
    for note in finding["notes"]:
        print(f"  note: {_safe(note)}")
    print(SYNTHETIC_NOTE)
    return EXIT_OK


def _cmd_info(args) -> int:
    with _read_conn(args) as conn:
        info = queries.database_info(conn)
    if args.json:
        _print_json(info)
        return EXIT_OK
    print(f"Database {args.db}  schema version {info['schema_version']}")
    print("Rows: " + ", ".join(f"{k}={v}" for k, v in info["counts"].items()))
    if info["last_event"]:
        print(f"Last audit event #{info['last_event']['seq']} at {info['last_event']['occurred_at']}")
    print(info["data_policy"])
    return EXIT_OK


def _cmd_verify(args) -> int:
    with _read_conn(args) as conn:
        report = verify_database(conn, artifacts_dir=args.reports_dir)
    for check in report.checks:
        print(f"checked: {check}")
    for warning in report.warnings:
        print(f"warning: {warning}")
    if report.ok:
        print("OK: no problems found. (Tamper-evidence only: someone who can write the file can rebuild the hash chain.)")
        return EXIT_OK
    for problem in report.problems:
        print(f"PROBLEM: {problem}", file=sys.stderr)
    return EXIT_VERIFY_FAILED


def _cmd_migrate(args) -> int:
    result = migrate_database(args.db)
    if result.backup_path is None:
        print(f"{args.db} is already at schema version {result.to_version}; nothing to do.")
    else:
        print(f"Migrated {args.db} from version {result.from_version} to {result.to_version}. Backup: {result.backup_path}")
    return EXIT_OK


_COMMANDS = {"import-sandbox": _cmd_import_sandbox, "sandbox-runs": _cmd_sandbox_runs, "show-sandbox": _cmd_show_sandbox,
             "init": _cmd_init, "import": _cmd_import, "import-analysis": _cmd_import_analysis, "runs": _cmd_runs,
             "show-run": _cmd_show_run, "findings": _cmd_findings, "show-finding": _cmd_show_finding,
             "info": _cmd_info, "verify": _cmd_verify, "migrate": _cmd_migrate}


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _COMMANDS[args.command](args)
    except StorageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
