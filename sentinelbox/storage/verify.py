"""Integrity verification of an audit database (read-only)."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from . import audit, schema


@dataclass
class VerifyReport:
    problems: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    checks: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


def _sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:  # read-only
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_database(conn: sqlite3.Connection, *, artifacts_dir: Path | str | None = None) -> VerifyReport:
    """Check SQLite integrity, the audit chain, append-only triggers, row counts and (optionally) source files."""
    report = VerifyReport()

    result = conn.execute("PRAGMA integrity_check").fetchall()
    if [r[0] for r in result] != ["ok"]:
        report.problems.extend(f"SQLite integrity_check: {r[0]}" for r in result[:5])
    report.checks.append("SQLite integrity_check")

    violations = conn.execute("PRAGMA foreign_key_check").fetchall()
    if violations:
        report.problems.append(f"{len(violations)} foreign key violation(s), first in table {violations[0][0]}")
    report.checks.append("foreign keys")

    report.problems.extend(audit.verify_chain(conn))
    report.checks.append("audit hash chain")

    present = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")}
    expected = {f"{table}_no_{action}" for table in schema.TABLES for action in ("update", "delete")}
    for name in sorted(expected - present):
        report.problems.append(f"append-only trigger {name} is missing (the database was altered)")
    report.checks.append("append-only triggers")

    for row in conn.execute("SELECT r.run_id, r.planned, (SELECT COUNT(*) FROM executions e WHERE e.run_id = r.run_id) AS n FROM runs r"):
        if row["planned"] != row["n"]:
            report.problems.append(f"run {row['run_id']}: planned {row['planned']} but {row['n']} executions stored")
    for row in conn.execute("SELECT a.analysis_id, a.record_count, (SELECT COUNT(*) FROM findings f WHERE f.analysis_id = a.analysis_id) AS n FROM analyses a"):
        if row["record_count"] != row["n"]:
            report.problems.append(f"analysis {row['analysis_id']}: {row['record_count']} records declared but {row['n']} findings stored")
    imported = {(r["event_type"], r["run_id"], r["analysis_id"]) for r in conn.execute(
        "SELECT event_type, run_id, analysis_id FROM audit_events WHERE event_type IN ('run_imported', 'analysis_imported')")}
    for row in conn.execute("SELECT run_id FROM runs"):
        if ("run_imported", row["run_id"], None) not in imported:
            report.problems.append(f"run {row['run_id']} has no run_imported audit event")
    for row in conn.execute("SELECT analysis_id, run_id FROM analyses"):
        if ("analysis_imported", row["run_id"], row["analysis_id"]) not in imported:
            report.problems.append(f"analysis {row['analysis_id']} has no analysis_imported audit event")
    recorded = {}
    for r in conn.execute("SELECT detail_json, run_id, analysis_id FROM audit_events WHERE event_type = 'sandbox_run_recorded'"):
        try:
            recorded[json.loads(r["detail_json"]).get("sandbox_run_id")] = (r["run_id"], r["analysis_id"])
        except (ValueError, AttributeError):
            report.problems.append("a sandbox_run_recorded event has unreadable detail")
    stored_sandbox = set()
    for row in conn.execute("SELECT sandbox_run_id, run_id, analysis_id FROM sandbox_runs"):
        stored_sandbox.add(row["sandbox_run_id"])
        if row["sandbox_run_id"] not in recorded:
            report.problems.append(f"sandbox run {row['sandbox_run_id']} has no sandbox_run_recorded audit event")
        elif recorded[row["sandbox_run_id"]] != (row["run_id"], row["analysis_id"]):
            report.problems.append(f"sandbox run {row['sandbox_run_id']}: its audit event refers to a different run or analysis")
    for sid in sorted(set(recorded) - stored_sandbox, key=str):
        report.problems.append(f"audit event for sandbox run {sid} has no sandbox_runs row")
    report.checks.append("row counts and audit coverage")

    if artifacts_dir is not None:
        folder = Path(artifacts_dir)
        entries = [("report", r["run_id"], r["report_file_name"], r["report_sha256"])
                   for r in conn.execute("SELECT run_id, report_file_name, report_sha256 FROM runs")]
        entries += [("analysis", r["analysis_id"], r["analysis_file_name"], r["analysis_sha256"])
                    for r in conn.execute("SELECT analysis_id, analysis_file_name, analysis_sha256 FROM analyses")]
        entries += [("sandbox record", r["sandbox_run_id"], r["record_file_name"], r["record_sha256"])
                    for r in conn.execute("SELECT sandbox_run_id, record_file_name, record_sha256 FROM sandbox_runs")]
        for kind, ident, name, sha in entries:
            path = folder / name
            if not path.is_file():
                report.warnings.append(f"{kind} file {name} (for {ident[:12]}) was not found in {folder}; its hash was not checked")
            elif _sha256_of(path) != sha:
                report.problems.append(f"{kind} file {path} no longer matches the SHA-256 stored when {ident[:12]} was imported")
        report.checks.append("source files in " + str(folder))
    return report
