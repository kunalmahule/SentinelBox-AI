"""Transactional import of a runner report and/or a rule-engine analysis.

Rules enforced here:

* Validation (structure, credential-looking text, loopback target) happens before any SQL runs.
* Each import is one ``BEGIN IMMEDIATE`` transaction: everything is stored together or nothing is.
* All values go through parameterized SQL.
* Re-importing identical content is a reported no-op; the same run or analysis id with different content
  is a conflict and is rejected. Existing rows are never updated or deleted (triggers enforce it too).
* An analysis can only be stored against an already stored run whose report hash it was produced from, and
  it must cover exactly that run's executions.
* The source files are not touched; only their SHA-256 and file names are recorded.
* A sandbox record is stored with one ``sandbox_runs`` row and one ``sandbox_run_recorded`` event. Whatever it
  references (run report, analysis) must already be stored with the same hash, or be supplied in the same call
  and is then stored in the same transaction.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime

from . import audit, schema
from .database import StorageError, transaction
from .documents import Document, DocumentError, check_analysis, check_report, check_sandbox_record

ALREADY_IMPORTED = "already_imported"
IMPORTED = "imported"


class ImportConflictError(StorageError):
    """The document clashes with what is already stored (or what it refers to is missing)."""


@dataclass(frozen=True)
class RunImport:
    run_id: str
    status: str
    executions: int


@dataclass(frozen=True)
class AnalysisImport:
    analysis_id: str
    run_id: str
    status: str
    findings: int
    matches: int


def _dump(value: object) -> str:
    return audit.canonical_json(value)


def execution_id(run_id: str, test_id: str, target_mode: str) -> str:
    return f"{run_id}:{test_id}:{target_mode}"


def finding_id(analysis_id: str, ordinal: int) -> str:
    return f"{analysis_id}:{ordinal}"


# --- inserts (each is small so tests can inject a failure between them) ----------------------------------------
def _insert_run(conn: sqlite3.Connection, doc: Document, imported_at: str) -> None:
    r = doc.data
    conn.execute(
        "INSERT INTO runs (run_id, report_sha256, report_file_name, report_schema_version, tool_name, tool_version, "
        "status, stop_reason, started_at, finished_at, target_base_url, library_name, library_version, "
        "library_file_name, library_sha256, library_case_count, modes_json, planned, attempted, imported_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (r["run_id"], doc.sha256, doc.file_name, r["schema_version"], r["tool"]["name"], r["tool"]["version"],
         r["status"], r["stop_reason"], r["started_at"], r["finished_at"], r["target"]["base_url"],
         r["library"]["name"], r["library"]["version"], r["library"]["file_name"], r["library"]["sha256"],
         r["library"]["case_count"], _dump(r["modes"]), r["summary"]["planned"], r["summary"]["attempted"], imported_at),
    )


def _insert_executions(conn: sqlite3.Connection, doc: Document) -> int:
    run_id = doc.data["run_id"]
    rows = [
        (execution_id(run_id, e["test_id"], e["target_mode"]), run_id, i, e["test_id"], e["category"], e["target_mode"],
         e["timestamp"], e["duration_ms"], e["http_status"], e["outcome"], e["response_text"], e["raw_body"],
         int(e["raw_body_truncated"]), e["error"])
        for i, e in enumerate(doc.data["results"])
    ]
    conn.executemany(
        "INSERT INTO executions (execution_id, run_id, ordinal, test_id, category, target_mode, timestamp, duration_ms, "
        "http_status, outcome, response_text, raw_body, raw_body_truncated, error) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)
    return len(rows)


def _insert_analysis(conn: sqlite3.Connection, doc: Document, imported_at: str) -> None:
    a = doc.data
    conn.execute(
        "INSERT INTO analyses (analysis_id, analysis_sha256, analysis_file_name, schema_version, tool_name, tool_version, "
        "created_at, scope, run_id, report_sha256, rule_set_version, rule_set_json, expectations_json, metrics_json, "
        "known_limitations_json, disclaimer, record_count, imported_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (a["analysis_id"], doc.sha256, doc.file_name, a["schema_version"], a["tool"]["name"], a["tool"]["version"],
         a["created_at"], a["scope"], a["input"]["report_run_id"], a["input"]["report_sha256"], a["rule_set"]["version"],
         _dump(a["rule_set"]), None if a["expectations"] is None else _dump(a["expectations"]),
         _dump(a["metrics_by_mode"]), _dump(a["known_limitations"]), a["disclaimer"], len(a["results"]), imported_at),
    )


def _insert_findings(conn: sqlite3.Connection, doc: Document) -> int:
    a = doc.data
    run_id = a["input"]["report_run_id"]
    rows = [
        (finding_id(a["analysis_id"], r["index"]), a["analysis_id"], run_id,
         execution_id(run_id, r["test_id"], r["target_mode"]), r["index"], r["test_id"], r["category"], r["target_mode"],
         r["execution_outcome"], r["expected_behavior"], r["expected_detection"], r["verdict"],
         r["detection_correctness"], r["max_severity"], int(r["refusal_language"]), _dump(r["notes"]))
        for r in a["results"]
    ]
    conn.executemany(
        "INSERT INTO findings (finding_id, analysis_id, run_id, execution_id, ordinal, test_id, category, target_mode, "
        "execution_outcome, expected_behavior, expected_detection, verdict, detection_correctness, max_severity, "
        "refusal_language, notes_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)
    return len(rows)


def _insert_matches(conn: sqlite3.Connection, doc: Document) -> int:
    a = doc.data
    rows = []
    for r in a["results"]:
        fid = finding_id(a["analysis_id"], r["index"])
        for is_context, group in ((0, "matches"), (1, "context_matches")):
            for ordinal, m in enumerate(r[group]):
                ev = m["evidence"]
                rows.append((fid, a["analysis_id"], ordinal, is_context, m["rule_id"], m["family"], m["severity"],
                             m["base_confidence"], m["confidence"], m["effect"], ev["text"], ev["start"], ev["end"],
                             ev["context"], m["rationale"], _dump(m["adjustments"])))
    conn.executemany(
        "INSERT INTO finding_matches (finding_id, analysis_id, ordinal, is_context, rule_id, family, severity, "
        "base_confidence, confidence, effect, evidence_text, evidence_start, evidence_end, evidence_context, "
        "rationale, adjustments_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)
    return len(rows)


# --- transaction bodies -----------------------------------------------------------------------------------------
def _store_run(conn: sqlite3.Connection, doc: Document, now: datetime | None) -> RunImport:
    run_id = doc.data["run_id"]
    existing = conn.execute("SELECT report_sha256, report_file_name FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    if existing is not None:
        if existing["report_sha256"] == doc.sha256:
            count = conn.execute("SELECT COUNT(*) FROM executions WHERE run_id = ?", (run_id,)).fetchone()[0]
            return RunImport(run_id, ALREADY_IMPORTED, count)
        raise ImportConflictError(
            f"Run {run_id} is already stored from a different report file ({existing['report_file_name']}, "
            f"sha256 {existing['report_sha256'][:12]}...). This file has sha256 {doc.sha256[:12]}.... "
            "Stored records are never replaced; if this is a new run it needs a new run_id.")
    imported_at = audit.utc_timestamp(now)
    _insert_run(conn, doc, imported_at)
    count = _insert_executions(conn, doc)
    audit.append_event(conn, "run_imported", run_id=run_id, now=now, detail={
        "report_sha256": doc.sha256, "report_file_name": doc.file_name, "executions": count})
    return RunImport(run_id, IMPORTED, count)


def _check_analysis_links(conn: sqlite3.Connection, doc: Document) -> None:
    a = doc.data
    run_id, report_sha = a["input"]["report_run_id"], a["input"]["report_sha256"]
    run = conn.execute("SELECT report_sha256, report_file_name FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    if run is None:
        raise ImportConflictError(
            f"The analysis refers to run {run_id}, which is not in the database. "
            "Import the runner report first (or pass --report together with --analysis).")
    if run["report_sha256"] != report_sha:
        raise ImportConflictError(
            f"The analysis was produced from a report with sha256 {report_sha[:12]}..., but the stored run {run_id} "
            f"({run['report_file_name']}) has sha256 {run['report_sha256'][:12]}.... Re-run the rule engine on the stored report.")
    stored = {(r["test_id"], r["target_mode"]): (r["category"], r["outcome"]) for r in conn.execute(
        "SELECT test_id, target_mode, category, outcome FROM executions WHERE run_id = ?", (run_id,))}
    problems = []
    analysed = set()
    for r in a["results"]:
        key = (r["test_id"], r["target_mode"])
        analysed.add(key)
        if key not in stored:
            problems.append(f"results[{r['index']}] ({key[0]}, {key[1]}) has no matching execution in run {run_id}")
        elif stored[key] != (r["category"], r["execution_outcome"]):
            problems.append(f"results[{r['index']}] ({key[0]}, {key[1]}) disagrees with the stored execution "
                            f"(category/outcome {stored[key]} vs {(r['category'], r['execution_outcome'])})")
    missing = sorted(set(stored) - analysed)
    if missing:
        problems.append(f"the analysis does not cover {len(missing)} of the run's {len(stored)} executions "
                        f"(first missing: {missing[0][0]} in {missing[0][1]})")
    if problems:
        raise DocumentError(f"The analysis {doc.file_name} does not match the stored run {run_id}", problems)


def _store_analysis(conn: sqlite3.Connection, doc: Document, now: datetime | None) -> AnalysisImport:
    a = doc.data
    analysis_id, run_id = a["analysis_id"], a["input"]["report_run_id"]
    existing = conn.execute("SELECT analysis_sha256, analysis_file_name FROM analyses WHERE analysis_id = ?",
                            (analysis_id,)).fetchone()
    if existing is not None:
        if existing["analysis_sha256"] == doc.sha256:
            findings = conn.execute("SELECT COUNT(*) FROM findings WHERE analysis_id = ?", (analysis_id,)).fetchone()[0]
            matches = conn.execute("SELECT COUNT(*) FROM finding_matches WHERE analysis_id = ?", (analysis_id,)).fetchone()[0]
            return AnalysisImport(analysis_id, run_id, ALREADY_IMPORTED, findings, matches)
        raise ImportConflictError(
            f"Analysis {analysis_id} is already stored from a different file ({existing['analysis_file_name']}). "
            "Stored records are never replaced; re-run the rule engine to get a new analysis_id.")
    _check_analysis_links(conn, doc)
    imported_at = audit.utc_timestamp(now)
    _insert_analysis(conn, doc, imported_at)
    findings = _insert_findings(conn, doc)
    matches = _insert_matches(conn, doc)
    audit.append_event(conn, "analysis_imported", run_id=run_id, analysis_id=analysis_id, now=now, detail={
        "analysis_sha256": doc.sha256, "analysis_file_name": doc.file_name, "report_sha256": a["input"]["report_sha256"],
        "findings": findings, "matches": matches})
    return AnalysisImport(analysis_id, run_id, IMPORTED, findings, matches)


# --- public interface ----------------------------------------------------------------------------------------------
def import_report(conn: sqlite3.Connection, document: Document, *, now: datetime | None = None) -> RunImport:
    check_report(document)
    with transaction(conn):
        return _store_run(conn, document, now)


def import_analysis(conn: sqlite3.Connection, document: Document, *, now: datetime | None = None) -> AnalysisImport:
    check_analysis(document)
    with transaction(conn):
        return _store_analysis(conn, document, now)


def import_report_and_analysis(conn: sqlite3.Connection, report: Document, analysis: Document, *,
                               now: datetime | None = None) -> tuple[RunImport, AnalysisImport]:
    """Store both in a single transaction: if the analysis is rejected, the run is not stored either."""
    check_report(report)
    check_analysis(analysis)
    with transaction(conn):
        run = _store_run(conn, report, now)
        return run, _store_analysis(conn, analysis, now)


@dataclass(frozen=True)
class SandboxImport:
    sandbox_run_id: str
    status: str
    outcome: str
    run: RunImport | None
    analysis: AnalysisImport | None


def _insert_sandbox(conn: sqlite3.Connection, doc: Document, imported_at: str) -> None:
    s = doc.data
    r, refs, timing = s["result"], s["references"], s["timing"]
    conn.execute(
        "INSERT INTO sandbox_runs (sandbox_run_id, record_sha256, record_file_name, record_schema_version, tool_name, "
        "tool_version, policy_version, kind, outcome, controls_verified, controls_json, requested_json, effective_json, "
        "image_ref, image_id, image_digest, docker_client_version, docker_server_version, started_at, finished_at, "
        "duration_ms, exit_code, timed_out, stdout_truncated, stderr_truncated, stderr_summary, cases_requested, "
        "cases_returned, cleanup_status, cleanup_detail, run_id, analysis_id, report_file_name, report_sha256, "
        "analysis_file_name, analysis_sha256, note, imported_at) VALUES "
        "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (s["sandbox_run_id"], doc.sha256, doc.file_name, s["schema_version"], s["tool"]["name"], s["tool"]["version"],
         s["policy"]["version"], s["kind"], r["outcome"], int(s["controls"]["verified"]), _dump(s["controls"]),
         _dump(s["policy"]["requested"]), None if s["effective"] is None else _dump(s["effective"]),
         s["image"]["ref"], s["image"]["id"], s["image"]["digest"], s["docker"]["client_version"],
         s["docker"]["server_version"], timing["started_at"], timing["finished_at"], timing["duration_ms"],
         r["exit_code"], int(r["timed_out"]), int(r["stdout_truncated"]), int(r["stderr_truncated"]), r["stderr_summary"],
         r["cases_requested"], r["cases_returned"], s["cleanup"]["status"], s["cleanup"]["detail"], refs["run_id"],
         refs["analysis_id"], refs["report_file_name"], refs["report_sha256"], refs["analysis_file_name"],
         refs["analysis_sha256"], s["note"], imported_at),
    )


def _check_sandbox_links(conn: sqlite3.Connection, doc: Document) -> None:
    refs = doc.data["references"]
    problems = []
    if refs["run_id"] is not None:
        run = conn.execute("SELECT report_sha256, report_file_name FROM runs WHERE run_id = ?", (refs["run_id"],)).fetchone()
        if run is None:
            problems.append(f"it references run {refs['run_id']}, which is not stored (pass --report, or import the report first)")
        elif (run["report_sha256"], run["report_file_name"]) != (refs["report_sha256"], refs["report_file_name"]):
            problems.append(f"run {refs['run_id']} is stored from a different report file than the one the record references")
    if refs["analysis_id"] is not None:
        row = conn.execute("SELECT analysis_sha256, analysis_file_name, run_id FROM analyses WHERE analysis_id = ?",
                           (refs["analysis_id"],)).fetchone()
        if row is None:
            problems.append(f"it references analysis {refs['analysis_id']}, which is not stored (pass --analysis, or import it first)")
        elif (row["analysis_sha256"], row["analysis_file_name"], row["run_id"]) != (
                refs["analysis_sha256"], refs["analysis_file_name"], refs["run_id"]):
            problems.append(f"analysis {refs['analysis_id']} is stored from a different file or run than the record references")
    if problems:
        raise ImportConflictError(f"Sandbox record {doc.file_name} does not match what is stored: " + "; ".join(problems))


def _check_supplied(doc: Document | None, expected_name: str | None, expected_sha: str | None, label: str) -> None:
    if doc is None:
        return
    if expected_sha is None:
        raise DocumentError("The sandbox record does not match the supplied documents",
                            [f"a {label} was supplied but the record does not reference one"])
    if doc.sha256 != expected_sha or doc.file_name != expected_name:
        raise DocumentError("The sandbox record does not match the supplied documents",
                            [f"the supplied {label} ({doc.file_name}, sha256 {doc.sha256[:12]}...) is not the one the record "
                             f"references ({expected_name}, sha256 {expected_sha[:12]}...)"])


def import_sandbox_record(conn: sqlite3.Connection, record: Document, *, report: Document | None = None,
                          analysis: Document | None = None, now: datetime | None = None) -> SandboxImport:
    """Store a sandbox record (and, optionally, the report and analysis it references) in one transaction."""
    check_sandbox_record(record)
    refs = record.data["references"]
    if analysis is not None and report is None and refs["run_id"] is not None:
        pass  # the stored run is checked inside the transaction
    _check_supplied(report, refs["report_file_name"], refs["report_sha256"], "report")
    _check_supplied(analysis, refs["analysis_file_name"], refs["analysis_sha256"], "analysis")
    if report is not None:
        check_report(report)
    if analysis is not None:
        check_analysis(analysis)
    sid, outcome = record.data["sandbox_run_id"], record.data["result"]["outcome"]
    with transaction(conn):
        existing = conn.execute("SELECT record_sha256, record_file_name FROM sandbox_runs WHERE sandbox_run_id = ?",
                                (sid,)).fetchone()
        if existing is not None:
            if existing["record_sha256"] == record.sha256:
                return SandboxImport(sid, ALREADY_IMPORTED, outcome, None, None)
            raise ImportConflictError(
                f"Sandbox run {sid} is already stored from a different record ({existing['record_file_name']}). "
                "Stored records are never replaced.")
        other = conn.execute("SELECT sandbox_run_id FROM sandbox_runs WHERE record_sha256 = ?", (record.sha256,)).fetchone()
        if other is not None:
            raise ImportConflictError(f"This record file is already stored as sandbox run {other['sandbox_run_id']}")
        run_result = analysis_result = None
        if report is not None:
            run_result = _store_run(conn, report, now)
        if analysis is not None:
            analysis_result = _store_analysis(conn, analysis, now)
        _check_sandbox_links(conn, record)
        _insert_sandbox(conn, record, audit.utc_timestamp(now))
        audit.append_event(conn, "sandbox_run_recorded", run_id=refs["run_id"], analysis_id=refs["analysis_id"], now=now, detail={
            "sandbox_run_id": sid, "record_sha256": record.sha256, "record_file_name": record.file_name,
            "outcome": outcome, "controls_verified": record.data["controls"]["verified"], "kind": record.data["kind"]})
        return SandboxImport(sid, IMPORTED, outcome, run_result, analysis_result)
