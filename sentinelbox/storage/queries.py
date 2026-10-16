"""Read-only queries over the audit database. Values are always bound parameters; filter columns are fixed.

Every record returned carries ``data_classification`` ("synthetic_test_data"): responses and evidence come from
a local mock target and contain fictional canary values only.
"""

from __future__ import annotations

import json
import sqlite3

from . import schema
from .database import StorageError, table_counts

MAX_LIMIT = 1000
_SEVERITY_RANK = {name: rank for rank, name in enumerate(schema.SEVERITIES)}


class QueryError(StorageError):
    """A query argument is invalid or refers to nothing."""


def _limit(limit: int) -> int:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LIMIT:
        raise QueryError(f"limit must be an integer from 1 to {MAX_LIMIT}")
    return limit


def _choice(name: str, value: str | None, allowed: tuple[str, ...]) -> str | None:
    if value is not None and value not in allowed:
        raise QueryError(f"unknown {name} {value!r}; choose one of: {', '.join(allowed)}")
    return value


def resolve_run_id(conn: sqlite3.Connection, ref: str) -> str:
    """Accept a full run id or a unique prefix of at least 4 characters."""
    if not isinstance(ref, str) or len(ref) < 4:
        raise QueryError("give at least the first 4 characters of a run id")
    rows = conn.execute("SELECT run_id FROM runs WHERE substr(run_id, 1, ?) = ? ORDER BY run_id LIMIT 6",
                        (len(ref), ref)).fetchall()
    exact = [r["run_id"] for r in rows if r["run_id"] == ref]
    if exact:
        return exact[0]
    if not rows:
        raise QueryError(f"no stored run matches {ref!r}; list runs with: python -m sentinelbox.storage runs")
    if len(rows) > 1:
        raise QueryError(f"{ref!r} matches several runs ({', '.join(r['run_id'][:12] for r in rows)}); use more characters")
    return rows[0]["run_id"]


def resolve_analysis_id(conn: sqlite3.Connection, ref: str) -> str:
    if not isinstance(ref, str) or len(ref) < 4:
        raise QueryError("give at least the first 4 characters of an analysis id")
    rows = conn.execute("SELECT analysis_id FROM analyses WHERE substr(analysis_id, 1, ?) = ? ORDER BY analysis_id LIMIT 6",
                        (len(ref), ref)).fetchall()
    exact = [r["analysis_id"] for r in rows if r["analysis_id"] == ref]
    if exact:
        return exact[0]
    if not rows:
        raise QueryError(f"no stored analysis matches {ref!r}")
    if len(rows) > 1:
        raise QueryError(f"{ref!r} matches several analyses; use more characters")
    return rows[0]["analysis_id"]


def resolve_sandbox_run_id(conn: sqlite3.Connection, ref: str) -> str:
    if not isinstance(ref, str) or len(ref) < 4:
        raise QueryError("give at least the first 4 characters of a sandbox run id")
    rows = conn.execute("SELECT sandbox_run_id FROM sandbox_runs WHERE substr(sandbox_run_id, 1, ?) = ? "
                        "ORDER BY sandbox_run_id LIMIT 6", (len(ref), ref)).fetchall()
    exact = [r["sandbox_run_id"] for r in rows if r["sandbox_run_id"] == ref]
    if exact:
        return exact[0]
    if not rows:
        raise QueryError(f"no stored sandbox run matches {ref!r}; list them with: python -m sentinelbox.storage sandbox-runs")
    if len(rows) > 1:
        raise QueryError(f"{ref!r} matches several sandbox runs; use more characters")
    return rows[0]["sandbox_run_id"]


def list_sandbox_runs(conn: sqlite3.Connection, *, outcome: str | None = None, limit: int = 20) -> list[dict]:
    _choice("outcome", outcome, schema.SANDBOX_OUTCOMES)
    rows = conn.execute(
        "SELECT sandbox_run_id, kind, outcome, controls_verified, started_at, finished_at, duration_ms, exit_code, "
        "timed_out, cleanup_status, run_id, analysis_id, image_id, record_file_name, data_classification "
        "FROM sandbox_runs WHERE (? IS NULL OR outcome = ?) ORDER BY started_at DESC, sandbox_run_id LIMIT ?",
        (outcome, outcome, _limit(limit))).fetchall()
    result = [dict(r) for r in rows]
    for r in result:
        r["controls_verified"] = bool(r["controls_verified"])
        r["timed_out"] = bool(r["timed_out"])
    return result


def get_sandbox_run(conn: sqlite3.Connection, sandbox_run_id: str) -> dict:
    row = conn.execute("SELECT * FROM sandbox_runs WHERE sandbox_run_id = ?", (sandbox_run_id,)).fetchone()
    if row is None:
        raise QueryError(f"no stored sandbox run {sandbox_run_id!r}")
    result = dict(row)
    for key in ("controls_json", "requested_json", "effective_json"):
        value = result.pop(key)
        result[key[:-5]] = None if value is None else json.loads(value)
    for key in ("controls_verified", "timed_out", "stdout_truncated", "stderr_truncated"):
        result[key] = bool(result[key])
    return result


def list_runs(conn: sqlite3.Connection, *, status: str | None = None, limit: int = 20) -> list[dict]:
    _choice("status", status, schema.RUN_STATUSES)
    rows = conn.execute(
        "SELECT r.run_id, r.status, r.started_at, r.finished_at, r.planned, r.attempted, r.report_file_name, "
        "r.report_sha256, r.imported_at, r.data_classification, "
        "(SELECT COUNT(*) FROM executions e WHERE e.run_id = r.run_id) AS executions, "
        "(SELECT COUNT(*) FROM analyses a WHERE a.run_id = r.run_id) AS analyses "
        "FROM runs r WHERE (? IS NULL OR r.status = ?) ORDER BY r.started_at DESC, r.run_id LIMIT ?",
        (status, status, _limit(limit))).fetchall()
    return [dict(r) for r in rows]


def get_run(conn: sqlite3.Connection, run_id: str) -> dict:
    run = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    if run is None:
        raise QueryError(f"no stored run {run_id!r}")
    outcomes: dict[str, dict[str, int]] = {}
    for row in conn.execute("SELECT target_mode, outcome, COUNT(*) AS n FROM executions WHERE run_id = ? "
                            "GROUP BY target_mode, outcome ORDER BY target_mode, outcome", (run_id,)):
        outcomes.setdefault(row["target_mode"], {})[row["outcome"]] = row["n"]
    analyses = [dict(r) for r in conn.execute(
        "SELECT analysis_id, created_at, rule_set_version, record_count, imported_at FROM analyses "
        "WHERE run_id = ? ORDER BY created_at, analysis_id", (run_id,))]
    result = dict(run)
    result["modes"] = json.loads(result.pop("modes_json"))
    result["outcomes_by_mode"] = outcomes
    result["analyses"] = analyses
    return result


def verdict_summary(conn: sqlite3.Connection, analysis_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT target_mode, verdict, detection_correctness, COUNT(*) AS n FROM findings WHERE analysis_id = ? "
        "GROUP BY target_mode, verdict, detection_correctness ORDER BY target_mode, verdict, detection_correctness",
        (analysis_id,)).fetchall()
    return [dict(r) for r in rows]


def rule_summary(conn: sqlite3.Connection, analysis_id: str) -> list[dict]:
    """How often each rule fired in an analysis, split by what the hit did to the verdict."""
    rows = conn.execute(
        "SELECT rule_id, severity, effect, COUNT(*) AS hits, COUNT(DISTINCT finding_id) AS findings "
        "FROM finding_matches WHERE analysis_id = ? GROUP BY rule_id, severity, effect ORDER BY rule_id, effect",
        (analysis_id,)).fetchall()
    return [dict(r) for r in rows]


def latest_analysis_id(conn: sqlite3.Connection, run_id: str) -> str | None:
    row = conn.execute("SELECT analysis_id FROM analyses WHERE run_id = ? ORDER BY created_at DESC, analysis_id DESC LIMIT 1",
                       (run_id,)).fetchone()
    return None if row is None else row["analysis_id"]


def list_findings(conn: sqlite3.Connection, *, run_id: str | None = None, analysis_id: str | None = None,
                  target_mode: str | None = None, category: str | None = None, verdicts: tuple[str, ...] | None = None,
                  rule_id: str | None = None, min_severity: str | None = None, test_id: str | None = None,
                  correctness: str | None = None, limit: int = 100) -> list[dict]:
    """Findings (one per analysed execution) with their rule hits. ``verdicts=None`` means every verdict."""
    _choice("target mode", target_mode, schema.TARGET_MODES)
    _choice("category", category, schema.CATEGORIES)
    _choice("correctness", correctness, schema.CORRECTNESS)
    _choice("severity", min_severity, schema.SEVERITIES)
    for verdict in verdicts or ():
        _choice("verdict", verdict, schema.VERDICTS)
    clauses, params = [], []
    for column, value in (("f.run_id", run_id), ("f.analysis_id", analysis_id), ("f.target_mode", target_mode),
                          ("f.category", category), ("f.test_id", test_id), ("f.detection_correctness", correctness)):
        if value is not None:
            clauses.append(f"{column} = ?")  # column names come from the fixed tuple above
            params.append(value)
    if verdicts:
        clauses.append(f"f.verdict IN ({', '.join('?' for _ in verdicts)})")
        params.extend(verdicts)
    if min_severity is not None:
        allowed = [s for s, rank in _SEVERITY_RANK.items() if rank >= _SEVERITY_RANK[min_severity]]
        clauses.append(f"f.max_severity IN ({', '.join('?' for _ in allowed)})")
        params.extend(allowed)
    if rule_id is not None:
        clauses.append("EXISTS (SELECT 1 FROM finding_matches m WHERE m.finding_id = f.finding_id AND m.rule_id = ?)")
        params.append(rule_id)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    rows = conn.execute(
        "SELECT f.finding_id, f.analysis_id, f.run_id, f.ordinal, f.test_id, f.category, f.target_mode, "
        "f.execution_outcome, f.expected_behavior, f.expected_detection, f.verdict, f.detection_correctness, "
        "f.max_severity, f.refusal_language, f.data_classification FROM findings f "
        f"{where} ORDER BY f.run_id, f.analysis_id, f.ordinal LIMIT ?", (*params, _limit(limit))).fetchall()
    findings = [dict(r) for r in rows]
    if findings:
        ids = [f["finding_id"] for f in findings]
        by_finding: dict[str, list[dict]] = {fid: [] for fid in ids}
        for m in conn.execute(
                f"SELECT finding_id, rule_id, severity, effect, is_context FROM finding_matches "
                f"WHERE finding_id IN ({', '.join('?' for _ in ids)}) ORDER BY finding_id, is_context, ordinal", ids):
            by_finding[m["finding_id"]].append({"rule_id": m["rule_id"], "severity": m["severity"],
                                                "effect": m["effect"], "is_context": bool(m["is_context"])})
        for f in findings:
            f["refusal_language"] = bool(f["refusal_language"])
            f["rules"] = by_finding[f["finding_id"]]
    return findings


def get_finding(conn: sqlite3.Connection, finding_id: str) -> dict:
    """One finding with the stored response text and every rule hit including evidence and rationale."""
    row = conn.execute(
        "SELECT f.*, e.response_text, e.http_status, e.timestamp AS executed_at FROM findings f "
        "JOIN executions e ON e.execution_id = f.execution_id WHERE f.finding_id = ?", (finding_id,)).fetchone()
    if row is None:
        raise QueryError(f"no stored finding {finding_id!r}")
    result = dict(row)
    result["notes"] = json.loads(result.pop("notes_json"))
    result["refusal_language"] = bool(result["refusal_language"])
    result["matches"] = [
        {**{k: m[k] for k in ("rule_id", "family", "severity", "base_confidence", "confidence", "effect",
                              "evidence_text", "evidence_start", "evidence_end", "evidence_context", "rationale")},
         "is_context": bool(m["is_context"]), "adjustments": json.loads(m["adjustments_json"])}
        for m in conn.execute("SELECT * FROM finding_matches WHERE finding_id = ? ORDER BY is_context, ordinal", (finding_id,))
    ]
    return result


def database_info(conn: sqlite3.Connection) -> dict:
    meta = {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM db_meta")}
    last = conn.execute("SELECT seq, occurred_at, event_hash FROM audit_events ORDER BY seq DESC LIMIT 1").fetchone()
    return {
        "schema_version": conn.execute("PRAGMA user_version").fetchone()[0],
        "application_id": conn.execute("PRAGMA application_id").fetchone()[0],
        "migrations": [dict(r) for r in conn.execute("SELECT version, applied_at, description FROM schema_migrations ORDER BY version")],
        "data_policy": meta.get("data_policy"),
        "counts": table_counts(conn),
        "last_event": None if last is None else dict(last),
    }
