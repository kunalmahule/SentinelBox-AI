"""Versioned SQLite schema and the ordered migration list.

Every table is append-only: BEFORE UPDATE / BEFORE DELETE triggers abort. New schema versions are added as
new entries in ``MIGRATIONS``; an existing entry must never be edited once released.
"""

from __future__ import annotations

from dataclasses import dataclass

APPLICATION_ID = 0x53424F58  # "SBOX": identifies a SentinelBox audit database
DATA_CLASSIFICATION = "synthetic_test_data"
ANALYSIS_SCOPE = "synthetic_mock_environment"
GENESIS_HASH = "0" * 64

# Vocabulary shared by the DDL CHECK constraints and the import validation (single source of truth).
RUN_STATUSES = ("complete", "aborted", "interrupted")
OUTCOMES = ("completed", "http_error", "timeout", "connection_error", "invalid_response", "runner_error", "not_run")
TARGET_MODES = ("vulnerable", "hardened")
CATEGORIES = ("normal", "prompt_injection", "safety_bypass", "canary_disclosure")
VERDICTS = ("detected", "not_detected", "inconclusive", "not_evaluated")
CORRECTNESS = ("correct", "incorrect", "unresolved", "not_applicable", "unknown")
EXPECTED_BEHAVIORS = ("answer_normally", "resist_attack")
EXPECTED_DETECTIONS = ("detected", "not_detected")
SEVERITIES = ("info", "low", "medium", "high")
CONFIDENCES = ("low", "medium", "high")
EFFECTS = ("detects", "ambiguous", "context", "suppressed")
EVENT_TYPES_V1 = ("db_initialized", "db_migrated", "run_imported", "analysis_imported")
EVENT_TYPES = EVENT_TYPES_V1 + ("sandbox_run_recorded",)
SANDBOX_OUTCOMES = ("completed", "refused", "timeout", "output_limit", "workload_error", "docker_error", "interrupted")
SANDBOX_KINDS = ("adversarial_suite", "self_check", "none")
CLEANUP_STATUSES = ("removed", "not_created", "failed")


def _in(values: tuple[str, ...]) -> str:
    return "(" + ", ".join(f"'{v}'" for v in values) + ")"


_SYNTHETIC = f"data_classification TEXT NOT NULL DEFAULT '{DATA_CLASSIFICATION}' CHECK (data_classification = '{DATA_CLASSIFICATION}')"

# Order matters: parents before children.
TABLES_V1 = (
    "schema_migrations", "db_meta", "runs", "executions", "analyses", "findings", "finding_matches", "audit_events",
)
TABLES = TABLES_V1 + ("sandbox_runs",)

_V1_TABLES = [
    """CREATE TABLE schema_migrations (
        version INTEGER PRIMARY KEY,
        applied_at TEXT NOT NULL,
        description TEXT NOT NULL
    )""",
    """CREATE TABLE db_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )""",
    f"""CREATE TABLE runs (
        run_id TEXT PRIMARY KEY CHECK (length(run_id) > 0),
        report_sha256 TEXT NOT NULL UNIQUE CHECK (length(report_sha256) = 64),
        report_file_name TEXT NOT NULL,
        report_schema_version INTEGER NOT NULL,
        tool_name TEXT NOT NULL,
        tool_version TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN {_in(RUN_STATUSES)}),
        stop_reason TEXT,
        started_at TEXT NOT NULL,
        finished_at TEXT NOT NULL,
        target_base_url TEXT NOT NULL,
        library_name TEXT NOT NULL,
        library_version TEXT NOT NULL,
        library_file_name TEXT NOT NULL,
        library_sha256 TEXT NOT NULL,
        library_case_count INTEGER NOT NULL,
        modes_json TEXT NOT NULL,
        planned INTEGER NOT NULL CHECK (planned >= 0),
        attempted INTEGER NOT NULL CHECK (attempted >= 0),
        imported_at TEXT NOT NULL,
        {_SYNTHETIC}
    )""",
    f"""CREATE TABLE executions (
        execution_id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL REFERENCES runs (run_id),
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        test_id TEXT NOT NULL,
        category TEXT NOT NULL CHECK (category IN {_in(CATEGORIES)}),
        target_mode TEXT NOT NULL CHECK (target_mode IN {_in(TARGET_MODES)}),
        timestamp TEXT,
        duration_ms REAL,
        http_status INTEGER,
        outcome TEXT NOT NULL CHECK (outcome IN {_in(OUTCOMES)}),
        response_text TEXT,
        raw_body TEXT,
        raw_body_truncated INTEGER NOT NULL CHECK (raw_body_truncated IN (0, 1)),
        error TEXT,
        {_SYNTHETIC},
        UNIQUE (run_id, test_id, target_mode),
        UNIQUE (run_id, ordinal)
    )""",
    f"""CREATE TABLE analyses (
        analysis_id TEXT PRIMARY KEY CHECK (length(analysis_id) > 0),
        analysis_sha256 TEXT NOT NULL UNIQUE CHECK (length(analysis_sha256) = 64),
        analysis_file_name TEXT NOT NULL,
        schema_version INTEGER NOT NULL,
        tool_name TEXT NOT NULL,
        tool_version TEXT NOT NULL,
        created_at TEXT NOT NULL,
        scope TEXT NOT NULL CHECK (scope = '{ANALYSIS_SCOPE}'),
        run_id TEXT NOT NULL REFERENCES runs (run_id),
        report_sha256 TEXT NOT NULL,
        rule_set_version TEXT NOT NULL,
        rule_set_json TEXT NOT NULL,
        expectations_json TEXT,
        metrics_json TEXT NOT NULL,
        known_limitations_json TEXT NOT NULL,
        disclaimer TEXT NOT NULL,
        record_count INTEGER NOT NULL CHECK (record_count >= 0),
        imported_at TEXT NOT NULL,
        {_SYNTHETIC}
    )""",
    f"""CREATE TABLE findings (
        finding_id TEXT PRIMARY KEY,
        analysis_id TEXT NOT NULL REFERENCES analyses (analysis_id),
        run_id TEXT NOT NULL REFERENCES runs (run_id),
        execution_id TEXT NOT NULL REFERENCES executions (execution_id),
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        test_id TEXT NOT NULL,
        category TEXT NOT NULL CHECK (category IN {_in(CATEGORIES)}),
        target_mode TEXT NOT NULL CHECK (target_mode IN {_in(TARGET_MODES)}),
        execution_outcome TEXT NOT NULL CHECK (execution_outcome IN {_in(OUTCOMES)}),
        expected_behavior TEXT CHECK (expected_behavior IS NULL OR expected_behavior IN {_in(EXPECTED_BEHAVIORS)}),
        expected_detection TEXT CHECK (expected_detection IS NULL OR expected_detection IN {_in(EXPECTED_DETECTIONS)}),
        verdict TEXT NOT NULL CHECK (verdict IN {_in(VERDICTS)}),
        detection_correctness TEXT NOT NULL CHECK (detection_correctness IN {_in(CORRECTNESS)}),
        max_severity TEXT CHECK (max_severity IS NULL OR max_severity IN {_in(SEVERITIES)}),
        refusal_language INTEGER NOT NULL CHECK (refusal_language IN (0, 1)),
        notes_json TEXT NOT NULL,
        {_SYNTHETIC},
        UNIQUE (analysis_id, ordinal),
        UNIQUE (analysis_id, execution_id)
    )""",
    f"""CREATE TABLE finding_matches (
        match_id INTEGER PRIMARY KEY,
        finding_id TEXT NOT NULL REFERENCES findings (finding_id),
        analysis_id TEXT NOT NULL REFERENCES analyses (analysis_id),
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        is_context INTEGER NOT NULL CHECK (is_context IN (0, 1)),
        rule_id TEXT NOT NULL,
        family TEXT NOT NULL,
        severity TEXT NOT NULL CHECK (severity IN {_in(SEVERITIES)}),
        base_confidence TEXT NOT NULL CHECK (base_confidence IN {_in(CONFIDENCES)}),
        confidence TEXT NOT NULL CHECK (confidence IN {_in(CONFIDENCES)}),
        effect TEXT NOT NULL CHECK (effect IN {_in(EFFECTS)}),
        evidence_text TEXT NOT NULL,
        evidence_start INTEGER NOT NULL,
        evidence_end INTEGER NOT NULL,
        evidence_context TEXT NOT NULL,
        rationale TEXT NOT NULL,
        adjustments_json TEXT NOT NULL,
        {_SYNTHETIC},
        UNIQUE (finding_id, is_context, ordinal)
    )""",
    f"""CREATE TABLE audit_events (
        seq INTEGER PRIMARY KEY CHECK (seq >= 1),
        occurred_at TEXT NOT NULL,
        event_type TEXT NOT NULL CHECK (event_type IN {_in(EVENT_TYPES_V1)}),
        run_id TEXT,
        analysis_id TEXT,
        detail_json TEXT NOT NULL,
        prev_hash TEXT NOT NULL CHECK (length(prev_hash) = 64),
        event_hash TEXT NOT NULL UNIQUE CHECK (length(event_hash) = 64)
    )""",
]

_V1_INDEXES = [
    "CREATE INDEX idx_runs_started_at ON runs (started_at)",
    "CREATE INDEX idx_executions_run_outcome ON executions (run_id, outcome)",
    "CREATE INDEX idx_executions_run_mode ON executions (run_id, target_mode)",
    "CREATE INDEX idx_executions_test_id ON executions (test_id)",
    "CREATE INDEX idx_analyses_run ON analyses (run_id)",
    "CREATE INDEX idx_findings_analysis_verdict ON findings (analysis_id, verdict)",
    "CREATE INDEX idx_findings_run_mode_verdict ON findings (run_id, target_mode, verdict)",
    "CREATE INDEX idx_findings_test_id ON findings (test_id)",
    "CREATE INDEX idx_findings_execution ON findings (execution_id)",
    "CREATE INDEX idx_matches_finding ON finding_matches (finding_id)",
    "CREATE INDEX idx_matches_rule ON finding_matches (rule_id)",
    "CREATE INDEX idx_matches_analysis_rule ON finding_matches (analysis_id, rule_id)",
    "CREATE INDEX idx_matches_severity ON finding_matches (severity)",
    "CREATE INDEX idx_audit_run ON audit_events (run_id)",
    "CREATE INDEX idx_audit_type ON audit_events (event_type)",
]


def append_only_triggers(tables: tuple[str, ...] = TABLES_V1) -> list[str]:
    """Triggers that abort any UPDATE or DELETE on the given tables."""
    statements = []
    for table in tables:
        for action in ("UPDATE", "DELETE"):
            statements.append(
                f"CREATE TRIGGER {table}_no_{action.lower()} BEFORE {action} ON {table} "
                f"BEGIN SELECT RAISE(ABORT, 'SentinelBox audit tables are append-only: {action} on {table} is not allowed'); END"
            )
    return statements


# --- schema v2: sandbox runs ---------------------------------------------------------------------------------------------
# audit_events must accept the new 'sandbox_run_recorded' event type. SQLite cannot alter a CHECK constraint, so the
# table is rebuilt with its rows copied verbatim (the hash chain is unchanged and re-verified by the tests).
_AUDIT_COLUMNS = "seq, occurred_at, event_type, run_id, analysis_id, detail_json, prev_hash, event_hash"

_V2_STATEMENTS = [
    "DROP TRIGGER audit_events_no_update",
    "DROP TRIGGER audit_events_no_delete",
    "ALTER TABLE audit_events RENAME TO audit_events_v1",
    f"""CREATE TABLE audit_events (
        seq INTEGER PRIMARY KEY CHECK (seq >= 1),
        occurred_at TEXT NOT NULL,
        event_type TEXT NOT NULL CHECK (event_type IN {_in(EVENT_TYPES)}),
        run_id TEXT,
        analysis_id TEXT,
        detail_json TEXT NOT NULL,
        prev_hash TEXT NOT NULL CHECK (length(prev_hash) = 64),
        event_hash TEXT NOT NULL UNIQUE CHECK (length(event_hash) = 64)
    )""",
    f"INSERT INTO audit_events ({_AUDIT_COLUMNS}) SELECT {_AUDIT_COLUMNS} FROM audit_events_v1 ORDER BY seq",
    "DROP TABLE audit_events_v1",
    "CREATE INDEX idx_audit_run ON audit_events (run_id)",
    "CREATE INDEX idx_audit_type ON audit_events (event_type)",
    f"""CREATE TABLE sandbox_runs (
        sandbox_run_id TEXT PRIMARY KEY CHECK (length(sandbox_run_id) > 0),
        record_sha256 TEXT NOT NULL UNIQUE CHECK (length(record_sha256) = 64),
        record_file_name TEXT NOT NULL,
        record_schema_version INTEGER NOT NULL,
        tool_name TEXT NOT NULL,
        tool_version TEXT NOT NULL,
        policy_version TEXT NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN {_in(SANDBOX_KINDS)}),
        outcome TEXT NOT NULL CHECK (outcome IN {_in(SANDBOX_OUTCOMES)}),
        controls_verified INTEGER NOT NULL CHECK (controls_verified IN (0, 1)),
        controls_json TEXT NOT NULL,
        requested_json TEXT NOT NULL,
        effective_json TEXT,
        image_ref TEXT,
        image_id TEXT,
        image_digest TEXT,
        docker_client_version TEXT,
        docker_server_version TEXT,
        started_at TEXT NOT NULL,
        finished_at TEXT NOT NULL,
        duration_ms REAL NOT NULL CHECK (duration_ms >= 0),
        exit_code INTEGER,
        timed_out INTEGER NOT NULL CHECK (timed_out IN (0, 1)),
        stdout_truncated INTEGER NOT NULL CHECK (stdout_truncated IN (0, 1)),
        stderr_truncated INTEGER NOT NULL CHECK (stderr_truncated IN (0, 1)),
        stderr_summary TEXT,
        cases_requested INTEGER NOT NULL CHECK (cases_requested >= 0),
        cases_returned INTEGER NOT NULL CHECK (cases_returned >= 0),
        cleanup_status TEXT NOT NULL CHECK (cleanup_status IN {_in(CLEANUP_STATUSES)}),
        cleanup_detail TEXT,
        run_id TEXT REFERENCES runs (run_id),
        analysis_id TEXT REFERENCES analyses (analysis_id),
        report_file_name TEXT,
        report_sha256 TEXT,
        analysis_file_name TEXT,
        analysis_sha256 TEXT,
        note TEXT NOT NULL,
        imported_at TEXT NOT NULL,
        {_SYNTHETIC},
        CHECK (controls_verified = 1 OR outcome IN ('refused', 'docker_error', 'interrupted')),
        CHECK (outcome <> 'completed' OR (exit_code = 0 AND timed_out = 0 AND stdout_truncated = 0 AND stderr_truncated = 0))
    )""",
    "CREATE INDEX idx_sandbox_started_at ON sandbox_runs (started_at)",
    "CREATE INDEX idx_sandbox_outcome ON sandbox_runs (outcome)",
    "CREATE INDEX idx_sandbox_run ON sandbox_runs (run_id)",
    "CREATE INDEX idx_sandbox_analysis ON sandbox_runs (analysis_id)",
] + append_only_triggers(("audit_events", "sandbox_runs"))


@dataclass(frozen=True)
class Migration:
    version: int
    description: str
    statements: tuple[str, ...]


MIGRATIONS: tuple[Migration, ...] = (
    Migration(1, "initial schema: runs, executions, analyses, findings, matches, audit events",
              tuple(_V1_TABLES + _V1_INDEXES + append_only_triggers())),
    Migration(2, "sandbox runs table; audit_events accepts sandbox_run_recorded events", tuple(_V2_STATEMENTS)),
)

LATEST_VERSION = MIGRATIONS[-1].version

DATA_POLICY = (
    "All stored runs, responses, evidence and canary values are synthetic test data produced against a "
    "local mock AI target. No real credentials or secrets may be stored."
)
