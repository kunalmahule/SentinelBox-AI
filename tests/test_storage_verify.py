"""verify_database and the audit hash chain: intact databases pass, alterations are reported."""

import contextlib
import hashlib
import sqlite3

import pytest
from storage_fakes import write_docs

from sentinelbox.storage import audit, importer, schema
from sentinelbox.storage.database import init_database, open_database
from sentinelbox.storage.verify import verify_database


@pytest.fixture
def populated(tmp_path):
    path = init_database(tmp_path / "audit.db")
    report_doc, analysis_doc = write_docs(tmp_path)
    with contextlib.closing(open_database(path)) as conn:
        importer.import_report_and_analysis(conn, report_doc, analysis_doc)
    return path


def raw(path):
    """A connection that bypasses SentinelBox (an attacker or careless user with file access)."""
    return contextlib.closing(sqlite3.connect(path, isolation_level=None))


def check(path, **kwargs):
    with contextlib.closing(open_database(path, readonly=True)) as conn:
        return verify_database(conn, **kwargs)


def drop_triggers(conn):
    for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'").fetchall():
        conn.execute(f"DROP TRIGGER {name}")


def test_an_untouched_database_verifies_cleanly(populated):
    report = check(populated)
    assert report.ok and report.problems == [] and report.warnings == []
    assert {"SQLite integrity_check", "audit hash chain", "append-only triggers"} <= set(report.checks)


def test_an_empty_database_verifies_cleanly(tmp_path):
    assert check(init_database(tmp_path / "e.db")).ok


def test_verify_is_read_only(populated):
    before = hashlib.sha256(populated.read_bytes()).hexdigest()
    check(populated)
    assert hashlib.sha256(populated.read_bytes()).hexdigest() == before


def test_a_dropped_trigger_is_reported(populated):
    with raw(populated) as conn:
        conn.execute("DROP TRIGGER executions_no_update")
    report = check(populated)
    assert not report.ok and any("executions_no_update" in p for p in report.problems)


def test_an_edited_audit_event_breaks_the_chain(populated):
    with raw(populated) as conn:
        drop_triggers(conn)
        conn.execute("UPDATE audit_events SET detail_json = '{\"executions\": 1}' WHERE seq = 2")
    problems = check(populated).problems
    assert any("event 2" in p and "edited" in p for p in problems)


def test_an_edited_event_hash_breaks_the_next_link(populated):
    with raw(populated) as conn:
        drop_triggers(conn)
        conn.execute("UPDATE audit_events SET event_hash = ? WHERE seq = 2", ("a" * 64,))
    problems = check(populated).problems
    assert any("event 2" in p for p in problems) and any("event 3" in p and "prev_hash" in p for p in problems)


def test_a_deleted_middle_event_is_detected(populated):
    with raw(populated) as conn:
        drop_triggers(conn)
        conn.execute("DELETE FROM audit_events WHERE seq = 2")
    problems = check(populated).problems
    assert any("missing" in p for p in problems)
    assert any("has no run_imported audit event" in p for p in problems)


def test_a_deleted_last_event_is_caught_by_audit_coverage(populated):
    with raw(populated) as conn:
        drop_triggers(conn)
        conn.execute("DELETE FROM audit_events WHERE seq = 3")
    assert any("has no analysis_imported audit event" in p for p in check(populated).problems)


def test_a_deleted_execution_row_is_detected_by_the_counts(populated):
    with raw(populated) as conn:
        drop_triggers(conn)
        conn.execute("PRAGMA foreign_keys = OFF")
        conn.execute("DELETE FROM finding_matches WHERE finding_id IN (SELECT finding_id FROM findings WHERE ordinal = 5)")
        conn.execute("DELETE FROM findings WHERE ordinal = 5")
        conn.execute("DELETE FROM executions WHERE ordinal = 5")
    problems = check(populated).problems
    assert any("planned 6 but 5 executions" in p for p in problems)
    assert any("6 records declared but 5 findings" in p for p in problems)


def test_a_foreign_key_violation_is_reported(populated):
    with raw(populated) as conn:
        drop_triggers(conn)
        conn.execute("PRAGMA foreign_keys = OFF")
        conn.execute("DELETE FROM executions WHERE ordinal = 0")
    assert any("foreign key" in p for p in check(populated).problems)


def test_chain_verification_alone_flags_each_kind_of_edit(populated):
    with raw(populated) as conn:
        drop_triggers(conn)
        conn.execute("UPDATE audit_events SET occurred_at = '2000-01-01T00:00:00+00:00' WHERE seq = 1")
    with contextlib.closing(open_database(populated, readonly=True)) as conn:
        assert any("event 1" in p for p in audit.verify_chain(conn))


def test_event_hashes_depend_on_every_field():
    base = ("2026-01-01T00:00:00+00:00", "run_imported", "r", "a", "{}", "0" * 64)
    reference = audit.compute_event_hash(1, *base)
    variants = [(2, *base), (1, "2026-01-01T00:00:01+00:00", *base[1:]), (1, base[0], "db_migrated", *base[2:]),
                (1, *base[:2], "r2", *base[3:]), (1, *base[:3], "a2", *base[4:]), (1, *base[:4], '{"x":1}', base[5]),
                (1, *base[:5], "1" * 64)]
    assert len({reference, *(audit.compute_event_hash(*v) for v in variants)}) == len(variants) + 1


def test_unknown_event_types_cannot_be_appended(populated):
    with contextlib.closing(open_database(populated)) as conn, pytest.raises(ValueError, match="unknown audit event type"):
        audit.append_event(conn, "something_else")


# --- stored hashes of the original JSON artifacts ------------------------------------------------------------------------------
def test_matching_source_files_pass_the_artifact_check(populated, tmp_path):
    report = check(populated, artifacts_dir=tmp_path)
    assert report.ok and report.warnings == [] and any(c.startswith("source files") for c in report.checks)


def test_a_modified_source_file_is_reported(populated, tmp_path):
    (tmp_path / "run.json").write_text((tmp_path / "run.json").read_text() + " ", encoding="utf-8")
    problems = check(populated, artifacts_dir=tmp_path).problems
    assert len(problems) == 1 and "run.json" in problems[0] and "no longer matches" in problems[0]


def test_a_missing_source_file_is_a_warning_not_a_failure(populated, tmp_path):
    (tmp_path / "run.analysis.json").unlink()
    report = check(populated, artifacts_dir=tmp_path)
    assert report.ok and any("run.analysis.json" in w and "not found" in w for w in report.warnings)


def test_the_artifact_check_never_writes_to_the_source_files(populated, tmp_path):
    files = [tmp_path / "run.json", tmp_path / "run.analysis.json"]
    before = [(f.read_bytes(), f.stat().st_mtime_ns) for f in files]
    check(populated, artifacts_dir=tmp_path)
    assert [(f.read_bytes(), f.stat().st_mtime_ns) for f in files] == before


def test_expected_tables_constant_matches_the_database(populated):
    with contextlib.closing(open_database(populated, readonly=True)) as conn:
        tables = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")}
    assert tables == set(schema.TABLES)
