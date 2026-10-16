"""Schema creation, explicit initialisation, version checks and append-only protection."""

import contextlib
import hashlib
import os
import sqlite3

import pytest
from storage_fakes import make_report, make_sandbox_record, write_docs, write_sandbox_doc

from sentinelbox.storage import audit, database, importer, schema
from sentinelbox.storage.database import (DatabaseExistsError, DatabaseNotFoundError, NotASentinelDatabase,
                                          SchemaVersionError, init_database, open_database)


@pytest.fixture
def db_path(tmp_path):
    return init_database(tmp_path / "audit.db")


@pytest.fixture
def populated(tmp_path):
    path = init_database(tmp_path / "populated.db")
    report_doc, analysis_doc = write_docs(tmp_path)
    with contextlib.closing(open_database(path)) as conn:
        importer.import_report_and_analysis(conn, report_doc, analysis_doc)
        importer.import_sandbox_record(conn, write_sandbox_doc(tmp_path, make_sandbox_record(report_doc, analysis_doc)))
    return path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --- initialisation --------------------------------------------------------------------------------------------
def test_init_creates_every_table_with_version_and_application_id(db_path):
    with contextlib.closing(open_database(db_path)) as conn:
        tables = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        assert set(schema.TABLES) <= tables
        assert conn.execute("PRAGMA user_version").fetchone()[0] == schema.LATEST_VERSION == 2
        assert conn.execute("PRAGMA application_id").fetchone()[0] == schema.APPLICATION_ID


def test_init_records_the_migration_the_data_policy_and_a_first_audit_event(db_path):
    with contextlib.closing(open_database(db_path)) as conn:
        assert [r["version"] for r in conn.execute("SELECT version FROM schema_migrations ORDER BY version")] == [1, 2]
        policy = conn.execute("SELECT value FROM db_meta WHERE key = 'data_policy'").fetchone()[0]
        assert "synthetic" in policy and "No real credentials" in policy
        events = conn.execute("SELECT seq, event_type, prev_hash FROM audit_events").fetchall()
        assert [(e["seq"], e["event_type"], e["prev_hash"]) for e in events] == [(1, "db_initialized", schema.GENESIS_HASH)]
        assert audit.verify_chain(conn) == []


def test_init_creates_parent_directories_and_leaves_no_temporary_files(tmp_path):
    target = tmp_path / "a" / "b" / "audit.db"
    init_database(target)
    assert sorted(p.name for p in target.parent.iterdir()) == ["audit.db"]


@pytest.mark.parametrize("content", [b"", b"not a database", b"x" * 5000])
def test_init_never_touches_an_existing_file(tmp_path, content):
    path = tmp_path / "existing.db"
    path.write_bytes(content)
    before = (sha(path), path.stat().st_mtime_ns)
    with pytest.raises(DatabaseExistsError, match="already exists"):
        init_database(path)
    assert (sha(path), path.stat().st_mtime_ns) == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["existing.db"]


def test_init_refuses_to_replace_an_initialised_database_and_keeps_its_data(populated):
    before = sha(populated)
    with pytest.raises(DatabaseExistsError):
        init_database(populated)
    assert sha(populated) == before


def test_init_refuses_a_dangling_symlink(tmp_path):
    link = tmp_path / "link.db"
    os.symlink(tmp_path / "nowhere.db", link)
    with pytest.raises(DatabaseExistsError):
        init_database(link)
    assert not (tmp_path / "nowhere.db").exists()


def test_init_race_when_the_destination_appears_is_not_overwritten(tmp_path, monkeypatch):
    target = tmp_path / "audit.db"
    real_link = os.link

    def racing_link(src, dst, *args, **kwargs):
        target.write_bytes(b"someone else's file")
        return real_link(src, dst, *args, **kwargs)

    monkeypatch.setattr(os, "link", racing_link)
    with pytest.raises(DatabaseExistsError):
        init_database(target)
    assert target.read_bytes() == b"someone else's file"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["audit.db"]


def test_init_falls_back_when_hard_links_are_unsupported(tmp_path, monkeypatch):
    def no_links(*args, **kwargs):
        raise OSError("links not supported")

    monkeypatch.setattr(os, "link", no_links)
    path = init_database(tmp_path / "audit.db")
    with contextlib.closing(open_database(path)) as conn:
        assert audit.verify_chain(conn) == []
    assert sorted(p.name for p in tmp_path.iterdir()) == ["audit.db"]


# --- opening and version checks -----------------------------------------------------------------------------------
def test_open_requires_an_existing_file_and_says_how_to_create_it(tmp_path):
    with pytest.raises(DatabaseNotFoundError, match="init --db"):
        open_database(tmp_path / "missing.db")
    assert list(tmp_path.iterdir()) == []  # opening never creates a database


def test_open_refuses_a_directory(tmp_path):
    with pytest.raises(DatabaseNotFoundError):
        open_database(tmp_path)


@pytest.mark.parametrize("content", [b"", b"just text, not sqlite" * 20])
def test_open_refuses_files_that_are_not_sqlite_databases(tmp_path, content):
    path = tmp_path / "x.db"
    path.write_bytes(content)
    with pytest.raises(NotASentinelDatabase):
        open_database(path)
    assert path.read_bytes() == content


def test_open_refuses_a_foreign_sqlite_database_without_modifying_it(tmp_path):
    path = tmp_path / "foreign.db"
    with contextlib.closing(sqlite3.connect(path)) as conn:
        conn.execute("CREATE TABLE notes (x TEXT)")
        conn.commit()
    before = sha(path)
    with pytest.raises(NotASentinelDatabase, match="not a SentinelBox"):
        open_database(path)
    assert sha(path) == before


def test_open_refuses_an_older_schema_and_points_to_migrate(db_path):
    with contextlib.closing(sqlite3.connect(db_path)) as conn:
        conn.execute("PRAGMA user_version = 0")
    with pytest.raises(SchemaVersionError, match="migrate") as info:
        open_database(db_path)
    assert (info.value.found, info.value.expected) == (0, 2)


def test_open_refuses_a_newer_schema(db_path):
    with contextlib.closing(sqlite3.connect(db_path)) as conn:
        conn.execute("PRAGMA user_version = 99")
    with pytest.raises(SchemaVersionError, match="newer than this tool") as info:
        open_database(db_path)
    assert info.value.found == 99


def test_a_failed_open_does_not_leak_the_connection(db_path, monkeypatch):
    closed = []
    real_connect = database.connect

    # sqlite3.Connection forbids setting attributes, so wrap it.
    class Wrapper:
        def __init__(self, conn):
            self._conn = conn

        def __getattr__(self, name):
            return getattr(self._conn, name)

        def close(self):
            closed.append(True)
            self._conn.close()

    monkeypatch.setattr(database, "connect", lambda *a, **k: Wrapper(real_connect(*a, **k)))
    with contextlib.closing(sqlite3.connect(db_path)) as conn:
        conn.execute("PRAGMA user_version = 99")
    with pytest.raises(SchemaVersionError):
        open_database(db_path)
    assert closed == [True]


def test_foreign_keys_are_enforced_on_every_connection(db_path):
    with contextlib.closing(open_database(db_path)) as conn:
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
            conn.execute(
                "INSERT INTO executions (execution_id, run_id, ordinal, test_id, category, target_mode, outcome, raw_body_truncated) "
                "VALUES ('e', 'no-such-run', 0, 'T', 'normal', 'vulnerable', 'completed', 0)")


def test_readonly_connections_cannot_write(populated):
    with contextlib.closing(open_database(populated, readonly=True)) as conn:
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            conn.execute("INSERT INTO db_meta (key, value) VALUES ('x', 'y')")


def test_readonly_open_works_with_unusual_characters_in_the_path(tmp_path):
    path = init_database(tmp_path / "my audit #1 (copy)?.db")
    with contextlib.closing(open_database(path, readonly=True)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 0


# --- append-only protection -------------------------------------------------------------------------------------------
@pytest.mark.parametrize("table", schema.TABLES)
def test_every_table_blocks_update_and_delete(populated, table):
    with contextlib.closing(open_database(populated)) as conn:
        before = database.table_counts(conn)
        assert before[table] > 0
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute(f"DELETE FROM {table}")
        first_column = conn.execute(f"SELECT name FROM pragma_table_info('{table}') LIMIT 1").fetchone()[0]
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute(f"UPDATE {table} SET {first_column} = {first_column}")
        assert database.table_counts(conn) == before


def test_an_expected_trigger_exists_for_every_table_and_action(db_path):
    with contextlib.closing(open_database(db_path)) as conn:
        names = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")}
    assert names == {f"{t}_no_{a}" for t in schema.TABLES for a in ("update", "delete")}


def test_rows_are_marked_synthetic_and_the_marker_cannot_be_changed(populated):
    with contextlib.closing(open_database(populated)) as conn:
        for table in ("runs", "executions", "analyses", "findings", "finding_matches"):
            values = {r[0] for r in conn.execute(f"SELECT DISTINCT data_classification FROM {table}")}
            assert values == {"synthetic_test_data"}, table
        with pytest.raises(sqlite3.IntegrityError, match="CHECK"):
            conn.execute(
                "INSERT INTO runs (run_id, report_sha256, report_file_name, report_schema_version, tool_name, tool_version, "
                "status, started_at, finished_at, target_base_url, library_name, library_version, library_file_name, "
                "library_sha256, library_case_count, modes_json, planned, attempted, imported_at, data_classification) "
                "VALUES ('r', ?, 'f', 1, 't', 'v', 'complete', 'a', 'b', 'u', 'n', 'v', 'f', 's', 1, '[]', 0, 0, 'i', 'production')",
                ("0" * 64,))


@pytest.mark.parametrize("sql", [
    "INSERT INTO executions (execution_id, run_id, ordinal, test_id, category, target_mode, outcome, raw_body_truncated) "
    "SELECT 'x', run_id, 99, 'T', 'normal', 'sideways', 'completed', 0 FROM runs LIMIT 1",
    "INSERT INTO executions (execution_id, run_id, ordinal, test_id, category, target_mode, outcome, raw_body_truncated) "
    "SELECT 'x', run_id, 99, 'T', 'normal', 'vulnerable', 'exploded', 0 FROM runs LIMIT 1",
    "INSERT INTO executions (execution_id, run_id, ordinal, test_id, category, target_mode, outcome, raw_body_truncated) "
    "SELECT 'x', run_id, 99, 'T', 'normal', 'vulnerable', 'completed', 7 FROM runs LIMIT 1",
    "INSERT INTO executions (execution_id, run_id, ordinal, test_id, category, target_mode, outcome, raw_body_truncated) "
    "SELECT 'x', run_id, 0, 'T', 'normal', 'vulnerable', 'completed', 0 FROM runs LIMIT 1",  # duplicate ordinal
])
def test_check_and_unique_constraints_reject_bad_rows(populated, sql):
    with contextlib.closing(open_database(populated)) as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(sql)


# --- indexes ---------------------------------------------------------------------------------------------------------
def test_expected_indexes_exist(db_path):
    with contextlib.closing(open_database(db_path)) as conn:
        names = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_%'")}
    assert {"idx_runs_started_at", "idx_findings_analysis_verdict", "idx_findings_run_mode_verdict", "idx_matches_rule",
            "idx_matches_analysis_rule", "idx_executions_run_outcome", "idx_analyses_run", "idx_audit_run"} <= names


@pytest.mark.parametrize("sql, params, index", [
    ("SELECT * FROM findings WHERE analysis_id = ? AND verdict = ?", ("a", "detected"), "idx_findings_analysis_verdict"),
    ("SELECT * FROM findings WHERE run_id = ? AND target_mode = ? AND verdict = ?", ("r", "vulnerable", "detected"), "idx_findings_run_mode_verdict"),
    ("SELECT * FROM finding_matches WHERE rule_id = ?", ("R-CANARY-001",), "idx_matches_rule"),
    ("SELECT * FROM finding_matches WHERE analysis_id = ? AND rule_id = ?", ("a", "R-CANARY-001"), "idx_matches_analysis_rule"),
    ("SELECT * FROM executions WHERE run_id = ? AND outcome = ?", ("r", "timeout"), "idx_executions_run_outcome"),
    ("SELECT * FROM analyses WHERE run_id = ?", ("r",), "idx_analyses_run"),
    ("SELECT * FROM findings WHERE test_id = ?", ("CAN-001",), "idx_findings_test_id"),
    ("SELECT * FROM runs ORDER BY started_at DESC", (), "idx_runs_started_at"),
])
def test_common_queries_use_an_index(db_path, sql, params, index):
    with contextlib.closing(open_database(db_path)) as conn:
        plan = " ".join(r["detail"] for r in conn.execute("EXPLAIN QUERY PLAN " + sql, params))
    assert index in plan, plan
