"""Migration framework: backups, atomicity, version policy."""

import contextlib
import dataclasses
import sqlite3

import pytest

from sentinelbox.storage import audit, database, schema
from sentinelbox.storage.database import (DatabaseExistsError, DatabaseNotFoundError, NotASentinelDatabase,
                                          SchemaVersionError, StorageError, init_database, migrate_database, open_database)

L3 = schema.Migration(3, "add runs.label", ("ALTER TABLE runs ADD COLUMN label TEXT",))
N4 = schema.Migration(4, "add executions.note", ("ALTER TABLE executions ADD COLUMN note TEXT",))
BROKEN = schema.Migration(3, "broken", ("ALTER TABLE runs ADD COLUMN ok_column TEXT", "ALTER TABLE no_such_table ADD COLUMN x TEXT"))


@pytest.fixture
def db_path(tmp_path):
    return init_database(tmp_path / "audit.db")


def version_of(path):
    with contextlib.closing(sqlite3.connect(path)) as conn:
        return conn.execute("PRAGMA user_version").fetchone()[0]


def test_migrating_a_current_database_is_a_no_op_without_a_backup(db_path):
    before = db_path.read_bytes()
    result = migrate_database(db_path)
    assert (result.from_version, result.to_version, result.backup_path) == (2, 2, None)
    assert db_path.read_bytes() == before
    assert [p.name for p in db_path.parent.iterdir()] == ["audit.db"]


def test_migrate_applies_pending_steps_backs_up_first_and_logs_the_event(db_path):
    result = migrate_database(db_path, migrations=schema.MIGRATIONS + (L3, N4))
    assert (result.from_version, result.to_version) == (2, 4)
    assert result.backup_path.name == "audit.db.bak-v2" and result.backup_path.exists()
    assert version_of(db_path) == 4 and version_of(result.backup_path) == 2
    with contextlib.closing(database.connect(db_path)) as conn:
        assert [r["version"] for r in conn.execute("SELECT version FROM schema_migrations ORDER BY version")] == [1, 2, 3, 4]
        assert "label" in [r["name"] for r in conn.execute("PRAGMA table_info(runs)")]
        events = [r["event_type"] for r in conn.execute("SELECT event_type FROM audit_events ORDER BY seq")]
        assert events == ["db_initialized", "db_migrated"]
        assert audit.verify_chain(conn) == []


def test_the_backup_is_a_usable_copy_of_the_old_database(db_path):
    result = migrate_database(db_path, migrations=schema.MIGRATIONS + (L3,))
    with contextlib.closing(open_database(result.backup_path)) as conn:  # still a valid database at its own version
        assert audit.verify_chain(conn) == []
        assert "label" not in [r["name"] for r in conn.execute("PRAGMA table_info(runs)")]


def test_migrate_refuses_to_overwrite_an_existing_backup_and_changes_nothing(db_path):
    backup = db_path.with_name("audit.db.bak-v2")
    backup.write_bytes(b"precious")
    before = db_path.read_bytes()
    with pytest.raises(DatabaseExistsError, match="backup"):
        migrate_database(db_path, migrations=schema.MIGRATIONS + (L3,))
    assert backup.read_bytes() == b"precious" and db_path.read_bytes() == before


def test_a_failing_migration_rolls_back_completely_and_removes_its_backup(db_path):
    before = db_path.read_bytes()
    with pytest.raises(sqlite3.OperationalError):
        migrate_database(db_path, migrations=schema.MIGRATIONS + (BROKEN,))
    assert version_of(db_path) == 2
    with contextlib.closing(database.connect(db_path)) as conn:
        assert "ok_column" not in [r["name"] for r in conn.execute("PRAGMA table_info(runs)")]
        assert conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 1
    assert [p.name for p in db_path.parent.iterdir()] == ["audit.db"]
    assert db_path.read_bytes() == before
    migrate_database(db_path, migrations=schema.MIGRATIONS + (L3,))  # a retry is possible afterwards


def test_a_failure_while_logging_the_event_also_rolls_everything_back(db_path, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("audit write failed")

    monkeypatch.setattr(audit, "append_event", boom)
    with pytest.raises(RuntimeError):
        migrate_database(db_path, migrations=schema.MIGRATIONS + (L3,))
    assert version_of(db_path) == 2
    with contextlib.closing(database.connect(db_path)) as conn:
        assert "label" not in [r["name"] for r in conn.execute("PRAGMA table_info(runs)")]


def test_a_gap_in_the_migration_list_is_rejected_before_anything_changes(db_path):
    before = db_path.read_bytes()
    with pytest.raises(StorageError, match="contiguous"):
        migrate_database(db_path, migrations=schema.MIGRATIONS + (N4,))
    assert db_path.read_bytes() == before and [p.name for p in db_path.parent.iterdir()] == ["audit.db"]


def test_migrate_refuses_a_database_newer_than_the_tool(db_path):
    with contextlib.closing(sqlite3.connect(db_path)) as conn:
        conn.execute("PRAGMA user_version = 7")
    with pytest.raises(SchemaVersionError, match="newer"):
        migrate_database(db_path)
    assert version_of(db_path) == 7


def test_migrate_refuses_foreign_and_missing_files(tmp_path):
    foreign = tmp_path / "foreign.db"
    with contextlib.closing(sqlite3.connect(foreign)) as conn:
        conn.execute("CREATE TABLE t (x)")
    with pytest.raises(NotASentinelDatabase):
        migrate_database(foreign)
    with pytest.raises(DatabaseNotFoundError):
        migrate_database(tmp_path / "missing.db")
    assert not (tmp_path / "missing.db").exists()


def test_open_demands_a_migration_when_the_code_expects_a_newer_schema(db_path, monkeypatch):
    monkeypatch.setattr(database, "LATEST_VERSION", 3)
    with pytest.raises(SchemaVersionError, match="migrate") as info:
        open_database(db_path)
    assert (info.value.found, info.value.expected) == (2, 3)


def test_existing_rows_survive_a_migration_unchanged(tmp_path):
    from storage_fakes import write_docs

    from sentinelbox.storage import importer

    path = init_database(tmp_path / "audit.db")
    report_doc, analysis_doc = write_docs(tmp_path)
    with contextlib.closing(open_database(path)) as conn:
        importer.import_report_and_analysis(conn, report_doc, analysis_doc)
        snapshot = {t: [tuple(r) for r in conn.execute(f"SELECT * FROM {t} ORDER BY 1")] for t in ("executions", "findings", "finding_matches")}
    migrate_database(path, migrations=schema.MIGRATIONS + (L3,))
    with contextlib.closing(database.connect(path)) as conn:
        for table, rows in snapshot.items():
            assert [tuple(r) for r in conn.execute(f"SELECT * FROM {table} ORDER BY 1")] == rows
        assert audit.verify_chain(conn) == []


def test_the_v1_ddl_is_unchanged_since_release():
    """Released migrations must never be edited; a change to v1 must be a new migration instead."""
    import hashlib

    digest = hashlib.sha256("\n".join(schema.MIGRATIONS[0].statements).encode()).hexdigest()
    assert len(schema.MIGRATIONS[0].statements) == 8 + 15 + 16  # tables + indexes + triggers
    assert digest == EXPECTED_V1_DIGEST


EXPECTED_V1_DIGEST = "92dd6ef2c12fff207e63561a30e493c0bc37cd5c8d817c52d2fa93931eaca8e2"


EXPECTED_V2_DIGEST = "5d2789d16262a8180285e1325362d54fbd9d06a16fdf54775e5512db2128149e"


def test_the_v2_ddl_is_unchanged_since_release():
    import hashlib

    digest = hashlib.sha256("\n".join(schema.MIGRATIONS[1].statements).encode()).hexdigest()
    assert digest == EXPECTED_V2_DIGEST


# --- the real v1 -> v2 upgrade ------------------------------------------------------------------------------------------
@pytest.fixture
def v1_path(tmp_path):
    return init_database(tmp_path / "v1.db", migrations=schema.MIGRATIONS[:1])


def _dump_tables(conn, tables):
    return {t: [tuple(r) for r in conn.execute(f"SELECT * FROM {t} ORDER BY 1")] for t in tables}


def test_a_v1_database_is_unusable_until_migrated_and_then_has_the_sandbox_table(v1_path):
    assert version_of(v1_path) == 1
    with pytest.raises(SchemaVersionError, match="migrate"):
        open_database(v1_path)
    result = migrate_database(v1_path)
    assert (result.from_version, result.to_version) == (1, 2) and result.backup_path.name == "v1.db.bak-v1"
    with contextlib.closing(open_database(v1_path)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM sandbox_runs").fetchone()[0] == 0
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        events = [r["event_type"] for r in conn.execute("SELECT event_type FROM audit_events ORDER BY seq")]
        assert events == ["db_initialized", "db_migrated"] and audit.verify_chain(conn) == []


def test_v1_to_v2_preserves_every_stored_row_and_the_hash_chain(tmp_path):
    from storage_fakes import write_docs

    from sentinelbox.storage import importer

    path = init_database(tmp_path / "v1.db", migrations=schema.MIGRATIONS[:1])
    report_doc, analysis_doc = write_docs(tmp_path)
    # a v1 database can only be written with the v1 vocabulary, so import through a v1-era connection
    with contextlib.closing(database.connect(path)) as conn:
        importer.import_report_and_analysis(conn, report_doc, analysis_doc)
        before = _dump_tables(conn, ("runs", "executions", "analyses", "findings", "finding_matches", "db_meta", "schema_migrations"))
        events_before = [tuple(r) for r in conn.execute("SELECT * FROM audit_events ORDER BY seq")]
    result = migrate_database(path)
    with contextlib.closing(database.connect(path)) as conn:
        after = _dump_tables(conn, before)
        assert after["schema_migrations"][:1] == before["schema_migrations"]  # version 1 row kept, version 2 appended
        assert {k: v for k, v in after.items() if k != "schema_migrations"} == {k: v for k, v in before.items() if k != "schema_migrations"}
        events_after = [tuple(r) for r in conn.execute("SELECT * FROM audit_events ORDER BY seq")]
        assert events_after[:len(events_before)] == events_before  # copied verbatim, same hashes
        assert events_after[-1][2] == "db_migrated" and audit.verify_chain(conn) == []
    with contextlib.closing(sqlite3.connect(result.backup_path)) as backup:  # the backup is the untouched v1 file
        assert backup.execute("PRAGMA user_version").fetchone()[0] == 1
        assert backup.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == len(events_before)
        assert "sandbox_runs" not in {r[0] for r in backup.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def test_v1_to_v2_keeps_the_append_only_triggers_and_indexes(v1_path):
    migrate_database(v1_path)
    with contextlib.closing(open_database(v1_path)) as conn:
        triggers = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")}
        assert triggers == {f"{t}_no_{a}" for t in schema.TABLES for a in ("update", "delete")}
        indexes = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_%'")}
        assert {"idx_audit_run", "idx_audit_type", "idx_sandbox_started_at", "idx_sandbox_outcome"} <= indexes
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("DELETE FROM audit_events")


def test_v1_to_v2_failure_rolls_back_to_the_untouched_v1_file(v1_path, monkeypatch):
    before = v1_path.read_bytes()

    def boom(*args, **kwargs):
        raise RuntimeError("audit write failed")

    monkeypatch.setattr(audit, "append_event", boom)
    with pytest.raises(RuntimeError):
        migrate_database(v1_path)
    assert v1_path.read_bytes() == before and [p.name for p in v1_path.parent.iterdir()] == ["v1.db"]


def test_v1_to_v2_refuses_when_the_backup_name_is_taken(v1_path):
    backup = v1_path.with_name("v1.db.bak-v1")
    backup.write_bytes(b"precious")
    before = v1_path.read_bytes()
    with pytest.raises(DatabaseExistsError):
        migrate_database(v1_path)
    assert backup.read_bytes() == b"precious" and v1_path.read_bytes() == before


def test_the_migrated_database_accepts_the_new_event_type_but_a_v1_database_does_not(v1_path):
    with contextlib.closing(database.connect(v1_path)) as conn, pytest.raises(sqlite3.IntegrityError):
        with database.transaction(conn):
            conn.execute("INSERT INTO audit_events (seq, occurred_at, event_type, detail_json, prev_hash, event_hash) "
                         "VALUES (99, 'x', 'sandbox_run_recorded', '{}', ?, ?)", ("0" * 64, "1" * 64))
    migrate_database(v1_path)
    with contextlib.closing(open_database(v1_path)) as conn, database.transaction(conn):
        audit.append_event(conn, "sandbox_run_recorded", detail={"sandbox_run_id": "x"})
