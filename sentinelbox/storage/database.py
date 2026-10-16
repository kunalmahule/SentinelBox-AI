"""Explicit database lifecycle: init, open (with version checks), migrate, transactions.

Nothing here creates a database implicitly. ``init_database`` refuses an existing file, ``open_database``
refuses a missing, foreign, outdated or newer-than-supported file, and ``migrate_database`` backs the file up
before changing it and never overwrites an existing backup.
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
import uuid
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .. import __version__
from . import audit
from .schema import APPLICATION_ID, DATA_POLICY, LATEST_VERSION, MIGRATIONS, TABLES, Migration

DEFAULT_DB_PATH = Path("data") / "sentinelbox-audit.db"
BUSY_TIMEOUT_SECONDS = 5.0


class StorageError(Exception):
    """Base class for errors that carry an actionable message."""


class DatabaseExistsError(StorageError):
    pass


class DatabaseNotFoundError(StorageError):
    pass


class NotASentinelDatabase(StorageError):
    pass


class SchemaVersionError(StorageError):
    def __init__(self, message: str, found: int, expected: int):
        super().__init__(message)
        self.found = found
        self.expected = expected


def connect(path: Path | str, *, readonly: bool = False) -> sqlite3.Connection:
    """Low-level connection with the project's settings. Callers own closing it."""
    path = Path(path)
    if readonly:
        conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, timeout=BUSY_TIMEOUT_SECONDS,
                               isolation_level=None)
    else:
        conn = sqlite3.connect(path, timeout=BUSY_TIMEOUT_SECONDS, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextlib.contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """One write transaction: all statements commit together or none do."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


def _identify(conn: sqlite3.Connection, path: Path) -> int:
    """Check this is a SentinelBox database and return its schema version."""
    try:
        application_id = conn.execute("PRAGMA application_id").fetchone()[0]
        version = conn.execute("PRAGMA user_version").fetchone()[0]
    except sqlite3.DatabaseError as exc:
        raise NotASentinelDatabase(f"{path} is not a SQLite database ({exc})") from exc
    if application_id != APPLICATION_ID:
        raise NotASentinelDatabase(
            f"{path} is not a SentinelBox audit database (application_id {application_id:#x}); refusing to use it"
        )
    return version


def _apply(conn: sqlite3.Connection, migration: Migration, now: datetime | None) -> None:
    for statement in migration.statements:
        conn.execute(statement)
    conn.execute(f"PRAGMA user_version = {int(migration.version)}")
    conn.execute("INSERT INTO schema_migrations (version, applied_at, description) VALUES (?, ?, ?)",
                 (migration.version, audit.utc_timestamp(now), migration.description))


def init_database(path: Path | str, *, now: datetime | None = None,
                  migrations: Sequence[Migration] = MIGRATIONS) -> Path:
    """Create a new database at ``path``. Refuses to touch anything that already exists.

    ``migrations`` exists so tests can create an older-schema database; normal use always applies all of them.
    """
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise DatabaseExistsError(f"{path} already exists; init never replaces or modifies an existing file")
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{uuid.uuid4().hex[:8]}.tmp")
    try:
        conn = connect(temp)
        try:
            conn.execute("PRAGMA journal_mode = DELETE")
            conn.execute(f"PRAGMA application_id = {APPLICATION_ID}")
            with transaction(conn):
                for migration in migrations:
                    _apply(conn, migration, now)
                conn.execute("INSERT INTO db_meta (key, value) VALUES ('data_policy', ?)", (DATA_POLICY,))
                conn.execute("INSERT INTO db_meta (key, value) VALUES ('created_by', ?)", (f"sentinelbox {__version__}",))
                audit.append_event(conn, "db_initialized", detail={"schema_version": migrations[-1].version,
                                                                    "tool_version": __version__}, now=now)
        finally:
            conn.close()
        try:
            os.link(temp, path)  # atomic and fails if the destination appeared meanwhile
        except FileExistsError:
            raise DatabaseExistsError(f"{path} appeared while it was being created; not replacing it") from None
        except OSError:  # file systems without hard links
            if path.exists():
                raise DatabaseExistsError(f"{path} appeared while it was being created; not replacing it") from None
            os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)
    return path


def open_database(path: Path | str, *, readonly: bool = False) -> sqlite3.Connection:
    """Open an existing, current-version SentinelBox database or raise an actionable error."""
    path = Path(path)
    if not path.is_file():
        raise DatabaseNotFoundError(f"{path} does not exist; create it first with: python -m sentinelbox.storage init --db {path}")
    conn = connect(path, readonly=readonly)
    try:
        version = _identify(conn, path)
        if version < LATEST_VERSION:
            raise SchemaVersionError(
                f"{path} uses schema version {version}, this tool needs {LATEST_VERSION}; "
                f"run: python -m sentinelbox.storage migrate --db {path}", version, LATEST_VERSION)
        if version > LATEST_VERSION:
            raise SchemaVersionError(
                f"{path} uses schema version {version}, newer than this tool supports ({LATEST_VERSION}); "
                "upgrade SentinelBox instead of opening it", version, LATEST_VERSION)
    except BaseException:
        conn.close()
        raise
    return conn


@dataclass(frozen=True)
class MigrationResult:
    from_version: int
    to_version: int
    backup_path: Path | None


def migrate_database(path: Path | str, *, now: datetime | None = None,
                     migrations: Sequence[Migration] = MIGRATIONS) -> MigrationResult:
    """Bring an older database up to date. Backs it up first; all steps run in one transaction."""
    path = Path(path)
    if not path.is_file():
        raise DatabaseNotFoundError(f"{path} does not exist")
    latest = migrations[-1].version
    conn = connect(path)
    try:
        version = _identify(conn, path)
        if version > latest:
            raise SchemaVersionError(f"{path} uses schema version {version}, newer than this tool supports ({latest})",
                                     version, latest)
        if version == latest:
            return MigrationResult(version, version, None)
        pending = [m for m in migrations if m.version > version]
        if [m.version for m in pending] != list(range(version + 1, latest + 1)):
            raise StorageError(f"migration list is not contiguous from version {version + 1} to {latest}")
        backup = path.with_name(f"{path.name}.bak-v{version}")
        if backup.exists():
            raise DatabaseExistsError(f"backup {backup} already exists; move it away before migrating")
        target = sqlite3.connect(backup)
        try:
            conn.backup(target)
        finally:
            target.close()
        try:
            with transaction(conn):
                for migration in pending:
                    _apply(conn, migration, now)
                audit.append_event(conn, "db_migrated", detail={"from_version": version, "to_version": latest}, now=now)
                problems = conn.execute("PRAGMA foreign_key_check").fetchall()
                if problems:
                    raise StorageError(f"migration left {len(problems)} foreign key violations; rolled back")
        except BaseException:
            backup.unlink(missing_ok=True)  # the database is unchanged, so the backup we just made is redundant
            raise
        return MigrationResult(version, latest, backup)
    finally:
        conn.close()


def table_counts(conn: sqlite3.Connection) -> dict[str, int]:
    return {table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in TABLES}  # fixed table names
