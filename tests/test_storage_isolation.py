"""Static guards: the storage layer is separate from the runner and rule engine, SQL is parameterized,
the source JSON files are never written, and nothing here can delete stored data."""

import ast
import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1] / "sentinelbox"
STORAGE_FILES = sorted((ROOT / "storage").glob("*.py"))
SOURCES = {p.name: p.read_text(encoding="utf-8") for p in STORAGE_FILES}
NETWORK_AND_PROCESS = {"urllib", "socket", "http", "ssl", "requests", "httpx", "httpx2", "aiohttp", "urllib3",
                       "subprocess", "multiprocessing", "ftplib", "smtplib"}
AI_CLIENTS = {"openai", "anthropic", "cohere", "mistralai", "groq", "ollama", "litellm", "google"}


def imports_of(source):
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found += [(0, a.name) for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                found.append((node.level, node.module))
            else:
                found += [(node.level, a.name) for a in node.names]
    return found


def touches(level, module, package):
    parts = module.split(".")
    return package in parts or (level > 0 and parts[0] == package)


# Interpolations allowed inside SQL f-strings: fixed identifiers/fragments, never user-supplied values.
ALLOWED_SQL_INTERPOLATIONS = {
    "_in(RUN_STATUSES)", "_in(CATEGORIES)", "_in(TARGET_MODES)", "_in(OUTCOMES)", "_in(EXPECTED_BEHAVIORS)",
    "_in(EXPECTED_DETECTIONS)", "_in(VERDICTS)", "_in(CORRECTNESS)", "_in(SEVERITIES)", "_in(CONFIDENCES)",
    "_in(EFFECTS)", "_in(EVENT_TYPES)", "_SYNTHETIC", "ANALYSIS_SCOPE",
    "int(migration.version)", "APPLICATION_ID",                                   # database._apply (PRAGMA cannot be parameterized)
    "table", "action", "action.lower()",                          # schema trigger generation, fixed tuples
    "column",                                                     # queries.list_findings: column from a fixed tuple
    "where",                                                      # queries.list_findings: built from fixed clauses
    "', '.join(('?' for _ in verdicts))", "', '.join(('?' for _ in allowed))", "', '.join(('?' for _ in ids))",
    "'?'",                                                        # placeholder lists
}


def sql_calls(source):
    for node in ast.walk(ast.parse(source)):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"execute", "executemany", "executescript"}):
            yield node


def test_the_storage_package_exists():
    assert {"schema.py", "database.py", "documents.py", "importer.py", "queries.py", "audit.py", "verify.py", "cli.py"} <= set(SOURCES)


@pytest.mark.parametrize("name", sorted(SOURCES))
def test_storage_imports_nothing_from_the_mock_the_runner_or_the_rule_engine(name):
    bad = [i for i in imports_of(SOURCES[name]) if any(touches(*i, pkg) for pkg in ("mock_ai", "runner", "rule_engine"))]
    assert bad == []


def test_nothing_else_imports_the_storage_package():
    for package in ("runner", "mock_ai", "rule_engine"):
        for path in (ROOT / package).glob("*.py"):
            assert not [i for i in imports_of(path.read_text(encoding="utf-8")) if touches(*i, "storage")], path.name


@pytest.mark.parametrize("name", sorted(SOURCES))
def test_storage_uses_no_network_process_or_ai_client_modules(name):
    modules = {m for _, m in imports_of(SOURCES[name])} - {"urllib.parse"}  # a pure URL parser, no I/O
    used = {m.split(".")[0] for m in modules}
    assert not used & (NETWORK_AND_PROCESS | AI_CLIENTS)


def test_storage_uses_only_the_standard_library_and_itself():
    allowed = set(sys.stdlib_module_names) | {"sentinelbox"}
    for name, source in SOURCES.items():
        for level, module in imports_of(source):
            if level == 0:
                assert module.split(".")[0] in allowed, f"{name} imports {module}"


def test_the_scanners_really_detect_violations():
    assert any(touches(*i, "runner") for i in imports_of("from ..runner.report import validate_report"))
    assert any(touches(*i, "rule_engine") for i in imports_of("from .. import rule_engine"))
    calls = list(sql_calls("conn.execute('a'); cur.executemany(q, rows); c.executescript(s)"))
    assert len(calls) == 3


@pytest.mark.parametrize("name", sorted(SOURCES))
def test_sql_text_is_a_literal_or_an_f_string_of_allowed_fixed_fragments(name):
    for call in sql_calls(SOURCES[name]):
        query = call.args[0]
        where = f"{name}:{call.lineno}"
        if isinstance(query, ast.Constant) and isinstance(query.value, str):
            continue
        if isinstance(query, ast.JoinedStr):
            for part in query.values:
                if isinstance(part, ast.FormattedValue):
                    assert ast.unparse(part.value) in ALLOWED_SQL_INTERPOLATIONS, f"{where}: {ast.unparse(part.value)}"
            continue
        if isinstance(query, ast.BinOp) or (isinstance(query, ast.Call) and isinstance(query.func, ast.Attribute) and query.func.attr == "format"):
            pytest.fail(f"{where}: SQL built by concatenation, % or .format")
        # a plain variable (for example a statement taken from the migration tuple) must be a loop over fixed DDL
        assert isinstance(query, ast.Name) and query.id == "statement", f"{where}: unexpected SQL expression {ast.unparse(query)}"


@pytest.mark.parametrize("name", sorted(SOURCES))
def test_no_executescript_and_no_string_formatting_of_sql_values(name):
    source = SOURCES[name]
    assert "executescript" not in source
    for call in sql_calls(source):
        text = ast.unparse(call)
        assert ".format(" not in text and "% (" not in text and "%s" not in text, text


V2_REBUILD_STATEMENTS = {"DROP TRIGGER audit_events_no_update", "DROP TRIGGER audit_events_no_delete",
                          "DROP TABLE audit_events_v1"}


@pytest.mark.parametrize("name", sorted(SOURCES))
def test_no_code_path_deletes_updates_or_drops_stored_data(name):
    """Only the schema may mention UPDATE/DELETE, and only inside the append-only trigger text."""
    tree = ast.parse(SOURCES[name])
    strings = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    for text in strings:
        if name == "schema.py" and text in V2_REBUILD_STATEMENTS:
            continue  # the one migration that rebuilds audit_events (rows copied verbatim, then re-protected)
        assert not re.search(r"\bDELETE\s+FROM\b|\bDROP\s+(TABLE|TRIGGER|INDEX)\b|\bUPDATE\s+\w+\s+SET\b|\bTRUNCATE\b|\bREPLACE\s+INTO\b|\bINSERT\s+OR\s+(REPLACE|IGNORE)\b",
                             text, re.I), text


def test_the_only_data_modifying_sql_is_insert():
    for name, source in SOURCES.items():
        for call in sql_calls(source):
            query = call.args[0]
            if isinstance(query, ast.Constant) and isinstance(query.value, str):
                head = query.value.lstrip().split(None, 1)[0].upper()
                assert head in {"SELECT", "INSERT", "PRAGMA", "BEGIN", "COMMIT", "ROLLBACK", "EXPLAIN"}, f"{name}: {head}"


FILE_WRITERS = {"write_text", "write_bytes", "unlink", "rename", "replace", "remove", "rmdir", "rmtree", "chmod", "touch", "link", "symlink", "mkdir"}


@pytest.mark.parametrize("name", sorted(SOURCES))
def test_only_the_database_module_creates_or_removes_files(name):
    """documents.py reads the JSON artifacts; nothing but database.py (the .db and its backup) may write files."""
    tree = ast.parse(SOURCES[name])
    used = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in FILE_WRITERS:
            used.add(node.func.attr)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
            used.add("open")
    if name == "database.py":
        assert used <= {"unlink", "replace", "link", "mkdir"}
    else:
        assert used == set(), used


@pytest.mark.parametrize("name", sorted(SOURCES))
def test_files_are_only_opened_for_reading(name):
    for node in ast.walk(ast.parse(SOURCES[name])):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "open":
            modes = [a.value for a in node.args if isinstance(a, ast.Constant) and isinstance(a.value, str)]
            assert modes == ["rb"], f"{name}:{node.lineno} opens a file with {modes}"


def test_documents_never_touch_sqlite_and_the_database_modules_never_read_json_files():
    assert not [i for i in imports_of(SOURCES["documents.py"]) if "sqlite3" in i[1]]
    for name in ("schema.py", "database.py", "importer.py", "queries.py", "audit.py"):
        assert "read_bytes" not in SOURCES[name] and ".read_text" not in SOURCES[name], name


def test_generated_databases_and_backups_are_ignored_by_git():
    ignore = (ROOT.parent / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "reports/" in ignore and any(line.startswith("data") for line in ignore) and "*.db" in ignore
