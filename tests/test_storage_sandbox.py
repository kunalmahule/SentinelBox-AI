"""Storage of sandbox records: validation, import, linking, audit coverage, queries, CLI."""

import contextlib
import copy
import json
import sqlite3

import pytest
from storage_fakes import make_report, make_sandbox_record, write_docs, write_json, write_sandbox_doc

from sentinelbox.storage import audit, cli, database, importer, queries, schema
from sentinelbox.storage.database import init_database, open_database
from sentinelbox.storage.documents import DocumentError, read_document, validate_sandbox_record_document
from sentinelbox.storage.importer import ImportConflictError
from sentinelbox.storage.verify import verify_database


@pytest.fixture
def docs(tmp_path):
    return write_docs(tmp_path)


@pytest.fixture
def conn(tmp_path):
    path = init_database(tmp_path / "audit.db")
    with contextlib.closing(open_database(path)) as c:
        yield c


def record_for(docs, **kw):
    return make_sandbox_record(docs[0], docs[1], **kw)


def edit(record, fn):
    clone = copy.deepcopy(record)
    fn(clone)
    return clone


# --- validation ------------------------------------------------------------------------------------------------------
def test_a_consistent_record_has_no_problems(docs):
    assert validate_sandbox_record_document(record_for(docs)) == []
    for outcome in ("refused", "docker_error", "interrupted"):
        assert validate_sandbox_record_document(make_sandbox_record(outcome=outcome, kind="self_check")) == [], outcome


BAD = {
    "wrong schema": lambda r: r.update(schema_version=2),
    "bad id": lambda r: r.update(sandbox_run_id="has space"),
    "bad kind": lambda r: r.update(kind="shell"),
    "bad classification": lambda r: r.update(data_classification="real"),
    "extra field": lambda r: r.update(extra=1),
    "missing field": lambda r: r.pop("note"),
    "outcome vocabulary": lambda r: r["result"].update(outcome="great"),
    "completed with exit 1": lambda r: r["result"].update(exit_code=1),
    "completed but timed out": lambda r: r["result"].update(timed_out=True),
    "timeout flag missing": lambda r: r["result"].update(outcome="timeout", exit_code=None),
    "output_limit without truncation": lambda r: r["result"].update(outcome="output_limit"),
    "ran with unverified controls": lambda r: r["controls"].update(verified=False),
    "verified with a failed control": lambda r: r["controls"]["results"][0].update(ok=False),
    "verified with no results": lambda r: r["controls"].update(results=[]),
    "refused but verified": lambda r: r["result"].update(outcome="refused"),
    "negative duration": lambda r: r["timing"].update(duration_ms=-1),
    "bad timestamp": lambda r: r["timing"].update(started_at="yesterday"),
    "bad cleanup status": lambda r: r["cleanup"].update(status="maybe"),
    "path in file name": lambda r: r["references"].update(report_file_name="../x.json"),
    "report ref incomplete": lambda r: r["references"].update(report_sha256=None),
    "bad sha": lambda r: r["references"].update(analysis_sha256="ABC"),
    "analysis without run": lambda r: r["references"].update(run_id=None, report_sha256=None, report_file_name=None),
    "suite without references": lambda r: r["references"].update(analysis_id=None, analysis_sha256=None, analysis_file_name=None),
    "environment dump": lambda r: r["effective"].update(env={"PATH": "/usr/bin"}),
    "nested environment dump": lambda r: r["policy"]["requested"].update(inner=[{"environment": {}}]),
    "image fields": lambda r: r["image"].update(extra="x"),
}


@pytest.mark.parametrize("name", sorted(BAD))
def test_inconsistent_records_are_rejected(docs, name):
    assert validate_sandbox_record_document(edit(record_for(docs), BAD[name])), name


def test_non_objects_and_oversized_blobs_are_rejected(docs):
    assert validate_sandbox_record_document([]) and validate_sandbox_record_document("x")
    big = edit(record_for(docs), lambda r: r["effective"].update(blob="x" * 70000))
    assert any("larger than" in p for p in validate_sandbox_record_document(big))


def test_credential_looking_text_and_host_paths_are_refused_at_import(conn, tmp_path, docs):
    secret = edit(record_for(docs), lambda r: r.update(note="key AKIAABCDEFGHIJKLMNOP leaked"))
    with pytest.raises(DocumentError):
        importer.import_sandbox_record(conn, write_sandbox_doc(tmp_path, secret), report=docs[0], analysis=docs[1])
    path = edit(record_for(docs), lambda r: r["cleanup"].update(detail="removed /Users/someone/project/x"))
    with pytest.raises(DocumentError, match="sandbox record"):
        importer.import_sandbox_record(conn, write_sandbox_doc(tmp_path, path, "p.json"), report=docs[0], analysis=docs[1])
    assert database.table_counts(conn)["sandbox_runs"] == 0 and database.table_counts(conn)["runs"] == 0


def test_the_synthetic_canary_text_in_a_record_is_not_a_credential(conn, tmp_path, docs):
    fake = edit(record_for(docs), lambda r: r.update(note="synthetic SBX-FAKE-KEY-0000-NOT-REAL and SBX-CANARY-4f7a91c2 only"))
    importer.import_sandbox_record(conn, write_sandbox_doc(tmp_path, fake), report=docs[0], analysis=docs[1])


# --- import -------------------------------------------------------------------------------------------------------------
def test_import_stores_row_event_run_and_analysis_in_one_transaction(conn, tmp_path, docs):
    result = importer.import_sandbox_record(conn, write_sandbox_doc(tmp_path, record_for(docs)), report=docs[0], analysis=docs[1])
    assert result.status == importer.IMPORTED and result.run.status == importer.IMPORTED and result.analysis.status == importer.IMPORTED
    counts = database.table_counts(conn)
    assert (counts["runs"], counts["analyses"], counts["sandbox_runs"], counts["audit_events"]) == (1, 1, 1, 4)
    events = [r["event_type"] for r in conn.execute("SELECT event_type FROM audit_events ORDER BY seq")]
    assert events == ["db_initialized", "run_imported", "analysis_imported", "sandbox_run_recorded"]
    row = queries.get_sandbox_run(conn, "sbx-run-0001")
    assert row["outcome"] == "completed" and row["controls_verified"] is True and row["data_classification"] == "synthetic_test_data"
    assert row["controls"]["results"][0]["name"] == "network_mode" and row["requested"]["memory"] == "256m"
    assert audit.verify_chain(conn) == [] and verify_database(conn).ok


def test_import_is_idempotent_and_conflicts_are_rejected(conn, tmp_path, docs):
    doc = write_sandbox_doc(tmp_path, record_for(docs))
    importer.import_sandbox_record(conn, doc, report=docs[0], analysis=docs[1])
    again = importer.import_sandbox_record(conn, doc)
    assert again.status == importer.ALREADY_IMPORTED
    assert database.table_counts(conn)["audit_events"] == 4
    changed = write_sandbox_doc(tmp_path, edit(record_for(docs), lambda r: r.update(note="different")), "other.json")
    with pytest.raises(ImportConflictError, match="never replaced"):
        importer.import_sandbox_record(conn, changed)
    renamed = write_sandbox_doc(tmp_path, record_for(docs), "renamed.json")  # same content, same id: identical hash
    assert importer.import_sandbox_record(conn, renamed).status == importer.ALREADY_IMPORTED


def test_a_missing_or_mismatching_reference_is_rejected_and_rolls_back(conn, tmp_path, docs):
    doc = write_sandbox_doc(tmp_path, record_for(docs))
    with pytest.raises(ImportConflictError, match="not stored"):
        importer.import_sandbox_record(conn, doc)
    assert database.table_counts(conn)["sandbox_runs"] == 0
    sub = tmp_path / "other"
    sub.mkdir()
    other_report = write_docs(sub, report=make_report(run_id="run9999zzzz"))[0]
    with pytest.raises(DocumentError, match="does not match the supplied"):
        importer.import_sandbox_record(conn, doc, report=other_report, analysis=docs[1])
    assert database.table_counts(conn)["runs"] == 0


def test_supplying_a_document_the_record_does_not_reference_is_rejected(conn, tmp_path, docs):
    doc = write_sandbox_doc(tmp_path, make_sandbox_record(kind="self_check"))
    with pytest.raises(DocumentError, match="does not reference"):
        importer.import_sandbox_record(conn, doc, report=docs[0])
    assert database.table_counts(conn)["runs"] == 0


def test_a_failure_after_the_row_is_inserted_rolls_everything_back(conn, tmp_path, docs, monkeypatch):
    real = audit.append_event

    def fail_on_sandbox(c, event_type, **kw):
        if event_type == "sandbox_run_recorded":
            raise RuntimeError("disk full")
        return real(c, event_type, **kw)

    monkeypatch.setattr(audit, "append_event", fail_on_sandbox)
    with pytest.raises(RuntimeError):
        importer.import_sandbox_record(conn, write_sandbox_doc(tmp_path, record_for(docs)), report=docs[0], analysis=docs[1])
    counts = database.table_counts(conn)
    assert (counts["runs"], counts["analyses"], counts["sandbox_runs"], counts["audit_events"]) == (0, 0, 0, 1)


def test_non_completed_records_without_references_store_fine(conn, tmp_path):
    for i, outcome in enumerate(("refused", "docker_error", "interrupted")):
        rec = make_sandbox_record(sandbox_run_id=f"sbx-x-{i}", outcome=outcome, kind="self_check")
        assert importer.import_sandbox_record(conn, write_sandbox_doc(tmp_path, rec, f"r{i}.json")).status == importer.IMPORTED
    assert [r["outcome"] for r in queries.list_sandbox_runs(conn)] and len(queries.list_sandbox_runs(conn)) == 3


def test_database_rejects_inconsistent_rows_even_if_the_importer_is_bypassed(conn):
    cols = ("sandbox_run_id, record_sha256, record_file_name, record_schema_version, tool_name, tool_version, policy_version, "
            "kind, outcome, controls_verified, controls_json, requested_json, started_at, finished_at, duration_ms, "
            "exit_code, timed_out, stdout_truncated, stderr_truncated, cases_requested, cases_returned, cleanup_status, "
            "note, imported_at")
    base = ["s1", "a" * 64, "f.json", 1, "t", "1", "p", "self_check", "completed", 1, "{}", "{}", "x", "y", 1.0,
            0, 0, 0, 0, 0, 0, "removed", "n", "z"]
    marks = ", ".join("?" for _ in base)
    # completed with unverified controls; completed with exit code 1; unknown outcome; unknown kind
    for index, bad in ((9, 0), (15, 1), (8, "bogus"), (7, "shell")):
        row = list(base)
        row[index] = bad
        with pytest.raises(sqlite3.IntegrityError), database.transaction(conn):
            conn.execute(f"INSERT INTO sandbox_runs ({cols}) VALUES ({marks})", row)
    with database.transaction(conn):
        conn.execute(f"INSERT INTO sandbox_runs ({cols}) VALUES ({marks})", base)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute("DELETE FROM sandbox_runs")


# --- verify ---------------------------------------------------------------------------------------------------------------
def test_verify_detects_a_sandbox_row_without_its_event(tmp_path, docs):
    path = init_database(tmp_path / "v.db")
    with contextlib.closing(open_database(path)) as c:
        importer.import_sandbox_record(c, write_sandbox_doc(tmp_path, record_for(docs)), report=docs[0], analysis=docs[1])
    with contextlib.closing(sqlite3.connect(path)) as raw:  # an attacker with file access drops the protection and the event
        raw.execute("DROP TRIGGER audit_events_no_delete")
        raw.execute("DELETE FROM audit_events WHERE event_type = 'sandbox_run_recorded'")
        raw.commit()
    with contextlib.closing(open_database(path)) as c:
        problems = verify_database(c).problems
    assert any("no sandbox_run_recorded audit event" in p for p in problems) or any("trigger" in p for p in problems)
    assert any("no sandbox_run_recorded audit event" in p for p in problems)


def test_verify_checks_the_record_file_hash(tmp_path, docs):
    path = init_database(tmp_path / "v.db")
    doc = write_sandbox_doc(tmp_path, record_for(docs))
    with contextlib.closing(open_database(path)) as c:
        importer.import_sandbox_record(c, doc, report=docs[0], analysis=docs[1])
        assert verify_database(c, artifacts_dir=tmp_path).ok
        (tmp_path / "sandbox.json").write_text(json.dumps({"tampered": True}))
        assert any("sandbox record file" in p for p in verify_database(c, artifacts_dir=tmp_path).problems)


# --- queries and CLI ----------------------------------------------------------------------------------------------------------
def test_query_resolution_and_filters(conn, tmp_path, docs):
    importer.import_sandbox_record(conn, write_sandbox_doc(tmp_path, record_for(docs)), report=docs[0], analysis=docs[1])
    importer.import_sandbox_record(conn, write_sandbox_doc(tmp_path, make_sandbox_record(sandbox_run_id="sbx-run-0002", outcome="refused", kind="self_check"), "b.json"))
    assert queries.resolve_sandbox_run_id(conn, "sbx-run-0001") == "sbx-run-0001"
    with pytest.raises(queries.QueryError, match="several"):
        queries.resolve_sandbox_run_id(conn, "sbx-")
    with pytest.raises(queries.QueryError, match="no stored"):
        queries.resolve_sandbox_run_id(conn, "zzzz")
    with pytest.raises(queries.QueryError, match="at least"):
        queries.resolve_sandbox_run_id(conn, "sb")
    assert [r["outcome"] for r in queries.list_sandbox_runs(conn, outcome="refused")] == ["refused"]
    with pytest.raises(queries.QueryError):
        queries.list_sandbox_runs(conn, outcome="nope")
    with pytest.raises(queries.QueryError):
        queries.get_sandbox_run(conn, "missing")


def test_cli_import_list_show_and_verify(tmp_path, docs, capsys):
    db = tmp_path / "cli.db"
    rec = write_json(tmp_path / "sandbox.json", record_for(docs))
    assert cli.main(["init", "--db", str(db)]) == 0
    capsys.readouterr()
    args = ["import-sandbox", "--db", str(db), "--record", str(rec)]
    assert cli.main(args) == cli.EXIT_ERROR
    assert "not stored" in capsys.readouterr().err
    assert cli.main([*args, "--report", str(tmp_path / "run.json"), "--analysis", str(tmp_path / "run.analysis.json")]) == 0
    assert "Sandbox run sbx-run-0001: stored" in capsys.readouterr().out
    assert cli.main(args) == 0 and "already stored" in capsys.readouterr().out
    assert cli.main(["sandbox-runs", "--db", str(db)]) == 0 and "sbx-run-0001" in capsys.readouterr().out
    assert cli.main(["sandbox-runs", "--db", str(db), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["controls_verified"] is True
    assert cli.main(["show-sandbox", "--db", str(db), "sbx-r"]) == 0
    out = capsys.readouterr().out
    assert "Controls verified before execution: yes" in out and "[ok] network_mode" in out and "synthetic" in out
    assert cli.main(["show-sandbox", "--db", str(db), "sbx-run-0001", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["kind"] == "adversarial_suite"
    assert cli.main(["verify", "--db", str(db), "--reports-dir", str(tmp_path)]) == 0
    assert cli.main(["show-sandbox", "--db", str(db), "nope1"]) == cli.EXIT_ERROR
    assert cli.main(["info", "--db", str(db)]) == 0 and "sandbox_runs=1" in capsys.readouterr().out


def test_cli_reports_a_malformed_record_with_the_file_name(tmp_path, docs, capsys):
    db = tmp_path / "cli.db"
    cli.main(["init", "--db", str(db)])
    bad = write_json(tmp_path / "bad_sandbox.json", edit(record_for(docs), lambda r: r["result"].update(exit_code=1)))
    capsys.readouterr()
    assert cli.main(["import-sandbox", "--db", str(db), "--record", str(bad)]) == cli.EXIT_ERROR
    err = capsys.readouterr().err
    assert "bad_sandbox.json" in err and "exit code 0" in err
    assert read_document(bad, "sandbox record").file_name == "bad_sandbox.json"
