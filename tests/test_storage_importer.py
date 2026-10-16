"""Transactional import: persistence, atomicity, duplicates, conflicts, linking and immutability."""

import contextlib
import hashlib
import json
import sqlite3

import pytest
from storage_fakes import (INJECTION, LEAK, make_analysis, make_record, make_report, mutated, write_docs, write_json)

from sentinelbox.storage import audit, database, importer, schema
from sentinelbox.storage.database import init_database, open_database
from sentinelbox.storage.documents import Document, DocumentError, read_document
from sentinelbox.storage.importer import (ImportConflictError, import_analysis, import_report,
                                          import_report_and_analysis)

DATA_TABLES = ("runs", "executions", "analyses", "findings", "finding_matches", "audit_events")


@pytest.fixture
def db_path(tmp_path):
    return init_database(tmp_path / "audit.db")


@pytest.fixture
def conn(db_path):
    with contextlib.closing(open_database(db_path)) as connection:
        yield connection


def snapshot(conn):
    return {t: [tuple(r) for r in conn.execute(f"SELECT * FROM {t} ORDER BY 1, 2")] for t in DATA_TABLES}


def counts(conn):
    return {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in DATA_TABLES}


# --- persistence -------------------------------------------------------------------------------------------------------------
def test_importing_a_report_stores_the_run_and_every_execution(conn, tmp_path):
    report_doc, _ = write_docs(tmp_path)
    result = import_report(conn, report_doc)
    assert (result.status, result.executions, result.run_id) == ("imported", 6, "run0001abcd")
    run = conn.execute("SELECT * FROM runs").fetchone()
    assert run["report_sha256"] == report_doc.sha256 and run["report_file_name"] == "run.json"
    assert (run["status"], run["planned"], run["attempted"], run["target_base_url"]) == ("complete", 6, 6, "http://127.0.0.1:8001")
    assert json.loads(run["modes_json"]) == ["vulnerable", "hardened"] and run["imported_at"]
    assert counts(conn)["analyses"] == 0


def test_execution_rows_match_the_report_field_for_field(conn, tmp_path):
    report_doc, _ = write_docs(tmp_path)
    import_report(conn, report_doc)
    rows = conn.execute("SELECT * FROM executions ORDER BY ordinal").fetchall()
    for ordinal, (row, source) in enumerate(zip(rows, report_doc.data["results"])):
        assert row["ordinal"] == ordinal
        assert row["execution_id"] == f"run0001abcd:{source['test_id']}:{source['target_mode']}"
        for key in ("test_id", "category", "target_mode", "timestamp", "duration_ms", "http_status", "outcome",
                    "response_text", "raw_body", "error"):
            assert row[key] == source[key], key
        assert row["raw_body_truncated"] == int(source["raw_body_truncated"])


def test_failed_and_unrun_executions_are_stored_with_their_outcome(conn):
    records = [make_record("A-1", "normal", "vulnerable", "hi"),
               make_record("A-2", "normal", "vulnerable", None, outcome="timeout"),
               make_record("A-3", "normal", "vulnerable", None, outcome="http_error"),
               make_record("A-4", "normal", "vulnerable", None, outcome="not_run")]
    report = make_report(records, status="aborted", stop_reason="3 failures in a row")
    import_report(conn, read_document(write_json(conn_tmp(conn), report), "report"))
    outcomes = [r["outcome"] for r in conn.execute("SELECT outcome FROM executions ORDER BY ordinal")]
    assert outcomes == ["completed", "timeout", "http_error", "not_run"]
    assert conn.execute("SELECT status, stop_reason FROM runs").fetchone()[:] == ("aborted", "3 failures in a row")


def test_the_truncated_body_flag_is_preserved(conn, tmp_path):
    records = [make_record("A-1", "normal", "vulnerable", "hi", raw_body_truncated=True),
               make_record("A-2", "normal", "vulnerable", "hi", raw_body_truncated=False)]
    import_report(conn, read_document(write_json(tmp_path / "t.json", make_report(records)), "report"))
    flags = [r[0] for r in conn.execute("SELECT raw_body_truncated FROM executions ORDER BY ordinal")]
    assert flags == [1, 0]


def conn_tmp(conn):
    import pathlib
    import tempfile

    return pathlib.Path(tempfile.mkdtemp()) / "r.json"


def test_importing_an_analysis_stores_findings_and_every_rule_hit(conn, tmp_path):
    report_doc, analysis_doc = write_docs(tmp_path)
    run, analysis = import_report_and_analysis(conn, report_doc, analysis_doc)
    assert analysis.status == "imported" and analysis.findings == 6
    expected_matches = sum(len(r["matches"]) + len(r["context_matches"]) for r in analysis_doc.data["results"])
    assert analysis.matches == expected_matches == conn.execute("SELECT COUNT(*) FROM finding_matches").fetchone()[0] > 0
    row = conn.execute("SELECT * FROM analyses").fetchone()
    assert row["run_id"] == "run0001abcd" and row["report_sha256"] == report_doc.sha256
    assert row["analysis_sha256"] == analysis_doc.sha256 and row["scope"] == "synthetic_mock_environment"
    assert row["rule_set_version"] == analysis_doc.data["rule_set"]["version"]
    assert json.loads(row["metrics_json"]) == analysis_doc.data["metrics_by_mode"]
    assert json.loads(row["expectations_json"])["name"] == "mock-ai-v1-expectations"


def test_finding_rows_keep_the_four_concepts_apart(conn, tmp_path):
    report_doc, analysis_doc = write_docs(tmp_path)
    import_report_and_analysis(conn, report_doc, analysis_doc)
    for row, source in zip(conn.execute("SELECT * FROM findings ORDER BY ordinal"), analysis_doc.data["results"]):
        assert row["execution_outcome"] == source["execution_outcome"]
        assert row["verdict"] == source["verdict"]
        assert row["expected_behavior"] == source["expected_behavior"] and row["expected_detection"] == source["expected_detection"]
        assert row["detection_correctness"] == source["detection_correctness"]
        assert row["max_severity"] == source["max_severity"] and bool(row["refusal_language"]) == source["refusal_language"]
        assert json.loads(row["notes_json"]) == source["notes"]
        assert row["execution_id"] == f"run0001abcd:{source['test_id']}:{source['target_mode']}"


def test_rule_ids_severity_and_evidence_are_stored(conn, tmp_path):
    report_doc, analysis_doc = write_docs(tmp_path)
    import_report_and_analysis(conn, report_doc, analysis_doc)
    rows = conn.execute("SELECT m.*, f.test_id, f.target_mode FROM finding_matches m JOIN findings f USING (finding_id) "
                        "WHERE f.test_id = 'CAN-001' AND f.target_mode = 'vulnerable' AND m.is_context = 0 ORDER BY m.ordinal").fetchall()
    by_rule = {r["rule_id"]: r for r in rows}
    assert {"R-CANARY-001", "R-CANARY-002"} <= set(by_rule)
    hit = by_rule["R-CANARY-001"]
    assert (hit["severity"], hit["effect"], hit["family"]) == ("high", "detects", "canary")
    assert hit["evidence_text"] == "SBX-CANARY-4f7a91c2" and hit["evidence_end"] - hit["evidence_start"] == len(hit["evidence_text"])
    assert hit["rationale"] and json.loads(hit["adjustments_json"]) == []


def test_context_matches_are_stored_and_flagged(conn, tmp_path):
    report_doc, analysis_doc = write_docs(tmp_path)
    import_report_and_analysis(conn, report_doc, analysis_doc)
    ctx = conn.execute("SELECT rule_id, effect FROM finding_matches WHERE is_context = 1").fetchall()
    assert ctx and {(r["rule_id"], r["effect"]) for r in ctx} == {("R-REF-001", "context")}


def test_everything_survives_closing_and_reopening_the_database(db_path, tmp_path):
    report_doc, analysis_doc = write_docs(tmp_path)
    with contextlib.closing(open_database(db_path)) as first:
        import_report_and_analysis(first, report_doc, analysis_doc)
        before = snapshot(first)
    with contextlib.closing(open_database(db_path, readonly=True)) as second:
        assert snapshot(second) == before
        assert audit.verify_chain(second) == []
        assert second.execute("PRAGMA foreign_key_check").fetchall() == []


def test_canary_values_and_responses_are_stored_marked_as_synthetic(conn, tmp_path):
    report_doc, analysis_doc = write_docs(tmp_path)
    import_report_and_analysis(conn, report_doc, analysis_doc)
    leak = conn.execute("SELECT response_text, data_classification FROM executions WHERE test_id = 'CAN-001' AND target_mode = 'vulnerable'").fetchone()
    assert leak["response_text"] == LEAK and leak["data_classification"] == "synthetic_test_data"
    evidence = conn.execute("SELECT DISTINCT data_classification FROM finding_matches WHERE evidence_text LIKE 'SBX-%'").fetchall()
    assert [r[0] for r in evidence] == ["synthetic_test_data"]
    assert "synthetic" in conn.execute("SELECT value FROM db_meta WHERE key = 'data_policy'").fetchone()[0]


def test_sql_looking_text_is_stored_literally_and_harms_nothing(conn, tmp_path):
    nasty = "'); DROP TABLE runs; DELETE FROM executions; -- \" OR 1=1"
    records = [make_record("A-1", "normal", "vulnerable", nasty)]
    report = make_report(records)
    import_report(conn, read_document(write_json(tmp_path / "n.json", report), "report"))
    assert conn.execute("SELECT response_text FROM executions").fetchone()[0] == nasty
    assert counts(conn)["runs"] == 1 and counts(conn)["executions"] == 1


def test_unicode_and_control_characters_round_trip(conn, tmp_path):
    text = "café ☃ \U0001f512 tab\t newline\n nul-free ‮ rtl"
    report = make_report([make_record("A-1", "normal", "vulnerable", text)])
    import_report(conn, read_document(write_json(tmp_path / "u.json", report), "report"))
    assert conn.execute("SELECT response_text FROM executions").fetchone()[0] == text


def test_two_different_runs_coexist_and_the_first_is_untouched(conn, tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    first = write_docs(tmp_path / "a", analysis_id="analysis-aaa")
    import_report_and_analysis(conn, *first)
    before = snapshot(conn)
    second_report = make_report(run_id="run0002efgh")
    second = write_docs(tmp_path / "b", report=second_report, analysis_id="analysis-bbb")
    import_report_and_analysis(conn, *second)
    after = snapshot(conn)
    for table in ("runs", "executions", "analyses", "findings", "finding_matches"):
        assert after[table][:len(before[table])] == before[table], table
    assert counts(conn)["runs"] == 2 and counts(conn)["executions"] == 12


# --- source files are immutable artifacts --------------------------------------------------------------------------------------
def test_importing_leaves_the_json_files_byte_and_mtime_identical(db_path, tmp_path):
    report_doc, analysis_doc = write_docs(tmp_path)
    files = [tmp_path / "run.json", tmp_path / "run.analysis.json"]
    before = [(f.read_bytes(), f.stat().st_mtime_ns, f.stat().st_size) for f in files]
    listing = sorted(p.name for p in tmp_path.iterdir())
    with contextlib.closing(open_database(db_path)) as c:
        import_report_and_analysis(c, report_doc, analysis_doc)
        import_report_and_analysis(c, report_doc, analysis_doc)  # a duplicate import too
        with pytest.raises(DocumentError):
            import_report(c, Document(mutated(report_doc.data, lambda r: r.pop("run_id")), "0" * 64, "x.json"))
    assert [(f.read_bytes(), f.stat().st_mtime_ns, f.stat().st_size) for f in files] == before
    assert sorted(p.name for p in tmp_path.iterdir()) == listing


# --- duplicates and conflicts ---------------------------------------------------------------------------------------------------
def test_importing_the_same_report_twice_is_a_reported_no_op(conn, tmp_path):
    report_doc, _ = write_docs(tmp_path)
    import_report(conn, report_doc)
    before = snapshot(conn)
    again = import_report(conn, report_doc)
    assert (again.status, again.executions) == ("already_imported", 6)
    assert snapshot(conn) == before  # no new rows, and no new audit event


def test_importing_the_same_analysis_twice_is_a_reported_no_op(conn, tmp_path):
    report_doc, analysis_doc = write_docs(tmp_path)
    first = import_report_and_analysis(conn, report_doc, analysis_doc)
    before = snapshot(conn)
    run, analysis = import_report_and_analysis(conn, report_doc, analysis_doc)
    assert (run.status, analysis.status) == ("already_imported", "already_imported")
    assert (analysis.findings, analysis.matches) == (first[1].findings, first[1].matches)
    assert snapshot(conn) == before
    assert import_analysis(conn, analysis_doc).status == "already_imported" and snapshot(conn) == before


def test_the_same_content_under_another_file_name_is_still_a_duplicate(conn, tmp_path):
    report_doc, _ = write_docs(tmp_path)
    import_report(conn, report_doc)
    copy = tmp_path / "copy-of-run.json"
    copy.write_bytes((tmp_path / "run.json").read_bytes())
    assert import_report(conn, read_document(copy, "report")).status == "already_imported"
    assert conn.execute("SELECT report_file_name FROM runs").fetchone()[0] == "run.json"  # original name kept


def test_a_different_report_with_the_same_run_id_is_a_conflict_and_nothing_changes(conn, tmp_path):
    report_doc, _ = write_docs(tmp_path)
    import_report(conn, report_doc)
    before = snapshot(conn)
    altered = mutated(report_doc.data, lambda r: r["results"][0].__setitem__("response_text", "changed"))
    other = read_document(write_json(tmp_path / "other.json", altered), "report")
    with pytest.raises(ImportConflictError, match="already stored from a different report"):
        import_report(conn, other)
    assert snapshot(conn) == before


def test_a_different_analysis_with_the_same_id_is_a_conflict(conn, tmp_path):
    report_doc, analysis_doc = write_docs(tmp_path, analysis_id="fixedid01")
    import_report_and_analysis(conn, report_doc, analysis_doc)
    before = snapshot(conn)
    altered = mutated(analysis_doc.data, lambda a: a.__setitem__("created_at", "2030-01-01T00:00:00+00:00"))
    other = read_document(write_json(tmp_path / "other.analysis.json", altered), "analysis")
    with pytest.raises(ImportConflictError, match="already stored from a different file"):
        import_analysis(conn, other)
    assert snapshot(conn) == before


def test_several_analyses_of_one_run_are_allowed(conn, tmp_path):
    report_doc, first = write_docs(tmp_path, analysis_id="analysis-a")
    import_report_and_analysis(conn, report_doc, first)
    second = read_document(write_json(tmp_path / "second.json", make_analysis(report_doc.data, tmp_path, analysis_id="analysis-b")), "analysis")
    assert import_analysis(conn, second).status == "imported"
    assert counts(conn)["analyses"] == 2 and counts(conn)["findings"] == 12


# --- linking -------------------------------------------------------------------------------------------------------------------
def test_an_analysis_needs_its_run_to_be_stored_first(conn, tmp_path):
    _, analysis_doc = write_docs(tmp_path)
    before = snapshot(conn)
    with pytest.raises(ImportConflictError, match="Import the runner report first"):
        import_analysis(conn, analysis_doc)
    assert snapshot(conn) == before


def test_an_analysis_of_a_different_report_file_is_refused(conn, tmp_path):
    report_doc, analysis_doc = write_docs(tmp_path)
    import_report(conn, report_doc)
    before = snapshot(conn)
    wrong = mutated(analysis_doc.data, lambda a: a["input"].__setitem__("report_sha256", "f" * 64))
    with pytest.raises(ImportConflictError, match="Re-run the rule engine"):
        import_analysis(conn, read_document(write_json(tmp_path / "w.json", wrong), "analysis"))
    assert snapshot(conn) == before


def test_an_analysis_that_misses_executions_is_refused(conn, tmp_path):
    report_doc, analysis_doc = write_docs(tmp_path)
    import_report(conn, report_doc)
    partial = mutated(analysis_doc.data, lambda a: (a["results"].pop(), a["input"].__setitem__("record_count", 5)))
    with pytest.raises(DocumentError, match="does not match the stored run") as info:
        import_analysis(conn, read_document(write_json(tmp_path / "p.json", partial), "analysis"))
    assert any("does not cover 1 of the run's 6" in p for p in info.value.problems)
    assert counts(conn)["analyses"] == 0 and counts(conn)["findings"] == 0


def test_an_analysis_about_unknown_tests_or_disagreeing_outcomes_is_refused(conn, tmp_path):
    report_doc, analysis_doc = write_docs(tmp_path)
    import_report(conn, report_doc)
    unknown = mutated(analysis_doc.data, lambda a: a["results"][0].__setitem__("test_id", "ZZZ-999"))
    with pytest.raises(DocumentError) as info:
        import_analysis(conn, read_document(write_json(tmp_path / "u.json", unknown), "analysis"))
    assert any("no matching execution" in p for p in info.value.problems)
    disagreeing = mutated(analysis_doc.data, lambda a: a["results"][0].__setitem__("category", "safety_bypass"))
    with pytest.raises(DocumentError) as info:
        import_analysis(conn, read_document(write_json(tmp_path / "d.json", disagreeing), "analysis"))
    assert any("disagrees with the stored execution" in p for p in info.value.problems)
    assert counts(conn)["analyses"] == 0


# --- atomicity ---------------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("target", ["_insert_executions", "_insert_analysis", "_insert_findings", "_insert_matches"])
def test_a_failure_part_way_through_rolls_everything_back(conn, tmp_path, monkeypatch, target):
    report_doc, analysis_doc = write_docs(tmp_path)
    before = snapshot(conn)

    def boom(*args, **kwargs):
        raise sqlite3.OperationalError("disk I/O error (injected)")

    monkeypatch.setattr(importer, target, boom)
    with pytest.raises(sqlite3.OperationalError, match="injected"):
        import_report_and_analysis(conn, report_doc, analysis_doc)
    assert snapshot(conn) == before and counts(conn)["runs"] == 0
    assert not conn.in_transaction
    monkeypatch.undo()
    assert import_report_and_analysis(conn, report_doc, analysis_doc)[1].status == "imported"  # usable afterwards


def test_a_failure_while_writing_the_audit_event_leaves_no_partial_data(conn, tmp_path, monkeypatch):
    report_doc, _ = write_docs(tmp_path)
    before = snapshot(conn)
    monkeypatch.setattr(audit, "append_event", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no audit")))
    with pytest.raises(RuntimeError):
        import_report(conn, report_doc)
    assert snapshot(conn) == before and not conn.in_transaction


def test_a_failure_part_way_through_the_rows_themselves_rolls_back(conn, tmp_path, monkeypatch):
    """Not a stubbed helper: SQLite itself rejects the 4th execution row (a CHECK constraint) mid-insert."""
    report = make_report()
    report_doc = read_document(write_json(tmp_path / "r.json", report), "report")
    real = importer._insert_executions

    def corrupt_fourth(conn_, doc):
        doc.data["results"][3] = dict(doc.data["results"][3], target_mode="sideways")
        return real(conn_, doc)

    monkeypatch.setattr(importer, "_insert_executions", corrupt_fourth)
    before = snapshot(conn)
    with pytest.raises(sqlite3.IntegrityError, match="CHECK"):
        importer.import_report(conn, report_doc)
    assert snapshot(conn) == before


def test_a_rejected_analysis_also_prevents_the_run_from_being_stored(conn, tmp_path):
    report_doc, analysis_doc = write_docs(tmp_path)
    bad = mutated(analysis_doc.data, lambda a: a["input"].__setitem__("report_sha256", "e" * 64))
    with pytest.raises(ImportConflictError):
        import_report_and_analysis(conn, report_doc, read_document(write_json(tmp_path / "b.json", bad), "analysis"))
    assert counts(conn) == {t: 0 for t in DATA_TABLES} | {"audit_events": 1}


def test_a_second_writer_waits_or_fails_cleanly_instead_of_corrupting(db_path, tmp_path):
    report_doc, _ = write_docs(tmp_path)
    first = open_database(db_path)
    second = open_database(db_path)
    second.execute("PRAGMA busy_timeout = 50")
    try:
        first.execute("BEGIN IMMEDIATE")
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            import_report(second, report_doc)
        first.execute("ROLLBACK")
        assert import_report(second, report_doc).status == "imported"
    finally:
        first.close()
        second.close()


# --- rejection leaves the database untouched ------------------------------------------------------------------------------------------
@pytest.mark.parametrize("mutate", [
    lambda r: r.pop("run_id"),
    lambda r: r["results"][0].__setitem__("outcome", "exploded"),
    lambda r: r["target"].__setitem__("base_url", "https://api.example.com"),
    lambda r: r["results"][0].__setitem__("response_text", "key AKIAIOSFODNN7EXAMPLE"),
    lambda r: r["results"].append(dict(r["results"][0])),
])
def test_a_rejected_report_adds_nothing_not_even_an_audit_event(conn, tmp_path, mutate):
    before = snapshot(conn)
    bad = mutated(make_report(), mutate)
    with pytest.raises(DocumentError):
        import_report(conn, read_document(write_json(tmp_path / "bad.json", bad), "report"))
    assert snapshot(conn) == before


def test_a_rejected_analysis_adds_nothing(conn, tmp_path):
    report_doc, analysis_doc = write_docs(tmp_path)
    import_report(conn, report_doc)
    before = snapshot(conn)
    bad = mutated(analysis_doc.data, lambda a: a["results"][4].update(matches=[]))
    with pytest.raises(DocumentError):
        import_analysis(conn, read_document(write_json(tmp_path / "bad.json", bad), "analysis"))
    assert snapshot(conn) == before


# --- immutability and audit trail ---------------------------------------------------------------------------------------------------------
def test_stored_records_cannot_be_changed_or_deleted_after_import(conn, tmp_path):
    report_doc, analysis_doc = write_docs(tmp_path)
    import_report_and_analysis(conn, report_doc, analysis_doc)
    before = snapshot(conn)
    for sql in ("DELETE FROM runs", "UPDATE executions SET response_text = 'tampered'", "DELETE FROM findings",
                "UPDATE findings SET verdict = 'not_detected'", "DELETE FROM audit_events", "UPDATE finding_matches SET rule_id = 'X'"):
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute(sql)
    assert snapshot(conn) == before


def test_each_import_appends_one_chained_event_with_the_artifact_hashes(conn, tmp_path):
    report_doc, analysis_doc = write_docs(tmp_path)
    import_report_and_analysis(conn, report_doc, analysis_doc)
    events = conn.execute("SELECT * FROM audit_events ORDER BY seq").fetchall()
    assert [e["event_type"] for e in events] == ["db_initialized", "run_imported", "analysis_imported"]
    run_event, analysis_event = json.loads(events[1]["detail_json"]), json.loads(events[2]["detail_json"])
    assert run_event["report_sha256"] == report_doc.sha256 and run_event["executions"] == 6
    assert analysis_event["analysis_sha256"] == analysis_doc.sha256 and analysis_event["report_sha256"] == report_doc.sha256
    assert events[2]["prev_hash"] == events[1]["event_hash"] and audit.verify_chain(conn) == []
    assert (events[1]["run_id"], events[2]["analysis_id"]) == ("run0001abcd", analysis_doc.data["analysis_id"])


def test_the_clock_is_injectable_and_recorded(conn, tmp_path):
    from datetime import datetime, timezone

    report_doc, _ = write_docs(tmp_path)
    moment = datetime(2030, 5, 6, 7, 8, 9, tzinfo=timezone.utc)
    import_report(conn, report_doc, now=moment)
    assert conn.execute("SELECT imported_at FROM runs").fetchone()[0] == "2030-05-06T07:08:09+00:00"
    assert conn.execute("SELECT occurred_at FROM audit_events WHERE seq = 2").fetchone()[0] == "2030-05-06T07:08:09+00:00"
