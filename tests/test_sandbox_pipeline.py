"""Runner + rule engine + storage through the sandbox pipeline, with a fake Docker running the REAL workload in-process."""

import contextlib
import copy
import hashlib
import json
import sqlite3

import pytest
from sandbox_fakes import IMAGE_ID, IMAGE_TAG, FakeDocker, no_real_docker, run_real_workload  # noqa: F401

from sentinelbox.rule_engine.analysis import analyze_report, read_report, validate_analysis
from sentinelbox.rule_engine.expectations import load_expectations
from sentinelbox.runner.report import validate_report
from sentinelbox.sandbox import pipeline
from sentinelbox.sandbox import policy as pol
from sentinelbox.sandbox.docker_client import AttachResult
from sentinelbox.sandbox.executor import JobRejected
from sentinelbox.storage import audit, database, queries
from sentinelbox.storage.database import init_database, open_database
from sentinelbox.storage.documents import find_secret_like_strings, validate_sandbox_record_document
from sentinelbox.storage.verify import verify_database

pytestmark = pytest.mark.usefixtures("no_real_docker")
POLICY = pol.SandboxPolicy()


@pytest.fixture
def env(tmp_path):
    fake = FakeDocker()
    fake.attach_behavior = run_real_workload
    db = init_database(tmp_path / "audit.db")
    return fake, db, tmp_path / "reports"


def go(env, **kw):
    fake, db, reports = env
    args = dict(image_ref=IMAGE_TAG, policy=POLICY, modes=["vulnerable", "hardened"], reports_dir=reports, db_path=db)
    args.update(kw)
    return pipeline.run_suite(fake, **args)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --- the happy path -----------------------------------------------------------------------------------------------------------------
def test_a_completed_run_writes_report_analysis_and_record_and_stores_everything(env):
    fake, db, reports = env
    out = go(env)
    assert out.result.outcome == "completed" and out.db_status == "stored" and fake.containers == {}
    assert out.report_path.is_file() and out.analysis_path.is_file() and out.record_path.is_file()
    assert sorted(p.name for p in reports.iterdir()) == sorted([out.report_path.name, out.analysis_path.name, out.record_path.name])
    with contextlib.closing(open_database(db)) as conn:
        counts = database.table_counts(conn)
        assert (counts["runs"], counts["analyses"], counts["sandbox_runs"], counts["executions"]) == (1, 1, 1, 48)
        assert verify_database(conn, artifacts_dir=reports).ok and audit.verify_chain(conn) == []
        row = queries.get_sandbox_run(conn, out.result.job_id)
        assert row["outcome"] == "completed" and row["controls_verified"] and row["cleanup_status"] == "removed"
        assert row["run_id"] and row["analysis_id"] and row["image_id"] == IMAGE_ID and row["data_classification"] == "synthetic_test_data"
        assert row["controls"]["verified"] is True and len(row["controls"]["results"]) >= 45 and row["requested"]["timeout_seconds"] == 60.0


def test_the_report_is_a_valid_stage2_report_and_the_analysis_a_valid_stage3_analysis(env):
    out = go(env)
    report = json.loads(out.report_path.read_text())
    analysis = json.loads(out.analysis_path.read_text())
    assert validate_report(report) == [] and validate_analysis(analysis) == []
    assert report["status"] == "complete" and report["summary"]["planned"] == 48 and report["tool"]["name"] == "sentinelbox-runner"
    assert analysis["input"]["report_sha256"] == sha(out.report_path)
    assert analysis["input"]["report_run_id"] == report["run_id"]


def test_verdicts_come_from_the_host_rule_engine_and_match_an_independent_analysis(env):
    out = go(env)
    again = analyze_report(read_report(out.report_path), load_expectations(), analysis_id="independent")
    mine = json.loads(out.analysis_path.read_text())
    strip = lambda a: [{k: v for k, v in r.items()} for r in a["results"]]  # noqa: E731
    assert strip(again) == strip(mine) and again["metrics_by_mode"] == mine["metrics_by_mode"]
    confusion = mine["metrics_by_mode"]["vulnerable"]["confusion"]
    assert (confusion["tp"], confusion["fp"], confusion["tn"], confusion["fn"]) == (18, 0, 6, 0)  # same as the Stage 3 HTTP run
    assert mine["metrics_by_mode"]["hardened"]["verdict_counts"]["detected"] == 0


def test_the_sandbox_output_contains_no_verdicts_so_the_report_has_none(env):
    out = go(env)
    text = out.report_path.read_text().lower()
    assert '"verdict"' not in text and '"detected"' not in text


def test_the_synthetic_marker_and_fake_canaries_only(env):
    out = go(env)
    record = json.loads(out.record_path.read_text())
    assert record["data_classification"] == "synthetic_test_data" and "synthetic" in record["note"].lower()
    for path in (out.report_path, out.analysis_path, out.record_path):
        data = json.loads(path.read_text())
        assert find_secret_like_strings(data) == []
    assert "SBX-CANARY-4f7a91c2" in out.report_path.read_text()  # the fake canary is present and is the known fictional value


def test_the_record_is_valid_and_reflects_the_run(env):
    out = go(env)
    assert validate_sandbox_record_document(out.record) == []
    assert out.record["result"]["cases_requested"] == out.record["result"]["cases_returned"] == 48
    assert out.record["references"]["report_sha256"] == sha(out.report_path) and out.record["references"]["analysis_sha256"] == sha(out.analysis_path)
    assert out.record["policy"]["requested"]["memory_bytes"] == POLICY.memory_bytes


def test_category_filter_and_single_mode(env):
    out = go(env, modes=["hardened"], categories=["prompt_injection"])
    report = json.loads(out.report_path.read_text())
    assert report["modes"] == ["hardened"] and {r["category"] for r in report["results"]} == {"prompt_injection"}


def test_the_workload_receives_exactly_the_validated_request_and_nothing_else(env):
    fake, _, _ = env
    go(env)
    sent = json.loads(fake.stdin_seen[0])
    assert set(sent) == {"protocol", "job_id", "kind", "modes", "timeout_seconds", "max_consecutive_failures", "cases"}
    assert all(set(c) == {"test_id", "category", "title", "prompt"} for c in sent["cases"])


# --- no mutation of existing data --------------------------------------------------------------------------------------------------------
def test_existing_reports_and_database_rows_are_never_modified(env):
    fake, db, reports = env
    first = go(env)
    snapshot = {p.name: p.read_bytes() for p in reports.iterdir()}
    with contextlib.closing(open_database(db, readonly=True)) as conn:
        rows_before = [tuple(r) for r in conn.execute("SELECT * FROM executions ORDER BY execution_id")]
    fake2 = FakeDocker()
    fake2.attach_behavior = run_real_workload
    second = pipeline.run_suite(fake2, image_ref=IMAGE_TAG, policy=POLICY, modes=["vulnerable"], reports_dir=reports, db_path=db)
    assert second.report_path != first.report_path
    for name, content in snapshot.items():
        assert (reports / name).read_bytes() == content
    with contextlib.closing(open_database(db, readonly=True)) as conn:
        assert [tuple(r) for r in conn.execute("SELECT * FROM executions ORDER BY execution_id") if r["run_id"] == first.record["references"]["run_id"]] == rows_before
        assert conn.execute("SELECT COUNT(*) FROM sandbox_runs").fetchone()[0] == 2


def test_writing_never_overwrites_an_existing_file(tmp_path):
    target = tmp_path / "x.json"
    pipeline.write_json_exclusive(target, {"a": 1})
    with pytest.raises(FileExistsError):
        pipeline.write_json_exclusive(target, {"a": 2})
    assert json.loads(target.read_text()) == {"a": 1}
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(FileExistsError):
        pipeline.write_json_exclusive(link, {"a": 3})
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".")] == []


# --- the container is not trusted --------------------------------------------------------------------------------------------------------
def corrupt(mutator):
    def behaviour(stdin):
        response = json.loads(run_real_workload(stdin))
        mutator(response)
        return json.dumps(response).encode()
    return behaviour


@pytest.mark.parametrize("name,mutator", [
    ("claimed verdict", lambda r: r["results"][0].update(verdict="safe")),
    ("dropped result", lambda r: r["results"].pop()),
    ("wrong category", lambda r: r["results"][0].update(category="safety_bypass")),
    ("incomplete status", lambda r: r.update(status="aborted", stop_reason="x")),
    ("extra field", lambda r: r.update(trusted_verdict="all clear")),
    ("wrong job id", lambda r: r.update(job_id="someone-else")),
])
def test_a_lying_workload_is_rejected_recorded_and_produces_no_report(env, name, mutator):
    fake, db, reports = env
    fake.attach_behavior = corrupt(mutator)
    out = go(env)
    assert out.result.outcome == "workload_error" and out.report_path is None and out.analysis_path is None
    assert out.record["result"]["outcome"] == "workload_error" and out.record["references"]["run_id"] is None
    assert out.db_status == "stored"
    assert [p.name for p in reports.iterdir()] == [out.record_path.name]
    with contextlib.closing(open_database(db)) as conn:
        assert database.table_counts(conn)["runs"] == 0 and database.table_counts(conn)["sandbox_runs"] == 1


@pytest.mark.parametrize("stdout", [b"", b"not json", b"[]", b'{"a":1}', b"\xff\xfe"])
def test_garbage_output_is_a_workload_error_not_a_crash(env, stdout):
    fake, db, reports = env
    fake.attach_behavior = None
    fake.stdout = stdout
    out = go(env)
    assert out.result.outcome == "workload_error" and out.db_status == "stored" and fake.containers == {}


def test_a_nonzero_exit_even_with_valid_looking_output_is_not_a_completed_run(env):
    fake, _, _ = env
    fake.exit_code = 1
    out = go(env)
    assert out.result.outcome == "workload_error" and out.report_path is None


def test_the_container_exit_code_and_self_reports_are_never_the_source_of_a_verdict(env):
    fake, _, _ = env
    out = go(env)
    assert "verdict" not in out.record["result"] and out.record["result"]["exit_code"] == 0
    assert out.analysis is not None and "results" in out.analysis


# --- failures leave a complete, consistent trail -----------------------------------------------------------------------------------------
@pytest.mark.parametrize("setup,outcome", [
    (lambda f: f.fail.update(run_attached=KeyboardInterrupt()), "interrupted"),
    (lambda f: setattr(f, "attach_result", AttachResult(b"", b"", False, False, True, None)) or setattr(f, "attach_behavior", None), "timeout"),
    (lambda f: setattr(f, "attach_result", AttachResult(b"x", b"", True, False, False, None)) or setattr(f, "attach_behavior", None), "output_limit"),
])
def test_non_completed_runs_are_still_recorded_and_cleaned_up(env, setup, outcome):
    fake, db, reports = env
    setup(fake)
    out = go(env)
    assert out.result.outcome == outcome and out.report_path is None and fake.containers == {}
    assert out.db_status == "stored" and validate_sandbox_record_document(out.record) == []
    with contextlib.closing(open_database(db)) as conn:
        assert queries.get_sandbox_run(conn, out.result.job_id)["outcome"] == outcome
        assert verify_database(conn).ok


def test_a_refused_run_is_recorded_with_the_failed_controls(env):
    fake, db, _ = env
    fake.mutators.append(lambda c: c["HostConfig"].update(NetworkMode="host"))
    out = go(env)
    assert out.result.outcome == "refused" and fake.count("run_attached") == 0
    with contextlib.closing(open_database(db)) as conn:
        row = queries.get_sandbox_run(conn, out.result.job_id)
    failed = [c for c in row["controls"]["results"] if not c["ok"]]
    assert row["controls_verified"] is False and [c["name"] for c in failed] == ["network_mode_none"] and failed[0]["actual"] == "'host'"


def test_a_database_that_does_not_exist_or_is_old_fails_before_any_container_is_created(env, tmp_path):
    fake, db, reports = env
    with pytest.raises(database.StorageError):
        go(env, db_path=tmp_path / "missing.db")
    assert fake.calls == [] and not reports.exists()
    old = init_database(tmp_path / "old.db", migrations=database.MIGRATIONS[:1])
    with pytest.raises(database.SchemaVersionError):
        go(env, db_path=old)
    assert fake.calls == []


def test_no_db_mode_writes_files_only(env):
    fake, db, reports = env
    out = go(env, db_path=None)
    assert out.db_status == "not_requested" and out.record_path.is_file()
    with contextlib.closing(open_database(db)) as conn:
        assert database.table_counts(conn)["runs"] == 0


def test_a_storage_failure_keeps_the_files_rolls_the_database_back_and_prints_the_recovery_command(env, monkeypatch):
    fake, db, reports = env
    real = audit.append_event

    def fail_on_sandbox(c, event_type, **kw):
        if event_type == "sandbox_run_recorded":
            raise sqlite3.OperationalError("disk I/O error")
        return real(c, event_type, **kw)

    monkeypatch.setattr(audit, "append_event", fail_on_sandbox)
    with pytest.raises(sqlite3.OperationalError):
        go(env)
    # sqlite errors are not StorageError, so they propagate; the DB must be untouched either way
    with contextlib.closing(open_database(db)) as conn:
        counts = database.table_counts(conn)
        assert (counts["runs"], counts["analyses"], counts["sandbox_runs"], counts["audit_events"]) == (0, 0, 0, 1)
        assert verify_database(conn).ok
    assert len(list(reports.iterdir())) == 3  # report, analysis and record survive for a later import


def test_a_storage_conflict_is_reported_with_a_recovery_command_and_files_are_kept(env):
    fake, db, reports = env
    first = go(env)
    # same job id again in a new executor: the record already exists with different content -> conflict, files kept
    fake2 = FakeDocker()
    fake2.attach_behavior = run_real_workload
    out = pipeline.run_suite(fake2, image_ref=IMAGE_TAG, policy=POLICY, modes=["vulnerable"], reports_dir=reports, db_path=db,
                             job_id=first.result.job_id)
    assert out.db_status == "failed" and "sentinelbox.storage import-sandbox" in out.recovery_command and "never replaced" in out.db_error
    assert out.record_path.is_file()


def test_the_stored_database_can_be_reopened_and_still_verifies(env):
    fake, db, reports = env
    out = go(env)
    with contextlib.closing(open_database(db, readonly=True)) as conn:
        assert queries.get_sandbox_run(conn, out.result.job_id)["outcome"] == "completed"
        assert [r["event_type"] for r in conn.execute("SELECT event_type FROM audit_events ORDER BY seq")] == [
            "db_initialized", "run_imported", "analysis_imported", "sandbox_run_recorded"]
        assert verify_database(conn, artifacts_dir=reports).ok


def test_no_cases_selected_is_rejected_before_docker_is_contacted(env, tmp_path):
    fake, _, reports = env
    library = tmp_path / "lib.json"
    library.write_text(json.dumps({"schema_version": 1, "name": "n", "version": "1", "cases": [
        {"id": "A", "category": "normal", "title": "t", "prompt": "hello"}]}))
    with pytest.raises(JobRejected, match="no test cases"):
        pipeline.run_suite(fake, image_ref=IMAGE_TAG, policy=POLICY, modes=["vulnerable"], categories=["safety_bypass"],
                           library_path=library, reports_dir=reports, db_path=None)
    assert fake.calls == [] and not reports.exists()
