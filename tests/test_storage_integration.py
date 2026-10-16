"""Pipeline test: Stage 2 runner (in-process, real mock) -> Stage 3 analysis -> Stage 4 database."""

import contextlib
import hashlib
import json

import pytest
from runner_fakes import BASE_URL, MockAppTransport

from sentinelbox.rule_engine.analysis import analyze_report, read_report, write_analysis
from sentinelbox.rule_engine.expectations import load_expectations
from sentinelbox.runner.library import load_library
from sentinelbox.runner.models import TargetMode
from sentinelbox.runner.report import build_report, validate_report, write_report
from sentinelbox.runner.runner import run_suite
from sentinelbox.storage import audit, queries
from sentinelbox.storage.cli import EXIT_OK, main
from sentinelbox.storage.database import open_database
from sentinelbox.storage.documents import validate_analysis_document, validate_report_document

LIBRARY = load_library()
BOTH = [TargetMode.VULNERABLE, TargetMode.HARDENED]


@pytest.fixture
def pipeline(client, tmp_path):
    run = run_suite(LIBRARY.cases, BOTH, BASE_URL, MockAppTransport(client))
    report_path = write_report(build_report(run, LIBRARY, BASE_URL, BOTH, 10.0), tmp_path / "runner.json")
    analysis = analyze_report(read_report(report_path), load_expectations())
    analysis_path = write_analysis(analysis, tmp_path / "runner.analysis.json", input_path=report_path)
    return report_path, analysis_path, analysis


def test_real_runner_and_rule_engine_outputs_pass_storage_validation(pipeline):
    report_path, analysis_path, _ = pipeline
    assert validate_report_document(json.loads(report_path.read_text())) == []
    assert validate_analysis_document(json.loads(analysis_path.read_text())) == []
    assert validate_report(json.loads(report_path.read_text())) == []


def test_the_full_pipeline_lands_in_the_database(capsys, pipeline, tmp_path):
    report_path, analysis_path, analysis = pipeline
    db = tmp_path / "audit.db"
    assert main(["init", "--db", str(db)]) == EXIT_OK
    assert main(["import", "--db", str(db), "--report", str(report_path), "--analysis", str(analysis_path)]) == EXIT_OK
    capsys.readouterr()
    with contextlib.closing(open_database(db, readonly=True)) as conn:
        info = queries.database_info(conn)
        assert info["counts"]["executions"] == 48 and info["counts"]["findings"] == 48 and info["counts"]["runs"] == 1
        analysis_id = analysis["analysis_id"]
        summary = queries.verdict_summary(conn, analysis_id)

        def count(mode, verdict, correctness):
            return sum(r["n"] for r in summary if (r["target_mode"], r["verdict"], r["detection_correctness"]) == (mode, verdict, correctness))

        assert count("vulnerable", "detected", "correct") == analysis["metrics_by_mode"]["vulnerable"]["confusion"]["tp"] == 18
        assert count("vulnerable", "not_detected", "correct") == analysis["metrics_by_mode"]["vulnerable"]["confusion"]["tn"] == 6
        assert count("hardened", "not_detected", "correct") == analysis["metrics_by_mode"]["hardened"]["confusion"]["tn"] == 24
        stored_metrics = conn.execute("SELECT metrics_json FROM analyses").fetchone()[0]
        assert json.loads(stored_metrics) == analysis["metrics_by_mode"]  # published numbers are stored unmodified
        assert audit.verify_chain(conn) == []
        # the findings that matter: every vulnerable canary case names the canary rules
        canary = queries.list_findings(conn, category="canary_disclosure", target_mode="vulnerable", verdicts=("detected",))
        assert len(canary) == 6 and all({"R-CANARY-001", "R-CANARY-002"} <= {m["rule_id"] for m in f["rules"]} for f in canary)
        # hardened refusals are stored as clean, not as attacks
        assert queries.list_findings(conn, target_mode="hardened", verdicts=("detected", "inconclusive")) == []


def test_the_stored_responses_equal_the_runner_report_text(pipeline, tmp_path):
    report_path, analysis_path, _ = pipeline
    db = tmp_path / "audit.db"
    main(["init", "--db", str(db)])
    main(["import", "--db", str(db), "--report", str(report_path), "--analysis", str(analysis_path)])
    source = {(r["test_id"], r["target_mode"]): r for r in json.loads(report_path.read_text())["results"]}
    with contextlib.closing(open_database(db, readonly=True)) as conn:
        for row in conn.execute("SELECT * FROM executions"):
            record = source[(row["test_id"], row["target_mode"])]
            assert row["response_text"] == record["response_text"] and row["raw_body"] == record["raw_body"]
            assert row["http_status"] == record["http_status"] and row["outcome"] == record["outcome"]


def test_the_pipeline_never_changes_the_artifacts_and_verify_confirms_it(capsys, pipeline, tmp_path):
    report_path, analysis_path, _ = pipeline
    before = {p: (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mtime_ns) for p in (report_path, analysis_path)}
    db = tmp_path / "audit.db"
    main(["init", "--db", str(db)])
    main(["import", "--db", str(db), "--report", str(report_path), "--analysis", str(analysis_path)])
    main(["import", "--db", str(db), "--report", str(report_path), "--analysis", str(analysis_path)])
    assert main(["verify", "--db", str(db), "--reports-dir", str(tmp_path)]) == EXIT_OK
    assert {p: (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mtime_ns) for p in before} == before
    out = capsys.readouterr().out
    assert "already stored (unchanged)" in out and "OK: no problems found" in out


def test_a_second_run_can_be_stored_next_to_the_first(client, pipeline, tmp_path):
    report_path, analysis_path, _ = pipeline
    run = run_suite(LIBRARY.cases, BOTH, BASE_URL, MockAppTransport(client))
    second_report = write_report(build_report(run, LIBRARY, BASE_URL, BOTH, 10.0), tmp_path / "second.json")
    second_analysis = write_analysis(analyze_report(read_report(second_report), load_expectations()), tmp_path / "second.analysis.json")
    db = tmp_path / "audit.db"
    main(["init", "--db", str(db)])
    assert main(["import", "--db", str(db), "--report", str(report_path), "--analysis", str(analysis_path)]) == EXIT_OK
    assert main(["import", "--db", str(db), "--report", str(second_report), "--analysis", str(second_analysis)]) == EXIT_OK
    with contextlib.closing(open_database(db, readonly=True)) as conn:
        runs = queries.list_runs(conn)
        assert len(runs) == 2 and {r["executions"] for r in runs} == {48}
        assert queries.database_info(conn)["counts"]["findings"] == 96
