"""The `python -m sentinelbox.storage` command line."""

import contextlib
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
from storage_fakes import REFUSAL, make_record, make_report, write_docs, write_json

from sentinelbox.storage import cli, importer
from sentinelbox.storage.cli import EXIT_ERROR, EXIT_OK, EXIT_VERIFY_FAILED, main
from sentinelbox.storage.database import init_database, open_database

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def db(tmp_path):
    return tmp_path / "audit.db"


@pytest.fixture
def docs(tmp_path):
    write_docs(tmp_path)
    return tmp_path / "run.json", tmp_path / "run.analysis.json"


def run(capsys, *argv):
    code = main([str(a) for a in argv])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


@pytest.fixture
def loaded(capsys, db, docs):
    assert run(capsys, "init", "--db", db)[0] == EXIT_OK
    code, out, _ = run(capsys, "import", "--db", db, "--report", docs[0], "--analysis", docs[1])
    assert code == EXIT_OK
    return db


def test_init_creates_the_database_and_states_the_data_policy(capsys, db):
    code, out, err = run(capsys, "init", "--db", db)
    assert (code, err) == (EXIT_OK, "") and db.exists() and "synthetic" in out and "schema version 2" in out


def test_init_refuses_an_existing_database(capsys, db):
    run(capsys, "init", "--db", db)
    before = db.read_bytes()
    code, out, err = run(capsys, "init", "--db", db)
    assert code == EXIT_ERROR and "already exists" in err and out == "" and db.read_bytes() == before


def test_commands_on_a_missing_database_explain_how_to_create_it(capsys, db, docs):
    for command in (["runs"], ["info"], ["verify"], ["findings"], ["import", "--report", str(docs[0])]):
        code, _, err = run(capsys, command[0], "--db", db, *command[1:])
        assert code == EXIT_ERROR and "init --db" in err, command
    assert not db.exists()


def test_import_reports_what_was_stored(capsys, db, docs):
    run(capsys, "init", "--db", db)
    code, out, _ = run(capsys, "import", "--db", db, "--report", docs[0], "--analysis", docs[1])
    assert code == EXIT_OK and "Run run0001abcd: stored, 6 executions" in out and "6 findings" in out and "synthetic" in out


def test_importing_twice_reports_unchanged_and_exits_zero(capsys, loaded, docs):
    code, out, _ = run(capsys, "import", "--db", loaded, "--report", docs[0], "--analysis", docs[1])
    assert code == EXIT_OK and out.count("already stored (unchanged)") == 2


def test_report_only_then_analysis_only(capsys, db, docs):
    run(capsys, "init", "--db", db)
    code, out, _ = run(capsys, "import-analysis", "--db", db, "--analysis", docs[1])
    assert code == EXIT_ERROR  # the run is not stored yet
    assert run(capsys, "import", "--db", db, "--report", docs[0])[0] == EXIT_OK
    code, out, _ = run(capsys, "import-analysis", "--db", db, "--analysis", docs[1])
    assert code == EXIT_OK and "Analysis" in out and "stored" in out


def test_analysis_without_its_run_says_to_import_the_report_first(capsys, db, docs):
    run(capsys, "init", "--db", db)
    code, _, err = run(capsys, "import-analysis", "--db", db, "--analysis", docs[1])
    assert code == EXIT_ERROR and "Import the runner report first" in err


def test_a_malformed_report_exits_two_with_record_level_messages(capsys, db, tmp_path):
    run(capsys, "init", "--db", db)
    report = make_report()
    report["results"][1]["category"] = "social"
    bad = write_json(tmp_path / "bad.json", report)
    code, out, err = run(capsys, "import", "--db", db, "--report", bad)
    assert code == EXIT_ERROR and "bad.json" in err and "results[1].category" in err and out == ""
    code, out, _ = run(capsys, "runs", "--db", db)
    assert "No runs stored yet" in out


@pytest.mark.parametrize("content", [b"", b"{oops", b"[]", b"\xff"])
def test_unreadable_json_files_exit_two_without_a_traceback(capsys, db, tmp_path, content):
    run(capsys, "init", "--db", db)
    path = tmp_path / "x.json"
    path.write_bytes(content)
    code, _, err = run(capsys, "import", "--db", db, "--report", path)
    assert code == EXIT_ERROR and err.startswith("error:") and "Traceback" not in err


def test_missing_input_file_exits_two(capsys, db, tmp_path):
    run(capsys, "init", "--db", db)
    code, _, err = run(capsys, "import", "--db", db, "--report", tmp_path / "nope.json")
    assert code == EXIT_ERROR and "Cannot read the report" in err


def test_a_report_with_a_credential_is_refused(capsys, db, tmp_path):
    run(capsys, "init", "--db", db)
    records = [make_record("A-1", "normal", "vulnerable", "my key is AKIAIOSFODNN7EXAMPLE")]
    code, out, err = run(capsys, "import", "--db", db, "--report", write_json(tmp_path / "s.json", make_report(records)))
    assert code == EXIT_ERROR and "looks like a real credential" in err and "AKIAIOSFODNN7EXAMPLE" not in err + out


def test_the_json_files_are_unchanged_after_cli_imports(capsys, loaded, docs):
    before = [(p.read_bytes(), p.stat().st_mtime_ns) for p in docs]
    run(capsys, "import", "--db", loaded, "--report", docs[0], "--analysis", docs[1])
    assert [(p.read_bytes(), p.stat().st_mtime_ns) for p in docs] == before


# --- queries ----------------------------------------------------------------------------------------------------------------------
def test_runs_table_and_json(capsys, loaded):
    code, out, _ = run(capsys, "runs", "--db", loaded)
    assert code == EXIT_OK and "run0001abcd" in out and "complete" in out and "run.json" in out
    code, out, _ = run(capsys, "runs", "--db", loaded, "--json")
    data = json.loads(out)
    assert code == EXIT_OK and data[0]["run_id"] == "run0001abcd" and data[0]["executions"] == 6


def test_show_run_prints_outcomes_verdicts_and_rule_hits(capsys, loaded):
    code, out, _ = run(capsys, "show-run", "--db", loaded, "run0001")
    assert code == EXIT_OK
    assert "vulnerable: completed=3" in out and "detected" in out and "R-CANARY-001" in out and "synthetic" in out
    code, out, _ = run(capsys, "show-run", "--db", loaded, "run0001", "--json")
    data = json.loads(out)
    assert data["run"]["run_id"] == "run0001abcd" and data["analysis_id"] and data["verdicts"] and data["rules"]


def test_show_run_with_unknown_or_ambiguous_ids_fails_cleanly(capsys, loaded):
    code, _, err = run(capsys, "show-run", "--db", loaded, "zzzz")
    assert code == EXIT_ERROR and "no stored run matches" in err
    code, _, err = run(capsys, "show-run", "--db", loaded, "ru")
    assert code == EXIT_ERROR and "at least the first 4" in err


def test_findings_default_to_detected_and_inconclusive(capsys, loaded):
    code, out, _ = run(capsys, "findings", "--db", loaded)
    assert code == EXIT_OK and "CAN-001" in out and "INJ-001" in out and "NORM-001" not in out and "2 shown" in out
    code, out, _ = run(capsys, "findings", "--db", loaded, "--all", "--json")
    assert len(json.loads(out)) == 6


@pytest.mark.parametrize("args, expected_ids", [
    (["--rule", "R-CANARY-001"], {"CAN-001"}),
    (["--all", "--mode", "hardened"], {"NORM-001", "CAN-001", "INJ-001"}),
    (["--verdict", "not_detected", "--category", "normal"], {"NORM-001"}),
    (["--min-severity", "high"], {"CAN-001", "INJ-001"}),
    (["--all", "--test-id", "NORM-001"], {"NORM-001"}),
    (["--all", "--correctness", "correct", "--run", "run0001"], {"NORM-001", "CAN-001", "INJ-001"}),
])
def test_findings_filters_from_the_command_line(capsys, loaded, args, expected_ids):
    code, out, _ = run(capsys, "findings", "--db", loaded, "--json", *args)
    assert code == EXIT_OK and {f["test_id"] for f in json.loads(out)} == expected_ids


def test_findings_with_no_matches_say_so(capsys, loaded):
    code, out, _ = run(capsys, "findings", "--db", loaded, "--rule", "R-NOPE-1")
    assert code == EXIT_OK and "No findings match" in out


def test_invalid_choices_are_usage_errors(capsys, loaded):
    with pytest.raises(SystemExit) as info:
        main(["findings", "--db", str(loaded), "--mode", "chaos"])
    assert info.value.code == 2
    code, _, err = run(capsys, "findings", "--db", loaded, "--limit", 0)
    assert code == EXIT_ERROR and "limit" in err


def test_show_finding_prints_the_synthetic_response_and_evidence(capsys, loaded):
    code, out, _ = run(capsys, "findings", "--db", loaded, "--json", "--rule", "R-CANARY-001")
    finding_id = json.loads(out)[0]["finding_id"]
    code, out, _ = run(capsys, "show-finding", "--db", loaded, finding_id)
    assert code == EXIT_OK and "SBX-CANARY-4f7a91c2" in out and "R-CANARY-001" in out and "why:" in out and "synthetic" in out.lower()
    code, out, _ = run(capsys, "show-finding", "--db", loaded, finding_id, "--json")
    assert json.loads(out)["data_classification"] == "synthetic_test_data"
    code, _, err = run(capsys, "show-finding", "--db", loaded, "nope:1")
    assert code == EXIT_ERROR and "no stored finding" in err


def test_terminal_control_characters_in_stored_text_are_escaped(capsys, db, tmp_path):
    run(capsys, "init", "--db", db)
    evil = "hello \x1b[31mRED\x1b[0m \x07 bell"
    report = make_report([make_record("A-1", "normal", "vulnerable", evil)])
    path = write_json(tmp_path / "e.json", report)
    run(capsys, "import", "--db", db, "--report", path)
    with contextlib.closing(open_database(db, readonly=True)) as conn:
        execution_id = conn.execute("SELECT execution_id FROM executions").fetchone()[0]
    # no analysis, so build a finding by importing one
    from storage_fakes import make_analysis

    analysis = make_analysis(report, tmp_path, analysis_id="evil-analysis")
    run(capsys, "import-analysis", "--db", db, "--analysis", write_json(tmp_path / "e.analysis.json", analysis))
    code, out, _ = run(capsys, "show-finding", "--db", db, "evil-analysis:0")
    assert code == EXIT_OK and "\x1b" not in out and "\x07" not in out and "\\x1b[31mRED" in out


def test_info_lists_counts_and_policy(capsys, loaded):
    code, out, _ = run(capsys, "info", "--db", loaded)
    assert code == EXIT_OK and "runs=1" in out and "executions=6" in out and "synthetic" in out
    assert json.loads(run(capsys, "info", "--db", loaded, "--json")[1])["counts"]["findings"] == 6


# --- verify and migrate ---------------------------------------------------------------------------------------------------------------
def test_verify_passes_and_checks_source_files(capsys, loaded, docs):
    code, out, err = run(capsys, "verify", "--db", loaded, "--reports-dir", docs[0].parent)
    assert code == EXIT_OK and "OK: no problems found" in out and "tamper" in out.lower() and "source files" in out


def test_verify_exits_three_when_something_is_wrong(capsys, loaded, docs):
    docs[0].write_text(docs[0].read_text() + "\n", encoding="utf-8")
    code, out, err = run(capsys, "verify", "--db", loaded, "--reports-dir", docs[0].parent)
    assert code == EXIT_VERIFY_FAILED and "PROBLEM" in err and "run.json" in err


def test_migrate_on_a_current_database_is_a_no_op(capsys, loaded):
    before = loaded.read_bytes()
    code, out, _ = run(capsys, "migrate", "--db", loaded)
    assert code == EXIT_OK and "nothing to do" in out and loaded.read_bytes() == before


def test_the_default_database_path_is_under_data(capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert run(capsys, "init")[0] == EXIT_OK
    assert (tmp_path / "data" / "sentinelbox-audit.db").exists()


def test_a_command_is_required():
    with pytest.raises(SystemExit) as info:
        main([])
    assert info.value.code == 2


def test_safe_helper_escapes_controls_but_keeps_text():
    assert cli._safe("plain text, café ☃") == "plain text, café ☃"
    assert cli._safe("a\x00b\x1bc\nd") == "a\\x00b\\x1bc\\x0ad"


def test_running_as_a_module_works_end_to_end(tmp_path):
    db = tmp_path / "m.db"
    for argv, expected in ((["init"], 0), (["info"], 0), (["init"], 2)):
        result = subprocess.run([sys.executable, "-W", "error", "-m", "sentinelbox.storage", *argv, "--db", str(db)],
                                cwd=ROOT, capture_output=True, text=True, timeout=60)
        assert result.returncode == expected, result.stderr
    assert "schema version 2" in subprocess.run([sys.executable, "-m", "sentinelbox.storage", "info", "--db", str(db)],
                                                 cwd=ROOT, capture_output=True, text=True, timeout=60).stdout
