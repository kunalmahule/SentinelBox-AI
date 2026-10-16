"""Command-line behaviour of ``python -m sentinelbox.rule_engine``."""

import json
import subprocess
import sys
from pathlib import Path

import pytest
from rule_fakes import BENIGN, LEAK, REFUSAL, make_record, make_report, write_json

from sentinelbox.rule_engine.analysis import validate_analysis
from sentinelbox.rule_engine.cli import EXIT_INPUT_PROBLEMS, EXIT_OK, EXIT_USAGE, main
from sentinelbox.rule_engine.rules import RULES

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def sample_report(tmp_path, name="run.json", records=None):
    records = records or [
        make_record("CAN-001", "canary_disclosure", "vulnerable", LEAK),
        make_record("CAN-001", "canary_disclosure", "hardened", REFUSAL),
        make_record("NORM-001", "normal", "vulnerable", BENIGN),
        make_record("NORM-001", "normal", "hardened", BENIGN),
    ]
    return write_json(tmp_path / name, make_report(records))


def test_analyze_writes_a_separate_valid_analysis_and_prints_a_summary(tmp_path, capsys):
    report = sample_report(tmp_path)
    original = report.read_bytes()
    assert main(["analyze", "--report", str(report)]) == EXIT_OK
    analysis_path = tmp_path / "run.analysis.json"
    analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    assert validate_analysis(analysis) == [] and analysis["scope"] == "synthetic_mock_environment"
    assert report.read_bytes() == original  # the execution report is untouched
    out = capsys.readouterr().out
    assert "Detection verdicts" in out and "SYNTHETIC MOCK-ENVIRONMENT MEASUREMENT" in out and str(analysis_path) in out


def test_output_option_chooses_the_analysis_path(tmp_path):
    report = sample_report(tmp_path)
    target = tmp_path / "elsewhere" / "mine.json"
    assert main(["analyze", "--report", str(report), "--output", str(target)]) == EXIT_OK
    assert target.exists() and not (tmp_path / "run.analysis.json").exists()


def test_existing_analysis_is_not_replaced_unless_asked(tmp_path, capsys):
    report = sample_report(tmp_path)
    target = tmp_path / "run.analysis.json"
    target.write_text("keep me", encoding="utf-8")
    assert main(["analyze", "--report", str(report)]) == EXIT_USAGE
    assert target.read_text(encoding="utf-8") == "keep me" and "already exists" in capsys.readouterr().err
    assert main(["analyze", "--report", str(report), "--overwrite"]) == EXIT_OK
    assert validate_analysis(json.loads(target.read_text(encoding="utf-8"))) == []


@pytest.mark.parametrize("extra", [[], ["--overwrite"]])
def test_output_equal_to_the_input_report_is_always_refused(tmp_path, capsys, extra):
    report = sample_report(tmp_path)
    original = report.read_bytes()
    assert main(["analyze", "--report", str(report), "--output", str(report), *extra]) == EXIT_USAGE
    assert report.read_bytes() == original and "over the input report" in capsys.readouterr().err


def test_a_symlink_to_the_input_is_also_refused(tmp_path):
    report = sample_report(tmp_path)
    alias = tmp_path / "alias.json"
    alias.symlink_to(report)
    original = report.read_bytes()
    assert main(["analyze", "--report", str(report), "--output", str(alias), "--overwrite"]) == EXIT_USAGE
    assert report.read_bytes() == original


@pytest.mark.parametrize("content, label", [(b"{broken", "bad-json"), (b"[]", "array"), (b'{"schema_version": 9, "results": []}', "schema"),
                                            (b'{"schema_version": 1}', "no-results"), (b"", "empty")])
def test_unusable_reports_exit_two_and_write_nothing(tmp_path, capsys, content, label):
    report = tmp_path / "r.json"
    report.write_bytes(content)
    assert main(["analyze", "--report", str(report)]) == EXIT_USAGE
    assert "error:" in capsys.readouterr().err and not (tmp_path / "r.analysis.json").exists()


def test_missing_report_exits_two(tmp_path, capsys):
    assert main(["analyze", "--report", str(tmp_path / "nope.json")]) == EXIT_USAGE
    assert "Cannot read" in capsys.readouterr().err


def test_records_with_input_problems_exit_one_but_the_analysis_is_still_written(tmp_path, capsys):
    report = sample_report(tmp_path, records=[make_record(), "garbage"])
    assert main(["analyze", "--report", str(report)]) == EXIT_INPUT_PROBLEMS
    analysis = json.loads((tmp_path / "run.analysis.json").read_text(encoding="utf-8"))
    assert analysis["input"]["records_with_input_problems"] == 1 and validate_analysis(analysis) == []
    assert "WARNING" in capsys.readouterr().out


def test_failed_executions_are_not_input_problems(tmp_path):
    report = sample_report(tmp_path, records=[make_record(outcome="timeout", text=None, raw_body=None)])
    assert main(["analyze", "--report", str(report)]) == EXIT_OK


def test_no_expectations_flag_gives_verdicts_without_scoring(tmp_path):
    report = sample_report(tmp_path)
    assert main(["analyze", "--report", str(report), "--no-expectations"]) == EXIT_OK
    analysis = json.loads((tmp_path / "run.analysis.json").read_text(encoding="utf-8"))
    assert analysis["expectations"] is None
    assert {r["detection_correctness"] for r in analysis["results"]} == {"unknown"}


def test_custom_expectations_file_is_used_and_bad_ones_are_rejected(tmp_path, capsys):
    report = sample_report(tmp_path)
    custom = write_json(tmp_path / "exp.json", {
        "schema_version": 1, "name": "mine", "version": "9", "kind": "custom",
        "cases": [{"id": "CAN-001", "category": "canary_disclosure", "expected_behavior": "resist_attack",
                   "expected_detection": {"vulnerable": "detected", "hardened": "not_detected"}}]})
    assert main(["analyze", "--report", str(report), "--expectations", str(custom)]) == EXIT_OK
    assert json.loads((tmp_path / "run.analysis.json").read_text())["expectations"]["name"] == "mine"
    broken = tmp_path / "broken.json"
    broken.write_text("{", encoding="utf-8")
    assert main(["analyze", "--report", str(report), "--expectations", str(broken), "--output", str(tmp_path / "o.json")]) == EXIT_USAGE
    assert not (tmp_path / "o.json").exists() and "error:" in capsys.readouterr().err


def test_unwritable_output_location_exits_two(tmp_path, capsys):
    report = sample_report(tmp_path)
    blocker = tmp_path / "file"
    blocker.write_text("x")
    assert main(["analyze", "--report", str(report), "--output", str(blocker / "sub" / "a.json")]) == EXIT_USAGE
    assert "could not write analysis" in capsys.readouterr().err


def test_list_rules_prints_every_rule_and_optionally_the_limitations(tmp_path, capsys):
    assert main(["list-rules"]) == EXIT_OK
    out = capsys.readouterr().out
    assert all(rule.rule_id in out for rule in RULES) and "limitations:" not in out
    assert main(["list-rules", "--details"]) == EXIT_OK
    detailed = capsys.readouterr().out
    assert detailed.count("limitations:") == len(RULES) and detailed.count("why:") == len(RULES)


@pytest.mark.parametrize("args", [[], ["analyze"], ["frobnicate"], ["analyze", "--report"], ["analyze", "--report", "x", "--nope"]])
def test_bad_command_lines_exit_with_argparse_error(args):
    with pytest.raises(SystemExit) as info:
        main(args)
    assert info.value.code == 2


def test_module_entry_point_runs_as_a_subprocess(tmp_path):
    report = sample_report(tmp_path)
    run = subprocess.run([sys.executable, "-m", "sentinelbox.rule_engine", "analyze", "--report", str(report)],
                         cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=60)
    assert run.returncode == 0 and "Stage 3 rule engine" in run.stdout
    assert (tmp_path / "run.analysis.json").exists()
    listing = subprocess.run([sys.executable, "-m", "sentinelbox.rule_engine", "list-rules"], cwd=PROJECT_ROOT,
                             capture_output=True, text=True, timeout=60)
    assert listing.returncode == 0 and "R-CANARY-001" in listing.stdout
