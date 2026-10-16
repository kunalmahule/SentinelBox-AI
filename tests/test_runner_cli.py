"""Command-line interface behaviour (fake transport injected; no sockets)."""

import json
import subprocess
import sys
from pathlib import Path

import pytest
from runner_fakes import FakeTransport, ok, raw

from sentinelbox.runner.cli import EXIT_EXECUTION_PROBLEMS, EXIT_INTERRUPTED, EXIT_OK, EXIT_USAGE, main
from sentinelbox.runner.report import validate_report
from sentinelbox.runner.transport import TransportConnectionError

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def run_cli(tmp_path, *args, transport=None):
    out = tmp_path / "report.json"
    code = main(["--output", str(out), *args], transport=transport or FakeTransport())
    return code, out


def test_successful_run_exits_zero_writes_a_valid_report_and_prints_a_summary(tmp_path, capsys):
    code, out = run_cli(tmp_path)
    assert code == EXIT_OK
    report = json.loads(out.read_text(encoding="utf-8"))
    assert validate_report(report) == []
    assert report["summary"]["planned"] == 48 and report["modes"] == ["vulnerable", "hardened"]
    text = capsys.readouterr().out
    assert "48 attempted of 48 planned" in text and str(out) in text


@pytest.mark.parametrize("mode, expected", [("vulnerable", ["vulnerable"]), ("hardened", ["hardened"]),
                                            ("both", ["vulnerable", "hardened"])])
def test_mode_option_selects_target_modes(tmp_path, mode, expected):
    transport = FakeTransport()
    code, out = run_cli(tmp_path, "--mode", mode, transport=transport)
    assert code == EXIT_OK
    assert json.loads(out.read_text())["modes"] == expected
    assert {c["payload"]["mode"] for c in transport.calls} == set(expected)


def test_category_filter_limits_cases(tmp_path):
    transport = FakeTransport()
    code, out = run_cli(tmp_path, "--mode", "vulnerable", "--category", "prompt_injection", "--category", "normal",
                        transport=transport)
    assert code == EXIT_OK
    categories = {r["category"] for r in json.loads(out.read_text())["results"]}
    assert categories == {"prompt_injection", "normal"} and len(transport.calls) == 12


def test_default_output_goes_to_reports_directory_in_the_working_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main(["--mode", "vulnerable", "--category", "normal"], transport=FakeTransport()) == EXIT_OK
    files = list((tmp_path / "reports").glob("sbx-run-*.json"))
    assert len(files) == 1 and validate_report(json.loads(files[0].read_text())) == []


def test_verbose_prints_one_line_per_case(tmp_path, capsys):
    run_cli(tmp_path, "--mode", "hardened", "--category", "normal", "--verbose")
    out = capsys.readouterr().out
    assert out.count("NORM-00") == 6 and "completed" in out


def test_execution_problems_give_exit_code_one_but_still_write_the_report(tmp_path, capsys):
    code, out = run_cli(tmp_path, "--mode", "vulnerable", transport=FakeTransport([ok(), raw(500, "x")]))
    assert code == EXIT_EXECUTION_PROBLEMS
    report = json.loads(out.read_text())
    assert validate_report(report) == [] and report["summary"]["by_outcome"]["http_error"] > 0
    assert "Execution problems" in capsys.readouterr().out


def test_unreachable_target_aborts_with_exit_one_and_a_partial_report(tmp_path):
    transport = FakeTransport([TransportConnectionError("Connection refused")])
    code, out = run_cli(tmp_path, transport=transport)
    assert code == EXIT_EXECUTION_PROBLEMS
    report = json.loads(out.read_text())
    assert report["status"] == "aborted" and report["summary"]["by_outcome"]["not_run"] == 45
    assert len(transport.calls) == 3 and validate_report(report) == []


def test_max_consecutive_failures_option_is_respected(tmp_path):
    transport = FakeTransport([TransportConnectionError("x")])
    run_cli(tmp_path, "--max-consecutive-failures", "1", transport=transport)
    assert len(transport.calls) == 1


def test_ctrl_c_writes_a_partial_report_and_exits_130(tmp_path, capsys):
    code, out = run_cli(tmp_path, transport=FakeTransport([ok(), ok(), KeyboardInterrupt()]))
    assert code == EXIT_INTERRUPTED
    report = json.loads(out.read_text())
    assert report["status"] == "interrupted" and report["summary"]["attempted"] == 2
    assert validate_report(report) == [] and "interrupted" in capsys.readouterr().out


@pytest.mark.parametrize("url", ["http://example.com", "https://127.0.0.1:8001", "http://10.0.0.1:8001", "garbage"])
def test_non_loopback_urls_are_a_usage_error_and_send_nothing(tmp_path, capsys, url):
    transport = FakeTransport()
    code, out = run_cli(tmp_path, "--url", url, transport=transport)
    assert code == EXIT_USAGE and transport.calls == [] and not out.exists()
    assert "error:" in capsys.readouterr().err


def test_missing_or_invalid_library_is_a_usage_error(tmp_path, capsys):
    transport = FakeTransport()
    assert run_cli(tmp_path, "--library", str(tmp_path / "nope.json"), transport=transport)[0] == EXIT_USAGE
    bad = tmp_path / "bad.json"
    bad.write_text("{oops", encoding="utf-8")
    assert run_cli(tmp_path, "--library", str(bad), transport=transport)[0] == EXIT_USAGE
    assert transport.calls == [] and "error:" in capsys.readouterr().err


def test_category_missing_from_a_custom_library_is_a_usage_error(tmp_path, capsys):
    lib = tmp_path / "lib.json"
    lib.write_text(json.dumps({"schema_version": 1, "name": "n", "version": "1",
                               "cases": [{"id": "A", "category": "normal", "title": "t", "prompt": "hi"}]}))
    code, _ = run_cli(tmp_path, "--library", str(lib), "--category", "safety_bypass")
    assert code == EXIT_USAGE and "no test cases" in capsys.readouterr().err


@pytest.mark.parametrize("args", [["--timeout", "0"], ["--timeout", "-3"], ["--max-consecutive-failures", "0"]])
def test_invalid_numeric_options_are_a_usage_error(tmp_path, args):
    assert run_cli(tmp_path, *args)[0] == EXIT_USAGE


def test_existing_output_file_is_not_replaced_and_no_requests_are_made(tmp_path, capsys):
    out = tmp_path / "report.json"
    out.write_text("keep me", encoding="utf-8")
    transport = FakeTransport()
    code = main(["--output", str(out)], transport=transport)
    assert code == EXIT_USAGE and transport.calls == []
    assert out.read_text(encoding="utf-8") == "keep me"
    assert "already exists" in capsys.readouterr().err


def test_overwrite_flag_replaces_an_existing_report(tmp_path):
    out = tmp_path / "report.json"
    out.write_text("old", encoding="utf-8")
    assert main(["--output", str(out), "--overwrite", "--category", "normal"], transport=FakeTransport()) == EXIT_OK
    assert validate_report(json.loads(out.read_text())) == []


def test_unwritable_output_prints_the_summary_and_exits_with_usage_error(tmp_path, capsys):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    code = main(["--output", str(blocker / "sub" / "r.json"), "--category", "normal"], transport=FakeTransport())
    captured = capsys.readouterr()
    assert code == EXIT_USAGE and "could not write report" in captured.err and "attempted" in captured.out


@pytest.mark.parametrize("args", [["--mode", "reckless"], ["--category", "nope"], ["--unknown-flag"]])
def test_invalid_choices_exit_with_argparse_error(args):
    with pytest.raises(SystemExit) as info:
        main(args, transport=FakeTransport())
    assert info.value.code == 2


def test_module_entry_point_works_and_refuses_external_targets():
    help_run = subprocess.run([sys.executable, "-m", "sentinelbox.runner", "--help"], cwd=PROJECT_ROOT,
                              capture_output=True, text=True, timeout=30)
    assert help_run.returncode == 0 and "--mode" in help_run.stdout
    refused = subprocess.run([sys.executable, "-m", "sentinelbox.runner", "--url", "http://example.com"], cwd=PROJECT_ROOT,
                             capture_output=True, text=True, timeout=30)
    assert refused.returncode == 2 and "Refusing" in refused.stderr
