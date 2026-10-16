"""JSON report: building, validating, writing and the terminal summary."""

import copy
import json
import math

import pytest
from runner_fakes import BASE_URL, FakeTransport, fake_clock, fake_timer, ok, raw

from sentinelbox.runner.library import load_library
from sentinelbox.runner.models import TargetMode
from sentinelbox.runner.report import (
    build_report,
    default_report_name,
    format_summary,
    validate_report,
    write_report,
)
from sentinelbox.runner.runner import run_suite
from sentinelbox.runner.transport import TransportConnectionError, TransportTimeout

V, H = TargetMode.VULNERABLE, TargetMode.HARDENED
LIBRARY = load_library()


def make_report(script=None, cases=None, modes=(V, H), **kwargs):
    cases = LIBRARY.cases[:6] if cases is None else cases
    run = run_suite(cases, list(modes), BASE_URL, FakeTransport(script), clock=fake_clock(), timer=fake_timer(), **kwargs)
    return build_report(run, LIBRARY, BASE_URL, list(modes), 10.0, run_id="abc12345deadbeef")


def mixed_report():
    script = [ok("fine"), raw(500, "oops"), TransportTimeout("slow"), raw(200, "not json"), ok("fine")]
    return make_report(script, modes=(V,))


# --- building ------------------------------------------------------------------
def test_built_report_is_valid_and_has_the_expected_top_level_shape():
    report = make_report()
    assert validate_report(report) == []
    assert report["schema_version"] == 1
    assert report["run_id"] == "abc12345deadbeef"
    assert report["status"] == "complete" and report["stop_reason"] is None
    assert report["modes"] == ["vulnerable", "hardened"]
    assert report["target"] == {"base_url": BASE_URL, "chat_path": "/chat", "timeout_seconds": 10.0}
    assert report["library"] == {
        "name": LIBRARY.name, "version": LIBRARY.version, "file_name": LIBRARY.file_name,
        "sha256": LIBRARY.sha256, "case_count": 24,
    }
    assert report["tool"]["name"] == "sentinelbox-runner"
    assert "No security verdict" in report["note"]


def test_report_round_trips_through_json_unchanged():
    report = mixed_report()
    assert json.loads(json.dumps(report, allow_nan=False)) == report


def test_summary_counts_match_the_results():
    report = mixed_report()
    summary = report["summary"]
    assert summary["planned"] == 6 and summary["attempted"] == 6
    assert summary["by_outcome"] == {
        "completed": 3, "http_error": 1, "timeout": 1, "connection_error": 0,
        "invalid_response": 1, "runner_error": 0, "not_run": 0,
    }
    assert sum(sum(c.values()) for c in summary["by_category"].values()) == 6
    assert set(summary["by_mode"]) == {"vulnerable"}


def test_partial_run_report_is_valid_and_counts_not_run():
    report = make_report([ok(), TransportConnectionError("refused")], modes=(V,))
    assert validate_report(report) == []
    assert report["status"] == "aborted"
    assert report["summary"]["attempted"] == 4 and report["summary"]["by_outcome"]["not_run"] == 2
    assert "3 consecutive" in report["stop_reason"]


def test_report_results_contain_no_scenario_information():
    text = json.dumps([r for r in make_report()["results"]])
    assert "scenario" not in text and "matched_rule" not in text  # the fake replies carry no meta


def test_empty_run_report_is_still_valid():
    report = make_report(cases=[], modes=(V,))
    assert validate_report(report) == [] and report["results"] == []


# --- validation catches damage ----------------------------------------------------
def _mutate(change):
    report = copy.deepcopy(mixed_report())
    change(report)
    return report


BAD_MUTATIONS = {
    "wrong-schema": lambda r: r.update(schema_version=9),
    "missing-run-id": lambda r: r.pop("run_id"),
    "empty-started": lambda r: r.update(started_at=""),
    "bad-status": lambda r: r.update(status="fine"),
    "target-not-object": lambda r: r.update(target="x"),
    "no-modes": lambda r: r.update(modes=[]),
    "unknown-mode": lambda r: r.update(modes=["chaotic"]),
    "results-not-list": lambda r: r.update(results={}),
    "result-not-object": lambda r: r["results"].__setitem__(0, "x"),
    "extra-result-field": lambda r: r["results"][0].update(meta={}),
    "missing-result-field": lambda r: r["results"][0].pop("raw_body"),
    "unknown-outcome": lambda r: r["results"][0].update(outcome="maybe"),
    "unknown-category": lambda r: r["results"][0].update(category="magic"),
    "unknown-target-mode": lambda r: r["results"][0].update(target_mode="chaotic"),
    "completed-without-text": lambda r: r["results"][0].update(response_text=None),
    "completed-wrong-status": lambda r: r["results"][0].update(http_status=201),
    "text-on-failed-case": lambda r: r["results"][1].update(response_text="x"),
    "bool-status": lambda r: r["results"][0].update(http_status=True),
    "string-status": lambda r: r["results"][0].update(http_status="200"),
    "negative-duration": lambda r: r["results"][0].update(duration_ms=-1),
    "nan-duration": lambda r: r["results"][0].update(duration_ms=math.nan),
    "non-bool-truncated": lambda r: r["results"][0].update(raw_body_truncated="no"),
    "attempted-without-timestamp": lambda r: r["results"][0].update(timestamp=None),
    "summary-planned": lambda r: r["summary"].update(planned=99),
    "summary-outcomes": lambda r: r["summary"]["by_outcome"].update(completed=0),
    "summary-attempted": lambda r: r["summary"].update(attempted=0),
}


@pytest.mark.parametrize("name", list(BAD_MUTATIONS))
def test_validator_rejects_damaged_reports(name):
    assert validate_report(_mutate(BAD_MUTATIONS[name])) != []


def test_validator_rejects_not_run_case_with_timestamp():
    report = copy.deepcopy(make_report([ok(), TransportConnectionError("x")], modes=(V,)))
    not_run = next(r for r in report["results"] if r["outcome"] == "not_run")
    not_run["timestamp"] = "2026-01-01T00:00:00+00:00"
    assert any("not_run" in p for p in validate_report(report))


@pytest.mark.parametrize("junk", [None, [], "report", 5])
def test_validator_rejects_non_objects(junk):
    assert validate_report(junk) == ["report is not an object"]


# --- writing ----------------------------------------------------------------------
def test_write_report_creates_parent_dirs_and_valid_json(tmp_path):
    report = make_report()
    path = write_report(report, tmp_path / "nested" / "dir" / "run.json")
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert loaded == report and validate_report(loaded) == []
    assert path.read_text(encoding="utf-8").endswith("}\n")


def test_write_report_keeps_unicode_readable(tmp_path):
    report = make_report([ok("你好 \U0001F680 café")], cases=LIBRARY.cases[:1], modes=(V,))
    path = write_report(report, tmp_path / "u.json")
    assert "你好" in path.read_text(encoding="utf-8")
    assert json.loads(path.read_text(encoding="utf-8"))["results"][0]["response_text"] == "你好 \U0001F680 café"


def test_write_report_refuses_to_overwrite_by_default(tmp_path):
    target = tmp_path / "run.json"
    target.write_text("precious", encoding="utf-8")
    with pytest.raises(FileExistsError):
        write_report(make_report(), target)
    assert target.read_text(encoding="utf-8") == "precious"


def test_write_report_can_overwrite_when_asked(tmp_path):
    target = tmp_path / "run.json"
    target.write_text("old", encoding="utf-8")
    write_report(make_report(), target, overwrite=True)
    assert json.loads(target.read_text(encoding="utf-8"))["schema_version"] == 1


def test_write_report_refuses_invalid_reports_and_writes_nothing(tmp_path):
    bad = make_report()
    bad["status"] = "nonsense"
    with pytest.raises(ValueError, match="invalid report"):
        write_report(bad, tmp_path / "bad.json")
    assert list(tmp_path.iterdir()) == []


def test_write_report_leaves_no_temp_files_behind(tmp_path):
    write_report(make_report(), tmp_path / "run.json")
    assert [p.name for p in tmp_path.iterdir()] == ["run.json"]


def test_default_report_name_is_sortable_and_filesystem_safe():
    name = default_report_name(make_report())
    assert name == "sbx-run-20260102-030405-abc12345.json"
    assert all(ch not in name for ch in ':/\\ ')


# --- terminal summary -----------------------------------------------------------------
def test_summary_is_concise_and_contains_key_facts():
    one_per_category = LIBRARY.cases[::6]  # NORM-001, INJ-001, BYP-001, CAN-001
    text = format_summary(make_report(cases=one_per_category), "reports/run.json")
    assert len(text.splitlines()) <= 25
    for expected in ("abc12345", "status: complete", BASE_URL, LIBRARY.name, "8 attempted of 8 planned",
                     "vulnerable", "hardened", "normal", "prompt_injection", "safety_bypass",
                     "canary_disclosure", "Report: reports/run.json"):
        assert expected in text
    assert "No safe/unsafe verdict" in text


def test_summary_lists_execution_problems_with_reasons():
    text = format_summary(mixed_report())
    assert "Execution problems (3)" in text
    assert "http_error: HTTP 500" in text and "timeout: slow" in text and "invalid_response:" in text


def test_summary_caps_the_problem_list():
    report = make_report([TransportConnectionError("refused")], cases=LIBRARY.cases[:12], modes=(V,), max_consecutive_failures=99)
    text = format_summary(report, max_failures_shown=3)
    assert "Execution problems (12)" in text and "... and 9 more" in text


def test_summary_for_an_aborted_run_shows_the_reason_and_not_run_count():
    text = format_summary(make_report([TransportConnectionError("refused")], modes=(V,)))
    assert "status: aborted" in text and "Stopped after 3 consecutive" in text
    assert "3 attempted of 6 planned" in text


def test_summary_without_a_path_omits_the_report_line():
    assert "Report:" not in format_summary(make_report())
