"""Pipeline test: Stage 2 runner (in-process, against the real mock) -> report file -> Stage 3 analysis."""

import json

import pytest
from runner_fakes import BASE_URL, MockAppTransport

from sentinelbox.rule_engine.analysis import analyze_report, read_report, validate_analysis
from sentinelbox.rule_engine.cli import EXIT_OK, main
from sentinelbox.rule_engine.expectations import load_expectations
from sentinelbox.runner.library import load_library
from sentinelbox.runner.models import TargetMode
from sentinelbox.runner.report import build_report, write_report
from sentinelbox.runner.runner import run_suite

LIBRARY = load_library()
BOTH = [TargetMode.VULNERABLE, TargetMode.HARDENED]


@pytest.fixture
def report_path(client, tmp_path):
    run = run_suite(LIBRARY.cases, BOTH, BASE_URL, MockAppTransport(client))
    return write_report(build_report(run, LIBRARY, BASE_URL, BOTH, 10.0), tmp_path / "runner.json")


@pytest.fixture
def analysis(report_path):
    return analyze_report(read_report(report_path), load_expectations())


def test_every_record_is_evaluated_and_the_analysis_is_valid(analysis):
    assert len(analysis["results"]) == 48 and validate_analysis(analysis) == []
    assert {r["execution_outcome"] for r in analysis["results"]} == {"completed"}
    assert analysis["input"]["records_with_input_problems"] == 0


def test_vulnerable_mode_scores_18_detections_and_6_clean_controls(analysis):
    m = analysis["metrics_by_mode"]["vulnerable"]
    assert m["confusion"] == {"tp": 18, "fp": 0, "tn": 6, "fn": 0}
    assert m["verdict_counts"] == {"detected": 18, "not_detected": 6, "inconclusive": 0, "not_evaluated": 0}
    assert (m["precision"]["value"], m["recall"]["value"], m["f1"]["value"]) == (1.0, 1.0, 1.0)


def test_hardened_mode_has_no_positives_so_precision_recall_and_f1_are_undefined(analysis):
    m = analysis["metrics_by_mode"]["hardened"]
    assert m["confusion"] == {"tp": 0, "fp": 0, "tn": 24, "fn": 0}
    for name in ("precision", "recall", "f1"):
        assert m[name]["value"] is None and m[name]["note"].startswith("undefined")


def test_every_hardened_refusal_that_mentions_attack_words_stays_not_detected(analysis):
    refusals = [r for r in analysis["results"] if r["target_mode"] == "hardened" and r["category"] != "normal"]
    assert len(refusals) == 18
    assert {r["verdict"] for r in refusals} == {"not_detected"} and all(r["refusal_language"] for r in refusals)


def test_all_48_detections_are_correct_against_the_labels(analysis):
    assert {r["detection_correctness"] for r in analysis["results"]} == {"correct"}


def test_detections_explain_themselves_with_rules_evidence_and_severity(analysis):
    leak = next(r for r in analysis["results"] if r["test_id"] == "CAN-001" and r["target_mode"] == "vulnerable")
    assert {m["rule_id"] for m in leak["matches"]} == {"R-CANARY-001", "R-CANARY-002"}
    assert leak["max_severity"] == "high" and all(m["rationale"] and m["evidence"]["text"] for m in leak["matches"])
    injection = next(r for r in analysis["results"] if r["test_id"] == "INJ-001" and r["target_mode"] == "vulnerable")
    assert {m["rule_id"] for m in injection["matches"]} == {"R-INJ-001", "R-INJ-002"}


def test_verdicts_agree_with_the_mocks_own_ground_truth(report_path, analysis):
    """Test-only: this is the one place that may read the mock's meta, to measure the engine from outside."""
    raw = json.loads(report_path.read_text(encoding="utf-8"))["results"]
    verdict = {(r["test_id"], r["target_mode"]): r["verdict"] for r in analysis["results"]}
    for record in raw:
        scenario = json.loads(record["raw_body"])["meta"]["scenario"]
        attack_succeeded = record["target_mode"] == "vulnerable" and scenario != "normal"
        assert (verdict[(record["test_id"], record["target_mode"])] == "detected") == attack_succeeded


def test_scrambling_meta_in_the_report_changes_nothing(report_path, tmp_path):
    baseline = analyze_report(read_report(report_path), load_expectations(), analysis_id="a", now=None)
    data = json.loads(report_path.read_text(encoding="utf-8"))
    for i, record in enumerate(data["results"]):
        body = json.loads(record["raw_body"])
        body["meta"] = {"scenario": ["normal", "canary_disclosure", "prompt_injection", "safety_bypass"][i % 4],
                        "mode": "hardened", "matched_rule": f"liar_{i}", "deterministic": False}
        record["raw_body"] = json.dumps(body)
    scrambled_path = tmp_path / "scrambled.json"
    scrambled_path.write_text(json.dumps(data), encoding="utf-8")
    scrambled = analyze_report(read_report(scrambled_path), load_expectations(), analysis_id="a", now=None)
    strip = lambda a: [{k: v for k, v in r.items()} for r in a["results"]]  # noqa: E731
    assert strip(scrambled) == strip(baseline)
    assert scrambled["metrics_by_mode"] == baseline["metrics_by_mode"]


def test_removing_raw_bodies_entirely_changes_nothing(report_path, tmp_path):
    data = json.loads(report_path.read_text(encoding="utf-8"))
    baseline = analyze_report(read_report(report_path), load_expectations())["results"]
    for record in data["results"]:
        record["raw_body"] = None
    stripped = tmp_path / "stripped.json"
    stripped.write_text(json.dumps(data), encoding="utf-8")
    assert analyze_report(read_report(stripped), load_expectations())["results"] == baseline


def test_cli_end_to_end_on_a_real_runner_report(report_path, capsys):
    before = report_path.read_bytes()
    assert main(["analyze", "--report", str(report_path)]) == EXIT_OK
    assert report_path.read_bytes() == before
    out_path = report_path.with_name("runner.analysis.json")
    assert validate_analysis(json.loads(out_path.read_text(encoding="utf-8"))) == []
    text = capsys.readouterr().out
    assert "vulnerable" in text and "hardened" in text and "n/a" in text
