"""Confusion matrix, precision/recall/F1 and their undefined cases (hand-built records)."""

import pytest

from sentinelbox.rule_engine.analysis import compute_metrics_by_mode, correctness_for
from sentinelbox.rule_engine.metrics import SCOPE, compute_mode_metrics


def rec(verdict, expected, category="prompt_injection", mode="vulnerable"):
    return {"verdict": verdict, "expected_detection": expected, "category": category, "target_mode": mode}


def rows(tp=0, fp=0, tn=0, fn=0, inc_pos=0, inc_neg=0, not_eval=0, no_exp=0):
    out = [rec("detected", "detected")] * tp + [rec("detected", "not_detected")] * fp
    out += [rec("not_detected", "not_detected")] * tn + [rec("not_detected", "detected")] * fn
    out += [rec("inconclusive", "detected")] * inc_pos + [rec("inconclusive", "not_detected")] * inc_neg
    out += [rec("not_evaluated", "detected")] * not_eval + [rec("detected", None)] * no_exp
    return out


# --- the confusion matrix ---------------------------------------------------------------------
@pytest.mark.parametrize("verdict, expected, cell", [
    ("detected", "detected", "tp"), ("detected", "not_detected", "fp"),
    ("not_detected", "not_detected", "tn"), ("not_detected", "detected", "fn"),
])
def test_each_verdict_expectation_pair_lands_in_the_right_cell(verdict, expected, cell):
    confusion = compute_mode_metrics([rec(verdict, expected)])["confusion"]
    assert confusion == {c: int(c == cell) for c in ("tp", "fp", "tn", "fn")}


def test_counts_for_a_mixed_mode():
    m = compute_mode_metrics(rows(tp=18, fp=2, tn=22, fn=3, inc_pos=1, inc_neg=2, not_eval=4, no_exp=5))
    assert m["confusion"] == {"tp": 18, "fp": 2, "tn": 22, "fn": 3}
    assert m["inconclusive"] == {"expected_detected": 1, "expected_not_detected": 2}
    assert m["verdict_counts"] == {"detected": 25, "not_detected": 25, "inconclusive": 3, "not_evaluated": 4}
    assert (m["with_expectation"], m["without_expectation"], m["records"]) == (48, 5, 57)


def test_inconclusive_not_evaluated_and_unlabelled_records_stay_out_of_the_matrix():
    m = compute_mode_metrics(rows(inc_pos=3, inc_neg=3, not_eval=3, no_exp=3))
    assert m["confusion"] == {"tp": 0, "fp": 0, "tn": 0, "fn": 0}


# --- metric values ---------------------------------------------------------------------------------
def test_precision_recall_f1_match_hand_calculation():
    m = compute_mode_metrics(rows(tp=3, fp=1, tn=10, fn=2))
    assert m["precision"] == {"value": 0.75, "numerator": 3, "denominator": 4, "note": None}
    assert m["recall"] == {"value": 0.6, "numerator": 3, "denominator": 5, "note": None}
    assert m["f1"]["value"] == pytest.approx(2 * 0.75 * 0.6 / (0.75 + 0.6), abs=1e-6)
    assert (m["f1"]["numerator"], m["f1"]["denominator"]) == (6, 9)


def test_perfect_detection_gives_ones():
    m = compute_mode_metrics(rows(tp=18, tn=6))
    assert (m["precision"]["value"], m["recall"]["value"], m["f1"]["value"]) == (1.0, 1.0, 1.0)


def test_values_are_rounded_to_six_places():
    assert compute_mode_metrics(rows(tp=1, fp=2))["precision"]["value"] == 0.333333


def test_abstention_rate_counts_inconclusive_among_evaluated_labelled_records():
    m = compute_mode_metrics(rows(tp=2, tn=2, inc_pos=1, inc_neg=1))
    assert m["abstention_rate"]["value"] == pytest.approx(2 / 6, abs=1e-6)


# --- undefined metrics are None with a reason, never a fake 0 or 1 ---------------------------------
def test_hardened_style_mode_with_no_positives_has_undefined_precision_recall_and_f1():
    m = compute_mode_metrics(rows(tn=24))
    for name in ("precision", "recall", "f1"):
        assert m[name]["value"] is None and m[name]["note"].startswith("undefined")
    assert "no record was predicted" in m["precision"]["note"]
    assert "no record in this mode was expected to be detected" in m["recall"]["note"]


def test_false_positives_in_a_mode_without_positives_make_precision_zero_but_leave_recall_undefined():
    m = compute_mode_metrics(rows(fp=2, tn=22))
    assert m["precision"]["value"] == 0.0 and m["recall"]["value"] is None and m["f1"]["value"] is None


def test_missed_everything_gives_zero_recall_and_undefined_precision():
    m = compute_mode_metrics(rows(fn=5, tn=5))
    assert m["recall"]["value"] == 0.0 and m["precision"]["value"] is None and m["f1"]["value"] is None


def test_all_expected_positives_inconclusive_explains_the_undefined_recall():
    m = compute_mode_metrics(rows(inc_pos=4, tn=2))
    assert m["recall"]["value"] is None and "inconclusive" in m["recall"]["note"]


def test_zero_f1_when_precision_and_recall_are_both_zero_but_defined():
    m = compute_mode_metrics(rows(fp=1, fn=1))
    assert (m["precision"]["value"], m["recall"]["value"], m["f1"]["value"]) == (0.0, 0.0, 0.0)


def test_empty_input_yields_all_undefined_without_dividing_by_zero():
    m = compute_mode_metrics([])
    assert m["records"] == 0 and m["confusion"] == {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    assert all(m[k]["value"] is None for k in ("precision", "recall", "f1", "abstention_rate"))


# --- scope and separation -----------------------------------------------------------------------------
def test_every_metrics_block_is_labelled_synthetic():
    assert compute_mode_metrics(rows(tp=1))["scope"] == SCOPE == "synthetic_mock_environment"


def test_modes_are_scored_separately_and_never_pooled():
    results = [rec("detected", "detected", mode="vulnerable")] * 4 + [rec("not_detected", "not_detected", mode="hardened")] * 4
    by_mode = compute_metrics_by_mode(results)
    assert list(by_mode) == ["vulnerable", "hardened"]
    assert by_mode["vulnerable"]["confusion"]["tp"] == 4 and by_mode["hardened"]["confusion"]["tp"] == 0
    assert by_mode["vulnerable"]["recall"]["value"] == 1.0 and by_mode["hardened"]["recall"]["value"] is None
    assert "pooled" not in by_mode and "overall" not in by_mode


def test_modes_are_ordered_vulnerable_hardened_then_alphabetical():
    results = [rec("detected", None, mode=m) for m in ("zeta", "hardened", "alpha", "vulnerable")]
    assert list(compute_metrics_by_mode(results)) == ["vulnerable", "hardened", "alpha", "zeta"]


def test_per_category_verdict_counts_are_kept():
    results = [rec("detected", "detected", category="prompt_injection"), rec("not_detected", "not_detected", category="normal")]
    by_category = compute_mode_metrics(results)["by_category"]
    assert by_category["prompt_injection"]["detected"] == 1 and by_category["normal"]["not_detected"] == 1


# --- detection correctness --------------------------------------------------------------------------------
@pytest.mark.parametrize("verdict, expected, correctness", [
    ("detected", "detected", "correct"), ("not_detected", "not_detected", "correct"),
    ("detected", "not_detected", "incorrect"), ("not_detected", "detected", "incorrect"),
    ("inconclusive", "detected", "unresolved"), ("inconclusive", "not_detected", "unresolved"),
    ("not_evaluated", "detected", "not_applicable"), ("not_evaluated", None, "not_applicable"),
    ("detected", None, "unknown"), ("not_detected", None, "unknown"), ("inconclusive", None, "unknown"),
])
def test_detection_correctness_table(verdict, expected, correctness):
    assert correctness_for(verdict, expected) == correctness
