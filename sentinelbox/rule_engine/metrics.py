"""Confusion matrix and derived metrics, computed per target mode.

Definitions (positive = "detected"):

* TP: expected detected, verdict detected        FP: expected not detected, verdict detected
* FN: expected detected, verdict not_detected    TN: expected not detected, verdict not_detected

``inconclusive`` verdicts abstain: they are counted separately and excluded from the matrix, as are
``not_evaluated`` records and records with no expectation. A metric whose denominator is zero is
``None`` with an explanation, never 0 or 1.
"""

from __future__ import annotations

from .models import Verdict

SCOPE = "synthetic_mock_environment"
VERDICT_KEYS = [v.value for v in Verdict]


def _ratio(numerator: int, denominator: int, undefined: str) -> dict:
    if denominator > 0:
        return {"value": round(numerator / denominator, 6), "numerator": numerator,
                "denominator": denominator, "note": None}
    return {"value": None, "numerator": numerator, "denominator": denominator, "note": f"undefined: {undefined}"}


def _zero_verdicts() -> dict[str, int]:
    return {key: 0 for key in VERDICT_KEYS}


def compute_mode_metrics(results: list[dict]) -> dict:
    """*results* are analysis result dicts for ONE target mode."""
    verdicts = _zero_verdicts()
    by_category: dict[str, dict[str, int]] = {}
    tp = fp = tn = fn = 0
    inconclusive_pos = inconclusive_neg = 0
    with_expectation = without_expectation = 0

    for item in results:
        verdict = item["verdict"]
        verdicts[verdict] += 1
        by_category.setdefault(item["category"] or "unknown", _zero_verdicts())[verdict] += 1
        expected = item["expected_detection"]
        if verdict == Verdict.NOT_EVALUATED.value:
            continue
        if expected is None:
            without_expectation += 1
            continue
        with_expectation += 1
        positive = expected == "detected"
        if verdict == Verdict.INCONCLUSIVE.value:
            inconclusive_pos += positive
            inconclusive_neg += not positive
        elif verdict == Verdict.DETECTED.value:
            tp += positive
            fp += not positive
        else:
            fn += positive
            tn += not positive

    expected_positives = tp + fn + inconclusive_pos
    precision = _ratio(tp, tp + fp, "no record was predicted 'detected' (TP + FP = 0)")
    if tp + fn > 0:
        recall = _ratio(tp, tp + fn, "")
    else:
        reason = ("every record expected to be detected was inconclusive (TP + FN = 0)" if expected_positives
                  else "no record in this mode was expected to be detected (TP + FN = 0)")
        recall = _ratio(tp, 0, reason)
    if precision["value"] is not None and recall["value"] is not None:
        f1 = {"value": round(2 * tp / (2 * tp + fp + fn), 6), "numerator": 2 * tp,
              "denominator": 2 * tp + fp + fn, "note": None}
    else:
        f1 = {"value": None, "numerator": 2 * tp, "denominator": 2 * tp + fp + fn,
              "note": "undefined: precision or recall is undefined"}
    abstained = inconclusive_pos + inconclusive_neg
    return {
        "scope": SCOPE,
        "records": len(results),
        "verdict_counts": verdicts,
        "by_category": by_category,
        "with_expectation": with_expectation,
        "without_expectation": without_expectation,
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "inconclusive": {"expected_detected": inconclusive_pos, "expected_not_detected": inconclusive_neg},
        "abstention_rate": _ratio(abstained, abstained + tp + fp + tn + fn, "no record with an expectation was evaluated"),
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }
