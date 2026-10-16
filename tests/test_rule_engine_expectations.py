"""The hand-authored expectation labels: validity, coverage, and agreement with the real mock."""

import json
from collections import Counter

import pytest

from sentinelbox.mock_ai.engine import respond
from sentinelbox.mock_ai.scenarios import Mode, Scenario
from sentinelbox.rule_engine.expectations import DEFAULT_EXPECTATIONS_PATH, ExpectationsError, load_expectations
from sentinelbox.runner.library import load_library

EXPECTATIONS = load_expectations()
LIBRARY = load_library()


def test_bundled_expectations_load_and_are_labelled_as_a_synthetic_oracle():
    assert EXPECTATIONS.name == "mock-ai-v1-expectations" and EXPECTATIONS.kind == "synthetic_mock_oracle"
    assert len(EXPECTATIONS.cases) == 24 and len(EXPECTATIONS.sha256) == 64
    description = json.loads(DEFAULT_EXPECTATIONS_PATH.read_text(encoding="utf-8"))["description"]
    assert "NOT produced by the rule engine" in description and "synthetic" in description


def test_expectations_cover_exactly_the_prompt_library_with_matching_categories():
    assert set(EXPECTATIONS.cases) == {c.test_id for c in LIBRARY.cases}
    for case in LIBRARY.cases:
        assert EXPECTATIONS.cases[case.test_id].category == case.category.value


def test_benign_controls_never_expect_a_detection_and_hardened_mode_never_does():
    for exp in EXPECTATIONS.cases.values():
        assert exp.expected_detection["hardened"].value == "not_detected"
        if exp.category == "normal":
            assert exp.expected_behavior.value == "answer_normally"
            assert exp.expected_detection["vulnerable"].value == "not_detected"
        else:
            assert exp.expected_behavior.value == "resist_attack"
            assert exp.expected_detection["vulnerable"].value == "detected"


def test_label_counts():
    counts = Counter(e.expected_detection["vulnerable"].value for e in EXPECTATIONS.cases.values())
    assert counts == {"detected": 18, "not_detected": 6}


@pytest.mark.parametrize("case", LIBRARY.cases, ids=lambda c: c.test_id)
@pytest.mark.parametrize("mode", ["vulnerable", "hardened"])
def test_labels_agree_with_what_the_mock_is_actually_designed_to_do(case, mode):
    """Test-only cross-check against the mock's own ground truth (the one place that is allowed)."""
    result = respond(case.prompt, Mode(mode))
    attack_succeeds = mode == "vulnerable" and result.scenario is not Scenario.NORMAL
    expected = EXPECTATIONS.cases[case.test_id].expected_detection[mode].value
    assert expected == ("detected" if attack_succeeds else "not_detected")


# --- loader validation ----------------------------------------------------------------------------
def doc(*cases, **overrides):
    data = {"schema_version": 1, "name": "n", "version": "1", "kind": "k", "cases": list(cases) or [case()]}
    data.update(overrides)
    return data


def case(**overrides):
    base = {"id": "X-1", "category": "prompt_injection", "expected_behavior": "resist_attack",
            "expected_detection": {"vulnerable": "detected", "hardened": "not_detected"}}
    base.update(overrides)
    return base


def write(tmp_path, data):
    path = tmp_path / "e.json"
    path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
    return path


def test_minimal_valid_expectations_load(tmp_path):
    assert list(load_expectations(write(tmp_path, doc())).cases) == ["X-1"]


@pytest.mark.parametrize("data, message", [
    ("{oops", "not valid"), ("[]", "must be a JSON object"), (doc(schema_version=2), "schema_version"),
    (doc(name=""), "name"), (doc(kind=5), "kind"), (doc(cases=[]), "cases"), (doc(cases="x"), "cases"),
    (doc("x"), "must be an object"),
    (doc({"id": "X"}), "exactly the fields"),
    (doc(case(extra=1)), "exactly the fields"),
    (doc(case(id=" ")), "non-empty"), (doc(case(), case()), "Duplicate"),
    (doc(case(category="magic")), "unknown category"),
    (doc(case(expected_behavior="shrug")), "unknown expected_behavior"),
    (doc(case(category="normal")), "does not fit category"),
    (doc(case(expected_behavior="answer_normally")), "does not fit category"),
    (doc(case(expected_detection={"vulnerable": "detected"})), "exactly the modes"),
    (doc(case(expected_detection={"vulnerable": "detected", "hardened": "x"})), "unknown expected_detection"),
    (doc(case(expected_detection="detected")), "exactly the modes"),
    (doc(case(category="normal", expected_behavior="answer_normally")), "benign control cannot expect"),
], ids=["bad-json", "not-object", "schema", "empty-name", "int-kind", "no-cases", "cases-str", "case-str", "missing-fields",
        "extra-field", "blank-id", "duplicate", "bad-category", "bad-behavior", "normal-resist", "attack-answer",
        "missing-mode", "bad-detection", "detection-str", "control-expects-detection"])
def test_invalid_expectations_are_rejected(tmp_path, data, message):
    with pytest.raises(ExpectationsError, match=message):
        load_expectations(write(tmp_path, data))


def test_missing_file_and_directory_and_bad_bytes(tmp_path):
    with pytest.raises(ExpectationsError, match="Cannot read"):
        load_expectations(tmp_path / "nope.json")
    with pytest.raises(ExpectationsError, match="Cannot read"):
        load_expectations(tmp_path)
    bad = tmp_path / "bad.json"
    bad.write_bytes(b"\xff\xfe\x00")
    with pytest.raises(ExpectationsError, match="not valid"):
        load_expectations(bad)
