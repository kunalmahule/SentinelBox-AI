"""Load the hand-authored expectation labels used to score the engine.

Expectations live outside the Stage 2 prompt library on purpose: the library carries no ground truth,
and the runner never sees these labels. The engine does not use them to decide a verdict either; they
are only compared with the verdict afterwards.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from .models import ExpectedBehavior, ExpectedDetection

DEFAULT_EXPECTATIONS_PATH = Path(__file__).resolve().parent / "expectations" / "mock_ai_v1.json"
SUPPORTED_SCHEMA_VERSION = 1
KNOWN_CATEGORIES = {"normal", "prompt_injection", "safety_bypass", "canary_disclosure"}
KNOWN_MODES = {"vulnerable", "hardened"}
_CASE_KEYS = {"id", "category", "expected_behavior", "expected_detection"}
_MAX_BYTES = 1_048_576


class ExpectationsError(Exception):
    """The expectations file is missing, unreadable or invalid."""


@dataclass(frozen=True)
class CaseExpectation:
    test_id: str
    category: str
    expected_behavior: ExpectedBehavior
    expected_detection: dict[str, ExpectedDetection]  # keyed by target mode


@dataclass(frozen=True)
class Expectations:
    name: str
    version: str
    kind: str
    file_name: str
    sha256: str
    cases: dict[str, CaseExpectation]


def load_expectations(path: Path | str = DEFAULT_EXPECTATIONS_PATH) -> Expectations:
    path = Path(path)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ExpectationsError(f"Cannot read expectations file {path}: {exc.strerror or exc}") from exc
    if len(raw) > _MAX_BYTES:
        raise ExpectationsError("Expectations file is unreasonably large")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExpectationsError(f"Expectations file {path.name} is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ExpectationsError("Expectations file must be a JSON object")
    if data.get("schema_version") != SUPPORTED_SCHEMA_VERSION:
        raise ExpectationsError(f"Unsupported schema_version {data.get('schema_version')!r}")
    for key in ("name", "version", "kind"):
        if not isinstance(data.get(key), str) or not data[key].strip():
            raise ExpectationsError(f"Expectations file needs a non-empty string '{key}'")
    items = data.get("cases")
    if not isinstance(items, list) or not items:
        raise ExpectationsError("Expectations file needs a non-empty 'cases' list")

    cases: dict[str, CaseExpectation] = {}
    for index, item in enumerate(items):
        where = f"cases[{index}]"
        if not isinstance(item, dict):
            raise ExpectationsError(f"{where} must be an object")
        if set(item) != _CASE_KEYS:
            raise ExpectationsError(f"{where} must have exactly the fields {sorted(_CASE_KEYS)}")
        test_id, category = item["id"], item["category"]
        if not isinstance(test_id, str) or not test_id.strip():
            raise ExpectationsError(f"{where}.id must be a non-empty string")
        if test_id in cases:
            raise ExpectationsError(f"Duplicate test id {test_id!r}")
        if category not in KNOWN_CATEGORIES:
            raise ExpectationsError(f"{test_id}: unknown category {category!r}")
        try:
            behavior = ExpectedBehavior(item["expected_behavior"])
        except ValueError:
            raise ExpectationsError(f"{test_id}: unknown expected_behavior {item['expected_behavior']!r}") from None
        if (category == "normal") != (behavior is ExpectedBehavior.ANSWER_NORMALLY):
            raise ExpectationsError(f"{test_id}: expected_behavior {behavior.value!r} does not fit category {category!r}")
        detection = item["expected_detection"]
        if not isinstance(detection, dict) or set(detection) != KNOWN_MODES:
            raise ExpectationsError(f"{test_id}: expected_detection needs exactly the modes {sorted(KNOWN_MODES)}")
        try:
            parsed = {mode: ExpectedDetection(value) for mode, value in detection.items()}
        except ValueError:
            raise ExpectationsError(f"{test_id}: unknown expected_detection value") from None
        if behavior is ExpectedBehavior.ANSWER_NORMALLY and any(v is ExpectedDetection.DETECTED for v in parsed.values()):
            raise ExpectationsError(f"{test_id}: a benign control cannot expect a detection")
        cases[test_id] = CaseExpectation(test_id, category, behavior, parsed)

    return Expectations(
        name=data["name"].strip(), version=data["version"].strip(), kind=data["kind"].strip(),
        file_name=path.name, sha256=hashlib.sha256(raw).hexdigest(), cases=cases,
    )
