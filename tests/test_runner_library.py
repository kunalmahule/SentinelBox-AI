"""Prompt library: the bundled file and the loader's validation."""

import json
import re
from collections import Counter

import pytest

from sentinelbox.runner.library import DEFAULT_LIBRARY_PATH, LibraryError, load_library
from sentinelbox.runner.models import MAX_PROMPT_CHARS, Category


def test_bundled_library_loads_with_expected_shape():
    library = load_library()
    assert library.name == "sentinelbox-adversarial-v1"
    assert library.file_name == "adversarial_v1.json"
    assert re.fullmatch(r"[0-9a-f]{64}", library.sha256)
    assert len(library.cases) == 24
    assert Counter(c.category for c in library.cases) == {c: 6 for c in Category}


def test_bundled_case_ids_are_unique_and_prompts_are_within_limits():
    cases = load_library().cases
    assert len({c.test_id for c in cases}) == len(cases)
    assert all(c.prompt.strip() and len(c.prompt) <= MAX_PROMPT_CHARS for c in cases)


def test_bundled_library_contains_no_real_looking_secrets():
    text = DEFAULT_LIBRARY_PATH.read_text(encoding="utf-8")
    patterns = [
        r"sk-[A-Za-z0-9]{20,}", r"AKIA[0-9A-Z]{16}", r"ghp_[A-Za-z0-9]{30,}",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----", r"xox[abp]-[A-Za-z0-9-]{10,}",
    ]
    for pattern in patterns:
        assert not re.search(pattern, text), pattern


def test_bundled_library_has_no_expected_answer_or_verdict_fields():
    # The runner must not carry ground truth; the loader rejects unknown fields,
    # so loading successfully proves each case has only id/category/title/prompt.
    raw = json.loads(DEFAULT_LIBRARY_PATH.read_text(encoding="utf-8"))
    assert all(set(case) == {"id", "category", "title", "prompt"} for case in raw["cases"])


def test_loader_is_deterministic_and_hash_tracks_content(tmp_path):
    first, second = load_library(), load_library()
    assert first == second
    data = json.loads(DEFAULT_LIBRARY_PATH.read_text(encoding="utf-8"))
    data["cases"][0]["prompt"] = "A different benign question?"
    changed = tmp_path / "changed.json"
    changed.write_text(json.dumps(data), encoding="utf-8")
    assert load_library(changed).sha256 != first.sha256


def _write(tmp_path, data):
    path = tmp_path / "lib.json"
    path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
    return path


def _case(**overrides):
    case = {"id": "T-1", "category": "normal", "title": "t", "prompt": "hello"}
    case.update(overrides)
    return case


def _lib(*cases, **overrides):
    data = {"schema_version": 1, "name": "x", "version": "1", "cases": list(cases) or [_case()]}
    data.update(overrides)
    return data


def test_minimal_valid_library_loads(tmp_path):
    library = load_library(_write(tmp_path, _lib()))
    assert [c.test_id for c in library.cases] == ["T-1"]
    assert library.cases[0].category is Category.NORMAL


@pytest.mark.parametrize(
    "data, message",
    [
        ("{not json", "not valid"),
        ("[]", "must be a JSON object"),
        (_lib(schema_version=2), "schema_version"),
        (_lib(schema_version=None), "schema_version"),
        (_lib(name=""), "name"),
        (_lib(name=5), "name"),
        (_lib(version=""), "version"),
        (_lib(cases=[]), "cases"),
        (_lib(cases="nope"), "cases"),
        (_lib(_case(), "not-an-object"), "must be an object"),
        (_lib({"id": "T-1", "category": "normal", "title": "t"}), "missing field"),
        (_lib(_case(expected="refuse")), "unknown field"),
        (_lib(_case(prompt=5)), "must be a string"),
        (_lib(_case(id="  ")), "must not be empty"),
        (_lib(_case(), _case()), "Duplicate"),
        (_lib(_case(category="world_domination")), "unknown category"),
        (_lib(_case(prompt="   \n")), "blank"),
        (_lib(_case(prompt="x" * (MAX_PROMPT_CHARS + 1))), "longer than"),
    ],
    ids=[
        "bad-json", "not-object", "wrong-schema", "null-schema", "empty-name", "int-name", "empty-version",
        "no-cases", "cases-not-list", "case-not-object", "missing-field", "unknown-field", "non-string",
        "empty-id", "duplicate-id", "unknown-category", "blank-prompt", "oversized-prompt",
    ],
)
def test_invalid_libraries_are_rejected_with_a_clear_message(tmp_path, data, message):
    with pytest.raises(LibraryError, match=message):
        load_library(_write(tmp_path, data))


def test_missing_file_is_a_library_error(tmp_path):
    with pytest.raises(LibraryError, match="Cannot read"):
        load_library(tmp_path / "nope.json")


def test_directory_instead_of_file_is_a_library_error(tmp_path):
    with pytest.raises(LibraryError, match="Cannot read"):
        load_library(tmp_path)


def test_non_utf8_file_is_a_library_error(tmp_path):
    path = tmp_path / "bad.json"
    path.write_bytes(b"\xff\xfe{\x00")
    with pytest.raises(LibraryError, match="not valid"):
        load_library(path)
