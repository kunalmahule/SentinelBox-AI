"""Load and validate the adversarial prompt library."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from .models import MAX_PROMPT_CHARS, Category, TestCase

DEFAULT_LIBRARY_PATH = Path(__file__).resolve().parent / "prompt_library" / "adversarial_v1.json"
SUPPORTED_SCHEMA_VERSION = 1
_CASE_KEYS = {"id", "category", "title", "prompt"}


class LibraryError(Exception):
    """The prompt library is missing, unreadable or invalid."""


@dataclass(frozen=True)
class PromptLibrary:
    name: str
    version: str
    file_name: str
    sha256: str
    cases: tuple[TestCase, ...]


def load_library(path: Path | str = DEFAULT_LIBRARY_PATH) -> PromptLibrary:
    path = Path(path)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise LibraryError(f"Cannot read prompt library {path}: {exc.strerror or exc}") from exc
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LibraryError(f"Prompt library {path.name} is not valid UTF-8 JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise LibraryError("Prompt library must be a JSON object")
    if data.get("schema_version") != SUPPORTED_SCHEMA_VERSION:
        raise LibraryError(
            f"Unsupported schema_version {data.get('schema_version')!r}; expected {SUPPORTED_SCHEMA_VERSION}"
        )
    name, version = data.get("name"), data.get("version")
    if not isinstance(name, str) or not name.strip():
        raise LibraryError("Prompt library needs a non-empty string 'name'")
    if not isinstance(version, str) or not version.strip():
        raise LibraryError("Prompt library needs a non-empty string 'version'")
    raw_cases = data.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise LibraryError("Prompt library needs a non-empty 'cases' list")

    cases: list[TestCase] = []
    seen: set[str] = set()
    for index, item in enumerate(raw_cases):
        where = f"cases[{index}]"
        if not isinstance(item, dict):
            raise LibraryError(f"{where} must be an object")
        unknown = set(item) - _CASE_KEYS
        missing = _CASE_KEYS - set(item)
        if missing:
            raise LibraryError(f"{where} is missing field(s): {', '.join(sorted(missing))}")
        if unknown:
            raise LibraryError(f"{where} has unknown field(s): {', '.join(sorted(unknown))}")
        for key in _CASE_KEYS:
            if not isinstance(item[key], str):
                raise LibraryError(f"{where}.{key} must be a string")
        test_id = item["id"].strip()
        if not test_id:
            raise LibraryError(f"{where}.id must not be empty")
        if test_id in seen:
            raise LibraryError(f"Duplicate test id {test_id!r}")
        seen.add(test_id)
        try:
            category = Category(item["category"])
        except ValueError:
            valid = ", ".join(c.value for c in Category)
            raise LibraryError(f"{test_id}: unknown category {item['category']!r} (valid: {valid})") from None
        prompt = item["prompt"]
        if not prompt.strip():
            raise LibraryError(f"{test_id}: prompt must not be blank")
        if len(prompt) > MAX_PROMPT_CHARS:
            raise LibraryError(f"{test_id}: prompt longer than {MAX_PROMPT_CHARS} characters")
        cases.append(TestCase(test_id, category, item["title"].strip(), prompt))

    return PromptLibrary(
        name=name.strip(),
        version=version.strip(),
        file_name=path.name,
        sha256=hashlib.sha256(raw).hexdigest(),
        cases=tuple(cases),
    )
