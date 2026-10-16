"""The stdin/stdout contract between the host and the sandboxed workload (protocol version 1).

Used by BOTH sides: the workload builds responses with it, and the host validates everything it receives with it.
The host never trusts a response because it came from its own container; it re-checks every field.

* Request  (host -> container, one JSON object on stdin, at most ``MAX_REQUEST_BYTES``).
* Response (container -> host, one JSON object on stdout, at most the host's stdout limit).

Only data crosses this boundary: no code, no file paths, no shell commands, no environment values.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass

PROTOCOL_VERSION = 1
SYNTHETIC_BASE_URL = "http://127.0.0.1:8001"  # only builds the request path; nothing is ever contacted
KINDS = ("adversarial_suite", "self_check")
MODES = ("vulnerable", "hardened")
CATEGORIES = ("normal", "prompt_injection", "safety_bypass", "canary_disclosure")
STATUSES = ("complete", "aborted", "interrupted")
OUTCOMES = ("completed", "http_error", "timeout", "connection_error", "invalid_response", "runner_error", "not_run")

MAX_REQUEST_BYTES = 256 * 1024
MAX_CASES = 200
MAX_PROMPT_CHARS = 4000
MAX_TITLE_CHARS = 200
MAX_RESPONSE_TEXT_CHARS = 20_000
MAX_RAW_BODY_CHARS = 40_000
MAX_ERROR_CHARS = 500
MAX_OBSERVATION_ITEMS = 200

_JOB_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_TEST_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_REQUEST_FIELDS = {"protocol", "job_id", "kind", "modes", "timeout_seconds", "max_consecutive_failures", "cases"}
_CASE_FIELDS = {"test_id", "category", "title", "prompt"}
_RESPONSE_FIELDS = {"protocol", "job_id", "kind", "status", "stop_reason", "started_at", "finished_at", "planned",
                    "results", "observations"}
RESULT_FIELDS = {"test_id", "category", "target_mode", "timestamp", "duration_ms", "http_status", "outcome",
                 "response_text", "raw_body", "raw_body_truncated", "error"}


class ProtocolError(ValueError):
    """A request or response does not follow the protocol."""

    def __init__(self, message: str, problems: Sequence[str] = ()):
        super().__init__(message + ("".join(f"\n  - {p}" for p in problems) if problems else ""))
        self.problems = list(problems)


def _reject_constant(name: str):
    raise ValueError(f"non-finite number {name} is not allowed")


def loads_strict(raw: bytes | str, *, what: str) -> object:
    """UTF-8 JSON without NaN/Infinity, duplicate keys or absurd nesting."""
    try:
        text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
        return json.loads(text, parse_constant=_reject_constant, object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ProtocolError(f"{what} is not valid JSON: {exc}") from None


def _no_duplicates(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key in JSON object")
    return dict(pairs)


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


# --- request -----------------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class JobCase:
    test_id: str
    category: str
    title: str
    prompt: str


@dataclass(frozen=True)
class JobRequest:
    job_id: str
    kind: str
    modes: tuple[str, ...]
    timeout_seconds: float
    max_consecutive_failures: int
    cases: tuple[JobCase, ...]


def build_request(job_id: str, kind: str, modes: Sequence[str], cases: Sequence[JobCase], *,
                  timeout_seconds: float = 10.0, max_consecutive_failures: int = 3) -> dict:
    return {"protocol": PROTOCOL_VERSION, "job_id": job_id, "kind": kind, "modes": list(modes),
            "timeout_seconds": timeout_seconds, "max_consecutive_failures": max_consecutive_failures,
            "cases": [{"test_id": c.test_id, "category": c.category, "title": c.title, "prompt": c.prompt} for c in cases]}


def encode_request(request: dict) -> bytes:
    """Serialise and enforce the input size limit (the host calls this before anything is started)."""
    problems = validate_request(request)
    if problems:
        raise ProtocolError("The job request is invalid", problems)
    data = json.dumps(request, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
    if len(data) > MAX_REQUEST_BYTES:
        raise ProtocolError(f"The job request is {len(data)} bytes; the limit is {MAX_REQUEST_BYTES}")
    return data


def validate_request(request: object) -> list[str]:
    if not isinstance(request, dict):
        return ["the request is not a JSON object"]
    if set(request) != _REQUEST_FIELDS:
        return [f"the request has the wrong fields (missing {sorted(_REQUEST_FIELDS - set(request))}, "
                f"unexpected {sorted(set(request) - _REQUEST_FIELDS)})"]
    problems: list[str] = []
    if request["protocol"] != PROTOCOL_VERSION or isinstance(request["protocol"], bool):
        problems.append(f"protocol must be {PROTOCOL_VERSION}")
    if not (isinstance(request["job_id"], str) and _JOB_ID.match(request["job_id"])):
        problems.append("job_id must be 1 to 64 letters, digits, '.', '_' or '-'")
    if request["kind"] not in KINDS:
        problems.append(f"kind must be one of {', '.join(KINDS)}")
    modes, cases = request["modes"], request["cases"]
    if not isinstance(modes, list) or len(set(map(str, modes))) != len(modes) or any(m not in MODES for m in modes):
        problems.append(f"modes must be a list of distinct values from {', '.join(MODES)}")
    timeout = request["timeout_seconds"]
    if not _is_number(timeout) or not 0 < timeout <= 300:
        problems.append("timeout_seconds must be a number above 0 and at most 300")
    if not _is_int(request["max_consecutive_failures"]) or not 1 <= request["max_consecutive_failures"] <= 100:
        problems.append("max_consecutive_failures must be an integer from 1 to 100")
    if not isinstance(cases, list) or len(cases) > MAX_CASES:
        problems.append(f"cases must be a list of at most {MAX_CASES} items")
        return problems
    if request["kind"] == "self_check":
        if cases or modes:
            problems.append("a self_check request carries no cases and no modes")
    elif not cases or not modes:
        problems.append("an adversarial_suite request needs at least one mode and one case")
    seen: set[str] = set()
    for i, case in enumerate(cases):
        where = f"cases[{i}]"
        if not isinstance(case, dict) or set(case) != _CASE_FIELDS:
            problems.append(f"{where} must be an object with exactly {sorted(_CASE_FIELDS)}")
            continue
        if not (isinstance(case["test_id"], str) and _TEST_ID.match(case["test_id"])):
            problems.append(f"{where}.test_id is not a plain identifier")
        elif case["test_id"] in seen:
            problems.append(f"{where}.test_id {case['test_id']!r} is duplicated")
        else:
            seen.add(case["test_id"])
        if case["category"] not in CATEGORIES:
            problems.append(f"{where}.category is unknown")
        if not isinstance(case["title"], str) or len(case["title"]) > MAX_TITLE_CHARS:
            problems.append(f"{where}.title must be a string of at most {MAX_TITLE_CHARS} characters")
        prompt = case["prompt"]
        if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > MAX_PROMPT_CHARS:
            problems.append(f"{where}.prompt must be a non-blank string of at most {MAX_PROMPT_CHARS} characters")
    return problems


def parse_request(raw: bytes) -> JobRequest:
    """Container side: read the request. Treats every field, including prompts, as untrusted data."""
    if len(raw) > MAX_REQUEST_BYTES:
        raise ProtocolError(f"the request is larger than {MAX_REQUEST_BYTES} bytes")
    data = loads_strict(raw, what="the request")
    problems = validate_request(data)
    if problems:
        raise ProtocolError("The job request is invalid", problems)
    return JobRequest(
        job_id=data["job_id"], kind=data["kind"], modes=tuple(data["modes"]), timeout_seconds=float(data["timeout_seconds"]),
        max_consecutive_failures=data["max_consecutive_failures"],
        cases=tuple(JobCase(c["test_id"], c["category"], c["title"], c["prompt"]) for c in data["cases"]))


# --- response ------------------------------------------------------------------------------------------------------------
def build_response(request: JobRequest, *, status: str, stop_reason: str | None, started_at: str, finished_at: str,
                   planned: int, results: list[dict], observations: dict | None) -> dict:
    return {"protocol": PROTOCOL_VERSION, "job_id": request.job_id, "kind": request.kind, "status": status,
            "stop_reason": stop_reason, "started_at": started_at, "finished_at": finished_at, "planned": planned,
            "results": results, "observations": observations}


def _check_result(item: object, where: str, expected_case: JobCase, expected_mode: str) -> list[str]:
    if not isinstance(item, dict) or set(item) != RESULT_FIELDS:
        return [f"{where} must be an object with exactly the result fields"]
    problems: list[str] = []
    if item["test_id"] != expected_case.test_id or item["target_mode"] != expected_mode or item["category"] != expected_case.category:
        problems.append(f"{where} is not the planned case ({expected_case.test_id}, {expected_mode}, {expected_case.category})")
    outcome = item["outcome"]
    if outcome not in OUTCOMES:
        return problems + [f"{where}.outcome is unknown"]
    for key, limit in (("response_text", MAX_RESPONSE_TEXT_CHARS), ("raw_body", MAX_RAW_BODY_CHARS), ("error", MAX_ERROR_CHARS)):
        value = item[key]
        if value is not None and (not isinstance(value, str) or len(value) > limit):
            problems.append(f"{where}.{key} must be null or a string of at most {limit} characters")
    if not isinstance(item["raw_body_truncated"], bool):
        problems.append(f"{where}.raw_body_truncated must be a boolean")
    if item["http_status"] is not None and not (_is_int(item["http_status"]) and 100 <= item["http_status"] <= 599):
        problems.append(f"{where}.http_status must be null or an HTTP status code")
    duration = item["duration_ms"]
    if duration is not None and not (_is_number(duration) and 0 <= duration < 3.6e6):
        problems.append(f"{where}.duration_ms must be null or a non-negative number")
    if item["timestamp"] is not None and not (isinstance(item["timestamp"], str) and len(item["timestamp"]) <= 40):
        problems.append(f"{where}.timestamp must be null or a short string")
    if outcome == "not_run":
        if item["timestamp"] is not None or item["http_status"] is not None or item["response_text"] is not None:
            problems.append(f"{where}: a not_run case has no timestamp, status or response")
    else:
        if item["timestamp"] is None:
            problems.append(f"{where}: an attempted case needs a timestamp")
        if outcome == "completed" and (item["http_status"] != 200 or not isinstance(item["response_text"], str)):
            problems.append(f"{where}: a completed case needs HTTP 200 and response text")
        if outcome != "completed" and item["response_text"] is not None:
            problems.append(f"{where}: only completed cases carry response text")
    return problems


def validate_response(response: object, request: JobRequest) -> list[str]:
    """Host side: check a response against the request that was sent. Returns problems (empty = acceptable)."""
    if not isinstance(response, dict):
        return ["the response is not a JSON object"]
    if set(response) != _RESPONSE_FIELDS:
        return [f"the response has the wrong fields (missing {sorted(_RESPONSE_FIELDS - set(response))}, "
                f"unexpected {sorted(set(response) - _RESPONSE_FIELDS)})"]
    problems: list[str] = []
    if response["protocol"] != PROTOCOL_VERSION or isinstance(response["protocol"], bool):
        problems.append(f"protocol must be {PROTOCOL_VERSION}")
    if response["job_id"] != request.job_id:
        problems.append("job_id does not match the job that was started")
    if response["kind"] != request.kind:
        problems.append("kind does not match the job that was started")
    if response["status"] not in STATUSES:
        problems.append(f"status must be one of {', '.join(STATUSES)}")
    if response["stop_reason"] is not None and not (isinstance(response["stop_reason"], str) and len(response["stop_reason"]) <= MAX_ERROR_CHARS):
        problems.append("stop_reason must be null or a short string")
    for key in ("started_at", "finished_at"):
        if not (isinstance(response[key], str) and 10 <= len(response[key]) <= 40):
            problems.append(f"{key} must be a short timestamp string")
    results = response["results"]
    if request.kind == "self_check":
        if results != [] or response["planned"] != 0:
            problems.append("a self_check response carries no results")
        obs = response["observations"]
        if not isinstance(obs, dict) or len(json.dumps(obs)) > 64 * 1024:
            problems.append("a self_check response needs an observations object of at most 64 KiB")
        return problems
    if response["observations"] is not None:
        problems.append("a suite response carries no observations")
    plan = [(mode, case) for mode in request.modes for case in request.cases]
    if response["planned"] != len(plan) or not isinstance(results, list) or len(results) != len(plan):
        return problems + [f"the response must contain exactly the {len(plan)} planned results in planned order"]
    for i, ((mode, case), item) in enumerate(zip(plan, results)):
        problems.extend(_check_result(item, f"results[{i}]", case, mode))
        if len(problems) > 20:
            problems.append("... more problems omitted")
            break
    return problems


def parse_response(raw: bytes, request: JobRequest) -> dict:
    data = loads_strict(raw, what="the workload output")
    problems = validate_response(data, request)
    if problems:
        raise ProtocolError("The workload output was rejected", problems)
    return data  # type: ignore[return-value]
