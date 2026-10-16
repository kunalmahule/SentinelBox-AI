"""Reading and strictly validating the JSON documents that can be imported.

The importer's contract with the rest of the project is the two JSON formats (runner report v1 and rule-engine
analysis v1). Validation lives here, independently of the runner and the rule engine, so a malformed or
tampered file is rejected before any SQL runs. Source files are opened read-only and never written.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from . import schema
from .database import StorageError

SUPPORTED_REPORT_SCHEMA = 1
SUPPORTED_ANALYSIS_SCHEMA = 1
SUPPORTED_SANDBOX_SCHEMA = 1
MAX_SANDBOX_JSON_BYTES = 64 * 1024  # each free-form object (requested policy, effective settings, controls)
MAX_DOCUMENT_BYTES = 50 * 1024 * 1024
MAX_PROBLEMS_SHOWN = 10

_ID = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")  # no ':' so composite identifiers stay unambiguous
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

_REPORT_RESULT_FIELDS = {
    "test_id", "category", "target_mode", "timestamp", "duration_ms", "http_status", "outcome",
    "response_text", "raw_body", "raw_body_truncated", "error",
}
_ANALYSIS_RESULT_FIELDS = {
    "index", "test_id", "category", "target_mode", "execution_outcome", "http_status", "expected_behavior",
    "expected_detection", "verdict", "detection_correctness", "max_severity", "refusal_language", "matches",
    "context_matches", "notes", "input_problems",
}
_MATCH_FIELDS = {"rule_id", "family", "severity", "base_confidence", "confidence", "effect", "rationale",
                 "adjustments", "evidence"}
_EVIDENCE_FIELDS = {"text", "start", "end", "context"}

# Heuristic patterns for things that look like real credentials. Not exhaustive and not a guarantee.
SECRET_PATTERNS: dict[str, re.Pattern] = {
    "AWS access key ID": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "private key block": re.compile(r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "Slack token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "API secret key (sk-...)": re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,}"),
    "Stripe live key": re.compile(r"\b[sr]k_live_[0-9A-Za-z]{16,}"),
    "JSON Web Token": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    "password inside a URL": re.compile(r"://[^/\s:@]+:[^/\s:@]+@"),
}


class DocumentError(StorageError):
    """A document cannot be imported. ``problems`` lists every issue found (capped when displayed)."""

    def __init__(self, message: str, problems: list[str] | None = None):
        self.problems = list(problems or [])
        shown = self.problems[:MAX_PROBLEMS_SHOWN]
        text = message
        if shown:
            text += ":\n  - " + "\n  - ".join(shown)
            if len(self.problems) > len(shown):
                text += f"\n  - ... and {len(self.problems) - len(shown)} more"
        super().__init__(text)


@dataclass(frozen=True)
class Document:
    data: dict
    sha256: str
    file_name: str


def _reject_constant(name: str):
    raise ValueError(f"non-finite number {name} is not allowed")


def read_document(path: Path | str, label: str) -> Document:
    """Read a JSON file read-only. ``label`` ("report" or "analysis") is used in error messages."""
    path = Path(path)
    try:
        size = path.stat().st_size
        if size > MAX_DOCUMENT_BYTES:
            raise DocumentError(f"The {label} {path.name} is larger than {MAX_DOCUMENT_BYTES // (1024 * 1024)} MiB; refusing to load it")
        with path.open("rb") as handle:
            raw = handle.read(MAX_DOCUMENT_BYTES + 1)
    except OSError as exc:
        raise DocumentError(f"Cannot read the {label} {path}: {exc.strerror or exc}") from exc
    try:
        data = json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise DocumentError(f"The {label} {path.name} is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise DocumentError(f"The {label} {path.name} must contain a JSON object")
    return Document(data, hashlib.sha256(raw).hexdigest(), path.name)


# --- small checkers -------------------------------------------------------------------------------------------
def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _iso(value: object) -> bool:
    if not _nonempty(value):
        return False
    try:
        datetime.fromisoformat(value)
    except ValueError:
        return False
    return True


def _is_loopback(url: str) -> bool:
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return False
    if host == "localhost":
        return True
    try:
        return bool(host) and ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def find_secret_like_strings(value: object, path: str = "$") -> list[str]:
    """Return a description for every string that looks like a real credential. Never repeats the string."""
    found: list[str] = []
    stack = [(value, path)]
    while stack:
        current, where = stack.pop()
        if isinstance(current, str):
            for name, pattern in SECRET_PATTERNS.items():
                if pattern.search(current):
                    found.append(f"{where} contains text that looks like a real credential ({name}); "
                                 "SentinelBox stores synthetic test data only. Remove or redact it and re-run the test")
        elif isinstance(current, dict):
            stack.extend((v, f"{where}.{k}") for k, v in current.items())
        elif isinstance(current, list):
            stack.extend((v, f"{where}[{i}]") for i, v in enumerate(current))
    return sorted(found)


# --- runner report --------------------------------------------------------------------------------------------
def validate_report_document(report: object) -> list[str]:
    if not isinstance(report, dict):
        return ["the report is not a JSON object"]
    problems: list[str] = []
    if report.get("schema_version") != SUPPORTED_REPORT_SCHEMA:
        problems.append(f"schema_version must be {SUPPORTED_REPORT_SCHEMA} (found {report.get('schema_version')!r})")
    if not (isinstance(report.get("run_id"), str) and _ID.match(report["run_id"])):
        problems.append("run_id must be 1 to 64 letters, digits, '.', '_' or '-'")
    if report.get("status") not in schema.RUN_STATUSES:
        problems.append(f"status must be one of {', '.join(schema.RUN_STATUSES)}")
    if report.get("stop_reason") is not None and not isinstance(report.get("stop_reason"), str):
        problems.append("stop_reason must be a string or null")
    for key in ("started_at", "finished_at"):
        if not _iso(report.get(key)):
            problems.append(f"{key} must be an ISO 8601 timestamp")

    tool = report.get("tool")
    if not (isinstance(tool, dict) and _nonempty(tool.get("name")) and _nonempty(tool.get("version"))):
        problems.append("tool must be an object with non-empty name and version")
    target = report.get("target")
    if not isinstance(target, dict) or not _nonempty(target.get("base_url")):
        problems.append("target must be an object with a base_url")
    elif not _is_loopback(target["base_url"]):
        problems.append("target.base_url is not a loopback address; SentinelBox stores results from the local mock target only")
    library = report.get("library")
    if not (isinstance(library, dict) and all(_nonempty(library.get(k)) for k in ("name", "version", "file_name", "sha256"))
            and _is_int(library.get("case_count"))):
        problems.append("library must have name, version, file_name, sha256 and an integer case_count")
    modes = report.get("modes")
    if not (isinstance(modes, list) and modes and all(m in schema.TARGET_MODES for m in modes)):
        problems.append(f"modes must be a non-empty list drawn from {', '.join(schema.TARGET_MODES)}")
        modes = list(schema.TARGET_MODES)

    results = report.get("results")
    if not isinstance(results, list):
        return problems + ["results must be a list"]
    summary = report.get("summary")
    if not isinstance(summary, dict) or not _is_int(summary.get("planned")) or not _is_int(summary.get("attempted")):
        problems.append("summary must contain integer planned and attempted counts")
        summary = None

    seen: set[tuple[str, str]] = set()
    not_run = 0
    for i, item in enumerate(results):
        where = f"results[{i}]"
        if not isinstance(item, dict):
            problems.append(f"{where} is not an object")
            continue
        if set(item) != _REPORT_RESULT_FIELDS:
            problems.append(f"{where} has the wrong fields (missing {sorted(_REPORT_RESULT_FIELDS - set(item))}, "
                            f"unexpected {sorted(set(item) - _REPORT_RESULT_FIELDS)})")
            continue
        if not (isinstance(item["test_id"], str) and _ID.match(item["test_id"])):
            problems.append(f"{where}.test_id must be 1 to 64 letters, digits, '.', '_' or '-'")
        if item["category"] not in schema.CATEGORIES:
            problems.append(f"{where}.category {item['category']!r} is unknown")
        if item["target_mode"] not in schema.TARGET_MODES:
            problems.append(f"{where}.target_mode {item['target_mode']!r} is unknown")
        elif item["target_mode"] not in modes:
            problems.append(f"{where}.target_mode {item['target_mode']!r} is not listed in the report's modes")
        if isinstance(item["test_id"], str) and isinstance(item["target_mode"], str):
            pair = (item["test_id"], item["target_mode"])
            if pair in seen:
                problems.append(f"{where} repeats test {pair[0]} in mode {pair[1]}; each test and mode may appear once")
            seen.add(pair)
        if item["outcome"] not in schema.OUTCOMES:
            problems.append(f"{where}.outcome {item['outcome']!r} is unknown")
            continue
        if item["outcome"] == "not_run":
            not_run += 1
        if item["timestamp"] is not None and not _iso(item["timestamp"]):
            problems.append(f"{where}.timestamp must be an ISO 8601 string or null")
        if item["duration_ms"] is not None and (not _is_number(item["duration_ms"]) or item["duration_ms"] < 0):
            problems.append(f"{where}.duration_ms must be a non-negative number or null")
        if item["http_status"] is not None and not _is_int(item["http_status"]):
            problems.append(f"{where}.http_status must be an integer or null")
        for key in ("response_text", "raw_body", "error"):
            if item[key] is not None and not isinstance(item[key], str):
                problems.append(f"{where}.{key} must be a string or null")
        if not isinstance(item["raw_body_truncated"], bool):
            problems.append(f"{where}.raw_body_truncated must be true or false")
        if item["outcome"] == "completed":
            if item["http_status"] != 200 or not isinstance(item["response_text"], str):
                problems.append(f"{where}: a completed test needs HTTP 200 and a response_text string")
        elif item["response_text"] is not None:
            problems.append(f"{where}: only completed tests may carry response_text")
        if item["outcome"] == "not_run" and (item["timestamp"] is not None or item["http_status"] is not None):
            problems.append(f"{where}: a not_run test cannot have a timestamp or HTTP status")
    if summary is not None:
        if summary["planned"] != len(results):
            problems.append(f"summary.planned ({summary['planned']}) does not match the number of results ({len(results)})")
        if summary["attempted"] != len(results) - not_run:
            problems.append(f"summary.attempted ({summary['attempted']}) does not match the results ({len(results) - not_run})")
    return problems


# --- rule-engine analysis -------------------------------------------------------------------------------------
def _validate_match(match: object, where: str, problems: list[str]) -> str | None:
    if not isinstance(match, dict) or set(match) != _MATCH_FIELDS:
        problems.append(f"{where} is not a match object with exactly the expected fields")
        return None
    for key in ("rule_id", "family", "rationale"):
        if not _nonempty(match[key]):
            problems.append(f"{where}.{key} must be a non-empty string")
    for key, allowed in (("severity", schema.SEVERITIES), ("base_confidence", schema.CONFIDENCES),
                         ("confidence", schema.CONFIDENCES), ("effect", schema.EFFECTS)):
        if match[key] not in allowed:
            problems.append(f"{where}.{key} {match[key]!r} is unknown")
    if not (isinstance(match["adjustments"], list) and all(isinstance(a, str) for a in match["adjustments"])):
        problems.append(f"{where}.adjustments must be a list of strings")
    evidence = match["evidence"]
    if not (isinstance(evidence, dict) and set(evidence) == _EVIDENCE_FIELDS):
        problems.append(f"{where}.evidence must have exactly text, start, end and context")
    elif not (isinstance(evidence["text"], str) and isinstance(evidence["context"], str)
              and _is_int(evidence["start"]) and _is_int(evidence["end"]) and 0 <= evidence["start"] <= evidence["end"]):
        problems.append(f"{where}.evidence has invalid text, context or offsets")
    return match["effect"] if match["effect"] in schema.EFFECTS else None


def validate_analysis_document(analysis: object) -> list[str]:
    if not isinstance(analysis, dict):
        return ["the analysis is not a JSON object"]
    problems: list[str] = []
    if analysis.get("schema_version") != SUPPORTED_ANALYSIS_SCHEMA:
        problems.append(f"schema_version must be {SUPPORTED_ANALYSIS_SCHEMA} (found {analysis.get('schema_version')!r})")
    if analysis.get("scope") != schema.ANALYSIS_SCOPE:
        problems.append(f"scope must be '{schema.ANALYSIS_SCOPE}'")
    if not (isinstance(analysis.get("analysis_id"), str) and _ID.match(analysis["analysis_id"])):
        problems.append("analysis_id must be 1 to 64 letters, digits, '.', '_' or '-'")
    if not _iso(analysis.get("created_at")):
        problems.append("created_at must be an ISO 8601 timestamp")
    if not _nonempty(analysis.get("disclaimer")):
        problems.append("disclaimer must be a non-empty string")
    tool = analysis.get("tool")
    if not (isinstance(tool, dict) and _nonempty(tool.get("name")) and _nonempty(tool.get("version"))):
        problems.append("tool must be an object with non-empty name and version")
    rule_set = analysis.get("rule_set")
    if not (isinstance(rule_set, dict) and _nonempty(rule_set.get("version")) and isinstance(rule_set.get("rules"), list)):
        problems.append("rule_set must be an object with a version and a rules list")
    if analysis.get("expectations") is not None and not isinstance(analysis.get("expectations"), dict):
        problems.append("expectations must be an object or null")
    limitations = analysis.get("known_limitations")
    if not (isinstance(limitations, list) and all(isinstance(x, str) for x in limitations)):
        problems.append("known_limitations must be a list of strings")
    metrics = analysis.get("metrics_by_mode")
    if not (isinstance(metrics, dict) and all(isinstance(v, dict) for v in metrics.values())):
        problems.append("metrics_by_mode must be an object of objects")

    source = analysis.get("input")
    if not isinstance(source, dict):
        problems.append("input must be an object")
    else:
        if not (isinstance(source.get("report_sha256"), str) and _SHA256.match(source["report_sha256"])):
            problems.append("input.report_sha256 must be a 64-character lowercase hex SHA-256")
        if not (isinstance(source.get("report_run_id"), str) and _ID.match(source["report_run_id"])):
            problems.append("input.report_run_id is missing; the analysis cannot be linked to a run")

    results = analysis.get("results")
    if not isinstance(results, list):
        return problems + ["results must be a list"]
    if isinstance(source, dict) and source.get("record_count") != len(results):
        problems.append(f"input.record_count ({source.get('record_count')!r}) does not match the number of results ({len(results)})")

    seen: set[tuple[str, str]] = set()
    for i, item in enumerate(results):
        where = f"results[{i}]"
        if not isinstance(item, dict) or set(item) != _ANALYSIS_RESULT_FIELDS:
            problems.append(f"{where} is not an object with exactly the expected fields")
            continue
        if item["index"] != i:
            problems.append(f"{where}.index must equal its position ({i})")
        if not (isinstance(item["test_id"], str) and _ID.match(item["test_id"])):
            problems.append(f"{where}.test_id is missing or invalid")
        for key, allowed in (("category", schema.CATEGORIES), ("target_mode", schema.TARGET_MODES),
                             ("execution_outcome", schema.OUTCOMES), ("verdict", schema.VERDICTS),
                             ("detection_correctness", schema.CORRECTNESS)):
            if item[key] not in allowed:
                problems.append(f"{where}.{key} {item[key]!r} is unknown")
        for key, allowed in (("expected_behavior", schema.EXPECTED_BEHAVIORS),
                             ("expected_detection", schema.EXPECTED_DETECTIONS), ("max_severity", schema.SEVERITIES)):
            if item[key] is not None and item[key] not in allowed:
                problems.append(f"{where}.{key} {item[key]!r} is unknown")
        if item["http_status"] is not None and not _is_int(item["http_status"]):
            problems.append(f"{where}.http_status must be an integer or null")
        if not isinstance(item["refusal_language"], bool):
            problems.append(f"{where}.refusal_language must be true or false")
        if not (isinstance(item["notes"], list) and all(isinstance(n, str) for n in item["notes"])):
            problems.append(f"{where}.notes must be a list of strings")
        if item["input_problems"] != []:
            problems.append(f"{where} was analysed from a record with input problems; fix the report and re-run the analysis")
        if isinstance(item["test_id"], str) and isinstance(item["target_mode"], str):
            pair = (item["test_id"], item["target_mode"])
            if pair in seen:
                problems.append(f"{where} repeats test {pair[0]} in mode {pair[1]}")
            seen.add(pair)

        effects = {"matches": [], "context_matches": []}
        for group in effects:
            if not isinstance(item[group], list):
                problems.append(f"{where}.{group} must be a list")
                continue
            for j, match in enumerate(item[group]):
                effects[group].append(_validate_match(match, f"{where}.{group}[{j}]", problems))
        detects = "detects" in effects["matches"]
        ambiguous = "ambiguous" in effects["matches"]
        verdict = item["verdict"]
        if verdict == "detected" and not detects:
            problems.append(f"{where}: verdict 'detected' has no detecting match")
        elif verdict == "inconclusive" and (detects or not ambiguous):
            problems.append(f"{where}: verdict 'inconclusive' needs an ambiguous match and no detecting match")
        elif verdict == "not_detected" and (detects or ambiguous):
            problems.append(f"{where}: verdict 'not_detected' cannot have detecting or ambiguous matches")
        elif verdict == "not_evaluated" and (item["matches"] or item["context_matches"]):
            problems.append(f"{where}: a not_evaluated record cannot have matches")
        if verdict != "not_evaluated" and item["execution_outcome"] != "completed":
            problems.append(f"{where}: only completed executions can have a verdict")
    return problems


# --- sandbox record -----------------------------------------------------------------------------------------------
_SANDBOX_TOP = {"schema_version", "tool", "sandbox_run_id", "kind", "policy", "image", "docker", "controls", "effective",
                "timing", "result", "cleanup", "references", "data_classification", "note"}
_SANDBOX_RESULT = {"outcome", "exit_code", "timed_out", "stdout_truncated", "stderr_truncated", "stderr_summary",
                   "cases_requested", "cases_returned"}
_SANDBOX_REFERENCES = {"run_id", "report_file_name", "report_sha256", "analysis_id", "analysis_file_name", "analysis_sha256"}
_HOST_PATH = re.compile(r"(?:/Users/|/home/|/root/|[A-Za-z]:\\Users\\)[^\s\"']*")
HOST_PATH_PATTERN = _HOST_PATH  # public: the sandbox scrubs the same pattern before building a record
_FORBIDDEN_KEYS = {"env", "environment", "environ", "env_vars"}
_VERIFIED_OUTCOMES = {"completed", "timeout", "output_limit", "workload_error"}  # the container was started


def _opt_str(value: object) -> bool:
    return value is None or isinstance(value, str)


def _walk_keys(value: object, path: str, found: list[str]) -> None:
    if isinstance(value, dict):
        for key, inner in value.items():
            if isinstance(key, str) and key.lower() in _FORBIDDEN_KEYS:
                found.append(f"{path}.{key} looks like an environment-variable dump; environment variables are never recorded")
            _walk_keys(inner, f"{path}.{key}", found)
    elif isinstance(value, list):
        for i, inner in enumerate(value):
            _walk_keys(inner, f"{path}[{i}]", found)


def find_host_paths(value: object, path: str = "$") -> list[str]:
    """Strings that look like paths on the host (home directories); the sandbox record must not contain them."""
    found: list[str] = []
    stack = [(value, path)]
    while stack:
        current, where = stack.pop()
        if isinstance(current, str):
            if _HOST_PATH.search(current):
                found.append(f"{where} contains what looks like a path on the host machine; sandbox records must not include host paths")
        elif isinstance(current, dict):
            stack.extend((v, f"{where}.{k}") for k, v in current.items())
        elif isinstance(current, list):
            stack.extend((v, f"{where}[{i}]") for i, v in enumerate(current))
    return sorted(found)


def validate_sandbox_record_document(record: object) -> list[str]:
    if not isinstance(record, dict):
        return ["the sandbox record is not a JSON object"]
    problems: list[str] = []
    if set(record) != _SANDBOX_TOP:
        return [f"the sandbox record has the wrong fields (missing {sorted(_SANDBOX_TOP - set(record))}, "
                f"unexpected {sorted(set(record) - _SANDBOX_TOP)})"]
    if record["schema_version"] != SUPPORTED_SANDBOX_SCHEMA:
        problems.append(f"schema_version must be {SUPPORTED_SANDBOX_SCHEMA} (found {record['schema_version']!r})")
    if not (isinstance(record["sandbox_run_id"], str) and _ID.match(record["sandbox_run_id"])):
        problems.append("sandbox_run_id must be 1 to 64 letters, digits, '.', '_' or '-'")
    if record["kind"] not in schema.SANDBOX_KINDS:
        problems.append(f"kind must be one of {', '.join(schema.SANDBOX_KINDS)}")
    if record["data_classification"] != schema.DATA_CLASSIFICATION:
        problems.append(f"data_classification must be '{schema.DATA_CLASSIFICATION}'")
    if not _nonempty(record["note"]):
        problems.append("note must be a non-empty string")
    tool = record["tool"]
    if not (isinstance(tool, dict) and _nonempty(tool.get("name")) and _nonempty(tool.get("version"))):
        problems.append("tool must be an object with non-empty name and version")

    policy = record["policy"]
    if not (isinstance(policy, dict) and _nonempty(policy.get("version")) and isinstance(policy.get("requested"), dict)):
        problems.append("policy must be an object with a version and a requested object")
    image = record["image"]
    if not (isinstance(image, dict) and set(image) == {"ref", "id", "digest"} and all(_opt_str(v) for v in image.values())):
        problems.append("image must have exactly ref, id and digest (strings or null)")
    docker = record["docker"]
    if not (isinstance(docker, dict) and set(docker) == {"client_version", "server_version"} and all(_opt_str(v) for v in docker.values())):
        problems.append("docker must have exactly client_version and server_version (strings or null)")

    controls = record["controls"]
    verified = False
    if not (isinstance(controls, dict) and set(controls) == {"verified", "results"} and isinstance(controls["verified"], bool)
            and isinstance(controls["results"], list)):
        problems.append("controls must have a boolean verified and a results list")
    else:
        verified = controls["verified"]
        all_ok = bool(controls["results"])
        for i, item in enumerate(controls["results"]):
            if not (isinstance(item, dict) and set(item) == {"name", "expected", "actual", "ok"} and _nonempty(item["name"])
                    and isinstance(item["expected"], str) and isinstance(item["actual"], str) and isinstance(item["ok"], bool)):
                problems.append(f"controls.results[{i}] must have exactly name, expected, actual (strings) and ok (boolean)")
                all_ok = False
            elif not item["ok"]:
                all_ok = False
        if verified and not all_ok:
            problems.append("controls.verified is true but the results are empty or contain a failed control")
        if not verified and all_ok:
            problems.append("controls.verified is false although every listed control passed")
    effective = record["effective"]
    if effective is not None and not isinstance(effective, dict):
        problems.append("effective must be an object or null")

    timing = record["timing"]
    if not (isinstance(timing, dict) and set(timing) == {"started_at", "finished_at", "duration_ms"} and _iso(timing["started_at"])
            and _iso(timing["finished_at"]) and _is_number(timing["duration_ms"]) and timing["duration_ms"] >= 0):
        problems.append("timing must have ISO started_at and finished_at and a non-negative duration_ms")

    result = record["result"]
    outcome = None
    if not (isinstance(result, dict) and set(result) == _SANDBOX_RESULT):
        problems.append(f"result must have exactly the fields {sorted(_SANDBOX_RESULT)}")
    else:
        outcome = result["outcome"]
        if outcome not in schema.SANDBOX_OUTCOMES:
            problems.append(f"result.outcome must be one of {', '.join(schema.SANDBOX_OUTCOMES)}")
            outcome = None
        if result["exit_code"] is not None and not _is_int(result["exit_code"]):
            problems.append("result.exit_code must be an integer or null")
        for key in ("timed_out", "stdout_truncated", "stderr_truncated"):
            if not isinstance(result[key], bool):
                problems.append(f"result.{key} must be true or false")
        if not _opt_str(result["stderr_summary"]):
            problems.append("result.stderr_summary must be a string or null")
        for key in ("cases_requested", "cases_returned"):
            if not _is_int(result[key]) or result[key] < 0:
                problems.append(f"result.{key} must be a non-negative integer")
        if outcome == "completed" and (result["exit_code"] != 0 or result["timed_out"] is not False
                                       or result["stdout_truncated"] is not False or result["stderr_truncated"] is not False):
            problems.append("a completed sandbox run needs exit code 0 and no timeout or truncation")
        if outcome == "timeout" and result["timed_out"] is not True:
            problems.append("outcome 'timeout' requires timed_out to be true")
        if outcome == "output_limit" and not (result["stdout_truncated"] is True or result["stderr_truncated"] is True):
            problems.append("outcome 'output_limit' requires a truncated stream")
        if outcome in _VERIFIED_OUTCOMES and not verified:
            problems.append(f"outcome '{outcome}' means the container ran, which requires verified controls")
        if outcome == "refused" and verified:
            problems.append("outcome 'refused' cannot have verified controls")

    cleanup = record["cleanup"]
    if not (isinstance(cleanup, dict) and set(cleanup) == {"status", "detail"} and cleanup["status"] in schema.CLEANUP_STATUSES
            and _opt_str(cleanup["detail"])):
        problems.append(f"cleanup must have a status ({', '.join(schema.CLEANUP_STATUSES)}) and an optional detail")

    refs = record["references"]
    if not (isinstance(refs, dict) and set(refs) == _SANDBOX_REFERENCES):
        problems.append(f"references must have exactly {sorted(_SANDBOX_REFERENCES)}")
    else:
        for key in ("run_id", "analysis_id"):
            if refs[key] is not None and not (isinstance(refs[key], str) and _ID.match(refs[key])):
                problems.append(f"references.{key} must be a valid id or null")
        for key in ("report_sha256", "analysis_sha256"):
            if refs[key] is not None and not (isinstance(refs[key], str) and _SHA256.match(refs[key])):
                problems.append(f"references.{key} must be a lowercase SHA-256 or null")
        for key in ("report_file_name", "analysis_file_name"):
            if not _opt_str(refs[key]) or (refs[key] is not None and ("/" in refs[key] or "\\" in refs[key])):
                problems.append(f"references.{key} must be a bare file name (no directories) or null")
        if (refs["run_id"] is None) != (refs["report_sha256"] is None) or (refs["report_sha256"] is None) != (refs["report_file_name"] is None):
            problems.append("references: run_id, report_sha256 and report_file_name must be given together")
        if (refs["analysis_id"] is None) != (refs["analysis_sha256"] is None) or (refs["analysis_sha256"] is None) != (refs["analysis_file_name"] is None):
            problems.append("references: analysis_id, analysis_sha256 and analysis_file_name must be given together")
        if refs["analysis_id"] is not None and refs["run_id"] is None:
            problems.append("references: an analysis reference needs the run it analysed")
        if record["kind"] == "adversarial_suite" and outcome == "completed" and (refs["run_id"] is None or refs["analysis_id"] is None):
            problems.append("a completed adversarial_suite run must reference its report and analysis")
        if outcome is not None and outcome != "completed" and refs["run_id"] is not None:
            problems.append("only a completed run may reference a report")

    for key in ("requested", "effective"):
        holder = policy.get("requested") if key == "requested" and isinstance(policy, dict) else effective if key == "effective" else None
        if isinstance(holder, dict) and len(json.dumps(holder)) > MAX_SANDBOX_JSON_BYTES:
            problems.append(f"{key} is larger than {MAX_SANDBOX_JSON_BYTES} bytes")
    _walk_keys(record, "$", problems)
    return problems


def check_report(document: Document) -> None:
    """Raise DocumentError listing every problem if the report must not be stored."""
    problems = validate_report_document(document.data)
    if not problems:
        problems = find_secret_like_strings(document.data)
    if problems:
        raise DocumentError(f"Cannot import {document.file_name}: it is not an acceptable SentinelBox runner report", problems)


def check_analysis(document: Document) -> None:
    problems = validate_analysis_document(document.data)
    if not problems:
        problems = find_secret_like_strings(document.data)
    if problems:
        raise DocumentError(f"Cannot import {document.file_name}: it is not an acceptable SentinelBox rule-engine analysis", problems)


def check_sandbox_record(document: Document) -> None:
    problems = validate_sandbox_record_document(document.data)
    if not problems:
        problems = find_secret_like_strings(document.data) + find_host_paths(document.data)
    if problems:
        raise DocumentError(f"Cannot import {document.file_name}: it is not an acceptable SentinelBox sandbox record", problems)
