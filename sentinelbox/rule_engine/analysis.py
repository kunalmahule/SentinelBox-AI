"""Turn a Stage 2 runner report into a separate analysis report.

The runner report is opened read-only and is never modified. Only these fields are read from each
record: test_id, category, target_mode, outcome, http_status, response_text. In particular the raw HTTP
body (which can include the mock's ``meta``) is never parsed or even named in this package.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .. import __version__
from .engine import evaluate_response
from .expectations import Expectations
from .metrics import SCOPE, VERDICT_KEYS, compute_mode_metrics
from .models import Correctness, Effect, ExpectedBehavior, ExpectedDetection, Verdict
from .rules import RULE_SET_VERSION, RULES

ANALYSIS_SCHEMA_VERSION = 1
TOOL_NAME = "sentinelbox-rule-engine"
SUPPORTED_REPORT_SCHEMA = 1
MAX_REPORT_BYTES = 50 * 1024 * 1024
KNOWN_OUTCOMES = {"completed", "http_error", "timeout", "connection_error", "invalid_response", "runner_error", "not_run"}

DISCLAIMER = (
    "SYNTHETIC MOCK-ENVIRONMENT MEASUREMENT. These verdicts and metrics describe how the rules behave on the "
    "deterministic Stage 1 mock target, scored against hand-authored labels. They are not an estimate of real-world "
    "AI security or of how any detector would perform on real model output."
)
KNOWN_LIMITATIONS = [
    "Rules inspect the response text only; they cannot see intent, the prompt, or side effects.",
    "Injection and bypass detection leans on the mock's documented sentinel tokens (SIM-...-SUCCESS) plus phrase patterns; "
    "a real model would not print sentinels, so those rules would not transfer.",
    "Only the known fictional canary values are recognised; encoded, translated or paraphrased leaks are missed.",
    "The Stage 2 library produces only a handful of distinct response strings, so high scores on it are expected "
    "by construction and say little about detector quality.",
    "'not_detected' means no known indicator was found, not that the response is safe.",
    "Expectation labels are hand-authored for the mock's designed behaviour and share an author with the rules.",
]


class ReportFormatError(Exception):
    """The runner report cannot be analysed at all."""

    def __init__(self, message: str, problems: list[str] | None = None):
        super().__init__(message)
        self.problems = problems or []


@dataclass(frozen=True)
class LoadedReport:
    data: dict
    sha256: str
    file_name: str


def _reject_constant(name: str):
    raise ValueError(f"non-finite number {name} is not allowed")


def read_report(path: Path | str) -> LoadedReport:
    path = Path(path)
    try:
        size = path.stat().st_size
        if size > MAX_REPORT_BYTES:
            raise ReportFormatError(f"Report is larger than {MAX_REPORT_BYTES // (1024 * 1024)} MiB; refusing to load it")
        with path.open("rb") as handle:  # read-only
            raw = handle.read(MAX_REPORT_BYTES + 1)
    except OSError as exc:
        raise ReportFormatError(f"Cannot read report {path}: {exc.strerror or exc}") from exc
    try:
        data = json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ReportFormatError(f"{path.name} is not valid UTF-8 JSON: {exc}") from exc
    problems = []
    if not isinstance(data, dict):
        problems.append("report is not a JSON object")
    else:
        if data.get("schema_version") != SUPPORTED_REPORT_SCHEMA:
            problems.append(f"schema_version must be {SUPPORTED_REPORT_SCHEMA} (found {data.get('schema_version')!r})")
        if not isinstance(data.get("results"), list):
            problems.append("'results' must be a list")
    if problems:
        raise ReportFormatError(f"{path.name} is not a supported SentinelBox runner report", problems)
    return LoadedReport(data, hashlib.sha256(raw).hexdigest(), path.name)


def _parse_record(item: object) -> tuple[dict, list[str]]:
    """Pick the few fields the engine needs; never touches anything else in the record."""
    if not isinstance(item, dict):
        return {"test_id": None, "category": None, "target_mode": None, "outcome": None,
                "http_status": None, "response_text": None}, ["record is not an object"]
    problems: list[str] = []
    record = {}
    for key in ("test_id", "category", "target_mode"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            record[key] = value
        else:
            record[key] = None
            problems.append(f"{key} is missing or not a non-empty string")
    outcome = item.get("outcome")
    if outcome in KNOWN_OUTCOMES:
        record["outcome"] = outcome
    else:
        record["outcome"] = None
        problems.append(f"outcome {outcome!r} is missing or unknown")
    status = item.get("http_status")
    if status is None or (isinstance(status, int) and not isinstance(status, bool)):
        record["http_status"] = status
    else:
        record["http_status"] = None
        problems.append("http_status is not an integer or null")
    text = item.get("response_text")
    record["response_text"] = text if isinstance(text, str) else None
    if record["outcome"] == "completed" and not isinstance(text, str):
        problems.append("outcome is 'completed' but response_text is missing or not a string")
    return record, problems


def _match_dict(match) -> dict:
    return {
        "rule_id": match.rule_id, "family": match.family, "severity": match.severity.value,
        "base_confidence": match.base_confidence.value, "confidence": match.confidence.value,
        "effect": match.effect.value, "rationale": match.rationale, "adjustments": list(match.adjustments),
        "evidence": {"text": match.evidence.text, "start": match.evidence.start, "end": match.evidence.end,
                     "context": match.evidence.context},
    }


def correctness_for(verdict: str, expected_detection: str | None) -> str:
    if verdict == Verdict.NOT_EVALUATED.value:
        return Correctness.NOT_APPLICABLE.value
    if expected_detection is None:
        return Correctness.UNKNOWN.value
    if verdict == Verdict.INCONCLUSIVE.value:
        return Correctness.UNRESOLVED.value
    return (Correctness.CORRECT if verdict == expected_detection else Correctness.INCORRECT).value


def _analyse_record(index: int, item: object, expectations: Expectations | None, duplicate: bool = False) -> dict:
    record, problems = _parse_record(item)
    if duplicate:
        problems.append("duplicate (test_id, target_mode) pair in the report")
    notes: list[str] = []
    expectation = None
    if expectations is not None and record["test_id"] is not None:
        expectation = expectations.cases.get(record["test_id"])
        if expectation is not None and expectation.category != record["category"]:
            notes.append(f"Category in the report ({record['category']!r}) differs from the expectations file "
                         f"({expectation.category!r}); the expectation was ignored.")
            expectation = None
        elif expectation is None:
            notes.append("No expectation is defined for this test id.")
    expected_behavior = expectation.expected_behavior if expectation else None
    expected_detection = expectation.expected_detection.get(record["target_mode"]) if expectation else None

    matches: list[dict] = []
    context: list[dict] = []
    refusal = None
    severity = None
    if problems:
        verdict = Verdict.NOT_EVALUATED.value
        notes.append("Not evaluated because the record has input problems (fail closed).")
    elif record["outcome"] == "completed" and isinstance(record["response_text"], str):
        evaluation = evaluate_response(record["response_text"], expected_behavior)
        verdict = evaluation.verdict.value
        matches = [_match_dict(m) for m in evaluation.matches]
        context = [_match_dict(m) for m in evaluation.context_matches]
        refusal = evaluation.refusal_language
        severity = evaluation.max_severity.value if evaluation.max_severity else None
        notes.extend(evaluation.notes)
    else:
        verdict = Verdict.NOT_EVALUATED.value
        if record["outcome"] is not None:
            notes.append(f"Execution outcome was '{record['outcome']}', so there is no response to evaluate.")
    if expectation is not None and expected_detection is None:
        notes.append(f"The expectation has no label for target mode {record['target_mode']!r}.")

    expected_detection_value = expected_detection.value if expected_detection else None
    return {
        "index": index,
        "test_id": record["test_id"],
        "category": record["category"],
        "target_mode": record["target_mode"],
        "execution_outcome": record["outcome"],
        "http_status": record["http_status"],
        "expected_behavior": expected_behavior.value if expected_behavior else None,
        "expected_detection": expected_detection_value,
        "verdict": verdict,
        "detection_correctness": correctness_for(verdict, expected_detection_value),
        "max_severity": severity,
        "refusal_language": refusal,
        "matches": matches,
        "context_matches": context,
        "notes": notes,
        "input_problems": problems,
    }


def _mode_order(modes: list[str]) -> list[str]:
    preferred = [m for m in ("vulnerable", "hardened") if m in modes]
    return preferred + sorted(m for m in modes if m not in preferred)


def compute_metrics_by_mode(results: list[dict]) -> dict:
    grouped: dict[str, list[dict]] = {}
    for item in results:
        grouped.setdefault(item["target_mode"] or "unknown", []).append(item)
    return {mode: compute_mode_metrics(grouped[mode]) for mode in _mode_order(list(grouped))}


def rule_set_description() -> dict:
    return {
        "version": RULE_SET_VERSION,
        "rules": [
            {"rule_id": r.rule_id, "family": r.family, "title": r.title, "severity": r.severity.value,
             "base_confidence": r.confidence.value, "context_sensitive": r.context_sensitive,
             "context_only": r.context_only, "control_only": r.control_only,
             "rationale": r.rationale, "limitations": r.limitations}
            for r in RULES
        ],
    }


def analyze_report(
    loaded: LoadedReport,
    expectations: Expectations | None,
    *,
    now: datetime | None = None,
    analysis_id: str | None = None,
) -> dict:
    data = loaded.data
    seen: set[tuple[str, str]] = set()
    results = []
    for i, item in enumerate(data["results"]):
        parsed, _ = _parse_record(item)
        key = (parsed["test_id"], parsed["target_mode"])
        duplicate = None not in key and key in seen  # a repeated pair would double-count in the metrics
        if None not in key:
            seen.add(key)
        results.append(_analyse_record(i, item, expectations, duplicate))
    library = data.get("library") if isinstance(data.get("library"), dict) else {}
    created = (now or datetime.now(timezone.utc)).isoformat(timespec="seconds")
    return {
        "schema_version": ANALYSIS_SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": __version__},
        "analysis_id": analysis_id or uuid.uuid4().hex,
        "created_at": created,
        "scope": SCOPE,
        "disclaimer": DISCLAIMER,
        "input": {
            "report_file_name": loaded.file_name,
            "report_sha256": loaded.sha256,
            "report_run_id": data.get("run_id") if isinstance(data.get("run_id"), str) else None,
            "report_status": data.get("status") if isinstance(data.get("status"), str) else None,
            "report_schema_version": data.get("schema_version"),
            "library_name": library.get("name") if isinstance(library.get("name"), str) else None,
            "library_version": library.get("version") if isinstance(library.get("version"), str) else None,
            "record_count": len(results),
            "records_with_input_problems": sum(1 for r in results if r["input_problems"]),
        },
        "expectations": (
            {"name": expectations.name, "version": expectations.version, "kind": expectations.kind,
             "file_name": expectations.file_name, "sha256": expectations.sha256, "case_count": len(expectations.cases)}
            if expectations is not None else None
        ),
        "rule_set": rule_set_description(),
        "known_limitations": KNOWN_LIMITATIONS,
        "metrics_by_mode": compute_metrics_by_mode(results),
        "results": results,
    }


# --- validation ---------------------------------------------------------------------------------------
_RESULT_KEYS = {
    "index", "test_id", "category", "target_mode", "execution_outcome", "http_status", "expected_behavior",
    "expected_detection", "verdict", "detection_correctness", "max_severity", "refusal_language", "matches",
    "context_matches", "notes", "input_problems",
}


def validate_analysis(analysis: object) -> list[str]:
    """Return problems; an empty list means the analysis is internally consistent."""
    if not isinstance(analysis, dict):
        return ["analysis is not an object"]
    try:
        json.dumps(analysis, allow_nan=False)
    except (TypeError, ValueError) as exc:
        return [f"analysis is not JSON-serialisable: {exc}"]
    problems: list[str] = []
    if analysis.get("schema_version") != ANALYSIS_SCHEMA_VERSION:
        problems.append(f"schema_version must be {ANALYSIS_SCHEMA_VERSION}")
    if analysis.get("scope") != SCOPE:
        problems.append("scope must be the synthetic mock-environment scope")
    for key in ("analysis_id", "created_at", "disclaimer"):
        if not isinstance(analysis.get(key), str) or not analysis[key]:
            problems.append(f"{key} must be a non-empty string")
    for key in ("tool", "input", "rule_set", "metrics_by_mode"):
        if not isinstance(analysis.get(key), dict):
            problems.append(f"{key} must be an object")
    results = analysis.get("results")
    if not isinstance(results, list):
        return problems + ["results must be a list"]

    verdicts, correctness = set(VERDICT_KEYS), {c.value for c in Correctness}
    effects = {e.value for e in Effect}
    for i, item in enumerate(results):
        where = f"results[{i}]"
        if not isinstance(item, dict) or set(item) != _RESULT_KEYS:
            problems.append(f"{where} is not an object with exactly the expected fields")
            continue
        if item["verdict"] not in verdicts:
            problems.append(f"{where}.verdict is unknown")
            continue
        if item["detection_correctness"] not in correctness:
            problems.append(f"{where}.detection_correctness is unknown")
        elif item["detection_correctness"] != correctness_for(item["verdict"], item["expected_detection"]):
            problems.append(f"{where}.detection_correctness does not follow from verdict and expected_detection")
        if item["expected_behavior"] not in [None] + [b.value for b in ExpectedBehavior]:
            problems.append(f"{where}.expected_behavior is unknown")
        if item["expected_detection"] not in [None] + [d.value for d in ExpectedDetection]:
            problems.append(f"{where}.expected_detection is unknown")
        match_effects = []
        for group in ("matches", "context_matches"):
            if not isinstance(item[group], list):
                problems.append(f"{where}.{group} must be a list")
                continue
            for m in item[group]:
                if not isinstance(m, dict) or m.get("effect") not in effects or not isinstance(m.get("evidence"), dict):
                    problems.append(f"{where}.{group} contains a malformed match")
                else:
                    match_effects.append((group, m["effect"]))
        detects = any(g == "matches" and e == "detects" for g, e in match_effects)
        ambiguous = any(g == "matches" and e == "ambiguous" for g, e in match_effects)
        if item["verdict"] == "detected" and not detects:
            problems.append(f"{where}: verdict 'detected' has no detecting match")
        if item["verdict"] == "inconclusive" and (detects or not ambiguous):
            problems.append(f"{where}: verdict 'inconclusive' needs an ambiguous match and no detecting match")
        if item["verdict"] == "not_detected" and (detects or ambiguous):
            problems.append(f"{where}: verdict 'not_detected' must not have detecting or ambiguous matches")
        if item["verdict"] == "not_evaluated" and (item["matches"] or item["context_matches"]):
            problems.append(f"{where}: a not_evaluated record cannot have matches")
        if item["input_problems"] and item["verdict"] != "not_evaluated":
            problems.append(f"{where}: a record with input problems must be not_evaluated")
        if item["verdict"] != "not_evaluated" and item["execution_outcome"] != "completed":
            problems.append(f"{where}: only completed executions can be evaluated")
    if not problems and analysis.get("metrics_by_mode") != compute_metrics_by_mode(results):
        problems.append("metrics_by_mode does not match the results")
    return problems


# --- writing --------------------------------------------------------------------------------------------
def same_file(a: Path, b: Path) -> bool:
    try:
        if a.exists() and b.exists():
            return os.path.samefile(a, b)
    except OSError:
        pass
    return a.resolve() == b.resolve()


def default_output_path(report_path: Path | str) -> Path:
    report_path = Path(report_path)
    return report_path.with_name(report_path.stem + ".analysis.json")


def write_analysis(analysis: dict, path: Path | str, *, overwrite: bool = False, input_path: Path | str | None = None) -> Path:
    problems = validate_analysis(analysis)
    if problems:
        raise ValueError("Refusing to write an inconsistent analysis: " + "; ".join(problems[:3]))
    path = Path(path)
    if input_path is not None and same_file(path, Path(input_path)):
        raise ValueError("Refusing to write over the input report; choose a different --output")
    if path.exists() and not overwrite:
        raise FileExistsError(f"{path} already exists (use --overwrite to replace it)")
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{uuid.uuid4().hex[:8]}.tmp")
    try:
        temp.write_text(json.dumps(analysis, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)
    return path


# --- terminal summary -------------------------------------------------------------------------------------
def _fmt(metric: dict) -> str:
    return "n/a" if metric["value"] is None else f"{metric['value']:.3f}"


def format_summary(analysis: dict, output_path: Path | str | None = None) -> str:
    info, exp = analysis["input"], analysis["expectations"]
    lines = [
        "SentinelBox AI - Stage 3 rule engine (analysis of an existing runner report)",
        f"Input:        {info['report_file_name']}  run {str(info['report_run_id'])[:8]}  status {info['report_status']}"
        f"  sha256 {info['report_sha256'][:12]}",
        f"Rules:        v{analysis['rule_set']['version']} ({len(analysis['rule_set']['rules'])} rules)",
        "Expectations: " + (f"{exp['name']} v{exp['version']} ({exp['case_count']} cases)" if exp else "none (correctness unknown)"),
        f"Records:      {info['record_count']}",
        "",
        "Detection verdicts".ljust(20) + "".join(k.rjust(15) for k in VERDICT_KEYS),
    ]
    for mode, block in analysis["metrics_by_mode"].items():
        lines.append(("  " + mode).ljust(20) + "".join(str(block["verdict_counts"][k]).rjust(15) for k in VERDICT_KEYS))
    lines += ["", "Detection correctness (verdict vs expected detection, abstentions excluded)",
              "  mode".ljust(14) + "".join(h.rjust(6) for h in ("TP", "FP", "TN", "FN")) + "inconcl.".rjust(10)
              + "precision".rjust(11) + "recall".rjust(8) + "F1".rjust(8)]
    for mode, b in analysis["metrics_by_mode"].items():
        c = b["confusion"]
        lines.append(("  " + mode).ljust(14) + "".join(str(c[k]).rjust(6) for k in ("tp", "fp", "tn", "fn"))
                     + str(sum(b["inconclusive"].values())).rjust(10) + _fmt(b["precision"]).rjust(11)
                     + _fmt(b["recall"]).rjust(8) + _fmt(b["f1"]).rjust(8))
    lines += ["", "n/a = undefined because the denominator is zero (see the JSON for the reason).",
              "Metrics are per mode and are never pooled.", "", analysis["disclaimer"]]
    if info["records_with_input_problems"]:
        lines += ["", f"WARNING: {info['records_with_input_problems']} record(s) had input problems and were not evaluated;"
                      " see input_problems in the JSON."]
    if output_path is not None:
        lines.append(f"Analysis: {output_path}")
    return "\n".join(lines)
