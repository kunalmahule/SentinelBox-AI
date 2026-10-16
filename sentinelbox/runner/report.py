"""Build, validate, write and summarise the machine-readable run report (schema v1)."""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import asdict
from pathlib import Path

from .. import __version__
from .library import PromptLibrary
from .models import Category, Outcome, RunStatus, TargetMode
from .runner import SuiteRun

REPORT_SCHEMA_VERSION = 1
TOOL_NAME = "sentinelbox-runner"
_OUTCOMES = [o.value for o in Outcome]
_CATEGORIES = [c.value for c in Category]
_MODES = [m.value for m in TargetMode]

_RESULT_FIELDS = {
    "test_id", "category", "target_mode", "timestamp", "duration_ms", "http_status", "outcome",
    "response_text", "raw_body", "raw_body_truncated", "error",
}


def _zero_counts() -> dict[str, int]:
    return {outcome: 0 for outcome in _OUTCOMES}


def build_report(
    run: SuiteRun,
    library: PromptLibrary,
    base_url: str,
    modes: list[TargetMode],
    timeout: float,
    run_id: str | None = None,
) -> dict:
    results = [asdict(r) for r in run.results]
    by_outcome = _zero_counts()
    by_mode: dict[str, dict[str, int]] = {}
    by_category: dict[str, dict[str, int]] = {}
    for item in results:
        by_outcome[item["outcome"]] += 1
        by_mode.setdefault(item["target_mode"], _zero_counts())[item["outcome"]] += 1
        by_category.setdefault(item["category"], _zero_counts())[item["outcome"]] += 1
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": __version__},
        "run_id": run_id or uuid.uuid4().hex,
        "status": run.status.value,
        "stop_reason": run.stop_reason,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "target": {"base_url": base_url, "chat_path": "/chat", "timeout_seconds": timeout},
        "library": {
            "name": library.name,
            "version": library.version,
            "file_name": library.file_name,
            "sha256": library.sha256,
            "case_count": len(library.cases),
        },
        "modes": [m.value for m in dict.fromkeys(modes)],
        "note": (
            "Outcomes describe how each test executed, not whether the target's answer was safe. "
            "No security verdict is made at this stage."
        ),
        "summary": {
            "planned": run.planned,
            "attempted": run.planned - by_outcome[Outcome.NOT_RUN.value],
            "by_outcome": by_outcome,
            "by_mode": by_mode,
            "by_category": by_category,
        },
        "results": results,
    }


def validate_report(report: object) -> list[str]:
    """Return a list of problems; an empty list means the report is valid."""
    problems: list[str] = []
    if not isinstance(report, dict):
        return ["report is not an object"]
    try:
        json.dumps(report, allow_nan=False)
    except (TypeError, ValueError) as exc:
        return [f"report is not JSON-serialisable: {exc}"]

    if report.get("schema_version") != REPORT_SCHEMA_VERSION:
        problems.append(f"schema_version must be {REPORT_SCHEMA_VERSION}")
    for key in ("run_id", "started_at", "finished_at"):
        if not isinstance(report.get(key), str) or not report.get(key):
            problems.append(f"{key} must be a non-empty string")
    if report.get("status") not in [s.value for s in RunStatus]:
        problems.append("status is not a known run status")
    for key in ("tool", "target", "library", "summary"):
        if not isinstance(report.get(key), dict):
            problems.append(f"{key} must be an object")
    modes = report.get("modes")
    if not isinstance(modes, list) or not modes or any(m not in _MODES for m in modes):
        problems.append("modes must be a non-empty list of known target modes")

    results = report.get("results")
    if not isinstance(results, list):
        return problems + ["results must be a list"]

    counts = _zero_counts()
    for i, item in enumerate(results):
        where = f"results[{i}]"
        if not isinstance(item, dict):
            problems.append(f"{where} is not an object")
            continue
        if set(item) != _RESULT_FIELDS:
            problems.append(f"{where} has wrong fields (missing {sorted(_RESULT_FIELDS - set(item))}, "
                            f"extra {sorted(set(item) - _RESULT_FIELDS)})")
            continue
        if not isinstance(item["test_id"], str) or not item["test_id"]:
            problems.append(f"{where}.test_id must be a non-empty string")
        if item["category"] not in _CATEGORIES:
            problems.append(f"{where}.category is unknown")
        if item["target_mode"] not in _MODES:
            problems.append(f"{where}.target_mode is unknown")
        if item["outcome"] not in _OUTCOMES:
            problems.append(f"{where}.outcome is unknown")
            continue
        counts[item["outcome"]] += 1
        if not isinstance(item["raw_body_truncated"], bool):
            problems.append(f"{where}.raw_body_truncated must be a boolean")
        if item["http_status"] is not None and (
            isinstance(item["http_status"], bool) or not isinstance(item["http_status"], int)
        ):
            problems.append(f"{where}.http_status must be an integer or null")
        for key in ("response_text", "raw_body", "error", "timestamp"):
            if item[key] is not None and not isinstance(item[key], str):
                problems.append(f"{where}.{key} must be a string or null")
        duration = item["duration_ms"]
        if duration is not None and (isinstance(duration, bool) or not isinstance(duration, (int, float)) or duration < 0):
            problems.append(f"{where}.duration_ms must be a non-negative number or null")
        if item["outcome"] == Outcome.NOT_RUN.value:
            if item["timestamp"] is not None or item["http_status"] is not None:
                problems.append(f"{where}: a not_run case must have no timestamp or HTTP status")
        else:
            if item["timestamp"] is None:
                problems.append(f"{where}: an attempted case needs a timestamp")
        if item["outcome"] == Outcome.COMPLETED.value:
            if item["http_status"] != 200 or not isinstance(item["response_text"], str):
                problems.append(f"{where}: a completed case needs HTTP 200 and response_text")
        elif item["response_text"] is not None:
            problems.append(f"{where}: only completed cases may carry response_text")

    summary = report.get("summary")
    if isinstance(summary, dict):
        if summary.get("planned") != len(results):
            problems.append("summary.planned does not match the number of results")
        if summary.get("by_outcome") != counts:
            problems.append("summary.by_outcome does not match the results")
        if summary.get("attempted") != len(results) - counts[Outcome.NOT_RUN.value]:
            problems.append("summary.attempted does not match the results")
    return problems


def write_report(report: dict, path: Path | str, *, overwrite: bool = False) -> Path:
    """Write the report as UTF-8 JSON. Refuses to replace an existing file unless asked."""
    problems = validate_report(report)
    if problems:
        raise ValueError("Refusing to write an invalid report: " + "; ".join(problems[:3]))
    path = Path(path)
    if path.exists() and not overwrite:
        raise FileExistsError(f"{path} already exists (use --overwrite to replace it)")
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{uuid.uuid4().hex[:8]}.tmp")
    try:
        temp.write_text(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)
    return path


def default_report_name(report: dict) -> str:
    stamp = report["started_at"][:19].replace("-", "").replace(":", "").replace("T", "-")
    return f"sbx-run-{stamp}-{report['run_id'][:8]}.json"


_COLUMNS = [
    ("completed", "completed"), ("http_error", "http_err"), ("timeout", "timeout"),
    ("connection_error", "conn_err"), ("invalid_response", "invalid"),
    ("runner_error", "runner_err"), ("not_run", "not_run"),
]


def _table(title: str, rows: dict[str, dict[str, int]]) -> list[str]:
    width = max([len(title)] + [len(name) for name in rows]) + 2
    lines = [title.ljust(width) + "".join(label.rjust(11) for _, label in _COLUMNS)]
    for name, counts in rows.items():
        lines.append(("  " + name).ljust(width) + "".join(str(counts.get(key, 0)).rjust(11) for key, _ in _COLUMNS))
    return lines


def format_summary(report: dict, report_path: Path | str | None = None, max_failures_shown: int = 10) -> str:
    summary = report["summary"]
    lib = report["library"]
    lines = [
        "SentinelBox AI - Stage 2 adversarial test runner",
        f"Run {report['run_id'][:8]}  status: {report['status']}"
        + (f"  ({report['stop_reason']})" if report.get("stop_reason") else ""),
        f"Target:  {report['target']['base_url']}  modes: {', '.join(report['modes'])}",
        f"Library: {lib['name']} v{lib['version']}  {lib['case_count']} cases  sha256 {lib['sha256'][:12]}",
        f"Cases:   {summary['attempted']} attempted of {summary['planned']} planned",
        "",
    ]
    lines += _table("By target mode", summary["by_mode"])
    lines.append("")
    lines += _table("By category", summary["by_category"])
    failures = [r for r in report["results"] if r["outcome"] not in ("completed", "not_run")]
    if failures:
        lines += ["", f"Execution problems ({len(failures)}):"]
        for r in failures[:max_failures_shown]:
            lines.append(f"  {r['test_id']} [{r['target_mode']}] {r['outcome']}: {r['error']}")
        if len(failures) > max_failures_shown:
            lines.append(f"  ... and {len(failures) - max_failures_shown} more (see the JSON report)")
    lines += ["", "These are execution outcomes only. No safe/unsafe verdict is made here;",
              "the Stage 3 rule engine will analyse the raw responses."]
    if report_path is not None:
        lines.append(f"Report: {report_path}")
    return "\n".join(lines)
