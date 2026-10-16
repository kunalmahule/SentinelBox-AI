"""Glue between the sandbox and the existing stages, without duplicating any of their logic.

    Stage 2 library (host)  ->  protocol request  ->  [container: Stage 1 mock + Stage 2 runner]  ->  validated output
    -> Stage 2 report writer (host)  ->  Stage 3 rule engine (host)  ->  sandbox record  ->  Stage 4 storage (host)

Every verdict comes from the host-side rule engine. Files are only ever created, never overwritten.
"""

from __future__ import annotations

import contextlib
import json
import os
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path

from ..rule_engine.analysis import analyze_report, default_output_path, read_report, validate_analysis
from ..rule_engine.expectations import load_expectations
from ..runner.library import DEFAULT_LIBRARY_PATH, PromptLibrary, load_library
from ..runner.models import CaseResult, RunStatus, TargetMode
from ..runner.report import build_report, default_report_name, validate_report
from ..runner.runner import SuiteRun
from ..sandbox_workload import protocol
from ..storage.database import StorageError, open_database
from ..storage.documents import DocumentError, read_document
from ..storage.importer import import_sandbox_record
from . import policy as pol
from .executor import JobRejected, SandboxExecutor, SandboxResult
from .docker_client import DockerClient
from .record import build_record

DEFAULT_REPORTS_DIR = Path("reports")


@dataclass
class PipelineResult:
    result: SandboxResult
    record: dict
    record_path: Path | None = None
    report_path: Path | None = None
    analysis_path: Path | None = None
    db_status: str = "not_requested"  # not_requested | stored | already_stored | failed
    db_error: str | None = None
    messages: list[str] = field(default_factory=list)
    recovery_command: str | None = None
    analysis: dict | None = None


def new_job_id(now: datetime | None = None) -> str:
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y%m%d-%H%M%S")
    return f"{stamp}-{uuid.uuid4().hex[:8]}"


def write_json_exclusive(path: Path, document: dict) -> Path:
    """Write ``document`` as JSON to a NEW file (same layout as the runner/rule engine writers); never overwrite."""
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"{path} already exists; sandbox runs never overwrite files")
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{uuid.uuid4().hex[:8]}.tmp")
    try:
        temp.write_text(json.dumps(document, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")
        try:
            os.link(temp, path)  # atomic, and fails if the destination appeared meanwhile
        except FileExistsError:
            raise FileExistsError(f"{path} appeared while it was being written; not replacing it") from None
        except OSError:
            if path.exists():
                raise FileExistsError(f"{path} appeared while it was being written; not replacing it") from None
            os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)
    return path


def select_cases(library: PromptLibrary, categories: list[str] | None) -> list[protocol.JobCase]:
    chosen = [c for c in library.cases if not categories or c.category.value in categories]
    return [protocol.JobCase(c.test_id, c.category.value, c.title, c.prompt) for c in chosen]


def _suite_run_from(response: dict) -> SuiteRun:
    results = tuple(CaseResult(**item) for item in response["results"])
    return SuiteRun(status=RunStatus(response["status"]), started_at=response["started_at"], finished_at=response["finished_at"],
                    planned=response["planned"], results=results, stop_reason=response["stop_reason"])


def run_suite(client: DockerClient, *, image_ref: str, policy: pol.SandboxPolicy, modes: list[str],
              categories: list[str] | None = None, library_path: Path = DEFAULT_LIBRARY_PATH,
              reports_dir: Path = DEFAULT_REPORTS_DIR, db_path: Path | None = None, job_id: str | None = None,
              executor: SandboxExecutor | None = None) -> PipelineResult:
    """Run the synthetic adversarial suite in the sandbox, analyse it on the host, and store everything."""
    library = load_library(library_path)
    cases = select_cases(library, categories)
    if not cases:
        raise JobRejected("no test cases match the selected categories")
    job_id = pol.validate_job_id(job_id or new_job_id())
    request_dict = protocol.build_request(job_id, "adversarial_suite", modes, cases, timeout_seconds=10.0)
    request_bytes = protocol.encode_request(request_dict)  # enforces the input size limit before anything starts
    request = protocol.parse_request(request_bytes)
    if db_path is not None:  # fail early, before a container is spent on a run that could not be stored
        with contextlib.closing(open_database(db_path)):
            pass
    executor = executor or SandboxExecutor(client, policy)
    result = executor.execute(job_id, request_bytes, image_ref)
    planned = len(request.modes) * len(request.cases)
    return _finalize(result, request, library, planned, reports_dir, db_path)


def _finalize(result: SandboxResult, request: protocol.JobRequest, library: PromptLibrary, planned: int,
              reports_dir: Path, db_path: Path | None) -> PipelineResult:
    messages: list[str] = []
    response = None
    if result.outcome == "completed":
        try:
            response = protocol.parse_response(result.stdout, request)
            if response["status"] != "complete":
                raise protocol.ProtocolError("The workload reported an incomplete run",
                                             [f"status {response['status']!r}: {response['stop_reason']}"])
        except protocol.ProtocolError as exc:
            result = replace(result, outcome="workload_error", error=str(exc).replace("\n", " ")[:500])
            response = None
    report_ref = analysis_ref = None
    analysis_summary = None
    report_path = analysis_path = None
    report_doc = analysis_doc = None
    returned = 0
    if response is not None:
        returned = len(response["results"])
        modes = [TargetMode(m) for m in request.modes]
        report = build_report(_suite_run_from(response), library, protocol.SYNTHETIC_BASE_URL, modes, request.timeout_seconds)
        problems = validate_report(report)
        if problems:
            result = replace(result, outcome="workload_error", error="host-built report failed validation: " + "; ".join(problems[:2]))
        else:
            report_path = write_json_exclusive(reports_dir / default_report_name(report), report)
            report_doc = read_document(report_path, "report")
            loaded = read_report(report_path)
            analysis = analyze_report(loaded, load_expectations())
            analysis_problems = validate_analysis(analysis)
            if analysis_problems:  # an internal bug in the rule engine; never silently stored
                raise RuntimeError("rule engine produced an inconsistent analysis: " + "; ".join(analysis_problems[:2]))
            analysis_path = write_json_exclusive(default_output_path(report_path), analysis)
            analysis_doc = read_document(analysis_path, "analysis")
            analysis_summary = analysis
            report_ref = {"run_id": report["run_id"], "file_name": report_doc.file_name, "sha256": report_doc.sha256}
            analysis_ref = {"analysis_id": analysis["analysis_id"], "file_name": analysis_doc.file_name, "sha256": analysis_doc.sha256}
            messages.append(f"report: {report_path}")
            messages.append(f"analysis: {analysis_path}")
    record = build_record(result, kind="adversarial_suite", cases_requested=planned, cases_returned=returned,
                          report_ref=report_ref, analysis_ref=analysis_ref)
    record_name = (report_path.stem + ".sandbox.json") if report_path else f"sbx-sandbox-{result.job_id}.sandbox.json"
    record_path = write_json_exclusive(reports_dir / record_name, record)
    messages.append(f"sandbox record: {record_path}")
    out = PipelineResult(result=result, record=record, record_path=record_path, report_path=report_path,
                         analysis_path=analysis_path, messages=messages, analysis=analysis_summary)
    if db_path is not None:
        _store(out, db_path, report_doc, analysis_doc)
    return out


def _store(out: PipelineResult, db_path: Path, report_doc, analysis_doc) -> None:
    assert out.record_path is not None
    command = f"python -m sentinelbox.storage import-sandbox --db {db_path} --record {out.record_path}"
    if out.report_path:
        command += f" --report {out.report_path} --analysis {out.analysis_path}"
    try:
        record_doc = read_document(out.record_path, "sandbox record")
        with contextlib.closing(open_database(db_path)) as conn:
            stored = import_sandbox_record(conn, record_doc, report=report_doc, analysis=analysis_doc)
        out.db_status = "already_stored" if stored.status == "already_imported" else "stored"
    except (StorageError, DocumentError) as exc:
        out.db_status = "failed"
        out.db_error = str(exc)
        out.recovery_command = command
