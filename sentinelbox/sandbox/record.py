"""Build the sandbox record (schema 1) that the Stage 4 storage layer validates and stores.

The record is assembled by the HOST from what the host observed. Free text that originated in the container
(stderr) or in error messages is trimmed, stripped of host-path look-alikes and withheld entirely if it resembles a
credential: an audit record must never become the place where something sensitive is persisted.
"""

from __future__ import annotations

from .. import __version__
from ..storage.documents import HOST_PATH_PATTERN, find_secret_like_strings
from .docker_client import short
from .executor import SandboxResult
from . import POLICY_VERSION

SCHEMA_VERSION = 1
TOOL_NAME = "sentinelbox-sandbox"
NOTE_PREFIX = ("Synthetic sandbox run against the deterministic local mock only; the container is an execution "
               "boundary and its output was validated by the host, never trusted.")
WITHHELD = "[withheld: matched a credential pattern]"


def sanitize(text: str | None, limit: int = 300) -> str | None:
    if text is None:
        return None
    cleaned = HOST_PATH_PATTERN.sub("[host path removed]", short(text, limit))
    if find_secret_like_strings({"v": cleaned}):
        return WITHHELD
    return cleaned or None


def build_record(result: SandboxResult, *, kind: str, cases_requested: int, cases_returned: int,
                 report_ref: dict | None = None, analysis_ref: dict | None = None) -> dict:
    refs = {"run_id": None, "report_file_name": None, "report_sha256": None,
            "analysis_id": None, "analysis_file_name": None, "analysis_sha256": None}
    if report_ref:
        refs.update(run_id=report_ref["run_id"], report_file_name=report_ref["file_name"], report_sha256=report_ref["sha256"])
    if analysis_ref:
        refs.update(analysis_id=analysis_ref["analysis_id"], analysis_file_name=analysis_ref["file_name"],
                    analysis_sha256=analysis_ref["sha256"])
    note = NOTE_PREFIX
    message = sanitize(result.error, 400)
    if message:
        note += f" Host message: {message}"
    image = result.image
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": __version__},
        "sandbox_run_id": result.job_id,
        "kind": kind,
        "policy": {"version": POLICY_VERSION, "requested": result.requested},
        "image": {"ref": image.ref if image else None, "id": image.image_id if image else None,
                  "digest": image.digest if image else None},
        "docker": {"client_version": result.docker_client_version, "server_version": result.docker_server_version},
        "controls": {"verified": result.controls_verified, "results": [c.as_dict() for c in result.controls]},
        "effective": result.effective,
        "timing": {"started_at": result.started_at, "finished_at": result.finished_at, "duration_ms": result.duration_ms},
        "result": {"outcome": result.outcome, "exit_code": result.exit_code, "timed_out": result.timed_out,
                   "stdout_truncated": result.stdout_truncated, "stderr_truncated": result.stderr_truncated,
                   "stderr_summary": sanitize(result.stderr_summary), "cases_requested": cases_requested,
                   "cases_returned": cases_returned},
        "cleanup": {"status": result.cleanup_status, "detail": sanitize(result.cleanup_detail, 300)},
        "references": refs,
        "data_classification": "synthetic_test_data",
        "note": note,
    }
