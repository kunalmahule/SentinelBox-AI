"""Runs an approved synthetic job inside the container by reusing the Stage 1 engine and the Stage 2 runner.

The runner talks to the mock through an in-process transport, so no socket is ever opened. The harness records
what the runner recorded; it makes no judgement about safety and has no access to the rule engine or any database.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from ..mock_ai.engine import MODEL_NAME, respond
from ..mock_ai.scenarios import Mode
from ..runner.models import Category, TargetMode, TestCase
from ..runner.runner import run_suite
from ..runner.transport import TransportResponse
from . import protocol

SYNTHETIC_BASE_URL = protocol.SYNTHETIC_BASE_URL
MAX_PROMPT_CHARS = 4000


class InProcessMockTransport:
    """Answers ``POST /chat`` by calling the deterministic mock engine directly (same JSON shape as the HTTP app)."""

    def post_json(self, url: str, payload: dict, timeout: float) -> TransportResponse:
        if not url.endswith("/chat"):
            return TransportResponse(404, b'{"detail":"not found"}')
        prompt, mode = payload.get("prompt"), payload.get("mode")
        valid = (set(payload) == {"prompt", "mode"} and isinstance(prompt, str) and prompt.strip()
                 and len(prompt) <= MAX_PROMPT_CHARS and mode in {m.value for m in Mode})
        if not valid:
            return TransportResponse(422, b'{"detail":"invalid request"}')
        result = respond(prompt, Mode(mode))
        body = {"model": MODEL_NAME, "response": result.response,
                "meta": {"scenario": result.scenario.value, "mode": result.mode.value,
                         "matched_rule": result.matched_rule, "deterministic": True}}
        return TransportResponse(200, json.dumps(body, ensure_ascii=False).encode("utf-8"))


def run_job(request: protocol.JobRequest) -> dict:
    """Execute a suite request and return a protocol response (a plain dict)."""
    cases = [TestCase(c.test_id, Category(c.category), c.title, c.prompt) for c in request.cases]
    modes = [TargetMode(m) for m in request.modes]
    run = run_suite(cases, modes, SYNTHETIC_BASE_URL, InProcessMockTransport(), timeout=request.timeout_seconds,
                    max_consecutive_failures=request.max_consecutive_failures)
    return protocol.build_response(
        request, status=run.status.value, stop_reason=run.stop_reason, started_at=run.started_at,
        finished_at=run.finished_at, planned=run.planned, results=[asdict(r) for r in run.results], observations=None)
