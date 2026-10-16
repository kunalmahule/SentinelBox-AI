"""Execute prompt-library cases against a target and record what came back.

The runner never decides whether a response is safe. It only records whether
each request executed and what the HTTP response contained. It sends
``{"prompt", "mode"}`` and nothing else, and it does not read any metadata
field of the reply.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone

from .models import CaseResult, Outcome, RunStatus, TargetMode, TestCase
from .transport import (
    CHAT_PATH,
    Transport,
    TransportConnectionError,
    TransportError,
    TransportResponse,
    TransportTimeout,
    validate_target_url,
)

DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_MAX_CONSECUTIVE_FAILURES = 3
_STOPPING_OUTCOMES = {Outcome.TIMEOUT.value, Outcome.CONNECTION_ERROR.value}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.isoformat(timespec="milliseconds")


@dataclass(frozen=True)
class SuiteRun:
    status: RunStatus
    started_at: str
    finished_at: str
    planned: int
    results: tuple[CaseResult, ...]
    stop_reason: str | None


def _parse_reply(response: TransportResponse) -> tuple[str | None, str | None]:
    """Return (assistant_text, problem). Exactly one of them is None."""
    if response.truncated:
        return None, "response body exceeded the size limit"
    try:
        text = response.body.decode("utf-8")
    except UnicodeDecodeError:
        return None, "response body is not valid UTF-8"
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return None, "response body is not valid JSON"
    if not isinstance(data, dict):
        return None, "response JSON is not an object"
    reply = data.get("response")
    if not isinstance(reply, str):
        return None, "response JSON has no string 'response' field"
    return reply, None


def execute_case(
    case: TestCase,
    mode: TargetMode,
    chat_url: str,
    transport: Transport,
    timeout: float,
    clock: Callable[[], datetime] = utc_now,
    timer: Callable[[], float] = time.perf_counter,
) -> CaseResult:
    started = clock()
    begin = timer()

    def result(outcome: Outcome, *, status=None, text=None, body=None, truncated=False, error=None) -> CaseResult:
        return CaseResult(
            test_id=case.test_id,
            category=case.category.value,
            target_mode=mode.value,
            timestamp=_iso(started),
            duration_ms=round((timer() - begin) * 1000, 3),
            http_status=status,
            outcome=outcome.value,
            response_text=text,
            raw_body=body,
            raw_body_truncated=truncated,
            error=error,
        )

    try:
        response = transport.post_json(chat_url, {"prompt": case.prompt, "mode": mode.value}, timeout)
    except TransportTimeout as exc:
        return result(Outcome.TIMEOUT, error=str(exc))
    except TransportConnectionError as exc:
        return result(Outcome.CONNECTION_ERROR, error=str(exc))
    except TransportError as exc:
        return result(Outcome.CONNECTION_ERROR, error=f"Transport error: {exc}")
    except Exception as exc:  # a bug in a custom transport must not kill the whole run
        return result(Outcome.RUNNER_ERROR, error=f"{type(exc).__name__}: {exc}")

    raw = response.body.decode("utf-8", errors="replace")
    common = {"status": response.status, "body": raw, "truncated": response.truncated}
    if response.status != 200:
        return result(Outcome.HTTP_ERROR, error=f"HTTP {response.status}", **common)
    reply, problem = _parse_reply(response)
    if problem is not None:
        return result(Outcome.INVALID_RESPONSE, error=problem, **common)
    return result(Outcome.COMPLETED, text=reply, **common)


def _not_run(case: TestCase, mode: TargetMode, reason: str) -> CaseResult:
    return CaseResult(
        test_id=case.test_id,
        category=case.category.value,
        target_mode=mode.value,
        timestamp=None,
        duration_ms=None,
        http_status=None,
        outcome=Outcome.NOT_RUN.value,
        response_text=None,
        raw_body=None,
        raw_body_truncated=False,
        error=reason,
    )


def run_suite(
    cases: Sequence[TestCase],
    modes: Sequence[TargetMode],
    base_url: str,
    transport: Transport,
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_consecutive_failures: int = DEFAULT_MAX_CONSECUTIVE_FAILURES,
    clock: Callable[[], datetime] = utc_now,
    timer: Callable[[], float] = time.perf_counter,
    on_result: Callable[[CaseResult], None] | None = None,
) -> SuiteRun:
    """Run every case in every mode (mode-major order).

    Stops early, and marks the remaining cases ``not_run``, after
    *max_consecutive_failures* timeouts/connection errors in a row or on Ctrl+C.
    """
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if max_consecutive_failures < 1:
        raise ValueError("max_consecutive_failures must be at least 1")
    chat_url = validate_target_url(base_url) + CHAT_PATH
    unique_modes = list(dict.fromkeys(modes))
    plan = [(mode, case) for mode in unique_modes for case in cases]

    started_at = _iso(clock())
    results: list[CaseResult] = []
    status, stop_reason = RunStatus.COMPLETE, None
    consecutive = 0

    for index, (mode, case) in enumerate(plan):
        try:
            outcome = execute_case(case, mode, chat_url, transport, timeout, clock, timer)
        except KeyboardInterrupt:
            status, stop_reason = RunStatus.INTERRUPTED, "Interrupted by user (Ctrl+C)"
            break
        results.append(outcome)
        if on_result is not None:
            on_result(outcome)
        consecutive = consecutive + 1 if outcome.outcome in _STOPPING_OUTCOMES else 0
        if consecutive >= max_consecutive_failures and index + 1 < len(plan):
            status = RunStatus.ABORTED
            stop_reason = f"Stopped after {consecutive} consecutive timeout/connection failures"
            break

    for mode, case in plan[len(results):]:
        results.append(_not_run(case, mode, stop_reason or "not run"))

    return SuiteRun(
        status=status,
        started_at=started_at,
        finished_at=_iso(clock()),
        planned=len(plan),
        results=tuple(results),
        stop_reason=stop_reason,
    )
