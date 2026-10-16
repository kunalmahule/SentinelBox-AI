"""Plain data types shared by the runner modules."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

# Mirrors the target's documented prompt limit; used only as a sanity check
# when loading a library so oversized cases fail early with a clear message.
MAX_PROMPT_CHARS = 4000


class Category(str, Enum):
    NORMAL = "normal"
    PROMPT_INJECTION = "prompt_injection"
    SAFETY_BYPASS = "safety_bypass"
    CANARY_DISCLOSURE = "canary_disclosure"


class TargetMode(str, Enum):
    VULNERABLE = "vulnerable"
    HARDENED = "hardened"


class Outcome(str, Enum):
    """How a test *executed*. Not a security verdict."""

    COMPLETED = "completed"  # HTTP 200 and a well-formed body
    HTTP_ERROR = "http_error"  # any non-200 status
    TIMEOUT = "timeout"
    CONNECTION_ERROR = "connection_error"
    INVALID_RESPONSE = "invalid_response"  # HTTP 200 but body unusable
    RUNNER_ERROR = "runner_error"  # unexpected failure inside the runner
    NOT_RUN = "not_run"  # run stopped before this case


class RunStatus(str, Enum):
    COMPLETE = "complete"  # every planned case was attempted
    ABORTED = "aborted"  # stopped after repeated connection failures
    INTERRUPTED = "interrupted"  # Ctrl+C


@dataclass(frozen=True)
class TestCase:
    __test__ = False  # not a pytest class, despite the name

    test_id: str
    category: Category
    title: str
    prompt: str


@dataclass(frozen=True)
class CaseResult:
    test_id: str
    category: str
    target_mode: str
    timestamp: str | None  # ISO 8601 UTC time the request started; None if never sent
    duration_ms: float | None
    http_status: int | None
    outcome: str
    response_text: str | None  # the assistant text field from a valid reply
    raw_body: str | None  # HTTP body verbatim (possibly truncated)
    raw_body_truncated: bool
    error: str | None
