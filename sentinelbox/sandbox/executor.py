"""Run ONE approved job in ONE container, with verified controls, bounded I/O and guaranteed cleanup.

Lifecycle: validate -> (docker) resolve image -> create -> inspect and verify every control -> start attached ->
inspect final state -> remove. The container is never started unless every control verified. There is no retry
anywhere: a job id can be executed at most once by an executor, and ``start`` is called at most once per container.
Whatever happens (success, failure, timeout, output flood, Ctrl+C) the container is killed and force-removed in the
``finally`` path, and the result says whether removal was confirmed.

The executor does not interpret the workload's output: it returns the bytes (bounded) and the facts the *host*
observed (exit state from ``docker inspect``, timeout, truncation). Judging the output is the pipeline's job.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import inspection
from . import policy as pol
from .docker_client import DockerClient, DockerError, short
from .image import ImageError, ResolvedImage, resolve_image

OUTCOMES = ("completed", "refused", "docker_error", "timeout", "output_limit", "workload_error", "interrupted")
LABEL_FILTER = f"{pol.LABEL_KEY}={pol.LABEL_VALUE}"


class JobRejected(Exception):
    """The job was refused before anything touched Docker (bad input, duplicate, too many jobs)."""


class ConcurrencyLimitError(JobRejected):
    pass


class DuplicateJobError(JobRejected):
    pass


@dataclass
class SandboxResult:
    job_id: str
    outcome: str
    started_at: str
    finished_at: str
    duration_ms: float
    requested: dict
    controls: list[inspection.ControlResult] = field(default_factory=list)
    effective: dict | None = None
    image: ResolvedImage | None = None
    docker_client_version: str | None = None
    docker_server_version: str | None = None
    exit_code: int | None = None
    timed_out: bool = False
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    stdout: bytes = b""
    stderr_summary: str | None = None
    cleanup_status: str = "not_created"
    cleanup_detail: str | None = None
    error: str | None = None
    container_started: bool = False

    @property
    def controls_verified(self) -> bool:
        return inspection.all_ok(self.controls)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat(timespec="seconds")


def _version(info: object, key: str) -> str | None:
    section = info.get(key) if isinstance(info, dict) else None
    value = section.get("Version") if isinstance(section, dict) else None
    return value if isinstance(value, str) else None


class SandboxExecutor:
    def __init__(self, client: DockerClient, policy: pol.SandboxPolicy, *,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
                 monotonic: Callable[[], float] = time.monotonic):
        self._client = client
        self._policy = pol.validate_policy(policy)
        self._clock = clock
        self._monotonic = monotonic
        self._slots = threading.BoundedSemaphore(policy.max_concurrent_jobs)
        self._lock = threading.Lock()
        self._used_job_ids: set[str] = set()

    @property
    def policy(self) -> pol.SandboxPolicy:
        return self._policy

    # --- public ---------------------------------------------------------------------------------------------------
    def execute(self, job_id: str, request: bytes, image_ref: str) -> SandboxResult:
        """Run one job. Raises :class:`JobRejected` only if nothing was attempted; otherwise returns a result."""
        pol.validate_job_id(job_id)
        pol.validate_image_reference(image_ref)
        if not isinstance(request, (bytes, bytearray)) or not request:
            raise JobRejected("the job input must be non-empty bytes")
        if len(request) > self._policy.max_input_bytes:
            raise JobRejected(f"the job input is {len(request)} bytes; the limit is {self._policy.max_input_bytes}")
        with self._lock:
            if job_id in self._used_job_ids:
                raise DuplicateJobError(f"job {job_id} was already executed by this process; jobs are never run twice")
            self._used_job_ids.add(job_id)
        if not self._slots.acquire(blocking=False):
            raise ConcurrencyLimitError(f"already running {self._policy.max_concurrent_jobs} sandbox job(s); not starting another")
        try:
            return self._execute(job_id, bytes(request), image_ref)
        finally:
            self._slots.release()

    def verify_only(self, job_id: str, image_ref: str) -> SandboxResult:
        """Create the container and verify every control, but NEVER start it; then remove it. Outcome ``completed``
        means every control verified, ``refused`` means at least one did not."""
        pol.validate_job_id(job_id)
        pol.validate_image_reference(image_ref)
        with self._lock:
            if job_id in self._used_job_ids:
                raise DuplicateJobError(f"job {job_id} was already used by this process")
            self._used_job_ids.add(job_id)
        if not self._slots.acquire(blocking=False):
            raise ConcurrencyLimitError(f"already running {self._policy.max_concurrent_jobs} sandbox job(s)")
        try:
            return self._execute(job_id, b"", image_ref, start=False)
        finally:
            self._slots.release()

    # --- lifecycle ---------------------------------------------------------------------------------------------------
    def _execute(self, job_id: str, request: bytes, image_ref: str, *, start: bool = True) -> SandboxResult:
        started = self._clock()
        begin = self._monotonic()
        result = SandboxResult(job_id=job_id, outcome="docker_error", started_at=_iso(started), finished_at=_iso(started),
                               duration_ms=0.0, requested=self._policy.as_requested())
        name = pol.container_name(job_id)
        target: str | None = None  # id once created
        create_attempted = False
        interrupted = False
        try:
            try:
                self._prepare(result, job_id, image_ref)
                if result.outcome == "refused":
                    return self._finish(result, started, begin)
                create_attempted = True
                target = self._create(result, job_id)
                self._verify(result, target)
                if result.outcome == "refused":
                    return self._finish(result, started, begin)
                if start:
                    self._run(result, target, request, begin)
                else:
                    result.outcome = "completed"  # verification-only: every control verified, nothing was started
            except KeyboardInterrupt:
                interrupted = True
                result.outcome = "interrupted"
                result.error = "interrupted by the user (Ctrl+C)"
            except DockerError as exc:
                result.outcome = "docker_error"
                result.error = short(str(exc))
        finally:
            if create_attempted:
                result.cleanup_status, result.cleanup_detail = self._cleanup(target, name)
            self._finish(result, started, begin)
        if interrupted:
            result.outcome = "interrupted"
        return result

    def _finish(self, result: SandboxResult, started: datetime, begin: float) -> SandboxResult:
        result.finished_at = _iso(self._clock())
        result.duration_ms = round((self._monotonic() - begin) * 1000, 3)
        return result

    def _prepare(self, result: SandboxResult, job_id: str, image_ref: str) -> None:
        info = self._client.version_info()
        result.docker_client_version = _version(info, "client")
        result.docker_server_version = _version(info, "server")
        if not isinstance(info, dict) or not info.get("server"):
            raise DockerError("The Docker daemon is not reachable", detail=str(info.get("error") or "") if isinstance(info, dict) else "")
        busy = [c for c in self._client.list_containers(LABEL_FILTER)
                if str(c.get("State", "")).lower() in ("running", "created", "restarting", "paused")]
        if len(busy) >= self._policy.max_concurrent_jobs:
            raise ConcurrencyLimitError(f"{len(busy)} sandbox container(s) already exist; the limit is {self._policy.max_concurrent_jobs}. "
                                        "List them with: python -m sentinelbox.sandbox containers")
        try:
            result.image = resolve_image(self._client, image_ref)
        except ImageError as exc:
            result.outcome = "refused"
            result.error = short(str(exc))

    def _create(self, result: SandboxResult, job_id: str) -> str:
        assert result.image is not None
        args = pol.build_create_args(self._policy, result.image.image_id, job_id)
        return self._client.create_container(args)

    def _verify(self, result: SandboxResult, target: str) -> None:
        assert result.image is not None
        inspected = self._client.inspect_container(target)
        if inspected is None:
            raise DockerError("The container disappeared after it was created")
        result.controls, result.effective = inspection.verify_container(inspected, self._policy, result.image)
        if not inspection.all_ok(result.controls):
            bad = inspection.failed(result.controls)
            result.outcome = "refused"
            result.error = "security controls not verified: " + "; ".join(f"{c.name} (expected {c.expected}, found {c.actual})" for c in bad[:6])

    def _run(self, result: SandboxResult, target: str, request: bytes, begin: float) -> None:
        budget = self._policy.max_lifetime_seconds - (self._monotonic() - begin)
        timeout = max(1.0, min(self._policy.timeout_seconds, budget))
        result.container_started = True  # recorded before the call: after this point the workload may have run
        attached = self._client.run_attached(target, request, timeout=timeout, max_stdout=self._policy.max_stdout_bytes,
                                             max_stderr=self._policy.max_stderr_bytes)
        result.timed_out = bool(attached.timed_out)
        result.stdout_truncated = bool(attached.stdout_truncated)
        result.stderr_truncated = bool(attached.stderr_truncated)
        result.stdout = attached.stdout
        if attached.stderr:
            result.stderr_summary = short(attached.stderr.decode("utf-8", "replace"), 300)
        state = (self._client.inspect_container(target) or {}).get("State")
        exit_code = state.get("ExitCode") if isinstance(state, dict) else None
        result.exit_code = exit_code if isinstance(exit_code, int) and not isinstance(exit_code, bool) else None
        if result.timed_out:
            result.outcome, result.error = "timeout", f"the workload exceeded {timeout:g} s and was killed"
        elif result.stdout_truncated or result.stderr_truncated:
            result.outcome, result.error = "output_limit", "the workload exceeded the output limit and was killed"
        elif not isinstance(state, dict) or state.get("Status") == "created":
            result.outcome, result.error = "docker_error", "the container did not start"
        elif state.get("OOMKilled") is True:
            result.outcome, result.error = "workload_error", "the workload was killed for exceeding the memory limit"
        elif result.exit_code != 0:
            result.outcome, result.error = "workload_error", f"the workload exited with status {result.exit_code}"
        else:
            result.outcome = "completed"

    # --- cleanup ---------------------------------------------------------------------------------------------------------
    def _cleanup(self, target: str | None, name: str) -> tuple[str, str | None]:
        """Kill and force-remove OUR container (by id), confirm removal. A second Ctrl+C cannot skip it.

        If creation failed we never remove anything by name: a container with that name that we did not create
        must not be touched. We only report it.
        """
        if target is None:
            try:
                leftover = self._client.inspect_container(name)
            except DockerError as exc:
                return "failed", f"could not check for a leftover container: {short(str(exc))}"
            if leftover is None:
                return "not_created", None
            return "failed", (f"a container named {name} exists but this run could not confirm creating it, so it was left alone; "
                              "inspect it with: python -m sentinelbox.sandbox containers")
        detail = None
        for _ in range(2):
            try:
                try:
                    self._client.kill_container(target)
                except DockerError:
                    pass  # not running, or already gone
                self._client.remove_container(target)
                if self._client.inspect_container(target) is None:
                    return "removed", None
                detail = "the container still exists after removal was requested"
            except KeyboardInterrupt:
                detail = "cleanup was interrupted and repeated"
            except DockerError as exc:
                detail = short(str(exc))
        return "failed", f"{detail or 'cleanup failed'}; remove it with: python -m sentinelbox.sandbox remove-container {name}"
