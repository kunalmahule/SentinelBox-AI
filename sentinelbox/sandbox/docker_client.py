"""The narrow interface the sandbox needs from Docker, with the typed results and errors around it.

The sandbox code only ever talks to a :class:`DockerClient`. Production uses :mod:`.docker_cli` (the ``docker``
command-line client, argument lists only, no shell); the daemon-independent tests use a fake that implements the same
protocol, so the whole policy / inspection / lifecycle logic is testable without a Docker daemon.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


class DockerError(Exception):
    """A Docker operation failed. ``detail`` is a short, already-trimmed message from Docker."""

    def __init__(self, message: str, *, detail: str = "", returncode: int | None = None):
        super().__init__(message if not detail else f"{message}: {detail}")
        self.detail = detail
        self.returncode = returncode


class DockerUnavailable(DockerError):
    """The Docker CLI is missing, or the daemon cannot be reached."""


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class AttachResult:
    """What came back from running a started container attached to stdin/stdout/stderr."""

    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool
    timed_out: bool
    cli_returncode: int | None


class DockerClient(Protocol):
    def version_info(self) -> dict: ...
    def info(self) -> dict: ...
    def inspect_image(self, ref: str) -> dict | None: ...
    def build_image(self, context: Path, dockerfile: Path, tag: str, build_args: Mapping[str, str],
                    labels: Mapping[str, str], *, legacy_builder: bool = False) -> CommandResult: ...
    def create_container(self, args: Sequence[str]) -> str: ...
    def inspect_container(self, ref: str) -> dict | None: ...
    def run_attached(self, container: str, stdin: bytes, *, timeout: float, max_stdout: int, max_stderr: int) -> AttachResult: ...
    def kill_container(self, ref: str) -> None: ...
    def remove_container(self, ref: str) -> None: ...
    def list_containers(self, label: str) -> list[dict]: ...
    def remove_image(self, ref: str) -> None: ...


def short(text: str, limit: int = 400) -> str:
    """Trim and flatten Docker output for error messages (control characters removed)."""
    flat = " ".join("".join(ch if ch.isprintable() else " " for ch in text).split())
    return flat if len(flat) <= limit else flat[: limit - 3] + "..."
