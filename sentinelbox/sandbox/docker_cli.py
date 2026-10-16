"""``DockerClient`` backed by the ``docker`` command-line client (the only module here that starts processes).

* Every command is an argument list; no shell is involved, and nothing from a job reaches a command line.
* Attached execution reads stdout and stderr through bounded readers, enforces a wall-clock deadline, and kills the
  *container* (not just the local CLI process) when a limit is exceeded, because the CLI exiting does not stop it.
* Nothing is retried here or anywhere else: a command that may have taken effect is never repeated.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from pathlib import Path

from .docker_client import AttachResult, CommandResult, DockerError, DockerUnavailable, short

COMMAND_TIMEOUT_SECONDS = 120.0
BUILD_TIMEOUT_SECONDS = 900.0
_NO_SUCH = ("no such container", "no such image", "no such object", "not found")


class _Capture:
    """Reads a stream up to ``limit`` bytes; keeps draining (and discarding) after that so the writer never blocks."""

    def __init__(self, limit: int):
        self.limit = limit
        self.data = bytearray()
        self.truncated = False

    def pump(self, stream) -> None:
        try:
            while True:
                chunk = stream.read1(65536) if hasattr(stream, "read1") else stream.read(65536)
                if not chunk:
                    return
                room = self.limit - len(self.data)
                if room > 0:
                    self.data += chunk[:room]
                if len(chunk) > room:
                    self.truncated = True
        except (OSError, ValueError):
            return


def _feed(stream, payload: bytes) -> None:
    try:
        stream.write(payload)
        stream.flush()
    except (BrokenPipeError, OSError, ValueError):
        pass
    finally:
        try:
            stream.close()
        except (OSError, ValueError):
            pass


class DockerCli:
    def __init__(self, docker_path: str | None = None, *, env: Mapping[str, str] | None = None):
        self._docker_path = docker_path
        self._env = dict(os.environ if env is None else env)

    # --- plumbing ---------------------------------------------------------------------------------------------------
    def _binary(self) -> str:
        found = self._docker_path if self._docker_path and os.path.sep in self._docker_path else shutil.which(self._docker_path or "docker", path=self._env.get("PATH"))
        if not found:
            raise DockerUnavailable("The Docker command-line client was not found on PATH",
                                    detail="install Docker Desktop (macOS) or Docker Engine and make sure `docker` runs in your terminal")
        return found

    def _run(self, args: Sequence[str], *, timeout: float = COMMAND_TIMEOUT_SECONDS, check: bool = True,
             extra_env: Mapping[str, str] | None = None) -> CommandResult:
        try:
            done = subprocess.run([self._binary(), *args], capture_output=True, timeout=timeout,
                                  env={**self._env, **(extra_env or {})}, stdin=subprocess.DEVNULL)
        except FileNotFoundError:
            raise DockerUnavailable("The Docker command-line client could not be started") from None
        except subprocess.TimeoutExpired:
            raise DockerError(f"`docker {args[0]}` did not finish within {timeout:g} seconds") from None
        result = CommandResult(done.returncode, done.stdout.decode("utf-8", "replace"), done.stderr.decode("utf-8", "replace"))
        if check and result.returncode != 0:
            raise self._classify(args[0], result)
        return result

    @staticmethod
    def _classify(command: str, result: CommandResult) -> DockerError:
        text = result.stderr.lower()
        if "cannot connect to the docker daemon" in text or "is the docker daemon running" in text or "error during connect" in text:
            return DockerUnavailable("The Docker daemon is not reachable",
                                     detail="start Docker Desktop (or the docker service) and retry; " + short(result.stderr, 200),
                                     returncode=result.returncode)
        return DockerError(f"`docker {command}` failed", detail=short(result.stderr or result.stdout), returncode=result.returncode)

    @staticmethod
    def _json(text: str, what: str):
        try:
            return json.loads(text)
        except ValueError:
            raise DockerError(f"Docker returned unreadable {what}") from None

    # --- queries ------------------------------------------------------------------------------------------------------
    def version_info(self) -> dict:
        result = self._run(["version", "--format", "{{json .}}"], check=False)
        data = None
        if result.stdout.strip():
            try:
                data = json.loads(result.stdout)
            except ValueError:
                data = None
        if not isinstance(data, dict):
            raise self._classify("version", result)
        return {"client": data.get("Client"), "server": data.get("Server"), "error": None if data.get("Server") else short(result.stderr, 300)}

    def info(self) -> dict:
        data = self._json(self._run(["info", "--format", "{{json .}}"]).stdout, "daemon information")
        if not isinstance(data, dict):
            raise DockerError("Docker returned unreadable daemon information")
        return data

    def inspect_image(self, ref: str) -> dict | None:
        result = self._run(["image", "inspect", ref], check=False)
        if result.returncode != 0:
            if any(m in result.stderr.lower() for m in _NO_SUCH):
                return None
            raise self._classify("image inspect", result)
        data = self._json(result.stdout, "image information")
        if not (isinstance(data, list) and len(data) == 1 and isinstance(data[0], dict)):
            raise DockerError("Docker returned unexpected image information")
        return data[0]

    def inspect_container(self, ref: str) -> dict | None:
        result = self._run(["inspect", "--type", "container", ref], check=False)
        if result.returncode != 0:
            if any(m in result.stderr.lower() for m in _NO_SUCH):
                return None
            raise self._classify("inspect", result)
        data = self._json(result.stdout, "container information")
        if not (isinstance(data, list) and len(data) == 1 and isinstance(data[0], dict)):
            raise DockerError("Docker returned unexpected container information")
        return data[0]

    def list_containers(self, label: str) -> list[dict]:
        out = self._run(["ps", "-a", "--no-trunc", "--filter", f"label={label}", "--format", "{{json .}}"]).stdout
        rows = []
        for line in out.splitlines():
            if line.strip():
                row = self._json(line, "container list")
                if isinstance(row, dict):
                    rows.append(row)
        return rows

    # --- changes ------------------------------------------------------------------------------------------------------
    def build_image(self, context: Path, dockerfile: Path, tag: str, build_args: Mapping[str, str],
                    labels: Mapping[str, str], *, legacy_builder: bool = False) -> CommandResult:
        # BuildKit resolves digest/ID bases through a registry; the legacy builder uses the local image store only.
        args = ["build", "--pull=false", *([] if legacy_builder else ["--progress=plain"]), "-f", str(dockerfile), "-t", tag]
        for key, value in build_args.items():
            args += ["--build-arg", f"{key}={value}"]
        for key, value in labels.items():
            args += ["--label", f"{key}={value}"]
        args.append(str(context))
        return self._run(args, timeout=BUILD_TIMEOUT_SECONDS, extra_env={"DOCKER_BUILDKIT": "0"} if legacy_builder else None)

    def create_container(self, args: Sequence[str]) -> str:
        if not args or args[0] != "create":
            raise DockerError("internal error: create_container needs a `create` argument list")
        out = self._run(list(args)).stdout.strip().splitlines()
        cid = out[-1].strip() if out else ""
        if len(cid) != 64 or any(c not in "0123456789abcdef" for c in cid):
            raise DockerError("Docker did not return a container id after create")
        return cid

    def kill_container(self, ref: str) -> None:
        self._run(["kill", ref], check=False)  # "is not running" is fine; the caller verifies state afterwards

    def remove_container(self, ref: str) -> None:
        result = self._run(["rm", "--force", "--volumes", ref], check=False)
        if result.returncode != 0 and not any(m in result.stderr.lower() for m in _NO_SUCH):
            raise self._classify("rm", result)

    def remove_image(self, ref: str) -> None:
        self._run(["image", "rm", ref])

    # --- attached execution ---------------------------------------------------------------------------------------------
    def run_attached(self, container: str, stdin: bytes, *, timeout: float, max_stdout: int, max_stderr: int) -> AttachResult:
        try:
            proc = subprocess.Popen([self._binary(), "start", "--attach", "--interactive", container], stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self._env)
        except FileNotFoundError:
            raise DockerUnavailable("The Docker command-line client could not be started") from None
        out, err = _Capture(max_stdout), _Capture(max_stderr)
        threads = [threading.Thread(target=out.pump, args=(proc.stdout,), daemon=True),
                   threading.Thread(target=err.pump, args=(proc.stderr,), daemon=True),
                   threading.Thread(target=_feed, args=(proc.stdin, stdin), daemon=True)]
        for thread in threads:
            thread.start()
        deadline = time.monotonic() + timeout
        timed_out = stop = False
        try:
            try:
                while True:
                    try:
                        proc.wait(timeout=0.05)
                        break
                    except subprocess.TimeoutExpired:
                        pass
                    if out.truncated or err.truncated:
                        stop = True
                        break
                    if time.monotonic() >= deadline:
                        timed_out = stop = True
                        break
                if stop:
                    self.kill_container(container)  # stopping the CLI alone would leave the container running
            except BaseException:
                self.kill_container(container)
                raise
            finally:
                self._reap(proc)
        finally:
            for thread in threads:
                thread.join(timeout=2.0)
            for stream in (proc.stdout, proc.stderr):
                try:
                    stream.close()
                except (OSError, ValueError):
                    pass
        return AttachResult(bytes(out.data), bytes(err.data), out.truncated, err.truncated, timed_out, proc.returncode)

    @staticmethod
    def _reap(proc: subprocess.Popen) -> None:
        try:
            proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                pass
