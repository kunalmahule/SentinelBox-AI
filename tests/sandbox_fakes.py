"""A fake Docker for the daemon-independent sandbox tests.

``FakeDocker`` implements the same ``DockerClient`` protocol as the real CLI client. ``inspect_from_create_args``
turns the arguments passed to ``create`` into inspect output shaped like a real daemon's (captured from Docker
29.8.2), so the verifier is tested against realistic JSON. Any flag the fake does not know about is an error: an
accidental new (possibly risky) flag in the argument builder fails loudly here.
"""

from __future__ import annotations

import copy
import io
import json
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from sentinelbox.sandbox import policy as pol
from sentinelbox.sandbox.docker_client import AttachResult, CommandResult, DockerError, DockerUnavailable

IMAGE_ID = "sha256:" + "c7" * 32
BASE_ID = "sha256:" + "13" * 32
IMAGE_TAG = "sentinelbox-sandbox:test"
IMAGE_ENV = ["PATH=/usr/local/bin:/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE=1", "PYTHONUNBUFFERED=1", "PYTHONNOUSERSITE=1",
             "PYTHONPATH=/app"]


@pytest.fixture
def no_real_docker(monkeypatch):
    """Daemon-independent tests must never reach a real `docker`: looking it up by name fails the test."""
    import shutil

    real_which = shutil.which

    def guarded(cmd, *args, **kwargs):
        if cmd == "docker":
            raise AssertionError("a daemon-independent test tried to locate the real docker client")
        return real_which(cmd, *args, **kwargs)

    monkeypatch.setattr(shutil, "which", guarded)


def make_image_inspect(image_id: str = IMAGE_ID, **overrides) -> dict:
    image = {
        "Id": image_id, "RepoTags": [IMAGE_TAG], "RepoDigests": [], "Architecture": "amd64", "Os": "linux",
        "Config": {"User": pol.USER_SPEC, "Env": list(IMAGE_ENV), "Entrypoint": list(pol.ENTRYPOINT), "Cmd": None,
                   "Volumes": None, "WorkingDir": "/app", "OnBuild": None,
                   "Labels": {pol.IMAGE_LABEL_KEY: pol.LABEL_VALUE, "io.sentinelbox.component": "sandbox-workload"}},
    }
    for key, value in overrides.items():
        image[key] = value
    return image


def _take(args: list[str], flag: str) -> list[str]:
    return [args[i + 1] for i, a in enumerate(args[:-1]) if a == flag]


def inspect_from_create_args(args: Sequence[str], image: dict, container_id: str) -> dict:
    """Realistic ``docker inspect`` output for a container created with ``args``."""
    args = list(args)
    assert args[0] == "create"
    known_value_flags = {"--name", "--pull", "--label", "--network", "--cap-drop", "--security-opt", "--user", "--pids-limit",
                         "--memory", "--memory-swap", "--cpus", "--tmpfs", "--ipc", "--shm-size", "--ulimit", "--log-driver",
                         "--restart"}
    known_bool_flags = {"--read-only", "--init", "--interactive"}
    i = 1
    while i < len(args) - 1:
        flag = args[i]
        if flag in known_value_flags:
            i += 2
        elif flag in known_bool_flags:
            i += 1
        else:
            raise AssertionError(f"the fake docker does not know the flag {flag!r}; review it for safety before allowing it")
    image_id = args[-1]
    one = lambda flag, default=None: (_take(args, flag) or [default])[-1]  # noqa: E731
    ulimits = []
    for spec in _take(args, "--ulimit"):
        name, _, limit = spec.partition("=")
        soft, _, hard = limit.partition(":")
        ulimits.append({"Name": name, "Hard": int(hard), "Soft": int(soft)})
    tmpfs = {}
    for spec in _take(args, "--tmpfs"):
        path, _, options = spec.partition(":")
        tmpfs[path] = options
    labels = dict(image["Config"].get("Labels") or {})
    labels.update(dict(item.split("=", 1) for item in _take(args, "--label")))
    cpus = float(one("--cpus", "0"))
    secopts = _take(args, "--security-opt")
    host = {
        "Binds": None, "ContainerIDFile": "", "LogConfig": {"Type": one("--log-driver", "json-file"), "Config": {}},
        "NetworkMode": (_take(args, "--network") or ["default"])[0], "PortBindings": {}, "RestartPolicy": {"Name": one("--restart", "no"), "MaximumRetryCount": 0},
        "AutoRemove": False, "VolumesFrom": None, "CapAdd": None, "CapDrop": _take(args, "--cap-drop") or None,
        "CgroupnsMode": "private", "Dns": None, "ExtraHosts": None, "IpcMode": one("--ipc", "shareable"), "Links": None,
        "PidMode": "", "Privileged": False, "PublishAllPorts": False, "ReadonlyRootfs": "--read-only" in args,
        "SecurityOpt": secopts or None, "Tmpfs": tmpfs or None, "UTSMode": "", "UsernsMode": "",
        "ShmSize": int(one("--shm-size", 67108864)), "Runtime": "runc", "Memory": int(one("--memory", 0)),
        "NanoCpus": int(round(cpus * 1e9)), "Devices": [], "DeviceCgroupRules": None, "DeviceRequests": None,
        "MemorySwap": int(one("--memory-swap", 0)), "OomKillDisable": False, "PidsLimit": int(one("--pids-limit", 0)) or None,
        "Ulimits": ulimits or None, "Init": "--init" in args,
    }
    return {
        "Id": container_id, "Name": "/" + one("--name", "unnamed"), "Image": image_id,
        "State": {"Status": "created", "Running": False, "Paused": False, "Restarting": False, "OOMKilled": False,
                  "Dead": False, "Pid": 0, "ExitCode": 0, "Error": ""},
        "Mounts": [],
        "Config": {"User": one("--user", image["Config"].get("User")), "Tty": False, "OpenStdin": "--interactive" in args,
                   "Env": list(image["Config"]["Env"]), "Cmd": None, "Entrypoint": list(image["Config"]["Entrypoint"]),
                   "Volumes": None, "Labels": labels},
        "HostConfig": host,
        "NetworkSettings": {"Networks": {n: {"NetworkID": "", "IPAddress": ""} for n in (_take(args, "--network") or ["bridge"])}},
    }


class FakeDocker:
    def __init__(self, *, image: dict | None = None):
        self.image = image or make_image_inspect()
        self.images: dict[str, dict] = {IMAGE_TAG: self.image, self.image["Id"]: self.image}
        self.containers: dict[str, dict] = {}
        self.calls: list[tuple[str, object]] = []
        self.client_version = "29.0.0"
        self.server_version: str | None = "29.0.0"
        self.daemon_error: str | None = None
        self.info_data: dict = {"OSType": "linux", "MemoryLimit": True, "SwapLimit": True, "CpuCfsQuota": True, "PidsLimit": True,
                                "SecurityOptions": ["name=seccomp,profile=builtin"], "DefaultRuntime": "runc", "CgroupVersion": "2",
                                "Driver": "overlayfs", "Architecture": "aarch64", "KernelVersion": "6.0"}
        self.stdout = b""
        self.stderr = b""
        self.exit_code = 0
        self.oom_killed = False
        self.attach_result: AttachResult | None = None
        self.attach_behavior = None  # callable(stdin) -> AttachResult | bytes, to run a real workload in-process
        self.fail: dict[str, Exception | list[Exception]] = {}  # operation -> exception raised when called
        self.mutators: list = []  # applied to inspect output at create time
        self.keep_on_remove = False  # simulate a container that cannot be removed
        self.other_containers: list[dict] = []
        self.stdin_seen: list[bytes] = []
        self.build_calls: list[dict] = []

    # --- helpers --------------------------------------------------------------------------------------------------
    def _maybe_fail(self, op: str) -> None:
        failure = self.fail.get(op)
        if isinstance(failure, list):
            if failure:
                raise failure.pop(0)
        elif failure is not None:
            raise failure

    def count(self, op: str) -> int:
        return sum(1 for name, _ in self.calls if name == op)

    def _find(self, ref: str) -> dict | None:
        for container in self.containers.values():
            if container["Id"] == ref or container["Name"].lstrip("/") == ref:
                return container
        return None

    # --- protocol ---------------------------------------------------------------------------------------------------
    def version_info(self) -> dict:
        self.calls.append(("version_info", None))
        self._maybe_fail("version_info")
        server = {"Version": self.server_version, "ApiVersion": "1.50", "Os": "linux", "Arch": "arm64"} if self.server_version else None
        return {"client": {"Version": self.client_version}, "server": server, "error": self.daemon_error}

    def info(self) -> dict:
        self.calls.append(("info", None))
        self._maybe_fail("info")
        return dict(self.info_data)

    def inspect_image(self, ref: str) -> dict | None:
        self.calls.append(("inspect_image", ref))
        self._maybe_fail("inspect_image")
        found = self.images.get(ref)
        return copy.deepcopy(found) if found else None

    def build_image(self, context: Path, dockerfile: Path, tag: str, build_args: Mapping[str, str], labels: Mapping[str, str], *,
                    legacy_builder: bool = False) -> CommandResult:
        self.calls.append(("build_image", tag))
        self._maybe_fail("build_image")
        files = sorted(str(p.relative_to(context)) for p in Path(context).rglob("*") if p.is_file())
        self.build_calls.append({"tag": tag, "args": dict(build_args), "labels": dict(labels), "files": files, "legacy": legacy_builder,
                                 "dockerfile": Path(dockerfile).read_text()})
        built = make_image_inspect("sha256:" + uuid.uuid4().hex * 2, RepoTags=[tag])
        built["Config"]["Labels"].update(labels)
        self.images[tag] = built
        self.images[built["Id"]] = built
        return CommandResult(0, "", "")

    def create_container(self, args: Sequence[str]) -> str:
        self.calls.append(("create_container", list(args)))
        self._maybe_fail("create_container")
        cid = uuid.uuid4().hex + uuid.uuid4().hex
        image = self.images[args[-1]]
        inspected = inspect_from_create_args(args, image, cid)
        for mutate in self.mutators:
            mutate(inspected)
        self.containers[cid] = inspected
        return cid

    def inspect_container(self, ref: str) -> dict | None:
        self.calls.append(("inspect_container", ref))
        self._maybe_fail("inspect_container")
        found = self._find(ref)
        return copy.deepcopy(found) if found else None

    def run_attached(self, container: str, stdin: bytes, *, timeout: float, max_stdout: int, max_stderr: int) -> AttachResult:
        self.calls.append(("run_attached", {"container": container, "timeout": timeout, "max_stdout": max_stdout, "max_stderr": max_stderr}))
        self.stdin_seen.append(stdin)
        self._maybe_fail("run_attached")
        state = self.containers[container]["State"]
        state.update(Status="exited", Running=False, ExitCode=self.exit_code, OOMKilled=self.oom_killed)
        if self.attach_behavior is not None:
            produced = self.attach_behavior(stdin)
            if isinstance(produced, AttachResult):
                return produced
            return AttachResult(produced, b"", False, False, False, 0)
        if self.attach_result is not None:
            if self.attach_result.timed_out:
                state["ExitCode"] = 137
            return self.attach_result
        return AttachResult(self.stdout, self.stderr, False, False, False, self.exit_code)

    def kill_container(self, ref: str) -> None:
        self.calls.append(("kill_container", ref))
        self._maybe_fail("kill_container")

    def remove_container(self, ref: str) -> None:
        self.calls.append(("remove_container", ref))
        self._maybe_fail("remove_container")
        found = self._find(ref)
        if found is not None and not self.keep_on_remove:
            del self.containers[found["Id"]]

    def list_containers(self, label: str) -> list[dict]:
        self.calls.append(("list_containers", label))
        self._maybe_fail("list_containers")
        rows = [{"ID": c["Id"], "Names": c["Name"].lstrip("/"), "State": c["State"]["Status"], "Status": c["State"]["Status"],
                 "Image": c["Image"]} for c in self.containers.values()]
        return rows + list(self.other_containers)

    def remove_image(self, ref: str) -> None:
        self.calls.append(("remove_image", ref))
        self._maybe_fail("remove_image")
        found = self.images.get(ref)
        if found is None:
            raise DockerError("no such image")
        for key in [k for k, v in self.images.items() if v is found]:
            del self.images[key]


def run_real_workload(stdin: bytes) -> bytes:
    """Attach behaviour that runs the REAL workload entry point in-process (what the container would do)."""
    from sentinelbox.sandbox_workload.__main__ import main

    out, err = io.StringIO(), io.StringIO()
    code = main(stdin=io.BytesIO(stdin), stdout=out, stderr=err)
    assert code == 0, err.getvalue()
    return out.getvalue().encode("utf-8")


def unreachable_daemon() -> DockerUnavailable:
    return DockerUnavailable("The Docker daemon is not reachable", detail="start Docker Desktop")


def job_json(**kw) -> bytes:
    return json.dumps(kw).encode()
