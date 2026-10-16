"""Fail-closed verification of a created (not yet started) container, from ``docker inspect`` output.

The workload is only started if EVERY control below is present with exactly the expected value. A field that is
missing, malformed, of the wrong type, or merely *weaker* than requested makes the control fail, and a failed control
means the container is removed without ever being started. Nothing here reads anything the container reports about
itself: this is the host looking at what the Docker daemon actually applied.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import policy as pol
from .image import ResolvedImage

MISSING = "<missing>"


@dataclass(frozen=True)
class ControlResult:
    name: str
    expected: str
    actual: str
    ok: bool

    def as_dict(self) -> dict:
        return {"name": self.name, "expected": self.expected, "actual": self.actual, "ok": self.ok}


def _get(data: object, *path: str) -> object:
    current = data
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return MISSING
        current = current[key]
    return current


def _fmt(value: object) -> str:
    if value is MISSING or value == MISSING:
        return MISSING
    text = repr(value)
    return text if len(text) <= 200 else text[:197] + "..."


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _empty(value: object) -> bool:
    return value is None or (isinstance(value, (list, dict, str)) and len(value) == 0)


def _parse_tmpfs_options(text: object) -> frozenset[str] | None:
    if not isinstance(text, str) or not text:
        return None
    return frozenset(part for part in text.split(",") if part)


def verify_container(inspected: object, policy: pol.SandboxPolicy, image: ResolvedImage) -> tuple[list[ControlResult], dict]:
    """Return every control's result and the effective settings read from the inspect output."""
    if not isinstance(inspected, dict):
        return [ControlResult("inspect_output", "a JSON object", _fmt(inspected), False)], {}
    results: list[ControlResult] = []

    def add(name: str, expected: object, actual: object, ok: bool) -> None:
        results.append(ControlResult(name, _fmt(expected), _fmt(actual), bool(ok) and actual is not MISSING))

    def exact(name: str, expected: object, *path: str, integer: bool = False) -> None:
        actual = _get(inspected, *path)
        ok = actual == expected and type(actual) is type(expected) if not integer else (_is_int(actual) and actual == expected)
        add(name, expected, actual, ok)

    def empty(name: str, *path: str, optional: bool = False) -> None:
        actual = _get(inspected, *path)
        add(name, "empty", actual, _empty(actual) or (optional and actual is MISSING))
        if optional and actual is MISSING:
            results[-1] = ControlResult(name, "empty", "empty (field omitted by Docker)", True)

    host = "HostConfig"
    exact("image_is_the_verified_image_id", image.image_id, "Image")
    add("state_is_created_not_started", "created", _get(inspected, "State", "Status"),
        _get(inspected, "State", "Status") == "created" and _get(inspected, "State", "Running") is False)
    exact("user_is_numeric_non_root", pol.USER_SPEC, "Config", "User")
    exact("entry_point_is_fixed", list(pol.ENTRYPOINT), "Config", "Entrypoint")
    cmd = _get(inspected, "Config", "Cmd")
    add("no_command_override", "null or empty", cmd, cmd is not MISSING and _empty(cmd))
    env = _get(inspected, "Config", "Env")
    add("environment_equals_image_environment", sorted(image.env), env,
        isinstance(env, list) and all(isinstance(e, str) for e in env) and sorted(env) == sorted(image.env))
    exact("network_mode_none", "none", host, "NetworkMode")
    networks = _get(inspected, "NetworkSettings", "Networks")
    is_map = isinstance(networks, dict) and all(isinstance(k, str) for k in networks)
    attached = sorted(networks) if is_map else networks
    add("attached_networks_only_none", ["none"], attached, is_map and attached == ["none"])
    exact("root_filesystem_read_only", True, host, "ReadonlyRootfs")
    exact("capabilities_all_dropped", ["ALL"], host, "CapDrop")
    empty("no_capabilities_added", host, "CapAdd")
    exact("not_privileged", False, host, "Privileged")
    sec = _get(inspected, host, "SecurityOpt")
    add("security_opt_only_no_new_privileges", "['no-new-privileges'] (nothing unconfined)", sec,
        isinstance(sec, list) and len(sec) >= 1 and all(isinstance(s, str) for s in sec)
        and all(s in ("no-new-privileges", "no-new-privileges:true") for s in sec))
    exact("pids_limit", policy.pids_limit, host, "PidsLimit", integer=True)
    exact("memory_limit_bytes", policy.memory_bytes, host, "Memory", integer=True)
    exact("memory_swap_equals_memory_(no_swap)", policy.memory_bytes, host, "MemorySwap", integer=True)
    exact("cpu_limit_nano_cpus", pol.cpus_to_nano(policy.cpus), host, "NanoCpus", integer=True)
    oom = _get(inspected, host, "OomKillDisable")
    add("oom_killer_not_disabled", "false", oom, oom is False or oom is None)
    tmpfs = _get(inspected, host, "Tmpfs")
    expected_opts = frozenset((*pol.TMPFS_OPTIONS, f"size={policy.tmpfs_bytes}", "mode=1777"))
    add("single_bounded_tmpfs", {pol.TMPFS_PATH: pol.tmpfs_option_string(policy)}, tmpfs,
        isinstance(tmpfs, dict) and list(tmpfs) == [pol.TMPFS_PATH] and _parse_tmpfs_options(tmpfs[pol.TMPFS_PATH]) == expected_opts)
    empty("no_host_bind_mounts", host, "Binds")
    empty("no_mount_entries", host, "Mounts", optional=True)
    empty("no_mounts_reported_by_docker", "Mounts")
    empty("no_image_volumes", "Config", "Volumes")
    empty("no_volumes_from", host, "VolumesFrom")
    empty("no_devices", host, "Devices")
    empty("no_device_requests", host, "DeviceRequests")
    empty("no_device_cgroup_rules", host, "DeviceCgroupRules")
    empty("no_published_ports", host, "PortBindings")
    exact("publish_all_ports_off", False, host, "PublishAllPorts")
    empty("no_exposed_ports", "Config", "ExposedPorts", optional=True)
    exact("host_pid_namespace_not_shared", "", host, "PidMode")
    exact("host_uts_namespace_not_shared", "", host, "UTSMode")
    exact("user_namespace_default", "", host, "UsernsMode")
    exact("ipc_namespace_private", "private", host, "IpcMode")
    cgroupns = _get(inspected, host, "CgroupnsMode")
    add("cgroup_namespace_declared", "private or host (daemon default)", cgroupns, cgroupns in ("private", "host"))
    exact("init_process_enabled", True, host, "Init")
    restart = _get(inspected, host, "RestartPolicy", "Name")
    add("no_restart_policy", "no", restart, restart in ("no", ""))
    exact("logging_driver_none", "none", host, "LogConfig", "Type")
    ulimits = _get(inspected, host, "Ulimits")
    found = {u.get("Name"): (u.get("Soft"), u.get("Hard")) for u in ulimits if isinstance(u, dict)} if isinstance(ulimits, list) else {}
    add("ulimits_nofile_and_core", "nofile=256:256, core=0:0", ulimits,
        found.get("nofile") == (pol.ULIMIT_NOFILE, pol.ULIMIT_NOFILE) and found.get("core") == (0, 0))
    exact("shm_size_bytes", pol.SHM_SIZE_BYTES, host, "ShmSize", integer=True)
    empty("no_links", host, "Links")
    empty("no_extra_hosts", host, "ExtraHosts")
    empty("no_custom_dns", host, "Dns")
    empty("no_sysctls", host, "Sysctls", optional=True)
    exact("auto_remove_off", False, host, "AutoRemove")
    exact("tty_off", False, "Config", "Tty")
    exact("stdin_open_for_the_job", True, "Config", "OpenStdin")

    effective = {
        "image_id": _get(inspected, "Image"), "user": _get(inspected, "Config", "User"),
        "network_mode": _get(inspected, host, "NetworkMode"), "read_only_rootfs": _get(inspected, host, "ReadonlyRootfs"),
        "cap_drop": _get(inspected, host, "CapDrop"), "security_opt": _get(inspected, host, "SecurityOpt"),
        "pids_limit": _get(inspected, host, "PidsLimit"), "memory_bytes": _get(inspected, host, "Memory"),
        "memory_swap_bytes": _get(inspected, host, "MemorySwap"), "nano_cpus": _get(inspected, host, "NanoCpus"),
        "tmpfs": _get(inspected, host, "Tmpfs"), "ipc_mode": _get(inspected, host, "IpcMode"),
        "pid_mode": _get(inspected, host, "PidMode"), "cgroupns_mode": _get(inspected, host, "CgroupnsMode"),
        "init": _get(inspected, host, "Init"), "log_driver": _get(inspected, host, "LogConfig", "Type"),
        "runtime": _get(inspected, host, "Runtime"), "shm_size_bytes": _get(inspected, host, "ShmSize"),
    }
    effective = {k: (None if v is MISSING else v) for k, v in effective.items()}
    return results, effective


def all_ok(results: list[ControlResult]) -> bool:
    return bool(results) and all(r.ok for r in results)


def failed(results: list[ControlResult]) -> list[ControlResult]:
    return [r for r in results if not r.ok]
