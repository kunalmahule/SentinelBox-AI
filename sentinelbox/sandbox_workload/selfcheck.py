"""Observations made from inside the container: user, capabilities, network, file system, limits.

These are SELF-REPORTED. The host never uses them to authorise anything (it verifies the container configuration with
``docker inspect`` instead); they are extra evidence that the configuration really had the expected effect, and the
opt-in real-Docker tests compare them with the inspected settings. Only names and numbers are reported: no environment
values, no host paths, no file contents.
"""

from __future__ import annotations

import errno
import os
import platform
import socket
import sys
from datetime import datetime, timezone

SOURCE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(path: str, limit: int = 4096) -> str | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read(limit).strip()
    except OSError:
        return None


def _status_fields() -> dict[str, str]:
    fields = {}
    for line in (_read("/proc/self/status", 16384) or "").splitlines():
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip()
    return fields


def _write_probe(path: str) -> str:
    """Try to create a file; report only the errno name (never leave anything behind)."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        return errno.errorcode.get(exc.errno or 0, "OSERROR")
    os.close(fd)
    try:
        os.unlink(path)
    except OSError:
        pass
    return "created"


def _connect_probe(host: str, port: int) -> str:
    try:
        sock = socket.create_connection((host, port), timeout=2)
    except OSError as exc:
        return errno.errorcode.get(exc.errno or 0, type(exc).__name__)
    except Exception as exc:  # noqa: BLE001 - report, never raise
        return type(exc).__name__
    sock.close()
    return "connected"


def _dns_probe() -> str:
    try:
        socket.getaddrinfo("example.com", 80)
    except OSError as exc:
        return type(exc).__name__ + (":" + errno.errorcode.get(exc.errno, "") if exc.errno else "")
    except Exception as exc:  # noqa: BLE001
        return type(exc).__name__
    return "resolved"


def _mounts() -> list[dict]:
    mounts = []
    for line in (_read("/proc/self/mountinfo", 65536) or "").splitlines()[:200]:
        left, _, right = line.partition(" - ")
        parts, tail = left.split(), right.split()
        if len(parts) >= 6 and len(tail) >= 1:
            mounts.append({"mount_point": parts[4], "read_only": "ro" in parts[5].split(","), "fs_type": tail[0]})
    return mounts


def _cgroup() -> dict:
    candidates = {
        "memory_max": ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"),
        "memory_swap_max": ("/sys/fs/cgroup/memory.swap.max", "/sys/fs/cgroup/memory/memory.memsw.limit_in_bytes"),
        "pids_max": ("/sys/fs/cgroup/pids.max", "/sys/fs/cgroup/pids/pids.max"),
        "cpu_max": ("/sys/fs/cgroup/cpu.max", None),
    }
    return {name: next((v for v in (_read(p) for p in paths if p) if v is not None), None) for name, paths in candidates.items()}


def observe() -> dict:
    status = _status_fields()
    tmp = None
    try:
        stat = os.statvfs("/tmp")
        tmp = {"size_bytes": stat.f_blocks * stat.f_frsize}
    except OSError:
        pass
    try:
        interfaces = sorted(os.listdir("/sys/class/net"))
    except OSError:
        interfaces = None
    numeric = [e for e in os.listdir("/proc") if e.isdigit()] if os.path.isdir("/proc") else []
    return {
        "note": "self-reported by the workload; not trusted by the host",
        "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "python": platform.python_version(), "machine": platform.machine(), "system": platform.system(),
        "uid": os.getuid(), "gid": os.getgid(), "euid": os.geteuid(), "egid": os.getegid(), "groups": sorted(os.getgroups()),
        "no_new_privs": status.get("NoNewPrivs"),
        "capabilities": {k: status.get(k) for k in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")},
        "seccomp": status.get("Seccomp"),
        "network": {"interfaces": interfaces,
                    "connect_external": _connect_probe("1.1.1.1", 53),
                    "connect_loopback_closed_port": _connect_probe("127.0.0.1", 9),
                    "dns": _dns_probe()},
        "filesystem": {"write_root": _write_probe("/sbx-write-probe"), "write_app": _write_probe(os.path.join(SOURCE_DIR, ".sbx-write-probe")),
                       "write_tmp": _write_probe("/tmp/.sbx-write-probe"), "tmp": tmp,
                       "docker_socket_present": os.path.exists("/var/run/docker.sock") or os.path.exists("/run/docker.sock")},
        "mounts": _mounts(),
        "environment_variable_names": sorted(os.environ)[:100],
        "process": {"pid": os.getpid(), "pid1_name": _read("/proc/1/comm"), "visible_processes": len(numeric)},
        "cgroup": _cgroup(),
        "argv_length": len(sys.argv),
    }
