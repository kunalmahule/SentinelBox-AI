"""The sandbox security policy: validated limits and the exact ``docker create`` arguments derived from them.

Every mandatory control is a fixed part of the policy (not an option): network none, read-only root file system,
all capabilities dropped, no-new-privileges, a numeric non-root user, a bounded tmpfs, no mounts, no published ports,
private PID/IPC/UTS namespaces, ``--init``, no logging driver, pinned image. Only the numeric limits are configurable,
and each has a documented upper bound that cannot be exceeded.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass

from . import POLICY_VERSION

# --- documented upper bounds -----------------------------------------------------------------------------------------
MAX_MEMORY_BYTES = 512 * 1024 * 1024
MIN_MEMORY_BYTES = 32 * 1024 * 1024
MAX_PIDS = 128
MIN_PIDS = 8
MAX_CPUS = 2.0
MIN_CPUS = 0.1
MAX_TMPFS_BYTES = 64 * 1024 * 1024
MIN_TMPFS_BYTES = 1024 * 1024
MAX_TIMEOUT_SECONDS = 300.0
MAX_STDOUT_BYTES = 4 * 1024 * 1024
MAX_STDERR_BYTES = 64 * 1024
MAX_INPUT_BYTES = 256 * 1024  # equals the workload protocol's request limit
MAX_CONCURRENT_JOBS = 4
MAX_KILL_GRACE_SECONDS = 30.0

# --- fixed (non-configurable) values ---------------------------------------------------------------------------------
RUN_AS_UID = 65532
RUN_AS_GID = 65532
USER_SPEC = f"{RUN_AS_UID}:{RUN_AS_GID}"
TMPFS_PATH = "/tmp"
TMPFS_OPTIONS = ("rw", "noexec", "nosuid", "nodev")
SHM_SIZE_BYTES = 1024 * 1024
ULIMIT_NOFILE = 256
ENTRYPOINT = ["python", "-B", "-s", "-m", "sentinelbox.sandbox_workload"]
LABEL_KEY = "io.sentinelbox.sandbox"
LABEL_VALUE = "1"
JOB_LABEL_KEY = "io.sentinelbox.job"
IMAGE_LABEL_KEY = "io.sentinelbox.sandbox"
NAME_PREFIX = "sbx-"

_DIGEST_REF = re.compile(r"^[a-z0-9][a-z0-9._:/-]{0,200}@sha256:[0-9a-f]{64}$")
_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_TAG_REF = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,127}:[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$")
_JOB_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class PolicyError(ValueError):
    """The requested configuration is outside the policy (or a mandatory control is absent)."""

    def __init__(self, problems: list[str]):
        super().__init__("sandbox policy violation:\n  - " + "\n  - ".join(problems))
        self.problems = problems


@dataclass(frozen=True)
class SandboxPolicy:
    memory_bytes: int = 256 * 1024 * 1024
    pids_limit: int = 64
    cpus: float = 1.0
    tmpfs_bytes: int = 16 * 1024 * 1024
    timeout_seconds: float = 60.0
    kill_grace_seconds: float = 10.0
    max_stdout_bytes: int = 1024 * 1024
    max_stderr_bytes: int = 16 * 1024
    max_input_bytes: int = MAX_INPUT_BYTES
    max_concurrent_jobs: int = 1

    @property
    def max_lifetime_seconds(self) -> float:
        """Upper bound for create -> removal, used as the overall budget of one job."""
        return self.timeout_seconds + self.kill_grace_seconds + 30.0

    def as_requested(self) -> dict:
        data = asdict(self)
        data["max_lifetime_seconds"] = self.max_lifetime_seconds
        return data


def validate_policy(policy: SandboxPolicy) -> SandboxPolicy:
    """Raise PolicyError listing every violation; return the policy when it is acceptable."""
    problems: list[str] = []

    def check(name: str, value: object, low, high, kinds=(int,)) -> None:
        if isinstance(value, bool) or not isinstance(value, kinds) or not (low <= value <= high):
            problems.append(f"{name} must be a number from {low} to {high} (got {value!r})")

    check("memory_bytes", policy.memory_bytes, MIN_MEMORY_BYTES, MAX_MEMORY_BYTES)
    check("pids_limit", policy.pids_limit, MIN_PIDS, MAX_PIDS)
    check("cpus", policy.cpus, MIN_CPUS, MAX_CPUS, (int, float))
    check("tmpfs_bytes", policy.tmpfs_bytes, MIN_TMPFS_BYTES, MAX_TMPFS_BYTES)
    check("timeout_seconds", policy.timeout_seconds, 1, MAX_TIMEOUT_SECONDS, (int, float))
    check("kill_grace_seconds", policy.kill_grace_seconds, 1, MAX_KILL_GRACE_SECONDS, (int, float))
    check("max_stdout_bytes", policy.max_stdout_bytes, 1024, MAX_STDOUT_BYTES)
    check("max_stderr_bytes", policy.max_stderr_bytes, 256, MAX_STDERR_BYTES)
    check("max_input_bytes", policy.max_input_bytes, 1024, MAX_INPUT_BYTES)
    check("max_concurrent_jobs", policy.max_concurrent_jobs, 1, MAX_CONCURRENT_JOBS)
    if problems:
        raise PolicyError(problems)
    return policy


def validate_image_reference(ref: str) -> str:
    """Accept ``name@sha256:<digest>``, ``sha256:<image id>`` or ``name:tag`` with an explicit non-``latest`` tag."""
    if not isinstance(ref, str) or not ref or ref != ref.strip() or any(c.isspace() or ord(c) < 32 for c in ref):
        raise PolicyError(["the image reference must be a non-empty string without whitespace"])
    if ref.startswith("-"):
        raise PolicyError(["the image reference must not start with '-'"])
    if _DIGEST_REF.match(ref) or _IMAGE_ID.match(ref):
        return ref
    if ref.startswith("sha256:"):
        raise PolicyError([f"image {ref!r} looks like an image id but is not sha256:<64 hex digits>"])
    if _TAG_REF.match(ref):
        tag = ref.rsplit(":", 1)[1]
        if tag.lower() == "latest":
            raise PolicyError([f"image {ref!r} uses the floating tag 'latest'; pin the image by digest, image ID or a specific tag"])
        return ref
    raise PolicyError([f"image {ref!r} is not a pinned reference: use name@sha256:<digest>, sha256:<image id> or name:<specific-tag>"])


def validate_base_image(ref: str) -> str:
    """The Dockerfile base must be immutable: a digest reference or an image ID. Tags are refused."""
    if not isinstance(ref, str) or not (_DIGEST_REF.match(ref) or _IMAGE_ID.match(ref)):
        raise PolicyError([f"base image {ref!r} is not pinned; use name@sha256:<64 hex digits> or sha256:<64 hex image id> "
                           "(find the digest of a local image with: python -m sentinelbox.sandbox pin-base --image <name:tag>)"])
    return ref


def validate_job_id(job_id: str) -> str:
    if not isinstance(job_id, str) or not _JOB_ID.match(job_id):
        raise PolicyError(["job id must be 1 to 64 letters, digits, '.', '_' or '-'"])
    return job_id


def container_name(job_id: str) -> str:
    return NAME_PREFIX + validate_job_id(job_id)


def tmpfs_option_string(policy: SandboxPolicy) -> str:
    return ",".join((*TMPFS_OPTIONS, f"size={policy.tmpfs_bytes}", "mode=1777"))


def cpus_to_nano(cpus: float) -> int:
    return int(round(cpus * 1_000_000_000))


def build_create_args(policy: SandboxPolicy, image_id: str, job_id: str) -> list[str]:
    """The complete argument list (without the leading ``docker``) for ``docker create``. No shell is involved.

    ``image_id`` must be an immutable ``sha256:`` image ID resolved by the host, so a tag cannot move between
    verification and use. Nothing from the job (prompts, file names) appears here.
    """
    validate_policy(policy)
    if not _IMAGE_ID.match(image_id):
        raise PolicyError(["containers are created from an immutable image ID (sha256:<64 hex>)"])
    name = container_name(job_id)
    return [
        "create",
        "--name", name,
        "--pull", "never",
        "--label", f"{LABEL_KEY}={LABEL_VALUE}",
        "--label", f"{JOB_LABEL_KEY}={job_id}",
        "--network", "none",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--user", USER_SPEC,
        "--pids-limit", str(policy.pids_limit),
        "--memory", str(policy.memory_bytes),
        "--memory-swap", str(policy.memory_bytes),
        "--cpus", f"{policy.cpus:g}",
        "--tmpfs", f"{TMPFS_PATH}:{tmpfs_option_string(policy)}",
        "--ipc", "private",
        "--shm-size", str(SHM_SIZE_BYTES),
        "--ulimit", f"nofile={ULIMIT_NOFILE}:{ULIMIT_NOFILE}",
        "--ulimit", "core=0:0",
        "--log-driver", "none",
        "--restart", "no",
        "--init",
        "--interactive",
        image_id,
    ]
