"""The sandbox policy: limits, upper bounds, image pinning and the exact `docker create` argument list."""

import dataclasses

import pytest
from sandbox_fakes import IMAGE_ID, no_real_docker  # noqa: F401

from sentinelbox.sandbox import policy as pol

pytestmark = pytest.mark.usefixtures("no_real_docker")

DEFAULT_ARGS = pol.build_create_args(pol.SandboxPolicy(), IMAGE_ID, "job-1")


def values_of(args, flag):
    return [args[i + 1] for i, a in enumerate(args[:-1]) if a == flag]


# --- the mandatory controls are in every argument list ----------------------------------------------------------------------
@pytest.mark.parametrize("flag,expected", [
    ("--network", ["none"]), ("--cap-drop", ["ALL"]), ("--security-opt", ["no-new-privileges"]), ("--user", ["65532:65532"]),
    ("--ipc", ["private"]), ("--pull", ["never"]), ("--log-driver", ["none"]), ("--restart", ["no"]),
])
def test_mandatory_value_flags_are_present_with_the_exact_value(flag, expected):
    assert values_of(DEFAULT_ARGS, flag) == expected


@pytest.mark.parametrize("flag", ["--read-only", "--init", "--interactive"])
def test_mandatory_boolean_flags_are_present(flag):
    assert flag in DEFAULT_ARGS


def test_limits_are_derived_from_the_policy_and_swap_equals_memory():
    args = pol.build_create_args(pol.SandboxPolicy(memory_bytes=64 * 2**20, pids_limit=16, cpus=0.5, tmpfs_bytes=2 * 2**20), IMAGE_ID, "j")
    assert values_of(args, "--memory") == values_of(args, "--memory-swap") == [str(64 * 2**20)]
    assert values_of(args, "--pids-limit") == ["16"] and values_of(args, "--cpus") == ["0.5"]
    assert values_of(args, "--tmpfs") == [f"/tmp:rw,noexec,nosuid,nodev,size={2 * 2**20},mode=1777"]


def test_the_image_is_the_last_argument_and_only_an_immutable_id_is_accepted():
    assert DEFAULT_ARGS[-1] == IMAGE_ID and DEFAULT_ARGS[0] == "create"
    for bad in ("python:3.13", "name@sha256:" + "a" * 64, "sha256:short", "latest", ""):
        with pytest.raises(pol.PolicyError):
            pol.build_create_args(pol.SandboxPolicy(), bad, "j")


FORBIDDEN_FLAGS = ["--privileged", "-v", "--volume", "--mount", "-p", "--publish", "-P", "--publish-all", "--env", "-e", "--env-file",
                   "--device", "--cap-add", "--pid", "--userns", "--uts", "--volumes-from", "--link", "--add-host", "--dns",
                   "--sysctl", "--security-opt=seccomp=unconfined", "--net", "--tty", "-t", "--rm", "--group-add", "--cgroupns",
                   "--entrypoint", "--workdir", "-w", "--hostname", "--ipc=host", "--gpus", "--runtime", "--oom-kill-disable"]


@pytest.mark.parametrize("flag", FORBIDDEN_FLAGS)
def test_no_risky_flag_is_ever_generated(flag):
    assert flag not in DEFAULT_ARGS
    assert not any(a == flag or a.startswith(flag + "=") for a in DEFAULT_ARGS)


def test_no_host_path_docker_socket_or_environment_appears_in_the_arguments():
    text = " ".join(DEFAULT_ARGS)
    for needle in ("docker.sock", "/var/run", "/Users", "/home", "/root", "HOME=", "PATH=", "KEY", "TOKEN", "host"):
        assert needle not in text, needle


def test_the_job_id_is_validated_and_only_appears_in_the_name_and_a_label():
    args = pol.build_create_args(pol.SandboxPolicy(), IMAGE_ID, "abc.DEF_1-2")
    assert values_of(args, "--name") == ["sbx-abc.DEF_1-2"]
    assert "io.sentinelbox.job=abc.DEF_1-2" in values_of(args, "--label")
    for bad in ("", "a b", "a;b", "../x", "$(id)", "x" * 65, "ünï", "a\nb", "-rf"[:0] + "--privileged "):
        with pytest.raises(pol.PolicyError):
            pol.build_create_args(pol.SandboxPolicy(), IMAGE_ID, bad)


def test_every_argument_is_a_plain_string_without_shell_interpretation_needed():
    assert all(isinstance(a, str) for a in DEFAULT_ARGS)


# --- the policy object ----------------------------------------------------------------------------------------------------------
def test_the_mandatory_controls_are_not_configurable_fields():
    names = {f.name for f in dataclasses.fields(pol.SandboxPolicy)}
    assert names == {"memory_bytes", "pids_limit", "cpus", "tmpfs_bytes", "timeout_seconds", "kill_grace_seconds",
                     "max_stdout_bytes", "max_stderr_bytes", "max_input_bytes", "max_concurrent_jobs"}
    for forbidden in ("network", "privileged", "user", "read_only", "cap_add", "mounts", "env", "ports", "entrypoint", "image"):
        assert forbidden not in names


def test_the_default_policy_is_valid_and_documents_its_lifetime():
    policy = pol.validate_policy(pol.SandboxPolicy())
    assert policy.max_lifetime_seconds == policy.timeout_seconds + policy.kill_grace_seconds + 30
    assert policy.as_requested()["max_lifetime_seconds"] == policy.max_lifetime_seconds


BOUNDS = [
    ("memory_bytes", pol.MIN_MEMORY_BYTES, pol.MAX_MEMORY_BYTES), ("pids_limit", pol.MIN_PIDS, pol.MAX_PIDS),
    ("cpus", pol.MIN_CPUS, pol.MAX_CPUS), ("tmpfs_bytes", pol.MIN_TMPFS_BYTES, pol.MAX_TMPFS_BYTES),
    ("timeout_seconds", 1, pol.MAX_TIMEOUT_SECONDS), ("kill_grace_seconds", 1, pol.MAX_KILL_GRACE_SECONDS),
    ("max_stdout_bytes", 1024, pol.MAX_STDOUT_BYTES), ("max_stderr_bytes", 256, pol.MAX_STDERR_BYTES),
    ("max_input_bytes", 1024, pol.MAX_INPUT_BYTES), ("max_concurrent_jobs", 1, pol.MAX_CONCURRENT_JOBS),
]


@pytest.mark.parametrize("name,low,high", BOUNDS)
def test_limits_accept_their_bounds_and_reject_anything_outside(name, low, high):
    for ok in (low, high):
        pol.validate_policy(dataclasses.replace(pol.SandboxPolicy(), **{name: ok}))
    for bad in (low - 1 if low >= 1 else low / 2, high + 1, -1, 0, None, "10", True, float("nan")):
        with pytest.raises(pol.PolicyError) as info:
            pol.validate_policy(dataclasses.replace(pol.SandboxPolicy(), **{name: bad}))
        assert name in str(info.value)


def test_all_violations_are_reported_together():
    with pytest.raises(pol.PolicyError) as info:
        pol.validate_policy(pol.SandboxPolicy(memory_bytes=10**12, pids_limit=10**6, cpus=64.0))
    assert len(info.value.problems) == 3


# --- image references ---------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("ref", ["sentinelbox-sandbox:stage5-abc123", "sha256:" + "a" * 64, "python@sha256:" + "b" * 64,
                                 "registry.example.com:5000/team/app@sha256:" + "c" * 64, "local/app:v1.2"])
def test_pinned_image_references_are_accepted(ref):
    assert pol.validate_image_reference(ref) == ref


@pytest.mark.parametrize("ref", ["python", "python:latest", "app:LATEST", "python:", ":tag", "", " python:3", "py thon:3", "-rm:3",
                                 "python@sha256:abc", "sha256:abc", "python:3\n", "a:1;b"])
def test_floating_or_malformed_image_references_are_refused(ref):
    with pytest.raises(pol.PolicyError):
        pol.validate_image_reference(ref)


def test_the_latest_tag_refusal_names_the_problem():
    with pytest.raises(pol.PolicyError, match="floating tag 'latest'"):
        pol.validate_image_reference("python:latest")


@pytest.mark.parametrize("ref", ["python:3.13-slim", "python", "python:latest", "app:v1", "", "python@sha256:abc", None])
def test_the_dockerfile_base_must_be_a_digest_or_image_id_never_a_tag(ref):
    with pytest.raises(pol.PolicyError, match="not pinned"):
        pol.validate_base_image(ref)


def test_digest_and_id_bases_are_accepted():
    pol.validate_base_image("python@sha256:" + "d" * 64)
    pol.validate_base_image("sha256:" + "e" * 64)
