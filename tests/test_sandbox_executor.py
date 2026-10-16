"""Execution lifecycle with a fake Docker: success, every failure path, cleanup, limits, concurrency, no double execution."""

import dataclasses

import pytest
from sandbox_fakes import IMAGE_ID, IMAGE_TAG, FakeDocker, make_image_inspect, no_real_docker  # noqa: F401
from test_sandbox_inspection import setp

from sentinelbox.sandbox import policy as pol
from sentinelbox.sandbox.docker_client import AttachResult, DockerError
from sentinelbox.sandbox.executor import ConcurrencyLimitError, DuplicateJobError, JobRejected, SandboxExecutor

pytestmark = pytest.mark.usefixtures("no_real_docker")

REQUEST = b'{"hello":"world"}'


def make(fake=None, **policy):
    fake = fake or FakeDocker()
    return fake, SandboxExecutor(fake, pol.SandboxPolicy(**policy))


def run(executor, job="j1", request=REQUEST, image=IMAGE_TAG):
    return executor.execute(job, request, image)


def assert_clean(fake, result):
    assert fake.containers == {}, "a container was left behind"
    assert result.cleanup_status in ("removed", "not_created")


# --- success ----------------------------------------------------------------------------------------------------------------
def test_success_verifies_starts_once_collects_and_removes():
    fake, ex = make()
    fake.stdout = b'{"ok":true}\n'
    result = run(ex)
    assert (result.outcome, result.exit_code, result.cleanup_status) == ("completed", 0, "removed")
    assert result.controls_verified and len(result.controls) >= 45 and result.container_started
    assert result.stdout == b'{"ok":true}\n' and fake.stdin_seen == [REQUEST]
    assert fake.count("create_container") == 1 and fake.count("run_attached") == 1
    assert result.image.image_id == IMAGE_ID and result.docker_server_version == "29.0.0"
    assert result.requested["timeout_seconds"] == 60.0 and result.effective["network_mode"] == "none"
    assert_clean(fake, result)


def test_the_container_is_created_from_the_resolved_image_id_not_the_tag():
    fake, ex = make()
    run(ex)
    create_args = next(arg for name, arg in fake.calls if name == "create_container")
    assert create_args[-1] == IMAGE_ID and IMAGE_TAG not in create_args


def test_verification_happens_before_start_and_start_is_the_only_run_call():
    fake, ex = make()
    run(ex)
    order = [name for name, _ in fake.calls]
    assert order.index("create_container") < order.index("inspect_container") < order.index("run_attached") < order.index("remove_container")


def test_timing_and_requested_limits_are_recorded():
    ticks = iter(range(0, 100))
    fake = FakeDocker()
    ex = SandboxExecutor(fake, pol.SandboxPolicy(timeout_seconds=30), monotonic=lambda: next(ticks) * 0.5)
    result = run(ex)
    assert result.duration_ms > 0 and result.requested["timeout_seconds"] == 30


# --- refusal ------------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("mutation", [setp("HostConfig.NetworkMode", "bridge"), setp("HostConfig.ReadonlyRootfs", False),
                                      setp("HostConfig.CapDrop", None), setp("HostConfig.Privileged", True),
                                      setp("HostConfig.Binds", ["/:/h"]), setp("HostConfig.PidsLimit", 0)])
def test_a_container_whose_controls_do_not_verify_is_never_started(mutation):
    fake = FakeDocker()
    fake.mutators.append(mutation)
    result = SandboxExecutor(fake, pol.SandboxPolicy()).execute("j1", REQUEST, IMAGE_TAG)
    assert result.outcome == "refused" and not result.controls_verified and not result.container_started
    assert fake.count("run_attached") == 0 and "security controls not verified" in result.error
    assert_clean(fake, result)


def test_an_unusable_image_is_refused_before_anything_is_created():
    bad = make_image_inspect()
    bad["Config"]["Entrypoint"] = ["/bin/sh"]
    fake = FakeDocker(image=bad)
    result = SandboxExecutor(fake, pol.SandboxPolicy()).execute("j1", REQUEST, IMAGE_TAG)
    assert result.outcome == "refused" and fake.count("create_container") == 0 and "entry point" in result.error
    assert result.cleanup_status == "not_created"


def test_a_missing_image_is_refused_with_a_build_hint():
    fake = FakeDocker()
    result = SandboxExecutor(fake, pol.SandboxPolicy()).execute("j1", REQUEST, "sentinelbox-sandbox:absent")
    assert result.outcome == "refused" and "build" in result.error and fake.count("create_container") == 0


def test_an_unpinned_image_reference_is_rejected_before_docker_is_contacted():
    fake, ex = make()
    with pytest.raises(pol.PolicyError):
        ex.execute("j1", REQUEST, "python:latest")
    assert fake.calls == []


# --- docker failures --------------------------------------------------------------------------------------------------------------
def test_daemon_unreachable_is_a_docker_error_and_nothing_is_created():
    fake, ex = make()
    fake.server_version = None
    fake.daemon_error = "cannot connect"
    result = run(ex)
    assert result.outcome == "docker_error" and fake.count("create_container") == 0 and "not reachable" in result.error


def test_create_failure_is_reported_and_nothing_is_run_or_removed_by_name():
    fake, ex = make()
    fake.fail["create_container"] = DockerError("`docker create` failed", detail="no space left")
    result = run(ex)
    assert result.outcome == "docker_error" and "no space left" in result.error
    assert fake.count("run_attached") == 0 and fake.count("remove_container") == 0
    assert result.cleanup_status == "not_created"


def test_a_foreign_container_with_the_same_name_is_never_removed_after_a_failed_create():
    fake, ex = make(max_concurrent_jobs=2)
    foreign = fake.create_container(pol.build_create_args(pol.SandboxPolicy(), IMAGE_ID, "j1"))
    fake.fail["create_container"] = DockerError("Conflict. The container name is already in use")
    result = ex.execute("j1", REQUEST, IMAGE_TAG)
    assert result.outcome == "docker_error" and result.cleanup_status == "failed" and "left alone" in result.cleanup_detail
    assert foreign in fake.containers and fake.count("remove_container") == 0


def test_start_failure_is_reported_and_the_container_is_removed():
    fake, ex = make()
    fake.fail["run_attached"] = DockerError("`docker start` failed", detail="exec format error")
    result = run(ex)
    assert result.outcome == "docker_error" and "exec format error" in result.error
    assert_clean(fake, result)


def test_a_container_that_never_started_is_a_docker_error():
    fake, ex = make()
    original = fake.run_attached

    def not_started(container, stdin, **kw):
        out = original(container, stdin, **kw)
        fake.containers[container]["State"]["Status"] = "created"
        return out

    fake.run_attached = not_started
    result = run(ex)
    assert result.outcome == "docker_error" and "did not start" in result.error
    assert_clean(fake, result)


def test_inspect_failing_after_the_run_does_not_leave_the_container():
    fake, ex = make()
    calls = {"n": 0}
    original = fake.inspect_container

    def flaky(ref):
        calls["n"] += 1
        if calls["n"] == 2:  # the post-run inspect
            raise DockerError("inspect failed")
        return original(ref)

    fake.inspect_container = flaky
    result = run(ex)
    assert result.outcome == "docker_error"
    assert_clean(fake, result)


# --- workload outcomes --------------------------------------------------------------------------------------------------------------
def test_non_zero_exit_is_a_workload_error_and_stderr_is_summarised():
    fake, ex = make()
    fake.exit_code, fake.stderr = 70, b"workload failed: ValueError\n"
    result = run(ex)
    assert (result.outcome, result.exit_code) == ("workload_error", 70) and "workload failed" in result.stderr_summary
    assert_clean(fake, result)


def test_out_of_memory_is_reported_as_such():
    fake, ex = make()
    fake.exit_code, fake.oom_killed = 137, True
    result = run(ex)
    assert result.outcome == "workload_error" and "memory limit" in result.error
    assert_clean(fake, result)


def test_a_timeout_kills_and_removes_and_discards_nothing_silently():
    fake, ex = make(timeout_seconds=5)
    fake.attach_result = AttachResult(b"partial", b"", False, False, True, None)
    result = run(ex)
    assert result.outcome == "timeout" and result.timed_out and result.exit_code == 137
    assert fake.calls[-1][0] in ("inspect_container",) and fake.count("kill_container") >= 1
    assert_clean(fake, result)


def test_the_wall_clock_limit_passed_to_the_client_is_the_policy_timeout():
    fake, ex = make(timeout_seconds=7)
    run(ex)
    call = next(arg for name, arg in fake.calls if name == "run_attached")
    assert call["timeout"] == 7 and call["max_stdout"] == ex.policy.max_stdout_bytes and call["max_stderr"] == ex.policy.max_stderr_bytes


@pytest.mark.parametrize("stdout_flag,stderr_flag", [(True, False), (False, True), (True, True)])
def test_oversized_output_is_an_output_limit_outcome(stdout_flag, stderr_flag):
    fake, ex = make()
    fake.attach_result = AttachResult(b"x" * 10, b"y" * 10, stdout_flag, stderr_flag, False, None)
    result = run(ex)
    assert result.outcome == "output_limit" and (result.stdout_truncated, result.stderr_truncated) == (stdout_flag, stderr_flag)
    assert_clean(fake, result)


# --- input validation ---------------------------------------------------------------------------------------------------------------------
def test_oversized_and_empty_input_is_rejected_before_docker_is_contacted():
    fake, ex = make()
    with pytest.raises(JobRejected, match="limit"):
        ex.execute("j1", b"x" * (ex.policy.max_input_bytes + 1), IMAGE_TAG)
    with pytest.raises(JobRejected):
        ex.execute("j2", b"", IMAGE_TAG)
    with pytest.raises(JobRejected):
        ex.execute("j3", "text", IMAGE_TAG)
    assert fake.calls == []


def test_input_exactly_at_the_limit_is_accepted():
    fake, ex = make()
    assert ex.execute("j1", b"x" * ex.policy.max_input_bytes, IMAGE_TAG).outcome == "completed"


def test_a_bad_job_id_is_rejected_before_docker_is_contacted():
    fake, ex = make()
    for bad in ("", "a b", "$(x)", "x" * 80):
        with pytest.raises(pol.PolicyError):
            ex.execute(bad, REQUEST, IMAGE_TAG)
    assert fake.calls == []


# --- cancellation and cleanup after every failure path ----------------------------------------------------------------------------------
def test_ctrl_c_during_the_run_kills_and_removes_the_container_and_reports_interrupted():
    fake, ex = make()
    fake.fail["run_attached"] = KeyboardInterrupt()
    result = run(ex)
    assert result.outcome == "interrupted" and result.container_started
    assert fake.count("kill_container") >= 1
    assert_clean(fake, result)


def test_ctrl_c_before_create_leaves_nothing_to_clean():
    fake, ex = make()
    fake.fail["create_container"] = KeyboardInterrupt()
    result = run(ex)
    assert result.outcome == "interrupted" and fake.containers == {}


def test_a_second_ctrl_c_during_cleanup_cannot_skip_removal():
    fake, ex = make()
    fake.fail["run_attached"] = KeyboardInterrupt()
    fake.fail["remove_container"] = [KeyboardInterrupt()]
    result = run(ex)
    assert result.outcome == "interrupted" and result.cleanup_status == "removed"
    assert fake.count("remove_container") == 2
    assert fake.containers == {}


@pytest.mark.parametrize("scenario", ["success", "nonzero", "create-ok-verify-fails", "start-fails", "timeout", "output", "interrupt", "oom"])
def test_no_container_survives_any_path(scenario):
    fake = FakeDocker()
    if scenario == "nonzero":
        fake.exit_code = 3
    elif scenario == "create-ok-verify-fails":
        fake.mutators.append(setp("HostConfig.NetworkMode", "host"))
    elif scenario == "start-fails":
        fake.fail["run_attached"] = DockerError("boom")
    elif scenario == "timeout":
        fake.attach_result = AttachResult(b"", b"", False, False, True, None)
    elif scenario == "output":
        fake.attach_result = AttachResult(b"x", b"", True, False, False, None)
    elif scenario == "interrupt":
        fake.fail["run_attached"] = KeyboardInterrupt()
    elif scenario == "oom":
        fake.exit_code, fake.oom_killed = 137, True
    result = SandboxExecutor(fake, pol.SandboxPolicy()).execute("j1", REQUEST, IMAGE_TAG)
    assert fake.containers == {} and result.cleanup_status == "removed"


def test_a_container_that_cannot_be_removed_is_reported_with_the_exact_command_to_remove_it():
    fake, ex = make()
    fake.keep_on_remove = True
    result = run(ex)
    assert result.cleanup_status == "failed" and "remove-container sbx-j1" in result.cleanup_detail
    assert result.outcome == "completed"  # the run itself finished; the audit record carries the failed cleanup


def test_a_failing_remove_is_retried_once_then_reported():
    fake, ex = make()
    fake.fail["remove_container"] = [DockerError("busy"), DockerError("busy")]
    result = run(ex)
    assert result.cleanup_status == "failed" and "busy" in result.cleanup_detail and fake.count("remove_container") == 2


# --- concurrency and duplicates --------------------------------------------------------------------------------------------------------------
def test_the_executor_refuses_to_run_a_job_id_twice_and_never_starts_it_a_second_time():
    fake, ex = make()
    run(ex)
    with pytest.raises(DuplicateJobError):
        run(ex)
    assert fake.count("run_attached") == 1 and fake.count("create_container") == 1


def test_a_failed_job_id_is_not_retried_either():
    fake, ex = make()
    fake.fail["create_container"] = DockerError("boom")
    assert run(ex).outcome == "docker_error"
    with pytest.raises(DuplicateJobError):
        run(ex)
    assert fake.count("create_container") == 1


def test_no_automatic_retry_after_a_start_failure():
    fake, ex = make()
    fake.fail["run_attached"] = DockerError("boom")
    run(ex)
    assert fake.count("run_attached") == 1 and fake.count("create_container") == 1


def test_existing_labelled_containers_count_against_the_concurrency_limit():
    fake, ex = make(max_concurrent_jobs=1)
    fake.other_containers = [{"ID": "a" * 64, "Names": "sbx-other", "State": "running", "Status": "Up", "Image": "x"}]
    with pytest.raises(ConcurrencyLimitError, match="already exist"):
        run(ex)
    assert fake.count("create_container") == 0 and fake.containers == {}


def test_exited_containers_do_not_block_new_jobs_but_are_not_silently_removed():
    fake, ex = make()
    fake.other_containers = [{"ID": "a" * 64, "Names": "sbx-old", "State": "exited", "Status": "Exited (0)", "Image": "x"}]
    assert run(ex).outcome == "completed"
    assert fake.count("remove_container") == 1  # only our own container


def test_the_in_process_slot_limit_blocks_a_second_concurrent_job():
    fake, ex = make(max_concurrent_jobs=1)
    seen = {}

    def during(stdin):
        try:
            ex.execute("j2", REQUEST, IMAGE_TAG)
        except ConcurrencyLimitError as exc:
            seen["error"] = exc
        return b"{}"

    fake.attach_behavior = during
    assert run(ex).outcome == "completed"
    assert "error" in seen and fake.count("create_container") == 1


def test_slots_are_released_after_failures_so_later_jobs_can_run():
    fake, ex = make(max_concurrent_jobs=1)
    fake.fail["run_attached"] = DockerError("boom")
    assert run(ex, "a").outcome == "docker_error"
    fake.fail.clear()
    assert run(ex, "b").outcome == "completed"


def test_policy_is_validated_when_the_executor_is_built():
    with pytest.raises(pol.PolicyError):
        SandboxExecutor(FakeDocker(), pol.SandboxPolicy(memory_bytes=10**12))


# --- verification-only ---------------------------------------------------------------------------------------------------------------------
def test_verify_only_never_starts_the_container_and_removes_it():
    fake, ex = make()
    result = ex.verify_only("v1", IMAGE_TAG)
    assert result.outcome == "completed" and result.controls_verified and not result.container_started
    assert fake.count("run_attached") == 0
    assert_clean(fake, result)


def test_verify_only_reports_refusal_for_a_weak_container():
    fake, ex = make()
    fake.mutators.append(setp("HostConfig.CapDrop", []))
    result = ex.verify_only("v1", IMAGE_TAG)
    assert result.outcome == "refused" and fake.count("run_attached") == 0
    assert_clean(fake, result)
