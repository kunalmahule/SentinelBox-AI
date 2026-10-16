"""Image building and checking, record sanitising, and the sandbox command-line interface (all with a fake Docker)."""

import contextlib
import json
import re

import pytest
from sandbox_fakes import IMAGE_ID, IMAGE_TAG, FakeDocker, make_image_inspect, no_real_docker, run_real_workload  # noqa: F401

from sentinelbox.sandbox import cli, executor, image, pipeline, record
from sentinelbox.sandbox import policy as pol
from sentinelbox.sandbox.docker_client import DockerUnavailable
from sentinelbox.storage.database import init_database, open_database

pytestmark = pytest.mark.usefixtures("no_real_docker")
BASE = "sha256:" + "ab" * 32


def run_cli(capsys, fake, *argv):
    code = cli.main(list(argv), client=fake)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


# --- image: staging and building ---------------------------------------------------------------------------------------------------
def test_the_build_context_contains_only_the_allowlisted_files():
    with image.staged_context() as root:
        files = sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())
    assert files == sorted(["Dockerfile", *(f"sentinelbox/{f}" for f in image.STAGED_FILES)])
    banned = ("storage", "rule_engine", "app.py", "schemas.py", "cli.py", "tests", "reports", "data", ".env", "requirements", "report.py", "library.py")
    assert not [f for f in files if any(b in f for b in banned)]


def test_staged_permissions_are_normalised():
    with image.staged_context() as root:
        modes = {p.relative_to(root).as_posix(): p.stat().st_mode & 0o777 for p in root.rglob("*")}
    assert all(m in (0o755, 0o644) for m in modes.values())


def test_build_requires_a_pinned_base_and_calls_docker_with_labels(capsys):
    fake = FakeDocker()
    result = image.build(fake, BASE)
    call = fake.build_calls[0]
    assert call["args"] == {"BASE_IMAGE": BASE} and call["labels"][image.SOURCE_LABEL] == image.source_digest()
    assert call["labels"][image.BASE_LABEL] == BASE and result.tag == image.default_tag() and not result.already_existed
    assert "Dockerfile" in call["files"] and "sentinelbox/sandbox_workload/__main__.py" in call["files"]


@pytest.mark.parametrize("base", ["python:3.13-slim", "python:latest", "python", "", "sha256:short"])
def test_an_unpinned_base_is_refused_before_docker_is_called(base):
    fake = FakeDocker()
    with pytest.raises(pol.PolicyError):
        image.build(fake, base)
    assert fake.calls == []


def test_build_never_replaces_an_existing_tag_but_is_idempotent_for_identical_inputs():
    fake = FakeDocker()
    first = image.build(fake, BASE)
    again = image.build(fake, BASE)
    assert again.already_existed and again.image_id == first.image_id and len(fake.build_calls) == 1
    with pytest.raises(image.ImageError, match="different sources or a different base"):
        image.build(fake, "sha256:" + "cd" * 32)
    assert len(fake.build_calls) == 1


def test_the_default_tag_changes_when_a_staged_source_changes(monkeypatch):
    before = image.default_tag()
    original = image.PACKAGE_ROOT
    monkeypatch.setattr(image, "source_digest", lambda: "f" * 64)
    assert image.default_tag() != before and image.default_tag().startswith("sentinelbox-sandbox:stage5-")
    assert image.PACKAGE_ROOT == original


def test_staging_refuses_a_missing_or_symlinked_source(monkeypatch, tmp_path):
    monkeypatch.setattr(image, "STAGED_FILES", ("__init__.py", "does_not_exist.py"))
    with pytest.raises(image.ImageError, match="missing"):
        with image.staged_context():
            pass


# --- image: checking what the image declares -------------------------------------------------------------------------------------------------
def image_with(**changes):
    inspected = make_image_inspect()
    for path, value in changes.items():
        parts = path.split("__")
        node = inspected
        for key in parts[:-1]:
            node = node[key]
        node[parts[-1]] = value
    return inspected


@pytest.mark.parametrize("changes,fragment", [
    ({"Config__User": "root"}, "numeric non-root"), ({"Config__User": "0:0"}, "numeric non-root"), ({"Config__User": ""}, "numeric non-root"),
    ({"Config__Entrypoint": ["sh"]}, "entry point"), ({"Config__Entrypoint": None}, "entry point"),
    ({"Config__Cmd": ["bash"]}, "default command"), ({"Config__Volumes": {"/data": {}}}, "volumes"),
    ({"Config__ExposedPorts": {"80/tcp": {}}}, "ports"), ({"Config__Labels": {}}, "label"), ({"Config__Labels": None}, "label"),
    ({"Config__OnBuild": ["RUN x"]}, "ONBUILD"), ({"Id": "sha256:short"}, "sha256 id"), ({"Config__Env": "x"}, "unreadable"),
])
def test_a_wrong_image_is_rejected_with_the_reason(changes, fragment):
    problems = image.check_image(image_with(**changes))
    assert any(fragment in p for p in problems), problems
    fake = FakeDocker(image=image_with(**changes))
    with pytest.raises(image.ImageError):
        image.resolve_image(fake, IMAGE_TAG)


def test_a_good_image_resolves_to_its_immutable_id_and_never_pulls():
    fake = FakeDocker()
    resolved = image.resolve_image(fake, IMAGE_TAG)
    assert resolved.image_id == IMAGE_ID and resolved.env and [n for n, _ in fake.calls] == ["inspect_image"]


def test_a_missing_image_names_the_build_command():
    with pytest.raises(image.ImageError, match="build --base-image"):
        image.resolve_image(FakeDocker(), "sentinelbox-sandbox:nope")


# --- the Dockerfile -------------------------------------------------------------------------------------------------------------------------
def dockerfile_lines():
    return [l.strip() for l in image.DOCKERFILE.read_text().splitlines() if l.strip() and not l.strip().startswith("#")]


def test_the_dockerfile_has_no_default_base_and_no_floating_tags():
    lines = dockerfile_lines()
    assert "ARG BASE_IMAGE" in lines and "FROM ${BASE_IMAGE}" in lines
    assert not any("latest" in l.lower() for l in lines) and sum(l.startswith("FROM") for l in lines) == 1


def test_the_dockerfile_runs_as_a_numeric_non_root_user_with_a_fixed_exec_form_entrypoint():
    text = "\n".join(dockerfile_lines())
    assert "USER 65532:65532" in text and "HEALTHCHECK NONE" in text and "CMD []" in text
    assert 'ENTRYPOINT ["python", "-B", "-s", "-m", "sentinelbox.sandbox_workload"]' in text
    assert json.loads(re.search(r"ENTRYPOINT (\[.*\])", text).group(1)) == pol.ENTRYPOINT


def test_the_dockerfile_copies_only_the_staged_package_and_installs_nothing():
    text = "\n".join(dockerfile_lines())
    assert re.findall(r"^COPY .*$", text, re.M) == ["COPY sentinelbox/ /app/sentinelbox/"]
    for banned in ("ADD ", "RUN ", "pip ", "apt", "curl", "wget", "sudo", "--chown", "chmod", "EXPOSE", "VOLUME", "docker.sock", "SECRET", "TOKEN", "PASSWORD", "KEY"):
        assert banned not in text, banned
    envs = re.findall(r"^ENV (.*?)(?=^\S|\Z)", text, re.M | re.S)
    assert "PYTHONPATH=/app" in text and "HOME" not in " ".join(envs)


# --- records ----------------------------------------------------------------------------------------------------------------------------------
def test_sanitize_strips_host_paths_and_withholds_credential_look_alikes():
    assert record.sanitize("failed at /Users/alice/project/x.py line 3") == "failed at [host path removed] line 3"
    assert record.sanitize("token AKIAABCDEFGHIJKLMNOP leaked") == record.WITHHELD
    assert record.sanitize(None) is None and record.sanitize("") is None
    assert len(record.sanitize("x" * 1000, 50)) <= 50
    assert record.sanitize("line1\nline2\x1b[31m") == "line1 line2 [31m"


def test_a_record_built_from_a_result_validates():
    from sentinelbox.storage.documents import validate_sandbox_record_document

    fake = FakeDocker()
    result = executor.SandboxExecutor(fake, pol.SandboxPolicy()).execute("r1", b"{}", IMAGE_TAG)
    rec = record.build_record(result, kind="self_check", cases_requested=0, cases_returned=0)
    assert validate_sandbox_record_document(rec) == [] and rec["image"]["id"] == IMAGE_ID and rec["cleanup"]["status"] == "removed"


# --- CLI: doctor ------------------------------------------------------------------------------------------------------------------------------------
def test_doctor_reports_a_healthy_environment(capsys):
    code, out, _ = run_cli(capsys, FakeDocker(), "doctor")
    assert code == 0 and "[ok] Docker CLI" in out and "[ok] Docker server 29.0.0" in out and "seccomp" in out


def test_doctor_explains_how_to_start_the_daemon(capsys):
    fake = FakeDocker()
    fake.server_version = None
    code, out, _ = run_cli(capsys, fake, "doctor")
    assert code == 2 and "[FAIL]" in out and "Docker Desktop" in out


def test_doctor_reports_a_missing_cli(capsys):
    fake = FakeDocker()
    fake.fail["version_info"] = DockerUnavailable("The Docker command-line client was not found on PATH", detail="install Docker Desktop")
    code, out, _ = run_cli(capsys, fake, "doctor")
    assert code == 2 and "not found" in out


@pytest.mark.parametrize("key", ["MemoryLimit", "SwapLimit", "CpuCfsQuota", "PidsLimit"])
def test_doctor_fails_when_a_required_limit_is_unsupported(capsys, key):
    fake = FakeDocker()
    fake.info_data[key] = False
    code, out, _ = run_cli(capsys, fake, "doctor")
    assert code == 2 and "[FAIL]" in out


def test_doctor_rejects_an_old_server_and_non_linux_containers(capsys):
    fake = FakeDocker()
    fake.server_version = "19.3.0"
    assert run_cli(capsys, fake, "doctor")[0] == 2
    fake = FakeDocker()
    fake.info_data["OSType"] = "windows"
    assert run_cli(capsys, fake, "doctor")[0] == 2


def test_doctor_warns_but_does_not_fail_without_seccomp_or_image(capsys):
    fake = FakeDocker()
    fake.info_data["SecurityOptions"] = []
    code, out, _ = run_cli(capsys, fake, "doctor", "--image", "sentinelbox-sandbox:absent")
    assert code == 0 and "[WARN]" in out and "not built yet" in out


def test_doctor_flags_a_bad_image(capsys):
    fake = FakeDocker(image=image_with(Config__User="root"))
    code, out, _ = run_cli(capsys, fake, "doctor", "--image", IMAGE_TAG)
    assert code == 2 and "would be rejected" in out


# --- CLI: pin-base, build, verify ---------------------------------------------------------------------------------------------------------------
def test_pin_base_prints_a_digest_reference_or_explains(capsys):
    fake = FakeDocker()
    fake.images["python:3.13-slim"] = {"Id": "sha256:" + "11" * 32, "RepoDigests": ["python@sha256:" + "22" * 32]}
    code, out, _ = run_cli(capsys, fake, "pin-base", "--image", "python:3.13-slim")
    assert code == 0 and "python@sha256:" + "22" * 32 in out
    fake.images["local:1"] = {"Id": "sha256:" + "33" * 32, "RepoDigests": []}
    code, _, err = run_cli(capsys, fake, "pin-base", "--image", "local:1")
    assert code == 2 and "image id" in err and "sha256:" + "33" * 32 in err
    code, _, err = run_cli(capsys, fake, "pin-base", "--image", "absent:1")
    assert code == 2 and "never pulls" in err


def test_build_command_reports_and_refuses_unpinned(capsys):
    fake = FakeDocker()
    code, out, _ = run_cli(capsys, fake, "build", "--base-image", BASE)
    assert code == 0 and "built" in out and image.default_tag() in out
    code, out, _ = run_cli(capsys, fake, "build", "--base-image", BASE)
    assert code == 0 and "already exists" in out
    code, _, err = run_cli(capsys, fake, "build", "--base-image", "python:3.13")
    assert code == 2 and "not pinned" in err and "pin-base" in err


def test_build_legacy_builder_flag_is_forwarded(capsys):
    fake = FakeDocker()
    run_cli(capsys, fake, "build", "--base-image", BASE, "--legacy-builder")
    assert fake.build_calls[0]["legacy"] is True


def test_verify_lists_every_control_and_never_starts_the_container(capsys):
    fake = FakeDocker()
    code, out, _ = run_cli(capsys, fake, "verify", "--image", IMAGE_TAG)
    assert code == 0 and "controls verified on a created, never-started container" in out and "[ok] network_mode_none" in out
    assert fake.count("run_attached") == 0 and fake.containers == {}


def test_verify_refuses_a_weak_container_with_exit_1(capsys):
    fake = FakeDocker()
    fake.mutators.append(lambda c: c["HostConfig"].update(ReadonlyRootfs=False))
    code, out, err = run_cli(capsys, fake, "verify", "--image", IMAGE_TAG)
    assert code == 1 and "[FAIL] root_filesystem_read_only" in out and "REFUSED" in err and fake.containers == {}


def test_verify_self_check_prints_observations_labelled_as_self_reported(capsys):
    fake = FakeDocker()
    fake.attach_behavior = run_real_workload
    code, out, _ = run_cli(capsys, fake, "verify", "--image", IMAGE_TAG, "--self-check")
    assert code == 0 and "SELF-REPORTED" in out and '"uid"' in out and '"mounts"' not in out


def test_limit_options_are_validated_against_the_bounds(capsys):
    fake = FakeDocker()
    code, _, err = run_cli(capsys, fake, "verify", "--memory-mb", "100000")
    assert code == 2 and "memory_bytes" in err and fake.calls == []
    code, _, err = run_cli(capsys, fake, "verify", "--timeout", "0")
    assert code == 2 and fake.calls == []


# --- CLI: run -------------------------------------------------------------------------------------------------------------------------------------
@pytest.fixture
def run_env(tmp_path):
    fake = FakeDocker()
    fake.attach_behavior = run_real_workload
    return fake, init_database(tmp_path / "audit.db"), tmp_path / "reports"


def test_run_prints_a_summary_and_stores_the_record(capsys, run_env):
    fake, db, reports = run_env
    code, out, err = run_cli(capsys, fake, "run", "--image", IMAGE_TAG, "--db", str(db), "--reports-dir", str(reports))
    assert code == 0 and err == "" and "completed" in out
    verified, total = re.search(r"controls verified before start: (\d+)/(\d+)", out).groups()
    assert verified == total and int(total) >= 45
    assert "Stage 3 rule engine" in out and "stored" in out and "TP" in out
    assert len(list(reports.iterdir())) == 3


def test_run_requires_an_existing_database_or_an_explicit_opt_out(capsys, run_env, tmp_path):
    fake, db, reports = run_env
    code, _, err = run_cli(capsys, fake, "run", "--image", IMAGE_TAG, "--db", str(tmp_path / "none.db"), "--reports-dir", str(reports))
    assert code == 2 and "storage init" in err and fake.calls == []
    code, out, _ = run_cli(capsys, fake, "run", "--image", IMAGE_TAG, "--no-db", "--reports-dir", str(reports))
    assert code == 0 and "not requested" in out


def test_run_exit_codes_follow_the_outcome(capsys, run_env):
    fake, db, reports = run_env
    fake.mutators.append(lambda c: c["HostConfig"].update(NetworkMode="bridge"))
    code, out, err = run_cli(capsys, fake, "run", "--image", IMAGE_TAG, "--db", str(db), "--reports-dir", str(reports))
    assert code == 1 and "refused" in out and "network_mode_none" in out
    fake2 = FakeDocker()
    fake2.attach_behavior = None
    fake2.fail["run_attached"] = KeyboardInterrupt()
    code, out, _ = run_cli(capsys, fake2, "run", "--image", IMAGE_TAG, "--db", str(db), "--reports-dir", str(reports))
    assert code == 130 and "interrupted" in out


def test_run_reports_a_storage_failure_with_the_recovery_command(capsys, run_env):
    fake, db, reports = run_env
    first = run_cli(capsys, fake, "run", "--image", IMAGE_TAG, "--db", str(db), "--reports-dir", str(reports), "--mode", "hardened")
    assert first[0] == 0
    # force a conflict: store a different record under the id the next run will use
    from sentinelbox.sandbox import pipeline as p

    record_file = next(reports.glob("*.sandbox.json"))
    job = json.loads(record_file.read_text())["sandbox_run_id"]
    fake2 = FakeDocker()
    fake2.attach_behavior = run_real_workload
    out = p.run_suite(fake2, image_ref=IMAGE_TAG, policy=pol.SandboxPolicy(), modes=["vulnerable"], reports_dir=reports, db_path=db, job_id=job)
    assert out.db_status == "failed" and out.recovery_command.startswith("python -m sentinelbox.storage import-sandbox")


def test_run_rejects_an_unpinned_image_with_exit_2(capsys, run_env):
    fake, db, reports = run_env
    code, _, err = run_cli(capsys, fake, "run", "--image", "python:latest", "--db", str(db), "--reports-dir", str(reports))
    assert code == 2 and "latest" in err and fake.calls == []


def test_run_with_docker_unavailable_is_a_recorded_docker_error_and_creates_nothing(capsys, run_env):
    fake, db, reports = run_env
    fake.fail["version_info"] = DockerUnavailable("The Docker daemon is not reachable", detail="start Docker Desktop")
    code, out, _ = run_cli(capsys, fake, "run", "--image", IMAGE_TAG, "--db", str(db), "--reports-dir", str(reports))
    assert code == 1 and "docker_error" in out and "not reachable" in out
    assert fake.containers == {} and fake.count("create_container") == 0


# --- CLI: container and image housekeeping ------------------------------------------------------------------------------------------------------
def test_containers_lists_and_remove_container_is_label_checked(capsys):
    fake = FakeDocker()
    mine = fake.create_container(pol.build_create_args(pol.SandboxPolicy(), IMAGE_ID, "j9"))
    code, out, _ = run_cli(capsys, fake, "containers")
    assert code == 0 and "sbx-j9" in out and "remove-container" in out
    stranger = fake.create_container(pol.build_create_args(pol.SandboxPolicy(), IMAGE_ID, "j8"))
    fake.containers[stranger]["Config"]["Labels"] = {}
    code, _, err = run_cli(capsys, fake, "remove-container", stranger)
    assert code == 2 and "not a SentinelBox sandbox container" in err and stranger in fake.containers
    fake.containers[stranger]["Config"]["Labels"] = {"io.sentinelbox.sandbox": "1"}
    fake.containers[stranger]["Name"] = "/other-name"
    assert run_cli(capsys, fake, "remove-container", stranger)[0] == 2 and stranger in fake.containers
    code, out, _ = run_cli(capsys, fake, "remove-container", "sbx-j9")
    assert code == 0 and mine not in fake.containers and "Removed container sbx-j9" in out
    assert run_cli(capsys, fake, "remove-container", "ghost")[0] == 2


def test_containers_with_none_says_so(capsys):
    assert "No sandbox containers" in run_cli(capsys, FakeDocker(), "containers")[1]


def test_remove_image_only_removes_images_built_by_the_tool_and_not_in_use(capsys):
    fake = FakeDocker()
    foreign = make_image_inspect("sha256:" + "55" * 32, RepoTags=["other:1"])
    foreign["Config"]["Labels"] = {}
    fake.images["other:1"] = foreign
    code, _, err = run_cli(capsys, fake, "remove-image", "other:1")
    assert code == 2 and "not built by" in err and "other:1" in fake.images
    fake.create_container(pol.build_create_args(pol.SandboxPolicy(), IMAGE_ID, "j1"))
    code, _, err = run_cli(capsys, fake, "remove-image", IMAGE_TAG)
    assert code == 2 and "still use" in err and IMAGE_TAG in fake.images
    fake.containers.clear()
    code, out, _ = run_cli(capsys, fake, "remove-image", IMAGE_TAG)
    assert code == 0 and IMAGE_TAG not in fake.images and "Removed image" in out
    assert run_cli(capsys, fake, "remove-image", "absent:1")[0] == 2
