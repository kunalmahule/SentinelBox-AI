"""The real `DockerCli` client, exercised against a stub `docker` program (no daemon needed)."""

import json
import os
import stat
import sys
import time

import pytest

from sentinelbox.sandbox import docker_cli
from sentinelbox.sandbox.docker_client import DockerError, DockerUnavailable

STUB = r'''#!{python}
import json, os, sys, time
log = os.environ["STUB_LOG"]
scenario = os.environ.get("STUB_SCENARIO", "ok")
args = sys.argv[1:]
with open(log, "a") as handle:
    handle.write(json.dumps({{"args": args, "buildkit": os.environ.get("DOCKER_BUILDKIT")}}) + "\n")
cmd = args[0] if args else ""
killed = os.path.join(os.path.dirname(log), "killed")
def err(text, code=1):
    sys.stderr.write(text + "\n"); sys.exit(code)
if cmd == "version":
    if scenario == "daemon-down":
        print(json.dumps({{"Client": {{"Version": "27.1.0"}}}})); err("Cannot connect to the Docker daemon at unix:///x. Is the docker daemon running?")
    print(json.dumps({{"Client": {{"Version": "27.1.0"}}, "Server": {{"Version": "27.1.1", "ApiVersion": "1.46"}}}}))
elif cmd == "info":
    if scenario == "daemon-down": err("Cannot connect to the Docker daemon", 1)
    print(json.dumps({{"OSType": "linux", "SecurityOptions": ["name=seccomp"]}}))
elif cmd == "image" and args[1] == "inspect":
    if args[2] == "missing": err("Error response from daemon: No such image: missing")
    if scenario == "junk": print("not json"); sys.exit(0)
    print(json.dumps([{{"Id": "sha256:" + "ab" * 32}}]))
elif cmd == "inspect":
    if args[-1] == "missing": err("Error response from daemon: No such container: missing")
    print(json.dumps([{{"Id": "c" * 64, "State": {{"Status": "exited", "ExitCode": 0}}}}]))
elif cmd == "create":
    if scenario == "create-noise": print("warning: something")
    print("e" * 64 if scenario != "create-bad" else "oops")
elif cmd == "kill":
    open(killed, "w").write("x"); sys.exit(0)
elif cmd == "rm":
    if scenario == "rm-missing": err("Error response from daemon: No such container: x")
    if scenario == "rm-fail": err("Error response from daemon: removal of container x is already in progress")
elif cmd == "ps":
    print(json.dumps({{"ID": "1" * 64, "Names": "sbx-a", "State": "running", "Status": "Up", "Image": "i"}}))
    print(json.dumps({{"ID": "2" * 64, "Names": "sbx-b", "State": "exited", "Status": "Exited", "Image": "i"}}))
elif cmd == "image" and args[1] == "rm":
    pass
elif cmd == "build":
    print("built")
elif cmd == "start":
    data = sys.stdin.buffer.read() if scenario != "sleep" else b""
    if scenario == "ok": sys.stdout.buffer.write(b"echo:" + data); sys.stderr.buffer.write(b"warn\n")
    elif scenario == "sleep":
        end = time.time() + 30
        while time.time() < end and not os.path.exists(killed): time.sleep(0.02)
        sys.exit(137)
    elif scenario == "flood":
        end = time.time() + 20
        chunk = b"A" * 65536
        while time.time() < end and not os.path.exists(killed):
            try: sys.stdout.buffer.write(chunk); sys.stdout.buffer.flush()
            except BrokenPipeError: break
        sys.exit(137)
    elif scenario == "errflood":
        end = time.time() + 20
        chunk = b"E" * 65536
        while time.time() < end and not os.path.exists(killed):
            try: sys.stderr.buffer.write(chunk); sys.stderr.buffer.flush()
            except BrokenPipeError: break
        sys.exit(137)
    elif scenario == "exit3": sys.exit(3)
else:
    err("unknown stub command " + cmd, 2)
'''


@pytest.fixture
def stub(tmp_path):
    path = tmp_path / "docker"
    path.write_text(STUB.format(python=sys.executable))
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    log = tmp_path / "log.jsonl"

    def make(scenario="ok"):
        env = {"PATH": os.environ["PATH"], "STUB_LOG": str(log), "STUB_SCENARIO": scenario}
        return docker_cli.DockerCli(str(path), env=env)

    def calls():
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    make.calls = calls
    make.killed = tmp_path / "killed"
    return make


def test_a_missing_docker_binary_gives_an_actionable_error(tmp_path):
    client = docker_cli.DockerCli("docker", env={"PATH": str(tmp_path)})
    with pytest.raises(DockerUnavailable, match="Docker Desktop"):
        client.version_info()


def test_version_info_parses_client_and_server(stub):
    info = stub().version_info()
    assert info["client"]["Version"] == "27.1.0" and info["server"]["Version"] == "27.1.1" and info["error"] is None


def test_an_unreachable_daemon_is_reported_not_raised_by_version_info(stub):
    info = stub("daemon-down").version_info()
    assert info["client"]["Version"] == "27.1.0" and info["server"] is None and "Cannot connect" in info["error"]


def test_daemon_down_is_classified_as_unavailable_for_other_commands(stub):
    with pytest.raises(DockerUnavailable, match="not reachable"):
        stub("daemon-down").info()


def test_image_inspect_distinguishes_missing_from_error_and_junk(stub):
    client = stub()
    assert client.inspect_image("missing") is None
    assert client.inspect_image("present")["Id"].startswith("sha256:")
    with pytest.raises(DockerError, match="unreadable"):
        stub("junk").inspect_image("present")


def test_container_inspect_missing_is_none(stub):
    assert stub().inspect_container("missing") is None
    assert stub().inspect_container("x")["State"]["Status"] == "exited"


def test_create_returns_the_container_id_and_rejects_other_output(stub):
    assert stub().create_container(["create", "--name", "sbx-x", "img"]) == "e" * 64
    assert stub("create-noise").create_container(["create", "img"]) == "e" * 64
    with pytest.raises(DockerError, match="container id"):
        stub("create-bad").create_container(["create", "img"])
    with pytest.raises(DockerError, match="internal"):
        stub().create_container(["run", "img"])


def test_arguments_are_passed_as_a_list_never_through_a_shell(stub, tmp_path):
    tricky = ["create", "--name", "sbx-$(touch " + str(tmp_path / "pwned") + ")", ";", "&&", "`id`", "img"]
    stub().create_container(tricky)
    assert stub.calls()[-1]["args"] == tricky and not (tmp_path / "pwned").exists()


def test_remove_container_tolerates_missing_but_reports_other_failures(stub):
    stub("rm-missing").remove_container("x")
    with pytest.raises(DockerError, match="in progress"):
        stub("rm-fail").remove_container("x")
    assert stub.calls()[-1]["args"] == ["rm", "--force", "--volumes", "x"]


def test_list_containers_parses_json_lines_and_filters_by_label(stub):
    rows = stub().list_containers("io.sentinelbox.sandbox=1")
    assert [r["Names"] for r in rows] == ["sbx-a", "sbx-b"]
    assert "label=io.sentinelbox.sandbox=1" in stub.calls()[-1]["args"]


def test_build_passes_pull_false_labels_and_buildargs_and_the_legacy_flag(stub, tmp_path):
    client = stub()
    client.build_image(tmp_path, tmp_path / "Dockerfile", "t:1", {"BASE_IMAGE": "sha256:" + "a" * 64}, {"k": "v"})
    first = stub.calls()[-1]
    assert "--pull=false" in first["args"] and "--progress=plain" in first["args"] and first["buildkit"] is None
    assert "BASE_IMAGE=sha256:" + "a" * 64 in first["args"] and "k=v" in first["args"]
    client.build_image(tmp_path, tmp_path / "Dockerfile", "t:2", {"BASE_IMAGE": "x"}, {}, legacy_builder=True)
    legacy = stub.calls()[-1]
    assert legacy["buildkit"] == "0" and "--progress=plain" not in legacy["args"]


# --- attached execution: bounded and killed ---------------------------------------------------------------------------------------
def test_attached_run_delivers_stdin_and_collects_bounded_output(stub):
    result = stub().run_attached("c1", b"payload", timeout=20, max_stdout=1000, max_stderr=1000)
    assert result.stdout == b"echo:payload" and result.stderr == b"warn\n"
    assert not result.timed_out and not result.stdout_truncated and result.cli_returncode == 0
    assert stub.calls()[-1]["args"] == ["start", "--attach", "--interactive", "c1"]


def test_a_large_stdin_is_delivered_completely(stub):
    payload = b"z" * 200_000
    result = stub().run_attached("c1", payload, timeout=20, max_stdout=1_000_000, max_stderr=1000)
    assert result.stdout == b"echo:" + payload


def test_the_exit_status_of_the_cli_is_reported(stub):
    assert stub("exit3").run_attached("c1", b"", timeout=20, max_stdout=100, max_stderr=100).cli_returncode == 3


def test_wall_clock_timeout_kills_the_container_not_just_the_cli(stub):
    start = time.monotonic()
    result = stub("sleep").run_attached("c1", b"", timeout=0.5, max_stdout=100, max_stderr=100)
    assert result.timed_out and time.monotonic() - start < 15
    assert ["kill", "c1"] in [c["args"] for c in stub.calls()] and stub.killed.exists()


def test_stdout_flood_is_truncated_and_kills_the_container(stub):
    start = time.monotonic()
    result = stub("flood").run_attached("c1", b"", timeout=30, max_stdout=100_000, max_stderr=100)
    assert result.stdout_truncated and len(result.stdout) == 100_000 and not result.timed_out
    assert time.monotonic() - start < 15 and ["kill", "c1"] in [c["args"] for c in stub.calls()]


def test_stderr_flood_is_truncated_and_kills_the_container(stub):
    result = stub("errflood").run_attached("c1", b"", timeout=30, max_stdout=100, max_stderr=50_000)
    assert result.stderr_truncated and len(result.stderr) == 50_000 and ["kill", "c1"] in [c["args"] for c in stub.calls()]


def test_ctrl_c_while_attached_kills_the_container_and_propagates(stub, monkeypatch):
    client = stub("sleep")
    calls = {"n": 0}
    original = docker_cli.time.monotonic

    def interrupting():
        calls["n"] += 1
        if calls["n"] > 5:
            raise KeyboardInterrupt
        return original()

    monkeypatch.setattr(docker_cli.time, "monotonic", interrupting)
    with pytest.raises(KeyboardInterrupt):
        client.run_attached("c1", b"", timeout=30, max_stdout=100, max_stderr=100)
    assert ["kill", "c1"] in [c["args"] for c in stub.calls()]
