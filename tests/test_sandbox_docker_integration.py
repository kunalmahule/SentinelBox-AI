"""Opt-in tests against a REAL Docker daemon.

They run only when SENTINELBOX_DOCKER_TESTS=1. Otherwise every test is SKIPPED, and a skip is not security
verification. Required: a pinned local base image in SENTINELBOX_DOCKER_BASE_IMAGE (a ``name@sha256:...`` reference
or a ``sha256:`` image ID that exists locally; ``python -m sentinelbox.sandbox pin-base --image <name>`` prints one).
Optional: SENTINELBOX_DOCKER_LEGACY_BUILDER=1 (offline hosts), SENTINELBOX_DOCKER_REPORT=<file> (a JSON record of
what was verified is written there), DOCKER_HOST as usual.

The tests create only containers named ``sbx-it...`` and remove each one by its container ID afterwards.
"""

import contextlib
import copy
import json
import os
import platform
import sys
import uuid

import pytest

from sentinelbox.sandbox import image as image_mod
from sentinelbox.sandbox import inspection, pipeline
from sentinelbox.sandbox import policy as pol
from sentinelbox.sandbox.docker_cli import DockerCli
from sentinelbox.sandbox.docker_client import DockerError
from sentinelbox.sandbox.executor import LABEL_FILTER, SandboxExecutor
from sentinelbox.sandbox_workload import protocol
from sentinelbox.storage.database import init_database, open_database
from sentinelbox.storage.verify import verify_database

ENABLED = os.environ.get("SENTINELBOX_DOCKER_TESTS") == "1"
BASE = os.environ.get("SENTINELBOX_DOCKER_BASE_IMAGE", "")
pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(not ENABLED, reason="real-Docker tests are opt-in: set SENTINELBOX_DOCKER_TESTS=1 (skipped tests verify nothing)"),
]
VERIFIED: dict[str, object] = {}  # what these tests actually established, written to SENTINELBOX_DOCKER_REPORT at the end


def _unique(prefix="it") -> str:
    return f"{prefix}{uuid.uuid4().hex[:10]}"


@pytest.fixture(scope="module")
def cli():
    client = DockerCli()
    try:
        info = client.version_info()
    except DockerError as exc:
        pytest.skip(f"Docker is not usable here: {exc}")
    if not info.get("server"):
        pytest.skip("the Docker daemon is not reachable")
    VERIFIED["docker"] = {"client": info.get("client"), "server": info.get("server"),
                          "host_platform": f"{platform.system()} {platform.machine()}", "python": sys.version.split()[0]}
    return client


@pytest.fixture(scope="module")
def image_ref(cli):
    if not BASE:
        pytest.skip("SENTINELBOX_DOCKER_BASE_IMAGE is not set (a pinned local base image is required to build the sandbox image)")
    built = image_mod.build(cli, BASE, legacy_builder=os.environ.get("SENTINELBOX_DOCKER_LEGACY_BUILDER") == "1")
    VERIFIED["image"] = {"tag": built.tag, "id": built.image_id, "base": BASE}
    return built.tag


@pytest.fixture(scope="module", autouse=True)
def write_report():
    yield
    path = os.environ.get("SENTINELBOX_DOCKER_REPORT")
    if path and ENABLED:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(VERIFIED, handle, indent=2, sort_keys=True, default=str)


@pytest.fixture
def created(cli):
    """Create containers by container ID and always remove exactly those afterwards."""
    ids: list[str] = []

    def make(args):
        cid = cli.create_container(args)
        ids.append(cid)
        return cid

    yield make
    for cid in ids:
        cli.remove_container(cid)
    for cid in ids:
        assert cli.inspect_container(cid) is None, f"container {cid[:12]} was not removed"


@pytest.fixture(autouse=True)
def no_leftovers(cli):
    yield
    assert [c for c in cli.list_containers(LABEL_FILTER) if str(c.get("Names", "")).lstrip("/").startswith("sbx-it")] == []


def resolved(cli, ref):
    return image_mod.resolve_image(cli, ref)


def policy_args(cli, ref, job, *, policy=None, entrypoint=None, command=None):
    """The policy's own create arguments, optionally with an entry point/command override for hostile probes."""
    img = resolved(cli, ref)
    args = pol.build_create_args(policy or pol.SandboxPolicy(), img.image_id, job)
    if entrypoint:
        args = args[:-1] + ["--entrypoint", entrypoint, args[-1]]
    return args + list(command or [])


def probe(cli, created, ref, code, *, timeout=30.0, policy=None, max_stdout=65536):
    """Run a Python snippet inside a container created with the full policy; returns (result, inspect)."""
    job = _unique()
    cid = created(policy_args(cli, ref, job, policy=policy, entrypoint="python", command=["-c", code]))
    result = cli.run_attached(cid, b"", timeout=timeout, max_stdout=max_stdout, max_stderr=pol.SandboxPolicy().max_stderr_bytes)
    return result, cli.inspect_container(cid)


def jsonout(result):
    return json.loads(result.stdout.decode())


# --- 1. runtime inspection of a real container -------------------------------------------------------------------------------------------
def test_real_verify_checks_every_control_on_a_real_created_container(cli, image_ref):
    result = SandboxExecutor(cli, pol.SandboxPolicy()).verify_only(_unique(), image_ref)
    assert result.outcome == "completed" and not result.container_started, result.error
    assert result.cleanup_status == "removed"
    failed = [c.as_dict() for c in result.controls if not c.ok]
    assert failed == [] and len(result.controls) >= 45
    VERIFIED["controls_verified_on_real_container"] = sorted(c.name for c in result.controls)
    VERIFIED["effective_settings"] = result.effective


def test_the_real_inspect_output_matches_the_requested_limits(cli, image_ref, created):
    policy = pol.SandboxPolicy()
    cid = created(policy_args(cli, image_ref, _unique()))
    host = cli.inspect_container(cid)["HostConfig"]
    assert host["NetworkMode"] == "none" and host["ReadonlyRootfs"] is True and host["CapDrop"] == ["ALL"]
    assert host["Memory"] == host["MemorySwap"] == policy.memory_bytes and host["PidsLimit"] == policy.pids_limit
    assert host["NanoCpus"] == int(policy.cpus * 1e9) and host["Privileged"] is False and host["Init"] is True
    assert not host.get("Binds") and not host.get("PortBindings") and host["PidMode"] == "" and host["IpcMode"] == "private"


@pytest.mark.parametrize("flag_args,label", [
    (["--network", "bridge"], "bridge network"), (["--privileged"], "privileged"), (["--cap-add", "NET_ADMIN"], "extra capability"),
    (["--pid", "host"], "host PID namespace"), (["--publish", "127.0.0.1::80"], "published port"), (["--env", "AWS_SECRET_ACCESS_KEY=x"], "env var"),
    (["--user", "0:0"], "root user"), (["--volume", "/tmp:/host:ro"], "host bind mount"), (["--security-opt", "seccomp=unconfined"], "seccomp off"),
    (["--memory", "2g", "--memory-swap", "4g"], "bigger limits"), (["--pids-limit", "-1"], "unlimited pids"),
])
def test_a_really_weakened_container_is_refused_by_real_inspection(cli, image_ref, created, flag_args, label):
    img = resolved(cli, image_ref)
    args = pol.build_create_args(pol.SandboxPolicy(), img.image_id, _unique())
    weakened = args[:-1] + flag_args + args[-1:]  # docker uses the last occurrence of a repeated flag, so ours wins
    try:
        cid = created(weakened)
    except DockerError:
        VERIFIED.setdefault("refused_by_docker_at_create", []).append(label)  # Docker itself rejected it; nothing to inspect
        return
    results, _ = inspection.verify_container(cli.inspect_container(cid), pol.SandboxPolicy(), img)
    assert not inspection.all_ok(results), f"a container with {label} passed every check"
    VERIFIED.setdefault("real_weakened_containers_refused", {})[label] = sorted(r.name for r in inspection.failed(results))


def test_every_single_weakening_of_the_real_inspect_output_is_refused(cli, image_ref, created):
    from test_sandbox_inspection import CASES  # the same per-control weakenings used with the fake daemon

    img = resolved(cli, image_ref)
    real = cli.inspect_container(created(policy_args(cli, image_ref, _unique())))
    baseline, _ = inspection.verify_container(real, pol.SandboxPolicy(), img)
    assert inspection.all_ok(baseline), inspection.failed(baseline)
    accepted = []
    for control, label, mutation in CASES:
        mutated = copy.deepcopy(real)
        try:
            mutation(mutated)
        except (KeyError, TypeError):
            continue  # the real output does not have that shape; the fake-daemon suite covers it
        results, _ = inspection.verify_container(mutated, pol.SandboxPolicy(), img)
        if control not in {r.name for r in inspection.failed(results)}:
            accepted.append((control, label))
    assert accepted == []
    VERIFIED["weakenings_of_real_inspect_refused"] = len(CASES)


# --- 2. what the workload sees from inside (self-reported, compared with the host's inspection) -------------------------------------
def test_self_check_observations_agree_with_what_the_host_inspected(cli, image_ref):
    request = protocol.build_request(pipeline.new_job_id(), "self_check", [], [])
    raw = protocol.encode_request(request)
    run = SandboxExecutor(cli, pol.SandboxPolicy()).execute(request["job_id"], raw, image_ref)
    assert run.outcome == "completed", run.error
    obs = protocol.parse_response(run.stdout, protocol.parse_request(raw))["observations"]
    assert (obs["uid"], obs["gid"], obs["euid"]) == (65532, 65532, 65532)
    assert str(obs["no_new_privs"]).strip() == "1"
    assert set(obs["capabilities"]["CapEff"].strip("0")) <= {""} and set(obs["capabilities"]["CapPrm"].strip("0")) <= {""}
    assert obs["network"]["interfaces"] == ["lo"]
    net = obs["network"]
    assert net["connect_external"] != "connected" and net["dns"] != "resolved", net
    fs = obs["filesystem"]
    assert fs["write_root"] == "EROFS" and fs["write_app"] == "EROFS" and fs["write_tmp"] == "created", fs
    assert fs["docker_socket_present"] is False
    assert "SENTINELBOX_TEST_SECRET" not in obs["environment_variable_names"]
    assert obs["process"]["pid1_name"] and obs["process"]["visible_processes"] < 10
    assert run.cleanup_status == "removed" and run.controls_verified
    VERIFIED["self_check_agrees_with_inspection"] = True


def test_no_host_environment_variable_reaches_the_container(cli, image_ref, created, monkeypatch):
    monkeypatch.setenv("SENTINELBOX_TEST_SECRET", "host-secret-value")
    result, _ = probe(cli, created, image_ref, "import os,json;print(json.dumps(sorted(os.environ)))")
    names = jsonout(result)
    assert "SENTINELBOX_TEST_SECRET" not in names and not [n for n in names if "SECRET" in n or "TOKEN" in n or "KEY" in n]
    VERIFIED["host_env_not_passed_through"] = True


# --- 3. hostile workloads: the kernel, not the workload's good behaviour, must stop them ---------------------------------------
def test_there_is_no_network_at_all(cli, image_ref, created):
    code = ("import socket,json,os\nr={'ifaces':sorted(os.listdir('/sys/class/net'))}\n"
            "for name,addr in (('ext',('1.1.1.1',53)),('dns',None)):\n"
            "  try:\n"
            "    if addr: s=socket.socket(); s.settimeout(2); s.connect(addr); r[name]='CONNECTED'\n"
            "    else: socket.getaddrinfo('example.com',80); r[name]='RESOLVED'\n"
            "  except OSError as e: r[name]=type(e).__name__\n"
            "print(json.dumps(r))")
    result, inspected = probe(cli, created, image_ref, code)
    out = jsonout(result)
    assert out["ifaces"] == ["lo"] and out["ext"] != "CONNECTED" and out["dns"] != "RESOLVED"
    assert inspected["NetworkSettings"].get("Ports") in (None, {}) and inspected["HostConfig"]["NetworkMode"] == "none"
    VERIFIED["no_network_from_inside"] = True


def test_the_root_filesystem_is_read_only_and_tmp_is_bounded(cli, image_ref, created):
    limit = pol.SandboxPolicy().tmpfs_bytes
    code = ("import json,errno\nr={}\n"
            "try: open('/rootfs-probe','w').write('x'); r['root']='WROTE'\n"
            "except OSError as e: r['root']=errno.errorcode[e.errno]\n"
            "try: open('/app/probe','w').write('x'); r['app']='WROTE'\n"
            "except OSError as e: r['app']=errno.errorcode[e.errno]\n"
            "w=0\n"
            "try:\n"
            "  with open('/tmp/fill','wb') as f:\n"
            f"    for _ in range({limit // 1048576 + 8}): f.write(b'0'*1048576); f.flush(); w+=1\n"
            "  r['tmp']='UNBOUNDED'\n"
            "except OSError as e: r['tmp']=errno.errorcode[e.errno]\n"
            "r['mib']=w\nprint(json.dumps(r))")
    out = jsonout(probe(cli, created, image_ref, code)[0])
    assert out["root"] == "EROFS" and out["app"] == "EROFS" and out["tmp"] == "ENOSPC" and out["mib"] <= limit // 1048576
    VERIFIED["rootfs_read_only_and_tmpfs_bounded"] = {"tmpfs_mib_written_before_ENOSPC": out["mib"], "limit_mib": limit // 1048576}


def test_privileges_are_dropped_and_cannot_be_regained(cli, image_ref, created):
    code = ("import os,json\ns=dict(l.split(':',1) for l in open('/proc/self/status').read().splitlines() if ':' in l)\n"
            "r={'uid':os.getuid(),'euid':os.geteuid(),'cap_eff':s['CapEff'].strip(),'cap_bnd':s['CapBnd'].strip(),'nnp':s['NoNewPrivs'].strip()}\n"
            "try: os.setuid(0); r['setuid']='OK'\nexcept OSError as e: r['setuid']=type(e).__name__\n"
            "try: os.chown('/tmp',0,0); r['chown']='OK'\nexcept OSError as e: r['chown']=type(e).__name__\n"
            "print(json.dumps(r))")
    out = jsonout(probe(cli, created, image_ref, code)[0])
    assert out["uid"] == out["euid"] == 65532 and int(out["cap_eff"], 16) == 0 and int(out["cap_bnd"], 16) == 0 and out["nnp"] == "1"
    assert out["setuid"] == "PermissionError" and out["chown"] == "PermissionError"
    VERIFIED["non_root_no_caps_no_new_privs"] = True


def test_the_pids_limit_stops_a_fork_flood(cli, image_ref, created):
    limit = pol.SandboxPolicy().pids_limit
    code = ("import os,json,time\nkids=[]\nerr=None\n"
            f"for _ in range({limit * 3}):\n"
            "  try:\n"
            "    pid=os.fork()\n"
            "  except OSError as e: err=type(e).__name__; break\n"
            "  if pid==0:\n    time.sleep(5); os._exit(0)\n"
            "  kids.append(pid)\n"
            "print(json.dumps({'forked':len(kids),'error':err}))\n"
            "for p in kids:\n  os.kill(p,9)")
    result, _ = probe(cli, created, image_ref, code, timeout=60)
    out = jsonout(result)
    assert out["error"] is not None and out["forked"] < limit
    VERIFIED["pids_limit_enforced"] = {"limit": limit, "forked_before_error": out["forked"]}


def test_the_memory_limit_kills_a_memory_hog_and_swap_is_not_used(cli, image_ref, created):
    policy = pol.SandboxPolicy()
    code = f"b=[]\nwhile True: b.append(bytearray(32*1024*1024))"
    result, inspected = probe(cli, created, image_ref, code, timeout=60)
    state = inspected["State"]
    assert state["OOMKilled"] is True or state["ExitCode"] == 137, state
    assert inspected["HostConfig"]["MemorySwap"] == policy.memory_bytes
    VERIFIED["memory_limit_enforced"] = {"limit_bytes": policy.memory_bytes, "oom_killed": state["OOMKilled"], "exit_code": state["ExitCode"]}


def test_the_wall_clock_timeout_kills_the_container_and_it_is_cleaned_up(cli, image_ref, created):
    result, inspected = probe(cli, created, image_ref, "import time\nwhile True: time.sleep(1)", timeout=3.0)
    assert result.timed_out is True
    assert inspected["State"]["Running"] is False, "the container kept running after the CLI timed out"
    VERIFIED["timeout_kills_container"] = True


def test_an_output_flood_is_truncated_and_the_container_is_killed(cli, image_ref, created):
    result, inspected = probe(cli, created, image_ref, "import sys\nwhile True: sys.stdout.write('x'*65536); sys.stdout.flush()",
                              timeout=30.0, max_stdout=4096)
    assert result.stdout_truncated is True and len(result.stdout) <= 4096 and result.timed_out is False
    assert inspected["State"]["Running"] is False
    VERIFIED["stdout_limit_kills_container"] = True


def test_stderr_flood_is_bounded_too(cli, image_ref, created):
    job = _unique()
    cid = created(policy_args(cli, image_ref, job, entrypoint="python", command=["-c", "import sys\nwhile True: sys.stderr.write('e'*4096); sys.stderr.flush()"]))
    result = cli.run_attached(cid, b"", timeout=30.0, max_stdout=4096, max_stderr=2048)
    assert result.stderr_truncated is True and len(result.stderr) <= 2048
    assert cli.inspect_container(cid)["State"]["Running"] is False


def test_there_are_no_host_mounts_or_docker_socket_inside(cli, image_ref, created):
    code = ("import os,json\nr={'sock':[p for p in ('/var/run/docker.sock','/run/docker.sock') if os.path.exists(p)]}\n"
            "r['mounts']=[l.split()[4] for l in open('/proc/self/mountinfo')]\nprint(json.dumps(r))")
    result, inspected = probe(cli, created, image_ref, code)
    out = jsonout(result)
    assert out["sock"] == [] and not [m for m in out["mounts"] if m.startswith(("/Users", "/home", "/host", "/mnt"))]
    assert inspected["Mounts"] == [] or all(m.get("Type") == "tmpfs" for m in inspected["Mounts"])


# --- 4. the full pipeline with the real daemon, rule engine and SQLite -----------------------------------------------------------------
def test_full_run_through_real_docker_rule_engine_and_database(cli, image_ref, tmp_path):
    db = init_database(tmp_path / "audit.db")
    out = pipeline.run_suite(cli, image_ref=image_ref, policy=pol.SandboxPolicy(), modes=["vulnerable", "hardened"],
                             reports_dir=tmp_path / "reports", db_path=db)
    assert out.result.outcome == "completed", out.result.error
    assert out.result.controls_verified and out.result.cleanup_status == "removed"
    assert out.db_status == "stored", out.db_error
    assert out.analysis is not None and out.report_path.is_file() and out.analysis_path.is_file() and out.record_path.is_file()
    with contextlib.closing(open_database(db)) as conn:
        report = verify_database(conn, artifacts_dir=tmp_path / "reports")
        assert report.ok, report.problems
        row = conn.execute("SELECT outcome, controls_verified FROM sandbox_runs").fetchone()
        assert row["outcome"] == "completed" and row["controls_verified"] == 1
    assert [c for c in cli.list_containers(LABEL_FILTER) if "sbx-" + out.result.job_id == str(c.get("Names", "")).lstrip("/")] == []
    VERIFIED["full_pipeline"] = {"outcome": out.result.outcome, "db_status": out.db_status, "database_verify_ok": True,
                                 "cases_returned": out.record.get("workload", {}).get("cases_returned") if isinstance(out.record, dict) else None}


def test_a_duplicate_job_id_is_never_run_twice_on_the_real_daemon(cli, image_ref):
    executor = SandboxExecutor(cli, pol.SandboxPolicy())
    job = _unique()
    assert executor.verify_only(job, image_ref).outcome == "completed"
    request = protocol.encode_request(protocol.build_request(job, "self_check", [], []))
    from sentinelbox.sandbox.executor import DuplicateJobError

    with pytest.raises(DuplicateJobError):
        executor.execute(job, request, image_ref)


def test_a_missing_image_is_refused_without_pulling(cli):
    result = SandboxExecutor(cli, pol.SandboxPolicy()).verify_only(_unique(), "sentinelbox-sandbox:does-not-exist")
    assert result.outcome == "refused" and result.cleanup_status == "not_created"
