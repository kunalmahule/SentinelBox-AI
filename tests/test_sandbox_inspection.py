"""Fail-closed verification of a created container: every control, deliberately weakened, must be refused."""

import copy

import pytest
from sandbox_fakes import FakeDocker, make_image_inspect, no_real_docker  # noqa: F401

from sentinelbox.sandbox import inspection, policy as pol
from sentinelbox.sandbox.image import ResolvedImage

pytestmark = pytest.mark.usefixtures("no_real_docker")

POLICY = pol.SandboxPolicy()


def resolved(image=None):
    image = image or make_image_inspect()
    return ResolvedImage("x", image["Id"], None, tuple(image["Config"]["Env"]), image)


def created(mutator=None):
    fake = FakeDocker()
    if mutator:
        fake.mutators.append(mutator)
    cid = fake.create_container(pol.build_create_args(POLICY, fake.image["Id"], "j1"))
    return fake.inspect_container(cid)


def setp(path, value):
    def apply(c):
        parts = path.split(".")
        for key in parts[:-1]:
            c = c[key]
        c[parts[-1]] = value
    return apply


def delp(path):
    def apply(c):
        parts = path.split(".")
        for key in parts[:-1]:
            c = c[key]
        del c[parts[-1]]
    return apply


H = "HostConfig."
# control name -> list of (description, mutation that weakens, removes or corrupts the setting)
WEAKENINGS = {
    "image_is_the_verified_image_id": [("other image", setp("Image", "sha256:" + "0" * 64)), ("missing", delp("Image"))],
    "state_is_created_not_started": [("running", setp("State.Status", "running")), ("flag", setp("State.Running", True)),
                                     ("no state", delp("State"))],
    "user_is_numeric_non_root": [("root", setp("Config.User", "root")), ("0:0", setp("Config.User", "0:0")), ("empty", setp("Config.User", "")),
                                 ("uid only", setp("Config.User", "65532")), ("missing", delp("Config.User")), ("named", setp("Config.User", "nobody"))],
    "entry_point_is_fixed": [("shell", setp("Config.Entrypoint", ["sh"])), ("none", setp("Config.Entrypoint", None)),
                             ("extra arg", setp("Config.Entrypoint", [*pol.ENTRYPOINT, "-c"])), ("missing", delp("Config.Entrypoint"))],
    "no_command_override": [("cmd", setp("Config.Cmd", ["id"])), ("missing", delp("Config.Cmd"))],
    "environment_equals_image_environment": [("extra var", setp("Config.Env", [*make_image_inspect()["Config"]["Env"], "AWS_SECRET=x"])),
                                             ("missing var", setp("Config.Env", ["PATH=/bin"])), ("not a list", setp("Config.Env", "A=b")),
                                             ("missing", delp("Config.Env")), ("non strings", setp("Config.Env", [1, 2]))],
    "network_mode_none": [(v, setp(H + "NetworkMode", v)) for v in ("bridge", "host", "default", "container:abc", "", None)]
                         + [("missing", delp(H + "NetworkMode"))],
    "attached_networks_only_none": [("bridge added", setp("NetworkSettings.Networks", {"none": {}, "bridge": {}})), ("bridge only", setp("NetworkSettings.Networks", {"bridge": {}})),
                                    ("empty", setp("NetworkSettings.Networks", {})), ("not a mapping", setp("NetworkSettings.Networks", ["none"])),
                                    ("missing", delp("NetworkSettings.Networks")), ("no settings", delp("NetworkSettings"))],
    "root_filesystem_read_only": [("false", setp(H + "ReadonlyRootfs", False)), ("string", setp(H + "ReadonlyRootfs", "true")),
                                  ("one", setp(H + "ReadonlyRootfs", 1)), ("missing", delp(H + "ReadonlyRootfs"))],
    "capabilities_all_dropped": [("none", setp(H + "CapDrop", None)), ("empty", setp(H + "CapDrop", [])),
                                 ("partial", setp(H + "CapDrop", ["NET_RAW"])), ("lowercase", setp(H + "CapDrop", ["all"])),
                                 ("missing", delp(H + "CapDrop"))],
    "no_capabilities_added": [("sys_admin", setp(H + "CapAdd", ["SYS_ADMIN"])), ("missing", delp(H + "CapAdd"))],
    "not_privileged": [("privileged", setp(H + "Privileged", True)), ("missing", delp(H + "Privileged")), ("string", setp(H + "Privileged", "false"))],
    "security_opt_only_no_new_privileges": [("none", setp(H + "SecurityOpt", None)), ("empty", setp(H + "SecurityOpt", [])),
                                            ("seccomp off", setp(H + "SecurityOpt", ["no-new-privileges", "seccomp=unconfined"])),
                                            ("apparmor off", setp(H + "SecurityOpt", ["no-new-privileges", "apparmor=unconfined"])),
                                            ("label off", setp(H + "SecurityOpt", ["no-new-privileges", "label=disable"])),
                                            ("systempaths", setp(H + "SecurityOpt", ["no-new-privileges", "systempaths=unconfined"])),
                                            ("only seccomp off", setp(H + "SecurityOpt", ["seccomp=unconfined"])),
                                            ("nnp false", setp(H + "SecurityOpt", ["no-new-privileges:false"])),
                                            ("missing", delp(H + "SecurityOpt"))],
    "pids_limit": [("unlimited", setp(H + "PidsLimit", None)), ("zero", setp(H + "PidsLimit", 0)), ("minus one", setp(H + "PidsLimit", -1)),
                   ("higher", setp(H + "PidsLimit", 65)), ("string", setp(H + "PidsLimit", "64")), ("bool", setp(H + "PidsLimit", True)),
                   ("missing", delp(H + "PidsLimit"))],
    "memory_limit_bytes": [("none", setp(H + "Memory", 0)), ("higher", setp(H + "Memory", POLICY.memory_bytes * 2)),
                           ("string", setp(H + "Memory", str(POLICY.memory_bytes))), ("missing", delp(H + "Memory"))],
    "memory_swap_equals_memory_(no_swap)": [("unlimited", setp(H + "MemorySwap", -1)), ("zero", setp(H + "MemorySwap", 0)),
                                            ("double", setp(H + "MemorySwap", POLICY.memory_bytes * 2)), ("missing", delp(H + "MemorySwap"))],
    "cpu_limit_nano_cpus": [("none", setp(H + "NanoCpus", 0)), ("double", setp(H + "NanoCpus", 2_000_000_000)),
                            ("float", setp(H + "NanoCpus", 1e9)), ("missing", delp(H + "NanoCpus"))],
    "oom_killer_not_disabled": [("disabled", setp(H + "OomKillDisable", True))],
    "single_bounded_tmpfs": [("none", setp(H + "Tmpfs", None)), ("huge", setp(H + "Tmpfs", {"/tmp": "rw,noexec,nosuid,nodev,size=99999999999,mode=1777"})),
                             ("exec allowed", setp(H + "Tmpfs", {"/tmp": f"rw,nosuid,nodev,size={POLICY.tmpfs_bytes},mode=1777"})),
                             ("no size", setp(H + "Tmpfs", {"/tmp": "rw,noexec,nosuid,nodev,mode=1777"})),
                             ("second tmpfs", setp(H + "Tmpfs", {"/tmp": f"rw,noexec,nosuid,nodev,size={POLICY.tmpfs_bytes},mode=1777", "/data": "rw"})),
                             ("wrong path", setp(H + "Tmpfs", {"/var/tmp": f"rw,noexec,nosuid,nodev,size={POLICY.tmpfs_bytes},mode=1777"})),
                             ("not a dict", setp(H + "Tmpfs", "/tmp")), ("missing", delp(H + "Tmpfs"))],
    "no_host_bind_mounts": [("bind", setp(H + "Binds", ["/:/host"])), ("socket", setp(H + "Binds", ["/var/run/docker.sock:/var/run/docker.sock"]))],
    "no_mount_entries": [("mount", setp(H + "Mounts", [{"Type": "bind", "Source": "/", "Target": "/h"}]))],
    "no_mounts_reported_by_docker": [("bind", setp("Mounts", [{"Type": "bind", "Source": "/", "Destination": "/h"}])),
                                     ("volume", setp("Mounts", [{"Type": "volume", "Name": "v"}])), ("missing", delp("Mounts"))],
    "no_image_volumes": [("volume", setp("Config.Volumes", {"/data": {}}))],
    "no_volumes_from": [("from", setp(H + "VolumesFrom", ["other"]))],
    "no_devices": [("device", setp(H + "Devices", [{"PathOnHost": "/dev/sda"}])), ("missing", delp(H + "Devices"))],
    "no_device_requests": [("gpu", setp(H + "DeviceRequests", [{"Driver": "nvidia"}]))],
    "no_device_cgroup_rules": [("rule", setp(H + "DeviceCgroupRules", ["c *:* rwm"]))],
    "no_published_ports": [("port", setp(H + "PortBindings", {"80/tcp": [{"HostPort": "80"}]})), ("missing", delp(H + "PortBindings"))],
    "publish_all_ports_off": [("all", setp(H + "PublishAllPorts", True)), ("missing", delp(H + "PublishAllPorts"))],
    "no_exposed_ports": [("port", setp("Config.ExposedPorts", {"80/tcp": {}}))],
    "host_pid_namespace_not_shared": [("host", setp(H + "PidMode", "host")), ("container", setp(H + "PidMode", "container:abc")),
                                      ("missing", delp(H + "PidMode"))],
    "host_uts_namespace_not_shared": [("host", setp(H + "UTSMode", "host")), ("missing", delp(H + "UTSMode"))],
    "user_namespace_default": [("host", setp(H + "UsernsMode", "host")), ("missing", delp(H + "UsernsMode"))],
    "ipc_namespace_private": [("host", setp(H + "IpcMode", "host")), ("shareable", setp(H + "IpcMode", "shareable")),
                              ("container", setp(H + "IpcMode", "container:x")), ("empty", setp(H + "IpcMode", "")),
                              ("missing", delp(H + "IpcMode"))],
    "cgroup_namespace_declared": [("unknown", setp(H + "CgroupnsMode", "weird")), ("missing", delp(H + "CgroupnsMode"))],
    "init_process_enabled": [("off", setp(H + "Init", False)), ("none", setp(H + "Init", None)), ("missing", delp(H + "Init"))],
    "no_restart_policy": [("always", setp(H + "RestartPolicy", {"Name": "always"})), ("on-failure", setp(H + "RestartPolicy", {"Name": "on-failure"})),
                          ("missing", delp(H + "RestartPolicy"))],
    "logging_driver_none": [("json-file", setp(H + "LogConfig", {"Type": "json-file"})), ("missing", delp(H + "LogConfig"))],
    "ulimits_nofile_and_core": [("none", setp(H + "Ulimits", None)),
                                ("big nofile", setp(H + "Ulimits", [{"Name": "nofile", "Soft": 1048576, "Hard": 1048576}, {"Name": "core", "Soft": 0, "Hard": 0}])),
                                ("core dumps", setp(H + "Ulimits", [{"Name": "nofile", "Soft": 256, "Hard": 256}])),
                                ("garbage", setp(H + "Ulimits", ["x"]))],
    "shm_size_bytes": [("default", setp(H + "ShmSize", 67108864)), ("missing", delp(H + "ShmSize"))],
    "no_links": [("link", setp(H + "Links", ["a:b"]))],
    "no_extra_hosts": [("host", setp(H + "ExtraHosts", ["h:1.2.3.4"]))],
    "no_custom_dns": [("dns", setp(H + "Dns", ["8.8.8.8"]))],
    "no_sysctls": [("sysctl", setp(H + "Sysctls", {"net.ipv4.ip_forward": "1"}))],
    "auto_remove_off": [("on", setp(H + "AutoRemove", True)), ("missing", delp(H + "AutoRemove"))],
    "tty_off": [("tty", setp("Config.Tty", True)), ("missing", delp("Config.Tty"))],
    "stdin_open_for_the_job": [("closed", setp("Config.OpenStdin", False)), ("missing", delp("Config.OpenStdin"))],
}

CASES = [(control, label, mutation) for control, items in WEAKENINGS.items() for label, mutation in items]


def test_a_correctly_created_container_passes_every_control():
    results, effective = inspection.verify_container(created(), POLICY, resolved())
    assert inspection.all_ok(results), inspection.failed(results)
    assert effective["network_mode"] == "none" and effective["read_only_rootfs"] is True and effective["cap_drop"] == ["ALL"]
    assert effective["memory_bytes"] == effective["memory_swap_bytes"] == POLICY.memory_bytes and effective["init"] is True


def test_every_control_has_at_least_one_weakening_test():
    names = {r.name for r in inspection.verify_container(created(), POLICY, resolved())[0]}
    assert names == set(WEAKENINGS), f"untested: {sorted(names - set(WEAKENINGS))}; stale: {sorted(set(WEAKENINGS) - names)}"
    assert len(names) >= 45


@pytest.mark.parametrize("control,label,mutation", CASES, ids=[f"{c}:{l}" for c, l, _ in CASES])
def test_a_weakened_or_missing_setting_makes_exactly_that_control_fail(control, label, mutation):
    inspected = created(mutation)
    results, _ = inspection.verify_container(inspected, POLICY, resolved())
    failed = {r.name for r in inspection.failed(results)}
    assert control in failed, f"{control} accepted: {label}"
    assert not inspection.all_ok(results)


@pytest.mark.parametrize("bad", [None, [], "inspect", 7, {"State": "x"}, {"HostConfig": "x", "Config": []}, {}])
def test_unusable_inspect_output_is_refused_without_raising(bad):
    results, _ = inspection.verify_container(bad, POLICY, resolved())
    assert not inspection.all_ok(results)


def test_a_policy_with_other_limits_changes_what_is_expected():
    inspected = created()
    strict = pol.SandboxPolicy(memory_bytes=64 * 2**20)
    results, _ = inspection.verify_container(inspected, strict, resolved())
    assert {"memory_limit_bytes", "memory_swap_equals_memory_(no_swap)"} <= {r.name for r in inspection.failed(results)}


def test_a_different_image_environment_is_detected():
    other = make_image_inspect()
    other["Config"]["Env"] = ["PATH=/bin"]
    results, _ = inspection.verify_container(created(), POLICY, resolved(other))
    assert "environment_equals_image_environment" in {r.name for r in inspection.failed(results)}


def test_results_are_serialisable_records():
    results, effective = inspection.verify_container(created(), POLICY, resolved())
    assert all(set(r.as_dict()) == {"name", "expected", "actual", "ok"} for r in results)
    import json

    json.dumps(effective)
