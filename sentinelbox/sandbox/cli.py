"""Command-line interface: ``python -m sentinelbox.sandbox``.

    doctor        check the Docker CLI, daemon, versions and the features the sandbox depends on
    pin-base      print the digest-pinned reference of a base image that is already present locally
    build         build the sandbox image from a pinned base (never replaces an existing tag)
    verify        create the container, verify every control, and remove it WITHOUT starting it
    run           run the synthetic suite in the sandbox, analyse it on the host and store the audit record
    containers    list sandbox containers (label io.sentinelbox.sandbox=1)
    remove-container / remove-image   remove one specifically identified sandbox container / image

Nothing is ever removed or overwritten implicitly.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Sequence
from pathlib import Path

from ..rule_engine.analysis import format_summary as format_analysis
from ..runner.library import DEFAULT_LIBRARY_PATH, LibraryError
from ..runner.models import Category
from ..sandbox_workload import protocol
from ..storage.database import DEFAULT_DB_PATH, StorageError
from ..storage.documents import DocumentError
from . import image as image_mod
from . import pipeline
from . import policy as pol
from .docker_cli import DockerCli
from .docker_client import DockerClient, DockerError, DockerUnavailable, short
from .executor import JobRejected, SandboxExecutor

EXIT_OK = 0
EXIT_SANDBOX_PROBLEM = 1  # the run did not complete (refused, timeout, docker error, workload error ...)
EXIT_USAGE = 2
EXIT_STORAGE_FAILED = 3  # the run completed but the audit database could not store it (files are kept)
EXIT_INTERRUPTED = 130

MIN_SERVER_VERSION = (20, 10)
_VERSION = re.compile(r"^(\d+)\.(\d+)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m sentinelbox.sandbox",
                                     description="Run the synthetic SentinelBox workload in a hardened Docker sandbox.")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("doctor", help="check Docker availability, versions and required features")
    p.add_argument("--image", help="also check this image (default: the image `build` would create)")

    p = sub.add_parser("pin-base", help="print the digest-pinned reference of a locally present base image")
    p.add_argument("--image", required=True, help="a local image such as python:3.13-slim (pull it yourself first)")

    p = sub.add_parser("build", help="build the sandbox image from a pinned base image")
    p.add_argument("--base-image", required=True, help="name@sha256:<digest> or sha256:<image id> (tags are refused)")
    p.add_argument("--tag", help="image tag (default: sentinelbox-sandbox:stage5-<hash of the staged sources>)")
    p.add_argument("--legacy-builder", action="store_true",
                   help="use the classic builder (DOCKER_BUILDKIT=0); needed only when BuildKit cannot resolve a local base")

    p = sub.add_parser("verify", help="create the container, verify every control and remove it without starting it")
    p.add_argument("--image", help="image to verify (default: the image `build` would create)")
    p.add_argument("--self-check", action="store_true",
                   help="then run the self-check job and print what the workload observed from inside (self-reported)")
    _add_limits(p)

    p = sub.add_parser("run", help="run the synthetic adversarial suite inside the sandbox")
    p.add_argument("--mode", choices=["vulnerable", "hardened", "both"], default="both")
    p.add_argument("--category", action="append", choices=[c.value for c in Category])
    p.add_argument("--library", type=Path, default=DEFAULT_LIBRARY_PATH)
    p.add_argument("--image", help="image to run (default: the image `build` would create)")
    p.add_argument("--reports-dir", type=Path, default=pipeline.DEFAULT_REPORTS_DIR)
    group = p.add_mutually_exclusive_group()
    group.add_argument("--db", type=Path, default=DEFAULT_DB_PATH, help="audit database (must already exist; default: %(default)s)")
    group.add_argument("--no-db", action="store_true", help="do not store anything in the audit database")
    _add_limits(p)

    sub.add_parser("containers", help="list sandbox containers")
    p = sub.add_parser("remove-container", help="remove one sandbox container (by name or id); refuses anything not labelled as a sandbox container")
    p.add_argument("container")
    p = sub.add_parser("remove-image", help="remove one sandbox image; refuses images not built by `build` or still used by a container")
    p.add_argument("image")
    return parser


def _add_limits(p: argparse.ArgumentParser) -> None:
    d = pol.SandboxPolicy()
    p.add_argument("--timeout", type=float, default=d.timeout_seconds, help=f"wall-clock limit in seconds (max {pol.MAX_TIMEOUT_SECONDS:g}; default %(default)s)")
    p.add_argument("--memory-mb", type=int, default=d.memory_bytes // 2**20, help=f"memory limit (max {pol.MAX_MEMORY_BYTES // 2**20}; default %(default)s)")
    p.add_argument("--pids", type=int, default=d.pids_limit, help=f"process limit (max {pol.MAX_PIDS}; default %(default)s)")
    p.add_argument("--cpus", type=float, default=d.cpus, help=f"CPU limit (max {pol.MAX_CPUS:g}; default %(default)s)")
    p.add_argument("--tmpfs-mb", type=int, default=d.tmpfs_bytes // 2**20, help=f"/tmp size (max {pol.MAX_TMPFS_BYTES // 2**20}; default %(default)s)")
    p.add_argument("--max-stdout-kb", type=int, default=d.max_stdout_bytes // 1024, help=f"stdout limit (max {pol.MAX_STDOUT_BYTES // 1024}; default %(default)s)")
    p.add_argument("--max-stderr-kb", type=int, default=d.max_stderr_bytes // 1024, help=f"stderr limit (max {pol.MAX_STDERR_BYTES // 1024}; default %(default)s)")


def _policy_from(args) -> pol.SandboxPolicy:
    return pol.validate_policy(pol.SandboxPolicy(
        memory_bytes=args.memory_mb * 2**20, pids_limit=args.pids, cpus=args.cpus, tmpfs_bytes=args.tmpfs_mb * 2**20,
        timeout_seconds=args.timeout, max_stdout_bytes=args.max_stdout_kb * 1024, max_stderr_bytes=args.max_stderr_kb * 1024))


def _parse_version(text: object) -> tuple[int, int] | None:
    match = _VERSION.match(text) if isinstance(text, str) else None
    return (int(match.group(1)), int(match.group(2))) if match else None


# --- commands ---------------------------------------------------------------------------------------------------------------
def cmd_doctor(args, client: DockerClient) -> int:
    ok = True

    def line(level: str, text: str) -> None:
        print(f"[{level}] {text}")

    try:
        versions = client.version_info()
    except DockerUnavailable as exc:
        line("FAIL", str(exc))
        return EXIT_USAGE
    cv = (versions.get("client") or {}).get("Version")
    line("ok", f"Docker CLI {cv or 'version unknown'}")
    server = versions.get("server")
    if not server:
        line("FAIL", "The Docker daemon is not reachable: start Docker Desktop (macOS) or the docker service, then retry. "
                     + (versions.get("error") or ""))
        return EXIT_USAGE
    sv = server.get("Version")
    parsed = _parse_version(sv)
    if parsed is None or parsed < MIN_SERVER_VERSION:
        line("FAIL", f"Docker server {sv} is older than the minimum {MIN_SERVER_VERSION[0]}.{MIN_SERVER_VERSION[1]}; update Docker")
        ok = False
    else:
        line("ok", f"Docker server {sv} (API {server.get('ApiVersion')}, {server.get('Os')}/{server.get('Arch')})")
    info = client.info()
    if info.get("OSType") != "linux":
        line("FAIL", f"the daemon runs {info.get('OSType')!r} containers; the sandbox needs Linux containers")
        ok = False
    for key, what in (("MemoryLimit", "memory limits"), ("SwapLimit", "swap limits (needed for --memory-swap)"),
                      ("CpuCfsQuota", "CPU limits"), ("PidsLimit", "process limits")):
        if info.get(key) is False:
            line("FAIL", f"the daemon reports no support for {what}; the sandbox would refuse to start (controls would not verify)")
            ok = False
    options = info.get("SecurityOptions") or []
    names = " ".join(options) if isinstance(options, list) else str(options)
    line("ok" if "seccomp" in names else "WARN",
         "default seccomp profile available" if "seccomp" in names else
         "no seccomp support reported: the default syscall filter may be absent (this cannot be verified through docker inspect)")
    if "rootless" in names:
        line("ok", "daemon runs rootless")
    line("info", f"runtime {info.get('DefaultRuntime')}, cgroup v{info.get('CgroupVersion')}, storage {info.get('Driver')}, "
                 f"{info.get('Architecture')}, kernel {info.get('KernelVersion')}")
    ref = args.image or image_mod.default_tag()
    try:
        inspected = client.inspect_image(ref)
    except DockerError as exc:
        line("WARN", f"could not look up image {ref}: {exc}")
        inspected = None
    if inspected is None:
        line("WARN", f"image {ref} is not built yet: run `python -m sentinelbox.sandbox pin-base --image <base>` then `... build --base-image <pinned>`")
    else:
        problems = image_mod.check_image(inspected)
        if problems:
            line("FAIL", f"image {ref} would be rejected: " + "; ".join(problems))
            ok = False
        else:
            line("ok", f"image {ref} present ({inspected['Id'][:19]}...) and consistent with the sandbox requirements")
    print("doctor checks the environment only; `verify` checks a real container's controls." if ok else "Fix the FAIL lines above, then run doctor again.")
    return EXIT_OK if ok else EXIT_USAGE


def cmd_pin_base(args, client: DockerClient) -> int:
    inspected = client.inspect_image(args.image)
    if inspected is None:
        print(f"error: image {args.image} is not present locally. Pull it yourself first (docker pull {args.image}); "
              "this tool never pulls images.", file=sys.stderr)
        return EXIT_USAGE
    digests = [d for d in inspected.get("RepoDigests") or [] if isinstance(d, str)]
    if not digests:
        print(f"error: image {args.image} has no repository digest (it was built or imported locally). "
              f"Pin it by image id instead: {inspected.get('Id')}", file=sys.stderr)
        return EXIT_USAGE
    for digest in digests:
        pol.validate_base_image(digest)
        print(digest)
    print(f"Use it with: python -m sentinelbox.sandbox build --base-image {digests[0]}")
    return EXIT_OK


def cmd_build(args, client: DockerClient) -> int:
    result = image_mod.build(client, args.base_image, args.tag, legacy_builder=args.legacy_builder)
    verb = "already exists with identical sources and base (nothing rebuilt)" if result.already_existed else "built"
    print(f"Image {result.tag} {verb}.")
    print(f"  image id: {result.image_id}")
    print(f"  base:     {result.base_image}")
    print("Next: python -m sentinelbox.sandbox verify")
    return EXIT_OK


def _print_controls(result) -> None:
    for c in result.controls:
        print(f"  [{'ok' if c.ok else 'FAIL'}] {c.name}: expected {c.expected}, found {c.actual}")


def cmd_verify(args, client: DockerClient) -> int:
    policy = _policy_from(args)
    ref = args.image or image_mod.default_tag()
    executor = SandboxExecutor(client, policy)
    result = executor.verify_only(pipeline.new_job_id(), ref)
    if result.image:
        print(f"Image {result.image.ref} -> {result.image.image_id}")
    if result.controls:
        _print_controls(result)
    print(f"Docker client {result.docker_client_version}, server {result.docker_server_version}")
    print(f"Cleanup: {result.cleanup_status}" + (f" ({result.cleanup_detail})" if result.cleanup_detail else ""))
    if result.outcome != "completed":
        print(f"REFUSED: {result.error}", file=sys.stderr)
        return EXIT_SANDBOX_PROBLEM
    print(f"All {len(result.controls)} controls verified on a created, never-started container.")
    if args.self_check:
        request = protocol.build_request(pipeline.new_job_id(), "self_check", [], [])
        run = executor.execute(request["job_id"], protocol.encode_request(request), ref)
        if run.outcome != "completed":
            print(f"self-check did not complete: {run.outcome}: {run.error}", file=sys.stderr)
            return EXIT_SANDBOX_PROBLEM
        try:
            response = protocol.parse_response(run.stdout, protocol.parse_request(protocol.encode_request(request)))
        except protocol.ProtocolError as exc:
            print(f"self-check output rejected: {exc}", file=sys.stderr)
            return EXIT_SANDBOX_PROBLEM
        print("Observations from inside the container (SELF-REPORTED, not used for any decision):")
        print(json.dumps({k: v for k, v in response["observations"].items() if k not in ("mounts",)}, indent=2, sort_keys=True))
    return EXIT_OK


def cmd_run(args, client: DockerClient) -> int:
    policy = _policy_from(args)
    modes = ["vulnerable", "hardened"] if args.mode == "both" else [args.mode]
    db_path = None if args.no_db else args.db
    if db_path is not None and not Path(db_path).is_file():
        print(f"error: audit database {db_path} does not exist. Create it with: python -m sentinelbox.storage init --db {db_path} "
              "(or pass --no-db to skip storage)", file=sys.stderr)
        return EXIT_USAGE
    out = pipeline.run_suite(client, image_ref=args.image or image_mod.default_tag(), policy=policy, modes=modes,
                             categories=args.category, library_path=args.library, reports_dir=args.reports_dir, db_path=db_path)
    result = out.result
    print(f"Sandbox run {result.job_id}: {result.outcome}")
    if result.controls:
        print(f"  controls verified before start: {sum(c.ok for c in result.controls)}/{len(result.controls)}")
    if result.outcome != "completed" and result.controls and not result.controls_verified:
        _print_controls(type("R", (), {"controls": [c for c in result.controls if not c.ok]})())
    if result.error:
        print(f"  {short(result.error, 500)}")
    print(f"  cleanup: {result.cleanup_status}" + (f" ({result.cleanup_detail})" if result.cleanup_detail else ""))
    for message in out.messages:
        print(f"  {message}")
    if out.analysis is not None:
        print()
        print(format_analysis(out.analysis, out.analysis_path))
    if db_path is None:
        print("\nAudit database: not requested (--no-db); the files above are the only record.")
    elif out.db_status in ("stored", "already_stored"):
        print(f"\nAudit database {db_path}: sandbox run {result.job_id} {out.db_status.replace('_', ' ')}.")
    else:
        print(f"\nAUDIT DATABASE NOT UPDATED: {out.db_error}", file=sys.stderr)
        print(f"The files above were kept. Store them later with:\n  {out.recovery_command}", file=sys.stderr)
        return EXIT_STORAGE_FAILED
    if result.outcome == "interrupted":
        return EXIT_INTERRUPTED
    return EXIT_OK if result.outcome == "completed" else EXIT_SANDBOX_PROBLEM


def cmd_containers(args, client: DockerClient) -> int:
    rows = client.list_containers(f"{pol.LABEL_KEY}={pol.LABEL_VALUE}")
    if not rows:
        print("No sandbox containers exist.")
        return EXIT_OK
    for row in rows:
        print(f"{row.get('Names')}  {str(row.get('ID', ''))[:12]}  {row.get('State')}  {row.get('Status')}")
    print("Remove one with: python -m sentinelbox.sandbox remove-container <name>")
    return EXIT_OK


def cmd_remove_container(args, client: DockerClient) -> int:
    inspected = client.inspect_container(args.container)
    if inspected is None:
        print(f"error: no container {args.container!r}", file=sys.stderr)
        return EXIT_USAGE
    labels = ((inspected.get("Config") or {}).get("Labels")) or {}
    name = str(inspected.get("Name", "")).lstrip("/")
    if labels.get(pol.LABEL_KEY) != pol.LABEL_VALUE or not name.startswith(pol.NAME_PREFIX):
        print(f"error: {args.container!r} is not a SentinelBox sandbox container (missing label {pol.LABEL_KEY}={pol.LABEL_VALUE} "
              f"or name prefix {pol.NAME_PREFIX}); refusing to remove it", file=sys.stderr)
        return EXIT_USAGE
    client.kill_container(args.container)
    client.remove_container(args.container)
    print(f"Removed container {name}.")
    return EXIT_OK


def cmd_remove_image(args, client: DockerClient) -> int:
    inspected = client.inspect_image(args.image)
    if inspected is None:
        print(f"error: no image {args.image!r}", file=sys.stderr)
        return EXIT_USAGE
    labels = ((inspected.get("Config") or {}).get("Labels")) or {}
    if labels.get(pol.IMAGE_LABEL_KEY) != pol.LABEL_VALUE:
        print(f"error: image {args.image!r} was not built by `sandbox build` (no {pol.IMAGE_LABEL_KEY} label); refusing to remove it",
              file=sys.stderr)
        return EXIT_USAGE
    users = [r for r in client.list_containers(f"{pol.LABEL_KEY}={pol.LABEL_VALUE}") if str(r.get("Image", "")) in (args.image, inspected.get("Id"))]
    if users:
        print(f"error: sandbox container(s) still use this image: {', '.join(str(u.get('Names')) for u in users)}", file=sys.stderr)
        return EXIT_USAGE
    client.remove_image(inspected["Id"] if "@" not in args.image and ":" not in args.image else args.image)
    print(f"Removed image {args.image}.")
    return EXIT_OK


_COMMANDS = {"doctor": cmd_doctor, "pin-base": cmd_pin_base, "build": cmd_build, "verify": cmd_verify, "run": cmd_run,
             "containers": cmd_containers, "remove-container": cmd_remove_container, "remove-image": cmd_remove_image}


def main(argv: Sequence[str] | None = None, client: DockerClient | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _COMMANDS[args.command](args, client or DockerCli())
    except pol.PolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except JobRejected as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except DockerUnavailable as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except DockerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_SANDBOX_PROBLEM
    except (LibraryError, StorageError, DocumentError, protocol.ProtocolError, FileExistsError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EXIT_INTERRUPTED
