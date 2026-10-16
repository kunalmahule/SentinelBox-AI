"""Building and checking the sandbox image.

The build context is staged from an explicit allowlist of files (never a glob of the repository), so the image can
contain neither the audit database, reports, tests, secrets nor Stage 3/4 code. The image is checked again before
every run: the host trusts the image only after looking at what it declares.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from . import policy
from .docker_client import DockerClient, DockerError

PACKAGE_ROOT = Path(__file__).resolve().parents[1]  # .../sentinelbox
DOCKERFILE = Path(__file__).resolve().parent / "Dockerfile"
IMAGE_REPOSITORY = "sentinelbox-sandbox"
SOURCE_LABEL = "io.sentinelbox.source-sha256"
BASE_LABEL = "io.sentinelbox.base-image"

# Exactly what the workload imports. Anything not listed here cannot end up in the image.
STAGED_FILES = (
    "__init__.py",
    "mock_ai/__init__.py", "mock_ai/engine.py", "mock_ai/scenarios.py",
    "runner/__init__.py", "runner/models.py", "runner/runner.py", "runner/transport.py",
    "sandbox_workload/__init__.py", "sandbox_workload/protocol.py", "sandbox_workload/harness.py",
    "sandbox_workload/selfcheck.py", "sandbox_workload/__main__.py",
)


class ImageError(DockerError):
    """The image is missing, unpinned or does not match what the sandbox requires."""


def source_digest() -> str:
    digest = hashlib.sha256()
    for rel in STAGED_FILES:
        digest.update(rel.encode() + b"\0")
        digest.update((PACKAGE_ROOT / rel).read_bytes())
        digest.update(b"\0")
    digest.update(DOCKERFILE.read_bytes())
    return digest.hexdigest()


def default_tag() -> str:
    return f"{IMAGE_REPOSITORY}:stage5-{source_digest()[:12]}"


@contextmanager
def staged_context() -> Iterator[Path]:
    """A temporary build context with only the allowlisted files and normalised permissions."""
    with tempfile.TemporaryDirectory(prefix="sbx-context-") as tmp:
        root = Path(tmp)
        for rel in STAGED_FILES:
            source = PACKAGE_ROOT / rel
            if not source.is_file() or source.is_symlink():
                raise ImageError(f"cannot stage {rel}: it is missing or a symbolic link")
            target = root / "sentinelbox" / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        for path in root.rglob("*"):
            os.chmod(path, 0o755 if path.is_dir() else 0o644)
        shutil.copyfile(DOCKERFILE, root / "Dockerfile")
        os.chmod(root / "Dockerfile", 0o644)
        yield root


@dataclass(frozen=True)
class BuildResult:
    tag: str
    image_id: str
    already_existed: bool
    base_image: str


def build(client: DockerClient, base_image: str, tag: str | None = None, *, legacy_builder: bool = False) -> BuildResult:
    """Build the sandbox image from a pinned base. Never replaces an existing tag."""
    policy.validate_base_image(base_image)
    tag = tag or default_tag()
    policy.validate_image_reference(tag if "@" in tag or ":" in tag else tag + ":x")
    existing = client.inspect_image(tag)
    if existing is not None:
        labels = (existing.get("Config") or {}).get("Labels") or {}
        if labels.get(SOURCE_LABEL) == source_digest() and labels.get(BASE_LABEL) == base_image:
            return BuildResult(tag, str(existing["Id"]), True, base_image)
        raise ImageError(f"image tag {tag} already exists but was built from different sources or a different base; "
                         "choose another --tag or remove that image yourself (nothing is replaced automatically)")
    with staged_context() as context:
        client.build_image(context, context / "Dockerfile", tag, {"BASE_IMAGE": base_image},
                           {SOURCE_LABEL: source_digest(), BASE_LABEL: base_image}, legacy_builder=legacy_builder)
    built = client.inspect_image(tag)
    if built is None:
        raise ImageError(f"the build finished but image {tag} cannot be found")
    return BuildResult(tag, str(built["Id"]), False, base_image)


@dataclass(frozen=True)
class ResolvedImage:
    ref: str
    image_id: str
    digest: str | None
    env: tuple[str, ...]
    inspect: dict


def _tuple_of_str(value: object) -> tuple[str, ...] | None:
    if value is None:
        return ()
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return tuple(value)
    return None


def check_image(inspected: dict) -> list[str]:
    """Problems with the image's own declarations (empty list = acceptable)."""
    problems: list[str] = []
    image_id = inspected.get("Id")
    if not (isinstance(image_id, str) and policy._IMAGE_ID.match(image_id)):
        problems.append("the image has no usable sha256 id")
    config = inspected.get("Config")
    if not isinstance(config, dict):
        return problems + ["the image has no Config section"]
    labels = config.get("Labels")
    if not (isinstance(labels, dict) and labels.get(policy.IMAGE_LABEL_KEY) == policy.LABEL_VALUE):
        problems.append(f"the image lacks the label {policy.IMAGE_LABEL_KEY}={policy.LABEL_VALUE} (it was not built by `sandbox build`)")
    if _tuple_of_str(config.get("Entrypoint")) != tuple(policy.ENTRYPOINT):
        problems.append(f"the image entry point is {config.get('Entrypoint')!r}, expected {policy.ENTRYPOINT!r}")
    if _tuple_of_str(config.get("Cmd")) not in ((), None):
        problems.append(f"the image sets a default command {config.get('Cmd')!r}; the entry point must receive no arguments")
    if config.get("User") != policy.USER_SPEC:
        problems.append(f"the image user is {config.get('User')!r}, expected the numeric non-root {policy.USER_SPEC!r}")
    if config.get("Volumes"):
        problems.append("the image declares volumes; the sandbox permits none")
    if config.get("ExposedPorts"):
        problems.append("the image exposes ports; the sandbox permits none")
    if _tuple_of_str(config.get("Env")) is None:
        problems.append("the image environment is unreadable")
    if config.get("OnBuild"):
        problems.append("the image has ONBUILD triggers")
    return problems


def resolve_image(client: DockerClient, ref: str) -> ResolvedImage:
    """Look the image up locally (never pulling), check it, and return its immutable id."""
    policy.validate_image_reference(ref)
    inspected = client.inspect_image(ref)
    if inspected is None:
        raise ImageError(f"image {ref} is not present locally; build it with: python -m sentinelbox.sandbox build --base-image <pinned base>")
    problems = check_image(inspected)
    if problems:
        raise ImageError(f"image {ref} was rejected", detail="; ".join(problems))
    digests = inspected.get("RepoDigests") or []
    return ResolvedImage(ref=ref, image_id=inspected["Id"], digest=digests[0] if digests else None,
                         env=_tuple_of_str((inspected.get("Config") or {}).get("Env")) or (), inspect=inspected)
