"""Tests that keep Stage 1 local and safe: no network, no external AI clients."""

import ast
import pathlib
import socket

import pytest

from sentinelbox.mock_ai.app import create_app

PACKAGE_DIR = pathlib.Path(__file__).resolve().parents[1] / "sentinelbox"

# Modules that would let the mock reach a network or an external AI service.
FORBIDDEN_IMPORTS = {
    "openai", "anthropic", "google", "cohere", "mistralai", "groq", "ollama", "litellm",
    "requests", "httpx", "httpx2", "aiohttp", "urllib3", "websockets", "socket", "ssl",
    "http", "ftplib", "smtplib", "subprocess",
}


def imported_top_level_modules(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            found.add(node.module.split(".")[0])
    return found


def test_package_has_python_sources():
    assert list(PACKAGE_DIR.rglob("*.py"))


@pytest.mark.parametrize("path", sorted(PACKAGE_DIR.rglob("*.py")), ids=lambda p: p.name)
def test_package_imports_no_network_or_external_ai_modules(path):
    allowed = STAGE5_EXEMPTIONS.get(path.relative_to(PACKAGE_DIR).as_posix(), set())
    assert not ((imported_top_level_modules(path) & FORBIDDEN_IMPORTS) - allowed)


# Stage 5 (sandbox): exactly two modules need one otherwise-forbidden import each, for a documented reason.
# Nothing else is exempt, and each exemption names the single module it permits.
STAGE5_EXEMPTIONS = {
    "sandbox/docker_cli.py": {"subprocess"},  # the ONLY module that starts the `docker` client (argument lists, no shell)
    "sandbox_workload/selfcheck.py": {"socket"},  # runs inside the no-network container to probe that it has no network
}


def test_the_stage5_exemptions_are_narrow_and_in_use():
    for rel, modules in STAGE5_EXEMPTIONS.items():
        path = PACKAGE_DIR / rel
        assert path.is_file()
        assert imported_top_level_modules(path) & FORBIDDEN_IMPORTS == modules
    assert sum(len(m) for m in STAGE5_EXEMPTIONS.values()) == 2


def test_network_guard_is_active():
    # Proves the autouse fixture really blocks outbound connections.
    with pytest.raises(RuntimeError, match="Network access is blocked"):
        socket.create_connection(("example.com", 80), timeout=1)
    with pytest.raises(RuntimeError, match="Network access is blocked"):
        socket.getaddrinfo("example.com", 80)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        with pytest.raises(RuntimeError, match="Network access is blocked"):
            sock.connect(("127.0.0.1", 9))


def test_app_exposes_only_the_documented_routes():
    paths = {route.path for route in create_app().routes}
    documented = {"/health", "/scenarios", "/chat"}
    assert documented <= paths
    # Anything else must be FastAPI's built-in documentation routes.
    assert paths - documented <= {"/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"}
