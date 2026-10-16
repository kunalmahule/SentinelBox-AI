"""Static guards that keep the runner independent of the mock's internals and offline-safe."""

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1] / "sentinelbox"
RUNNER_FILES = sorted((ROOT / "runner").glob("*.py"))
MOCK_FILES = sorted((ROOT / "mock_ai").glob("*.py"))

# Names the runner must never read or write: they are the mock's ground-truth metadata.
FORBIDDEN_NAMES = {"meta", "matched_rule", "scenario", "scenarios", "deterministic", "canary_token", "fake_api_key"}
NETWORK_MODULES = {"urllib", "socket", "http", "ssl", "requests", "httpx", "httpx2", "aiohttp", "urllib3"}


def imports_of(source: str) -> list[tuple[int, str]]:
    """(relative level, dotted module) for every import; ``from . import x`` yields module 'x'."""
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found += [(0, alias.name) for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                found.append((node.level, node.module))
            else:
                found += [(node.level, alias.name) for alias in node.names]
    return found


def forbidden_identifiers(source: str) -> set[str]:
    """Forbidden names appearing as identifiers, attributes, keyword args or non-docstring string literals."""
    tree = ast.parse(source)
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
                docstrings.add(id(body[0].value))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.keyword) and node.arg:
            names.add(node.arg)
        elif isinstance(node, ast.arg):
            names.add(node.arg)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings:
            names.add(node.value)
    return {n for n in names if n.lower() in FORBIDDEN_NAMES}


def touches_mock_ai(level: int, module: str) -> bool:
    parts = module.split(".")
    return "mock_ai" in parts or (level > 0 and parts[0] == "mock_ai")


# --- the scanners themselves must actually detect violations ---------------------------
def test_scanner_detects_mock_imports_and_metadata_access():
    assert any(touches_mock_ai(*i) for i in imports_of("from sentinelbox.mock_ai.engine import respond"))
    assert any(touches_mock_ai(*i) for i in imports_of("import sentinelbox.mock_ai"))
    assert any(touches_mock_ai(*i) for i in imports_of("from ..mock_ai import scenarios"))
    assert any(touches_mock_ai(*i) for i in imports_of("from .. import mock_ai"))
    assert forbidden_identifiers("x = data['meta']") == {"meta"}
    assert forbidden_identifiers("x = response.meta.scenario") == {"meta", "scenario"}
    assert forbidden_identifiers("f(matched_rule=1)") == {"matched_rule"}
    assert forbidden_identifiers('"""the meta field"""\nx = 1') == set()  # docstrings are prose, not code


# --- the real guards ---------------------------------------------------------------------
def test_runner_package_exists():
    assert {p.name for p in RUNNER_FILES} >= {"runner.py", "transport.py", "library.py", "report.py", "cli.py", "models.py"}


@pytest.mark.parametrize("path", RUNNER_FILES, ids=lambda p: p.name)
def test_runner_never_imports_the_mock_ai_package(path):
    assert not [i for i in imports_of(path.read_text(encoding="utf-8")) if touches_mock_ai(*i)]


@pytest.mark.parametrize("path", MOCK_FILES, ids=lambda p: p.name)
def test_mock_ai_never_imports_the_runner(path):
    assert not [m for lvl, m in imports_of(path.read_text(encoding="utf-8")) if "runner" in m.split(".")]


@pytest.mark.parametrize("path", RUNNER_FILES, ids=lambda p: p.name)
def test_runner_code_never_touches_scenario_metadata(path):
    assert forbidden_identifiers(path.read_text(encoding="utf-8")) == set()


@pytest.mark.parametrize("path", RUNNER_FILES, ids=lambda p: p.name)
def test_only_the_transport_module_uses_network_libraries(path):
    used = {m.split(".")[0] for _, m in imports_of(path.read_text(encoding="utf-8"))} & NETWORK_MODULES
    if path.name == "transport.py":
        assert used == {"urllib"}  # stdlib only; no third-party HTTP client
    else:
        assert not used


def test_no_ai_client_libraries_are_used_anywhere_in_the_runner():
    banned = {"openai", "anthropic", "cohere", "mistralai", "groq", "ollama", "litellm", "google"}
    for path in RUNNER_FILES:
        assert not {m.split(".")[0] for _, m in imports_of(path.read_text(encoding="utf-8"))} & banned


def test_runner_has_no_third_party_dependencies():
    stdlib_or_local = set(__import__("sys").stdlib_module_names) | {"sentinelbox"}
    for path in RUNNER_FILES:
        for level, module in imports_of(path.read_text(encoding="utf-8")):
            if level == 0:
                assert module.split(".")[0] in stdlib_or_local, f"{path.name} imports {module}"
