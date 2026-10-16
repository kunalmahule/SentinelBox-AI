"""Static guards: the rule engine reads text only and stays independent of the mock and the runner."""

import ast
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1] / "sentinelbox"
ENGINE_FILES = sorted((ROOT / "rule_engine").glob("*.py"))
ENGINE_SOURCES = {p.name: p.read_text(encoding="utf-8") for p in ENGINE_FILES}

# Names the engine must never read or write: the mock's ground-truth metadata and the raw HTTP body.
FORBIDDEN_NAMES = {"meta", "matched_rule", "scenario", "scenarios", "deterministic", "raw_body", "raw_body_truncated",
                   "canary_token", "fake_api_key", "injection_marker", "bypass_marker"}
NETWORK_AND_PROCESS = {"urllib", "socket", "http", "ssl", "requests", "httpx", "httpx2", "aiohttp", "urllib3",
                       "subprocess", "multiprocessing", "ftplib", "smtplib"}
AI_CLIENTS = {"openai", "anthropic", "cohere", "mistralai", "groq", "ollama", "litellm", "google"}


def imports_of(source):
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found += [(0, a.name) for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                found.append((node.level, node.module))
            else:
                found += [(node.level, a.name) for a in node.names]
    return found


def forbidden_identifiers(source):
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
        elif isinstance(node, (ast.keyword, ast.arg)) and (getattr(node, "arg", None)):
            names.add(node.arg)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings:
            names.add(node.value)
    return {n for n in names if n.lower() in FORBIDDEN_NAMES}


def touches(level, module, package):
    parts = module.split(".")
    return package in parts or (level > 0 and parts[0] == package)


# --- the scanners must really detect violations ------------------------------------------------------------
def test_scanner_detects_forbidden_access_and_imports():
    assert forbidden_identifiers("x = record['raw_body']") == {"raw_body"}
    assert forbidden_identifiers("x = body.meta.scenario") == {"meta", "scenario"}
    assert forbidden_identifiers("f(matched_rule=1)") == {"matched_rule"}
    assert forbidden_identifiers('"""about the meta field"""\nx = 1') == set()
    assert any(touches(*i, "mock_ai") for i in imports_of("from sentinelbox.mock_ai import scenarios"))
    assert any(touches(*i, "runner") for i in imports_of("from ..runner.report import validate_report"))
    assert any(touches(*i, "runner") for i in imports_of("from .. import runner"))


# --- the real guards ------------------------------------------------------------------------------------------
def test_engine_package_exists():
    assert {"engine.py", "rules.py", "analysis.py", "metrics.py", "cli.py", "expectations.py"} <= set(ENGINE_SOURCES)


@pytest.mark.parametrize("name", sorted(ENGINE_SOURCES))
def test_engine_imports_nothing_from_mock_ai_or_the_runner(name):
    bad = [i for i in imports_of(ENGINE_SOURCES[name]) if touches(*i, "mock_ai") or touches(*i, "runner")]
    assert bad == []


@pytest.mark.parametrize("name", sorted(ENGINE_SOURCES))
def test_engine_never_touches_meta_scenarios_or_raw_bodies(name):
    assert forbidden_identifiers(ENGINE_SOURCES[name]) == set()


@pytest.mark.parametrize("name", sorted(ENGINE_SOURCES))
def test_engine_uses_no_network_process_or_ai_client_modules(name):
    used = {m.split(".")[0] for _, m in imports_of(ENGINE_SOURCES[name])}
    assert not used & (NETWORK_AND_PROCESS | AI_CLIENTS)


def test_engine_uses_only_the_standard_library_and_itself():
    allowed = set(sys.stdlib_module_names) | {"sentinelbox"}
    for name, source in ENGINE_SOURCES.items():
        for level, module in imports_of(source):
            if level == 0:
                assert module.split(".")[0] in allowed, f"{name} imports {module}"


def test_runner_and_mock_do_not_import_the_engine():
    for package in ("runner", "mock_ai"):
        for path in (ROOT / package).glob("*.py"):
            assert not [i for i in imports_of(path.read_text(encoding="utf-8")) if touches(*i, "rule_engine")], path.name


def test_the_verdict_function_takes_text_and_expected_behavior_only():
    import inspect

    from sentinelbox.rule_engine.engine import evaluate_response
    assert list(inspect.signature(evaluate_response).parameters) == ["response_text", "expected_behavior"]
