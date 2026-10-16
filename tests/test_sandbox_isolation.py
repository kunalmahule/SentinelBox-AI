"""Static guards: what the in-container workload may import, and what code in the package may do."""

import ast
from pathlib import Path

from sentinelbox.sandbox import image

ROOT = Path(__file__).resolve().parents[1] / "sentinelbox"
WORKLOAD_STDLIB = {
    "__future__", "collections", "dataclasses", "datetime", "errno", "json", "os", "platform", "re", "socket", "sys",
    "enum", "typing", "math", "hashlib", "itertools", "functools", "string", "textwrap", "time", "uuid", "pathlib",
    "urllib", "ipaddress", "io", "copy", "decimal", "abc", "contextlib", "operator", "random", "base64", "binascii", "unicodedata",
}
FORBIDDEN_IN_WORKLOAD = {"subprocess", "sqlite3", "fastapi", "pydantic", "httpx", "requests", "http", "ctypes", "pickle", "marshal", "shutil", "importlib"}


def parse(path):
    return ast.parse(path.read_text(), filename=str(path))


def absolute_imports(path):
    """Imported module names, with relative imports resolved against the package layout."""
    rel = path.relative_to(ROOT.parent).with_suffix("")
    package = list(rel.parts[:-1]) if rel.name != "__init__" else list(rel.parts[:-1])
    names = set()
    for node in ast.walk(parse(path)):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package[: len(package) - (node.level - 1)]
                module = ".".join(base + ([node.module] if node.module else []))
                names.add(module)
                names.update(f"{module}.{a.name}" for a in node.names)
            else:
                names.add(node.module or "")
    return names


def staged_modules():
    mods = set()
    for rel in image.STAGED_FILES:
        parts = ["sentinelbox", *rel[:-3].split("/")]
        mods.add(".".join(parts[:-1] if parts[-1] == "__init__" else parts))
    return mods


def test_every_staged_file_exists_and_its_internal_imports_are_staged():
    staged = staged_modules()
    for rel in image.STAGED_FILES:
        path = ROOT / rel
        assert path.is_file(), rel
        for name in absolute_imports(path):
            if name.split(".")[0] == "sentinelbox":
                resolved = name
                while resolved and resolved not in staged:
                    resolved = resolved.rpartition(".")[0]
                assert resolved, f"{rel} imports {name}, which is not staged into the image"


def test_staged_files_use_only_allowlisted_standard_library_modules():
    staged = staged_modules()
    for rel in image.STAGED_FILES:
        for name in absolute_imports(ROOT / rel):
            top = name.split(".")[0]
            if top == "sentinelbox" or name == "":
                continue
            assert top in WORKLOAD_STDLIB, f"{rel} imports {name}"
            assert top not in FORBIDDEN_IN_WORKLOAD, f"{rel} imports {name}"
    assert staged


def test_the_image_does_not_contain_storage_rule_engine_or_host_side_code():
    for rel in image.STAGED_FILES:
        assert not rel.startswith(("storage/", "rule_engine/", "sandbox/")), rel
    for rel in image.STAGED_FILES:
        for name in absolute_imports(ROOT / rel):
            assert not name.startswith(("sentinelbox.storage", "sentinelbox.rule_engine", "sentinelbox.sandbox.")), (rel, name)


def test_the_workload_never_produces_verdict_fields():
    for rel in (r for r in image.STAGED_FILES if r.startswith("sandbox_workload/")):
        text = (ROOT / rel).read_text()
        assert "rule_engine" not in text and "classify" not in text


def python_files():
    return [p for p in ROOT.rglob("*.py")]


def test_no_shell_true_eval_exec_or_os_system_anywhere_in_the_package():
    offenders = []
    for path in python_files():
        for node in ast.walk(parse(path)):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Name) and func.id in ("eval", "exec", "compile", "__import__"):
                offenders.append((path.name, func.id, node.lineno))
            if (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id == "os"
                    and func.attr in ("system", "popen", "execv", "execve", "execvp", "spawnv", "fork")):
                offenders.append((path.name, "os." + func.attr, node.lineno))
            for kw in node.keywords:
                if kw.arg == "shell" and not (isinstance(kw.value, ast.Constant) and kw.value.value is False):
                    offenders.append((path.name, "shell", node.lineno))
    assert offenders == []


def test_only_the_docker_cli_module_uses_subprocess():
    users = sorted(p.relative_to(ROOT).as_posix() for p in python_files() if "subprocess" in absolute_imports(p))
    assert users == ["sandbox/docker_cli.py"]


def test_subprocess_is_always_called_with_an_argument_list():
    tree = parse(ROOT / "sandbox" / "docker_cli.py")
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in ("Popen", "run")
             and isinstance(n.func.value, ast.Name) and n.func.value.id == "subprocess"]
    assert calls
    for call in calls:
        first = call.args[0]
        assert not (isinstance(first, ast.Constant) and isinstance(first.value, str))


def test_stage_1_to_3_packages_do_not_import_the_sandbox():
    for package in ("mock_ai", "runner", "rule_engine"):
        for path in (ROOT / package).rglob("*.py"):
            assert not any(n.startswith("sentinelbox.sandbox") for n in absolute_imports(path)), path
