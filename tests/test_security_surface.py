from __future__ import annotations

import ast
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
CANONICAL_ROOT = REPO_ROOT / "src" / "ai_cyber_os"
SANCTIONED_EXECUTION_MODULE = CANONICAL_ROOT / "commands.py"

# Hardened component surface introduced/verified by the staged architecture.
# The monolithic HYDRA file contains preserved historical/forensic phase code
# and is covered by its own runtime verification rather than this AST policy.
SCANNED_MODULES = {
    "api.py",
    "backend.py",
    "commands.py",
    "knowledge.py",
    "relationships.py",
    "security_families.py",
    "situation.py",
}

FORBIDDEN_IMPORT_ROOTS = {
    "subprocess",
    "socket",
    "requests",
}
FORBIDDEN_CALLS = {
    ("os", "system"),
    ("os", "popen"),
    ("subprocess", "run"),
    ("subprocess", "Popen"),
    ("subprocess", "call"),
    ("subprocess", "check_call"),
    ("subprocess", "check_output"),
}
FORBIDDEN_BUILTINS = {"eval", "exec"}


def _dotted_name(node: ast.AST) -> str | None:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))
    return None


def _is_sanctioned(path: Path) -> bool:
    return path.resolve() == SANCTIONED_EXECUTION_MODULE.resolve()


def _has_constant_keyword(call: ast.Call, key: str, expected: object) -> bool:
    for keyword in call.keywords:
        if keyword.arg != key:
            continue
        return isinstance(keyword.value, ast.Constant) and keyword.value.value == expected
    return False


def test_hardened_component_surface_has_no_uncontrolled_execution_escape_hatches():
    violations: list[str] = []

    for filename in sorted(SCANNED_MODULES):
        path = CANONICAL_ROOT / filename
        if not path.is_file():
            violations.append(f"missing hardened module: {filename}")
            continue

        sanctioned = _is_sanctioned(path)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".", 1)[0]
                    if root in FORBIDDEN_IMPORT_ROOTS and not sanctioned:
                        violations.append(
                            f"{path.relative_to(REPO_ROOT)}:{node.lineno}: import {alias.name}"
                        )

            elif isinstance(node, ast.ImportFrom):
                root = (node.module or "").split(".", 1)[0]
                if root in FORBIDDEN_IMPORT_ROOTS and not sanctioned:
                    violations.append(
                        f"{path.relative_to(REPO_ROOT)}:{node.lineno}: from {node.module} import ..."
                    )

            elif isinstance(node, ast.Call):
                name = _dotted_name(node.func)
                if name in FORBIDDEN_BUILTINS:
                    violations.append(
                        f"{path.relative_to(REPO_ROOT)}:{node.lineno}: {name}(...)"
                    )
                elif name:
                    parts = tuple(name.split("."))
                    if len(parts) == 2 and parts in FORBIDDEN_CALLS:
                        if not sanctioned or name != "subprocess.run":
                            violations.append(
                                f"{path.relative_to(REPO_ROOT)}:{node.lineno}: {name}(...)"
                            )
                        elif not (
                            _has_constant_keyword(node, "shell", False)
                            and _has_constant_keyword(node, "capture_output", True)
                            and any(k.arg == "timeout" for k in node.keywords)
                        ):
                            violations.append(
                                f"{path.relative_to(REPO_ROOT)}:{node.lineno}: "
                                "sanctioned subprocess.run lacks required controls"
                            )

    assert not violations, "uncontrolled execution surface found:\n" + "\n".join(violations)
