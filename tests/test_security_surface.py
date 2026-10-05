from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CANONICAL_ROOT = REPO_ROOT / "src" / "ai_cyber_os"

FORBIDDEN_IMPORT_ROOTS = {"subprocess", "socket", "requests"}
FORBIDDEN_CALLS = {
    ("os", "system"), ("os", "popen"),
    ("subprocess", "run"), ("subprocess", "Popen"),
    ("subprocess", "call"), ("subprocess", "check_call"),
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

def test_canonical_runtime_has_no_live_execution_escape_hatches():
    violations: list[str] = []
    for path in sorted(CANONICAL_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".", 1)[0] in FORBIDDEN_IMPORT_ROOTS:
                        violations.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}: import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                if (node.module or "").split(".", 1)[0] in FORBIDDEN_IMPORT_ROOTS:
                    violations.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}: from {node.module} import ...")
            elif isinstance(node, ast.Call):
                name = _dotted_name(node.func)
                if name in FORBIDDEN_BUILTINS:
                    violations.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}: {name}(...)")
                elif name and len(name.split(".")) == 2 and tuple(name.split(".")) in FORBIDDEN_CALLS:
                    violations.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}: {name}(...)")
    assert not violations, "forbidden live-execution surface found:\n" + "\n".join(violations)
