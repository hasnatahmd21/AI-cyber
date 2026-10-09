"""Stage 10 dependency hardening checks."""
from __future__ import annotations

import ast
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_runtime_dependencies_are_minimal_and_declared():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    dependencies = project["dependencies"]

    assert any(item.startswith("pydantic>=") for item in dependencies)
    assert any(item.startswith("pydantic-settings>=") for item in dependencies)
    # cryptography was not imported by the runtime and forced an incompatible
    # downgrade of the preinstalled pyOpenSSL dependency in Kaggle.
    assert not any(item.lower().startswith("cryptography") for item in dependencies)


def test_runtime_source_does_not_import_removed_crypto_dependency():
    source_root = ROOT / "src" / "ai_cyber_os"
    for path in source_root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name.split(".", 1)[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module.split(".", 1)[0]]
            else:
                continue
            assert "cryptography" not in names, f"Unexpected cryptography import in {path}"
