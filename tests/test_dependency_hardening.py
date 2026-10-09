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

    crypto = next(
        (item.lower() for item in dependencies if item.lower().startswith("cryptography")),
        None,
    )
    assert crypto is not None, "protected_data.py requires cryptography for AES-GCM"
    # pyOpenSSL in the Kaggle runtime requires cryptography >=49,<51. Avoid the
    # old <47 pin, which caused pip to downgrade a compatible preinstalled build.
    assert ">=49" in crypto
    assert "<51" in crypto


def test_runtime_crypto_import_is_backed_by_declared_dependency():
    source_root = ROOT / "src" / "ai_cyber_os"
    crypto_import_found = False

    for path in source_root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name.split(".", 1)[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module.split(".", 1)[0]]
            else:
                continue

            if "cryptography" in names:
                crypto_import_found = True

    dependencies = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["dependencies"]
    assert crypto_import_found, "Expected AES-GCM cryptography import was not found"
    assert any(item.lower().startswith("cryptography>=49,<51") for item in dependencies)
