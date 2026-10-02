"""Explicit AI Cyber OS component health wiring.

This module does not duplicate security primitives. It verifies that the
canonical package components can be imported together.
"""
from __future__ import annotations
import importlib
from dataclasses import dataclass

@dataclass(frozen=True)
class ComponentHealth:
    name: str
    importable: bool
    error: str | None = None

CANONICAL_COMPONENTS = (
    ("core", "ai_cyber_os.core.hydra_core"),
    ("security", "ai_cyber_os.security.os_security"),
    ("audit", "ai_cyber_os.audit.forensic"),
)

def check_components() -> tuple[ComponentHealth, ...]:
    results: list[ComponentHealth] = []
    for name, module_name in CANONICAL_COMPONENTS:
        try:
            importlib.import_module(module_name)
        except Exception as exc:
            results.append(ComponentHealth(name, False, f"{type(exc).__name__}: {exc}"))
        else:
            results.append(ComponentHealth(name, True))
    return tuple(results)

def assert_healthy() -> None:
    failed = [item for item in check_components() if not item.importable]
    if failed:
        details = "; ".join(f"{item.name}: {item.error}" for item in failed)
        raise RuntimeError(f"AI Cyber OS health check failed: {details}")

if __name__ == "__main__":
    assert_healthy()
    print("AI Cyber OS: all canonical components import successfully.")
