from __future__ import annotations

import json
import shutil
import subprocess
import sys


def _assert_successful_json(result: subprocess.CompletedProcess[str]) -> dict:
    assert result.returncode == 0, result.stderr
    assert result.stdout.lstrip().startswith("{")
    assert result.stdout.rstrip().endswith("}")
    payload = json.loads(result.stdout)
    assert payload["phase_result"]["summary"]["success"] is True
    return payload


def test_module_entrypoint_runs():
    result = subprocess.run(
        [sys.executable, "-m", "ai_cyber_os", "--phase", "all", "--json"],
        capture_output=True,
        text=True,
        check=False,
    )
    payload = _assert_successful_json(result)
    assert "phase_result" in payload


def test_installed_console_entrypoint_runs():
    executable = shutil.which("ai-cyber")
    assert executable is not None, "installed console entrypoint is missing"
    result = subprocess.run(
        [executable, "--phase", "all", "--hardening", "--json"],
        capture_output=True,
        text=True,
        check=False,
    )
    payload = _assert_successful_json(result)
    assert payload["hardening_result"]["verified"] is True
    assert payload["hardening_result"]["failed"] == 0


def test_console_entrypoint_is_declared():
    from pathlib import Path

    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")
    assert "[project.scripts]" in text
    assert 'ai-cyber = "ai_cyber_os.__main__:main"' in text
