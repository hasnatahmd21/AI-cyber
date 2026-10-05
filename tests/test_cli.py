from __future__ import annotations

import shutil
import subprocess
import sys


def _assert_successful_json(result: subprocess.CompletedProcess[str]) -> None:
    assert result.returncode == 0, result.stderr
    assert '"phase_result"' in result.stdout
    assert '"success": true' in result.stdout


def test_module_entrypoint_runs():
    result = subprocess.run(
        [sys.executable, "-m", "ai_cyber_os", "--phase", "all", "--json"],
        capture_output=True,
        text=True,
        check=False,
    )
    _assert_successful_json(result)
    assert result.stderr or result.stdout.startswith("{")


def test_installed_console_entrypoint_runs():
    executable = shutil.which("ai-cyber")
    assert executable is not None, "installed console entrypoint is missing"
    result = subprocess.run(
        [executable, "--phase", "all", "--hardening", "--json"],
        capture_output=True,
        text=True,
        check=False,
    )
    _assert_successful_json(result)
    assert '"hardening_result"' in result.stdout
    assert '"verified": true' in result.stdout
    assert '"failed": 0' in result.stdout
    assert result.stdout.lstrip().startswith("{")


def test_console_entrypoint_is_declared():
    from pathlib import Path

    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")
    assert "[project.scripts]" in text
    assert 'ai-cyber = "ai_cyber_os.__main__:main"' in text
