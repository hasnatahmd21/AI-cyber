from __future__ import annotations

import subprocess
import sys


def test_module_entrypoint_runs():
    result = subprocess.run(
        [sys.executable, "-m", "ai_cyber_os", "--phase", "all", "--json"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert '"phase_result"' in result.stdout
    assert '"success": true' in result.stdout


def test_console_entrypoint_is_declared():
    from pathlib import Path

    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")
    assert "[project.scripts]" in text
    assert 'ai-cyber = "ai_cyber_os.__main__:main"' in text
