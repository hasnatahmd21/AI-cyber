from __future__ import annotations

import json
import shutil
import subprocess
import sys


def _ensure_explicit_test_baseline() -> None:
    root = Path(__file__).resolve().parents[1]
    state = root / ".ai_cyber"
    hydra = state / "hydra_baseline.json"
    it_tech = state / "it_tech_baseline.json"
    if hydra.is_file() and it_tech.is_file():
        return
    if hydra.exists() or it_tech.exists():
        raise AssertionError("incomplete local signing baseline; do not auto-rebaseline test state")
    result = subprocess.run(
        [
            sys.executable, "-m", "ai_cyber_os",
            "--defence-rebaseline", "--phase", "phase1", "--json",
        ],
        cwd=str(root), capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, (
        "explicit test baseline provisioning failed: "
        f"stdout={result.stdout[-1000:]} stderr={result.stderr[-1000:]}"
    )
    assert hydra.is_file() and it_tech.is_file()


def _assert_successful_json(result: subprocess.CompletedProcess[str]) -> dict:
    assert result.returncode == 0, result.stderr
    assert result.stdout.lstrip().startswith("{")
    assert result.stdout.rstrip().endswith("}")
    payload = json.loads(result.stdout)
    phase_result = payload["phase_result"]
    assert phase_result.get("success") is not False
    assert phase_result.get("verified") is not False
    assert phase_result.get("status") not in {"FAIL", "FAILED", "EXCEPTION", "NO_RESULT", "ERROR"}
    assert phase_result.get("failed", 0) in (0, False, [])
    assert phase_result.get("tests_failed", 0) in (0, False, [])
    summary = phase_result.get("summary")
    if isinstance(summary, dict):
        assert summary["success"] is True
    return payload


def test_module_entrypoint_runs():
    _ensure_explicit_test_baseline()
    result = subprocess.run(
        [sys.executable, "-m", "ai_cyber_os", "--phase", "all", "--json"],
        capture_output=True,
        text=True,
        check=False,
    )
    payload = _assert_successful_json(result)
    assert "phase_result" in payload



def test_individual_phase_entrypoint_returns_success():
    _ensure_explicit_test_baseline()
    executable = shutil.which("ai-cyber")
    assert executable is not None, "installed console entrypoint is missing"
    result = subprocess.run(
        [executable, "--phase", "phase1", "--json"],
        capture_output=True,
        text=True,
        check=False,
    )
    payload = _assert_successful_json(result)
    assert payload["phase_result"]["component"] == "nexora_cyber_core"
    assert payload["phase_result"]["verified"] is True


def test_installed_console_entrypoint_runs():
    _ensure_explicit_test_baseline()
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



def test_all_cli_commands_delegate_to_the_secure_runtime(monkeypatch):
    import ai_cyber_os.__main__ as entrypoint
    import ai_cyber_os.secured as secured

    seen = []
    monkeypatch.setattr(secured, "main", lambda argv=None: seen.append(list(argv or [])) or 23)

    assert entrypoint.main(["--phase", "phase1", "--json"]) == 23
    assert entrypoint.main(["demo"]) == 23
    assert entrypoint.main(["entry-points"]) == 23
    assert seen == [
        ["--phase", "phase1", "--json"],
        ["demo"],
        ["entry-points"],
    ]
