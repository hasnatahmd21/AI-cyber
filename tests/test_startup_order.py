from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import ai_cyber_os.__main__ as cli


ROOT = Path(__file__).resolve().parents[1]


def test_package_and_cli_import_do_not_eagerly_load_hydra():
    code = """
import sys
import ai_cyber_os
assert 'ai_cyber_os.hydra' not in sys.modules
assert 'ai_cyber_os.intelligence_hydra' not in sys.modules
import ai_cyber_os.__main__
assert 'ai_cyber_os.hydra' not in sys.modules
assert 'ai_cyber_os.intelligence_hydra' not in sys.modules
"""
    env = {
        **os.environ,
        "PYTHONPATH": os.pathsep.join(
            [str(ROOT / "src"), os.environ.get("PYTHONPATH", "")]
        ).rstrip(os.pathsep),
    }
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_main_enforces_before_first_runtime_call(monkeypatch):
    events = []
    fake_defence = ModuleType("ai_cyber_os._defence")
    fake_defence.enforce = lambda argv=None: events.append(("enforce", list(argv or [])))
    fake_defence.release = lambda: events.append(("release", None))
    monkeypatch.setitem(sys.modules, "ai_cyber_os._defence", fake_defence)
    monkeypatch.setattr(cli, "run_hydra_phase", lambda name: (events.append(("runtime", name)) or {
        "success": True, "summary": {"success": True, "phases": 1}
    }))
    monkeypatch.setattr(
        cli,
        "run_final_hardening_verification",
        lambda: {"verified": True, "failed": 0},
    )
    monkeypatch.setattr(
        cli,
        "run_all_extended",
        lambda: {"summary": {"success": True}},
    )

    result = cli.main(["--phase", "phase1", "--json"])

    assert result == 0
    assert events == [
        ("enforce", ["--phase", "phase1", "--json"]),
        ("runtime", "phase1"),
        ("release", None),
    ]
