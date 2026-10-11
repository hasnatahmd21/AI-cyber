from __future__ import annotations

import json
from pathlib import Path

from tools import codespace_start


def _workspace(root: Path) -> Path:
    state = root / ".ai_cyber"
    state.mkdir(parents=True)
    (state / "hydra_baseline.json").write_text("reviewed-baseline", encoding="utf-8")
    (state / "it_tech_baseline.json").write_text("reviewed-it-tech-baseline", encoding="utf-8")
    return state


def test_codespaces_start_never_auto_trusts_missing_baselines(tmp_path, monkeypatch, capsys):
    (tmp_path / ".ai_cyber").mkdir()
    monkeypatch.setattr(
        codespace_start.subprocess,
        "Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not launch")),
    )

    result = codespace_start.start(tmp_path)

    assert result == 2
    message = capsys.readouterr().err
    assert "will not auto-trust/rebaseline source" in message
    assert not (tmp_path / ".ai_cyber" / "hydra_baseline.json").exists()


def test_codespaces_start_refuses_symlinked_state_directory(tmp_path, capsys):
    target = tmp_path / "outside-state"
    target.mkdir()
    (tmp_path / ".ai_cyber").symlink_to(target, target_is_directory=True)

    assert codespace_start.start(tmp_path) == 2
    assert "is a symlink" in capsys.readouterr().err


def test_codespaces_start_does_not_adopt_unverified_pid(tmp_path, monkeypatch, capsys):
    state = _workspace(tmp_path)
    pid_file = state / "codespace-ui.pid"
    pid_file.write_text("4321\n", encoding="ascii")
    monkeypatch.setattr(codespace_start, "_process_exists", lambda _pid: True)
    monkeypatch.setattr(codespace_start, "_is_codespace_watchdog_process", lambda _pid: False)
    monkeypatch.setattr(
        codespace_start.subprocess,
        "Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not launch")),
    )

    assert codespace_start.start(tmp_path) == 2
    assert "unrelated or unverifiable process" in capsys.readouterr().err
    assert pid_file.read_text(encoding="ascii") == "4321\n"


def test_codespaces_start_reuses_only_healthy_managed_process(tmp_path, monkeypatch, capsys):
    state = _workspace(tmp_path)
    (state / "codespace-ui.pid").write_text("4321\n", encoding="ascii")
    monkeypatch.setattr(codespace_start, "_process_exists", lambda _pid: True)
    monkeypatch.setattr(codespace_start, "_is_codespace_watchdog_process", lambda _pid: True)
    monkeypatch.setattr(
        codespace_start,
        "_read_health",
        lambda: {"active": True, "ready": True, "status": "healthy"},
    )
    monkeypatch.setattr(
        codespace_start.subprocess,
        "Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must reuse")),
    )

    assert codespace_start.start(tmp_path) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["already_running"] is True
    assert output["defence"]["status"] == "healthy"


def test_devcontainer_autostarts_ui_without_implicit_rebaseline():
    config_path = Path(__file__).resolve().parents[1] / ".devcontainer" / "devcontainer.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))

    assert config["postCreateCommand"].find("pip install -e .") >= 0
    assert config["postStartCommand"] == "python tools/codespace_start.py"
    assert 8765 in config["forwardPorts"]
    assert config["portsAttributes"]["8765"]["visibility"] == "private"
    assert "--defence-rebaseline" not in config["postCreateCommand"]
    assert "--defence-rebaseline" not in config["postStartCommand"]

def test_watchdog_does_not_restart_ui_while_persistent_latch_is_active(tmp_path, monkeypatch):
    import threading

    from tools import codespace_watchdog

    class StopAfterWait:
        def __init__(self):
            self.stopped = False

        def is_set(self):
            return self.stopped

        def wait(self, _seconds):
            self.stopped = True
            return True

    def forbidden_launch(*_args, **_kwargs):
        raise AssertionError("watchdog must suppress UI launch while incident latch is active")

    monkeypatch.setattr(
        codespace_watchdog, "_incident_reason", lambda _root: "persistent incident latch active"
    )
    monkeypatch.setattr(codespace_watchdog.subprocess, "Popen", forbidden_launch)
    stop = StopAfterWait()

    assert codespace_watchdog.run(tmp_path, stop_event=stop) == 0


def test_watchdog_refuses_symlinked_state_directory(tmp_path, monkeypatch, capsys):
    from tools import codespace_watchdog

    target = tmp_path / "outside-state"
    target.mkdir()
    (tmp_path / ".ai_cyber").symlink_to(target, target_is_directory=True)

    assert codespace_watchdog.run(tmp_path) == 2
    assert "symlinked" in capsys.readouterr().err

