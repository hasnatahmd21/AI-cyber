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
        codespace_watchdog, "_restart_block_reason", lambda _root: "persistent incident latch active"
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

def test_codespaces_start_serializes_concurrent_launches(tmp_path, monkeypatch, capsys):
    import fcntl

    _workspace(tmp_path)
    monkeypatch.setattr(
        fcntl,
        "flock",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(BlockingIOError()),
    )
    monkeypatch.setattr(
        codespace_start.subprocess,
        "Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not launch")),
    )

    assert codespace_start.start(tmp_path) == 3
    assert "already running in another process" in capsys.readouterr().err

def test_watchdog_restarts_ui_after_unexpected_exit(tmp_path, monkeypatch, capsys):
    from tools import codespace_watchdog

    class StopAfterThreeWaits:
        def __init__(self):
            self.waits = 0
            self.stopped = False

        def is_set(self):
            return self.stopped

        def wait(self, _seconds):
            self.waits += 1
            if self.waits == 3:
                self.stopped = True
                return True
            return False

    class FakeChild:
        def __init__(self, exit_code):
            self.exit_code = exit_code

        def poll(self):
            return self.exit_code

        def terminate(self):
            if self.exit_code is None:
                self.exit_code = -15

        def wait(self, timeout=None):
            return self.exit_code

        def kill(self):
            self.exit_code = -9

    children = [FakeChild(1), FakeChild(None)]
    launches = []

    def fake_popen(command, **_kwargs):
        launches.append(command)
        return children.pop(0)

    monkeypatch.setattr(codespace_watchdog, "_restart_block_reason", lambda _root: None)
    monkeypatch.setattr(codespace_watchdog.subprocess, "Popen", fake_popen)

    assert codespace_watchdog.run(tmp_path, stop_event=StopAfterThreeWaits()) == 0
    assert len(launches) == 2
    assert launches[0][1:4] == ["-m", "ai_cyber_os.ui", "--no-browser"]
    assert "exited unexpectedly" in capsys.readouterr().out

def test_watchdog_suppresses_restart_when_persisted_audit_is_corrupt(tmp_path, monkeypatch):
    from ai_cyber_os.layered_defense.audit_store import save
    from ai_cyber_os.layered_defense.audit_telemetry import AuditLog
    from ai_cyber_os.layered_defense.supervisor import DefenceSupervisor
    from tools import codespace_watchdog

    state = tmp_path / ".ai_cyber"
    state.mkdir()
    service = DefenceSupervisor(str(tmp_path), interval_s=0.25)
    audit = AuditLog()
    audit.record("trusted prior event")
    path = state / "audit" / "prior.jsonl"
    save(audit, str(path), integrity=service.integrity)
    path.write_text(
        path.read_text(encoding="utf-8").replace("trusted prior event", "forged prior event"),
        encoding="utf-8",
    )

    reason = codespace_watchdog._restart_block_reason(tmp_path)
    assert reason is not None
    assert "persistent audit verification failed" in reason

    class StopAfterWait:
        def is_set(self):
            return False

        def wait(self, _seconds):
            return True

    monkeypatch.setattr(
        codespace_watchdog.subprocess,
        "Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("watchdog must not restart with a corrupt persisted audit")
        ),
    )
    assert codespace_watchdog.run(tmp_path, stop_event=StopAfterWait()) == 0

def test_codespaces_pid_writer_refuses_preexisting_hardlinked_temporary(tmp_path):
    import os
    import pytest

    state = _workspace(tmp_path)
    external = tmp_path / "external.txt"
    external.write_text("preserve me", encoding="utf-8")
    temporary = state / "codespace-ui.pid.tmp"
    try:
        os.link(external, temporary)
    except (OSError, NotImplementedError):
        pytest.skip("hard links are unavailable on this platform")

    with pytest.raises(FileExistsError):
        codespace_start._write_pid(state / "codespace-ui.pid", 1234)
    assert external.read_text(encoding="utf-8") == "preserve me"
    assert not (state / "codespace-ui.pid").exists()

