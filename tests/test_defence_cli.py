"""Regression coverage for canonical CLI defence wiring."""
from __future__ import annotations

import importlib

import ai_cyber_os.__main__ as cli

# Use the canonical module in sys.modules; the production CLI resolves this module
# lazily before dispatch so its guard cannot be bypassed by stale aliases.
defence = importlib.import_module("ai_cyber_os._defence")


def test_cli_enforces_once_before_hydra_and_strips_control_flags(monkeypatch):
    events = []

    monkeypatch.setattr(
        defence,
        "enforce",
        lambda argv=None: events.append(("enforce", list(argv or []))),
    )
    monkeypatch.setattr(defence, "release", lambda: events.append(("release", None)))
    monkeypatch.setattr(
        cli,
        "_main_impl",
        lambda argv=None: (events.append(("runtime", list(argv or []))) or 0),
    )

    result = cli.main(["--defence-restore", "--phase", "phase1"])

    assert result == 0
    assert events == [
        ("enforce", ["--defence-restore", "--phase", "phase1"]),
        ("runtime", ["--phase", "phase1"]),
        ("release", None),
    ]


def test_json_cli_keeps_defence_diagnostics_off_stdout(monkeypatch, capsys):
    from ai_cyber import secured

    def fake_enforce(argv=None, *, root=None, out=print):
        out("integrity: OK")
        return 0

    monkeypatch.setattr(secured, "enforce", fake_enforce)

    defence.enforce(["--json"])
    captured = capsys.readouterr()

    assert captured.out == ""
    assert "integrity: OK" in captured.err

def test_malicious_cli_arguments_block_before_runtime(monkeypatch, tmp_path):
    import subprocess

    from ai_cyber import secured

    root = tmp_path
    target = root / "src" / "ai_cyber_os"
    target.mkdir(parents=True)
    (target / "__init__.py").write_text("", encoding="utf-8")
    (target / "protected.py").write_text("TRUSTED = True\\n", encoding="utf-8")

    def git(*args):
        subprocess.run(
            ["git", "-C", str(root), "-c", "user.email=test@example.com",
             "-c", "user.name=Test", *args],
            check=True, capture_output=True,
        )

    git("init", "-q")
    git("add", "-A")
    git("commit", "-qm", "trusted baseline source")

    monkeypatch.setattr(defence, "enforce", lambda argv=None: secured.enforce(argv, root=str(root)))
    monkeypatch.setattr(defence, "release", lambda: setattr(secured, "ACTIVE", False))
    called = []
    monkeypatch.setattr(cli, "_main_impl", lambda argv=None: called.append(list(argv or [])) or 0)
    monkeypatch.setattr(secured, "ACTIVE", False)

    try:
        cli.main(["; rm " + "-rf /"])
        assert False, "malicious CLI input must be blocked"
    except SystemExit as exc:
        assert exc.code == 3
    assert called == []
    assert (root / ".ai_cyber" / "hydra_baseline.json").is_file()
