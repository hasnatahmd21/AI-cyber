"""Regression coverage for canonical CLI defence wiring."""
from __future__ import annotations

import ai_cyber_os.__main__ as cli
import ai_cyber_os._defence as defence


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
        lambda argv=None: events.append(("runtime", list(argv or [])) or 0),
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
