"""Tests for evidence-first telemetry and the controlled command gateway."""
from __future__ import annotations

from ai_cyber_os import command_gateway, telemetry


def test_telemetry_emits_real_event_snapshot():
    telemetry.reset()
    telemetry.begin("test", phase="phase1")
    telemetry.complete("test", success=True, phase="phase1", evidence={"verified": True})
    data = telemetry.snapshot()
    assert len(data["events"]) == 2
    assert data["events"][-1]["status"] == "PASS"
    assert data["events"][-1]["evidence"] == {"verified": True}
    assert data["run"]["active"] is False


def test_command_gateway_allows_only_controlled_operations():
    calls = []

    def run_phase(phase, hardening):
        calls.append(("run", phase, hardening))
        return {"success": True, "phase": phase}

    out = command_gateway.execute(
        "run phase 7",
        run_phase=run_phase,
        search=lambda q: {"query": q},
        status=lambda: {"runtime": "online"},
        regression=lambda: {"success": True},
        red_team=lambda: {"success": True},
    )
    assert out["action"] == "run_phase"
    assert calls == [("run", "phase7", False)]


def test_command_gateway_rejects_shell_like_input():
    try:
        command_gateway.execute(
            "python -c 'print(1)'",
            run_phase=lambda *_: {},
            search=lambda *_: {},
            status=lambda: {},
            regression=lambda: {},
            red_team=lambda: {},
        )
    except ValueError as exc:
        assert "unsupported command" in str(exc)
    else:
        raise AssertionError("arbitrary command was accepted")
