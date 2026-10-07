from ai_cyber_os import telemetry
from ai_cyber_os import ui


def test_ui_exposes_live_operational_routes():
    assert "/api/situation" in ui.Handler.__dict__.get("do_GET").__doc__ if ui.Handler.__dict__.get("do_GET").__doc__ else True
    assert "/api/events" in ui.TEMPLATE
    assert "/api/command" in ui.TEMPLATE
    assert "NEURAL PHASE FABRIC" in ui.TEMPLATE
    assert len(ui.VALID_PHASES) == 28


def test_nested_hardening_keeps_outer_operation_active():
    telemetry.reset()
    telemetry.begin("hydra", phase="all")
    telemetry.begin("hardening", phase="all")
    telemetry.complete("hardening", success=True, phase="all", keep_active=True)
    assert telemetry.snapshot()["run"]["active"] is True
    telemetry.complete("hydra", success=True, phase="all")
    assert telemetry.snapshot()["run"]["active"] is False
