from ai_cyber_os import telemetry
from ai_cyber_os import ui
import inspect


def test_ui_exposes_live_operational_routes():
    assert "/api/situation" in inspect.getsource(ui.Handler.do_GET)
    assert "/api/events" in inspect.getsource(ui.Handler.do_GET)
    assert "/api/command" in inspect.getsource(ui.Handler.do_POST)
    assert "/api/events" in ui.TEMPLATE
    assert "/api/command" in ui.TEMPLATE
    assert "NEURAL PHASE FABRIC" in ui.TEMPLATE
    assert len(ui.VALID_PHASES) == 28
    assert ui.VALID_PHASES == {"all", *{f"phase{i}" for i in range(1, 28)}}


def test_nested_hardening_keeps_outer_operation_active():
    telemetry.reset()
    telemetry.begin("hydra", phase="all")
    telemetry.begin("hardening", phase="all")
    telemetry.complete("hardening", success=True, phase="all", keep_active=True)
    assert telemetry.snapshot()["run"]["active"] is True
    telemetry.complete("hydra", success=True, phase="all")
    assert telemetry.snapshot()["run"]["active"] is False
