from ai_cyber_os import telemetry
from ai_cyber_os import ui
import inspect


def test_ui_exposes_live_operational_routes():
    assert "/api/situation" in inspect.getsource(ui.Handler.do_GET)
    assert "/api/events" in inspect.getsource(ui.Handler.do_GET)
    assert "/api/command" in inspect.getsource(ui.Handler.do_POST)
    assert "/api/events" in ui.TEMPLATE
    assert "/api/command" in ui.TEMPLATE
    assert "CYBER OS // Neural Phase Fabric" in ui.TEMPLATE
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


def test_cyber_os_is_the_only_served_ui_and_live_status_is_wired():
    from pathlib import Path

    source = inspect.getsource(ui.Handler.do_GET)
    assert "/api/live/summary" in source
    assert "/api/data-fabric/status" in source
    assert "/api/hydra/phases" in source
    assert "CYBER_OS_defence.html" in source
    assert 'id="s-fb"' in ui.TEMPLATE
    assert "DATA FABRIC // EVIDENCE + PROVENANCE" in ui.TEMPLATE
    assert "setInterval(ev,700)" not in ui.TEMPLATE
    assert "RUN SAMPLE REQUEST" not in ui.TEMPLATE
    assert not (Path(ui.PROJECT_ROOT) / "src" / "ai_cyber_os" / "ui_template.html").exists()
