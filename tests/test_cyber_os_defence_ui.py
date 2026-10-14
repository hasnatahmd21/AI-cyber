"""Contract tests for the primary CYBER OS live command centre."""
from __future__ import annotations

from ai_cyber_os import ui


def test_primary_ui_is_the_3d_cyber_os_console() -> None:
    assert ui.TEMPLATE_PATH.name == "CYBER_OS_defence.html"
    assert ui.TEMPLATE_PATH.is_file()
    html = ui.TEMPLATE
    for marker in (
        "DATA FABRIC // EVIDENCE + PROVENANCE",
        "WHOLE PROJECT // LIVE STATE",
        "HYDRA // 27 PHASES",
        "/api/live/summary",
        "/api/events",
        "/api/command",
        "/api/knowledge",
    ):
        assert marker in html
    # The old simulated dashboard controls and fabricated headline counters are not live UI.
    for marker in ("RUN SAMPLE REQUEST", "root@cyber:~#", "NODES <span id=\"n\">4096"):
        assert marker not in html


def test_live_summary_exposes_evidence_backed_component_contract() -> None:
    bundle = ui._live_status_bundle()
    assert bundle["success"] is True
    assert {"project", "defence", "hydra", "data_fabric", "telemetry"} <= bundle.keys()

    components = bundle["defence"]["components"]
    assert {
        "integrity",
        "barrier",
        "l1",
        "l2",
        "l3",
        "iso",
        "regen",
        "crypto",
        "hydra",
        "fabric",
        "project",
    } <= components.keys()

    assert len(bundle["hydra"]["phases"]) == 27
    fabric = bundle["data_fabric"]
    assert isinstance(fabric.get("manifests"), list)
    assert fabric.get("manifest_count") == len(fabric["manifests"])
    assert isinstance(bundle["telemetry"].get("events"), list)
