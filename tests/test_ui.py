"""Focused tests for the localhost HYDRA UI boundary."""

from __future__ import annotations

import json
from urllib.request import Request, urlopen

import pytest

from ai_cyber_os import ui


def test_execute_rejects_invalid_phase():
    with pytest.raises(ValueError):
        ui._execute("phase999", False)


def test_execute_uses_canonical_runtime(monkeypatch):
    calls = []

    def fake_phase(phase):
        calls.append(("phase", phase))
        return {"summary": {"success": True, "phases": 27, "auxiliary_checks": 1}}

    def fake_hardening():
        calls.append(("hardening",))
        return {"verified": True, "failed": 0}

    monkeypatch.setattr(ui, "run_hydra_phase", fake_phase)
    monkeypatch.setattr(ui, "run_final_hardening_verification", fake_hardening)

    result = ui._execute("phase1", True)

    assert result["success"] is True
    assert calls == [("phase", "phase1"), ("hardening",)]


def test_ui_rejects_non_local_host():
    with pytest.raises(SystemExit):
        ui.main(["--host", "0.0.0.0"])


def test_handler_home_and_invalid_api(monkeypatch):
    from http.client import HTTPConnection
    from threading import Thread

    server = ui.ThreadingHTTPServer(("127.0.0.1", 0), ui.Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        conn = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        conn.request("GET", "/")
        response = conn.getresponse()
        assert response.status == 200
        assert "AI-CYBER OS — HYDRA Command Center" in response.read().decode()

        conn.request("GET", "/not-found")
        response = conn.getresponse()
        assert response.status == 404
        assert json.loads(response.read())["error"] == "not found"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_ui_does_not_claim_unverified_subsystems():
    assert "DATABASE<br><span class=\"ok\">ONLINE" not in ui.HTML
    assert "EVENT BUS<br><span class=\"ok\">ONLINE" not in ui.HTML
    assert "GOVERNANCE<br><span class=\"ok\">ONLINE" not in ui.HTML
    assert 'names=phases.map(n=>"HYDRA PHASE "+String(n).padStart(2,"0"))' in ui.HTML
