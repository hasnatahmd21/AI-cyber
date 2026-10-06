"""Focused tests for the localhost HYDRA UI boundary."""

from __future__ import annotations

import json

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
        assert "27 PHASE MATRIX" in response.read().decode()

        conn.request("GET", "/not-found")
        response = conn.getresponse()
        assert response.status == 404
        assert json.loads(response.read())["error"] == "not found"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_ui_does_not_claim_unverified_subsystems():
    assert "DATABASE<br><span class=\"ok\">ONLINE" not in ui.TEMPLATE
    assert "EVENT BUS<br><span class=\"ok\">ONLINE" not in ui.TEMPLATE
    assert "GOVERNANCE<br><span class=\"ok\">ONLINE" not in ui.TEMPLATE
    assert "const P=[...Array(27)].map((_,i)=>i+1)" in ui.TEMPLATE


def _post_to_test_server(payload):
    from http.client import HTTPConnection
    from threading import Thread

    server = ui.ThreadingHTTPServer(("127.0.0.1", 0), ui.Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    conn = HTTPConnection("127.0.0.1", server.server_port, timeout=5)

    try:
        conn.request(
            "POST",
            "/api/run",
            body=json.dumps(payload),
            headers={"Content-Type": "application/json"},
        )
        response = conn.getresponse()
        body = json.loads(response.read())
        return response.status, body
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_handler_rejects_unknown_security_fields():
    status, body = _post_to_test_server({
        "phase": "phase1",
        "hardening": False,
        "admin": True,
        "approved": True,
        "bypass": True,
    })

    assert status == 400
    assert body["success"] is False
    assert "unknown request fields" in body["error"]


@pytest.mark.parametrize(
    "hardening_value",
    [
        {"enabled": True},
        "true",
        1,
        0,
        [],
        None,
    ],
)
def test_handler_rejects_non_boolean_hardening(hardening_value):
    status, body = _post_to_test_server({
        "phase": "phase1",
        "hardening": hardening_value,
    })

    assert status == 400
    assert body["success"] is False
    assert body["error"] == "ValueError: hardening must be a boolean"


@pytest.mark.parametrize(
    "phase_value",
    [
        1,
        True,
        False,
        [],
        {},
        None,
    ],
)
def test_handler_rejects_non_string_phase(phase_value):
    status, body = _post_to_test_server({
        "phase": phase_value,
        "hardening": False,
    })

    assert status == 400
    assert body["success"] is False
    assert body["error"] == "ValueError: phase must be a string"


def test_operational_report_endpoint(monkeypatch):
    from http.client import HTTPConnection
    from threading import Thread

    monkeypatch.setattr(ui, "load_report", lambda: {"kind": "test", "success": True})
    server = ui.ThreadingHTTPServer(("127.0.0.1", 0), ui.Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        conn = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        conn.request("GET", "/api/report")
        response = conn.getresponse()
        body = json.loads(response.read())
        assert response.status == 200
        assert body["report"]["kind"] == "test"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_test_center_rejects_unknown_kind():
    status, body = _post_to_test_server({"kind": "not-a-test"})
    assert status == 400
    assert body["success"] is False
    assert "invalid test kind" in body["error"]


def test_ui_has_operational_test_center():
    assert "OPERATIONAL TEST CENTER" in ui.TEMPLATE
    assert "RUN LOCAL RED-TEAM" in ui.TEMPLATE
    assert "RUN REGRESSION TESTS" in ui.TEMPLATE
    assert "/api/test" in ui.TEMPLATE
