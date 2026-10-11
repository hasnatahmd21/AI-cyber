"""Focused tests for the localhost HYDRA UI boundary."""

from __future__ import annotations

import json

import pytest

from ai_cyber_os import ui


def test_execute_rejects_invalid_phase():
    with pytest.raises(ValueError):
        ui._execute("phase999", False)


def test_execute_uses_secured_runtime(monkeypatch):
    calls = []

    class AllowingSupervisor:
        def authorize_hydra(self, phase, hardening):
            return True, "unit-test resident gate allow", {
                "decision": "allow", "phase": phase, "hardening": hardening,
            }

    monkeypatch.setattr(ui, "ACTIVE_SUPERVISOR", AllowingSupervisor())

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        payload = {
            "phase_result": {"summary": {"success": True, "phases": 27, "auxiliary_checks": 1}},
            "hardening_result": {"verified": True, "failed": 0},
        }
        return ui.subprocess.CompletedProcess(command, 0, stdout="defence: allow trace=[]\\n" + json.dumps(payload, indent=2), stderr="")

    monkeypatch.setattr(ui.subprocess, "run", fake_run)
    result = ui._execute("phase1", True)

    assert result["success"] is True
    assert len(calls) == 1
    assert calls[0][0][1:4] == ["-m", "ai_cyber_os", "--phase"]
    assert "--hardening" in calls[0][0]
    assert "--json" in calls[0][0]


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


def _post_to_test_server(payload, path="/api/run"):
    from http.client import HTTPConnection
    from threading import Thread

    server = ui.ThreadingHTTPServer(("127.0.0.1", 0), ui.Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    conn = HTTPConnection("127.0.0.1", server.server_port, timeout=5)

    try:
        conn.request(
            "POST",
            path,
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
    status, body = _post_to_test_server({"kind": "not-a-test"}, "/api/test")
    assert status == 400
    assert body["success"] is False
    assert "invalid test kind" in body["error"]


def test_ui_has_operational_test_center():
    assert "OPERATIONAL TEST CENTER" in ui.TEMPLATE
    assert "RUN LOCAL RED-TEAM" in ui.TEMPLATE
    assert "RUN REGRESSION TESTS" in ui.TEMPLATE
    assert "/api/test" in ui.TEMPLATE



def test_knowledge_status_endpoint(monkeypatch):
    from http.client import HTTPConnection
    from threading import Thread

    monkeypatch.setattr(
        ui,
        "knowledge_status",
        lambda db_path: {
            "ready": True,
            "records": 2,
            "datasets": [{"dataset": "demo", "records": 2}],
            "schema_version": 1,
        },
    )
    server = ui.ThreadingHTTPServer(("127.0.0.1", 0), ui.Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        conn = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        conn.request("GET", "/api/knowledge/status")
        response = conn.getresponse()
        body = json.loads(response.read())
        assert response.status == 200
        assert body["records"] == 2
        assert body["datasets"][0]["dataset"] == "demo"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_knowledge_search_endpoint(monkeypatch):
    from http.client import HTTPConnection
    from threading import Thread

    monkeypatch.setattr(
        ui,
        "knowledge_search",
        lambda query, db_path, dataset, limit: [
            {"record_id": "demo:1", "content": query, "dataset": dataset}
        ],
    )
    server = ui.ThreadingHTTPServer(("127.0.0.1", 0), ui.Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        conn = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        conn.request(
            "POST",
            "/api/knowledge",
            body=json.dumps({"action": "search", "query": "CVE-TEST-1"}),
            headers={"Content-Type": "application/json"},
        )
        response = conn.getresponse()
        body = json.loads(response.read())
        assert response.status == 200
        assert body["success"] is True
        assert body["results"][0]["record_id"] == "demo:1"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_knowledge_rejects_unknown_fields():
    status, body = _post_to_test_server(
        {"action": "search", "query": "CVE-1", "admin": True},
        "/api/knowledge",
    )
    assert status == 400
    assert "unknown request fields" in body["error"]


def test_live_events_endpoint():
    from http.client import HTTPConnection
    from threading import Thread

    ui.telemetry.reset()
    ui.telemetry.emit(
        "attack_observed",
        "test event",
        operation="red-team",
        status="BLOCKED",
        source="test",
    )
    server = ui.ThreadingHTTPServer(("127.0.0.1", 0), ui.Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        conn = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        conn.request("GET", "/api/events?since=0")
        response = conn.getresponse()
        body = json.loads(response.read())
        assert response.status == 200
        assert body["events"][-1]["type"] == "attack_observed"
        assert body["events"][-1]["status"] == "BLOCKED"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_command_endpoint_uses_allowlisted_gateway(monkeypatch):
    monkeypatch.setattr(
        ui,
        "_execute",
        lambda phase, hardening: {"success": True, "phase": phase, "hardening": hardening},
    )
    status, body = _post_to_test_server({"command": "run phase 7"}, "/api/command")
    assert status == 200
    assert body["success"] is True
    assert body["action"] == "run_phase"
    assert body["result"]["phase"] == "phase7"


def test_command_endpoint_rejects_arbitrary_shell():
    status, body = _post_to_test_server({"command": "rm -rf /"}, "/api/command")
    assert status == 400
    assert body["success"] is False
    assert "unsupported command" in body["error"]



def test_ui_hydra_execution_requires_resident_supervisor_allow(monkeypatch):
    class DenyingSupervisor:
        def authorize_hydra(self, phase, hardening):
            return False, "resident monitor blocked request", {"status": "blocked", "phase": phase}

    monkeypatch.setattr(ui, "ACTIVE_SUPERVISOR", DenyingSupervisor())
    monkeypatch.setattr(ui, "save_report", lambda _kind, result: result)

    def unexpected_dispatch(*_args, **_kwargs):
        pytest.fail("secured CLI must not be dispatched when resident gate denies")

    monkeypatch.setattr(ui.subprocess, "run", unexpected_dispatch)
    result = ui._execute("phase1", False)

    assert result["success"] is False
    assert result["blocked"] is True
    assert "resident monitor blocked" in result["error"]


def test_resident_defence_health_endpoint_is_explicit_when_not_started(monkeypatch):
    from http.client import HTTPConnection
    from threading import Thread

    monkeypatch.setattr(ui, "ACTIVE_SUPERVISOR", None)
    server = ui.ThreadingHTTPServer(("127.0.0.1", 0), ui.Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        conn = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        conn.request("GET", "/api/defence")
        response = conn.getresponse()
        body = json.loads(response.read())
        assert response.status == 200
        assert body["active"] is False
        assert body["ready"] is False
        assert body["status"] == "not_started"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_ui_execution_fails_closed_when_resident_supervisor_is_missing(monkeypatch):
    monkeypatch.setattr(ui, "ACTIVE_SUPERVISOR", None)
    monkeypatch.setattr(ui, "save_report", lambda _kind, result: result)

    def unexpected_dispatch(*_args, **_kwargs):
        pytest.fail("UI must not launch HYDRA without its resident defence supervisor")

    monkeypatch.setattr(ui.subprocess, "run", unexpected_dispatch)
    result = ui._execute("phase1", False)

    assert result["success"] is False
    assert result["blocked"] is True
    assert "supervisor is not running" in result["error"]
