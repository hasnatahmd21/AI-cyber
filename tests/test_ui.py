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
    monkeypatch.setattr(ui, "_guarded_operation", lambda operation, payload, action: action())

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
        assert "DATA FABRIC // EVIDENCE + PROVENANCE" in response.read().decode()

        conn.request("GET", "/not-found")
        response = conn.getresponse()
        assert response.status == 404
        assert json.loads(response.read())["error"] == "not found"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_ui_does_not_claim_unverified_subsystems():
    assert "DATABASE<br><span class=\\"ok\\">ONLINE" not in ui.TEMPLATE
    assert "EVENT BUS<br><span class=\\"ok\\">ONLINE" not in ui.TEMPLATE
    assert "GOVERNANCE<br><span class=\\"ok\\">ONLINE" not in ui.TEMPLATE
    assert "HYDRA // 27 PHASES" in ui.TEMPLATE
    assert "DATA FABRIC // EVIDENCE + PROVENANCE" in ui.TEMPLATE
    assert "/api/live/summary" in ui.TEMPLATE
    assert "setInterval(ev,700)" not in ui.TEMPLATE
    assert "RUN SAMPLE REQUEST" not in ui.TEMPLATE
    assert "SIMULATED:" not in ui.TEMPLATE
    assert "No synthetic threat records are created." in ui.TEMPLATE


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


def test_ui_has_live_hydra_and_data_fabric_controls():
    assert "HYDRA // 27 PHASES" in ui.TEMPLATE
    assert "DATA FABRIC // EVIDENCE + PROVENANCE" in ui.TEMPLATE
    assert "BUILD RAG CONTEXT (EVIDENCE ONLY)" in ui.TEMPLATE
    assert "/api/command" in ui.TEMPLATE



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

    monkeypatch.setattr(ui, "_guarded_operation", lambda operation, payload, action: action())
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
    monkeypatch.setattr(ui, "_guarded_operation", lambda operation, payload, action: action())
    monkeypatch.setattr(
        ui,
        "_execute_runtime",
        lambda phase, hardening: {"success": True, "phase": phase, "hardening": hardening},
    )
    status, body = _post_to_test_server({"command": "run phase 7"}, "/api/command")
    assert status == 200
    assert body["success"] is True
    assert body["action"] == "run_phase"
    assert body["result"]["phase"] == "phase7"


def test_command_endpoint_rejects_arbitrary_shell(monkeypatch):
    monkeypatch.setattr(ui, "_guarded_operation", lambda operation, payload, action: action())
    status, body = _post_to_test_server({"command": "rm -rf /"}, "/api/command")
    assert status == 400
    assert body["success"] is False
    assert "unsupported command" in body["error"]



def test_live_status_bundle_connects_project_defence_hydra_and_data_fabric():
    bundle = ui._live_status_bundle()
    assert bundle["success"] is True
    assert bundle["defence"]["source"] == "live"
    assert bundle["defence"]["components"]["ui"]["state"] == "passed"
    assert bundle["hydra"]["available_phases"] == 27
    assert bundle["data_fabric"]["engine"] == "SQLite FTS5"
    assert bundle["project"]["app"]["ui"] == "CYBER_OS_defence.html"


def test_root_ui_fails_closed_if_pinned_asset_changes(monkeypatch):
    from http.client import HTTPConnection
    from threading import Thread

    monkeypatch.setattr(
        ui.live_surface,
        "verify_ui_asset",
        lambda: {"state": "failed", "evidence": "test hash mismatch"},
    )
    server = ui.ThreadingHTTPServer(("127.0.0.1", 0), ui.Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        conn = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        conn.request("GET", "/")
        response = conn.getresponse()
        body = json.loads(response.read())
        assert response.status == 503
        assert body["success"] is False
        assert body["ui"]["state"] == "failed"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_main_refuses_to_serve_if_ui_integrity_fails(monkeypatch):
    monkeypatch.setattr(
        ui.live_surface,
        "verify_ui_asset",
        lambda: {"state": "failed", "evidence": "test hash mismatch"},
    )
    assert ui.main(["--no-browser", "--port", "0"]) == 5


def test_guard_failure_never_runs_requested_action(monkeypatch):
    from ai_cyber_os import _defence

    invoked = []
    def deny(argv, action):
        raise RuntimeError("gate unavailable")
    monkeypatch.setattr(_defence, "run_guarded", deny)
    with pytest.raises(PermissionError, match="defence preflight refused"):
        ui._guarded_operation("test", {"x": 1}, lambda: invoked.append(True))
    assert invoked == []


def test_operation_exception_is_not_misreported_as_guard_failure(monkeypatch):
    from ai_cyber_os import _defence
    monkeypatch.setattr(_defence, "run_guarded", lambda argv, action: action())
    with pytest.raises(ZeroDivisionError):
        ui._guarded_operation("test", {}, lambda: 1 / 0)
