"""Stage 8: end-to-end tests for real UI-to-backend API wiring."""
from __future__ import annotations

import json
import threading
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from ai_cyber_os import ui


@pytest.fixture
def api_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), ui.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _post_json(url: str, payload: object):
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def test_command_status_api_is_wired_to_live_status_handler(api_server, monkeypatch):
    snapshot = {"runtime": "online", "knowledge": {"records": 3}}
    monkeypatch.setattr(ui, "_command_status", lambda: snapshot)

    status, body = _post_json(f"{api_server}/api/command", {"command": "status"})

    assert status == 200
    assert body["success"] is True
    assert body["action"] == "status"
    assert body["result"] == snapshot


def test_command_phase_api_dispatches_to_canonical_runtime(api_server, monkeypatch):
    calls = []

    def fake_execute(phase, hardening):
        calls.append((phase, hardening))
        return {"success": True, "phase": phase, "verified": True}

    monkeypatch.setattr(ui, "_execute", fake_execute)

    status, body = _post_json(
        f"{api_server}/api/command", {"command": "run phase 7"}
    )

    assert status == 200
    assert body["success"] is True
    assert body["action"] == "run_phase"
    assert calls == [("phase7", False)]
    assert body["result"]["verified"] is True


def test_command_search_api_uses_runtime_intelligence(api_server, monkeypatch):
    calls = []

    def fake_analyze(query, *, db_path, limit):
        calls.append((query, db_path, limit))
        return {
            "success": True,
            "query": query,
            "evidence_only": True,
            "evidence": [{"record_id": "FIXTURE-1", "source": "test"}],
        }

    monkeypatch.setattr(ui, "intelligence_analyze", fake_analyze)

    status, body = _post_json(
        f"{api_server}/api/command",
        {"command": "search   CVE-2026-1234  "},
    )

    assert status == 200
    assert body["success"] is True
    assert body["action"] == "search"
    assert body["result"]["evidence_only"] is True
    assert body["result"]["evidence"][0]["record_id"] == "FIXTURE-1"
    assert calls == [("CVE-2026-1234", ui.DEFAULT_DB, 10)]


@pytest.mark.parametrize(
    "backend_result",
    [
        {"success": False, "error": "backend verification failed"},
        {"phase": "phase7", "verified": False},
        None,
    ],
)
def test_command_api_never_marks_failed_or_malformed_backend_green(
    api_server, monkeypatch, backend_result
):
    monkeypatch.setattr(ui, "_execute", lambda phase, hardening: backend_result)

    status, body = _post_json(
        f"{api_server}/api/command", {"command": "run phase 7"}
    )

    assert status == 422
    assert body["success"] is False


@pytest.mark.parametrize(
    "payload",
    [
        {"command": "python -c 'print(1)'"},
        {"command": "status", "extra": True},
        {"command": 123},
        [],
    ],
)
def test_command_api_rejects_untrusted_request_shapes(api_server, payload):
    status, body = _post_json(f"{api_server}/api/command", payload)

    assert status == 400
    assert body["success"] is False
    assert "error" in body
