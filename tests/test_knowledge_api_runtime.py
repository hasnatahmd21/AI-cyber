"""HTTP-level fail-closed tests for strict permanent Knowledge DB mode."""
from __future__ import annotations

import json
from http.client import HTTPConnection
from threading import Thread

from ai_cyber_os import ui


def _request(monkeypatch, tmp_path, method, path, payload=None):
    missing_db = tmp_path / "permanent-db-not-restored.sqlite3"
    monkeypatch.setenv("AI_CYBER_KNOWLEDGE_DB", str(missing_db))
    monkeypatch.setenv("AI_CYBER_REQUIRE_VERIFIED_DB", "1")
    monkeypatch.setattr(ui, "_guarded_operation", lambda operation, body, action: action())

    server = ui.ThreadingHTTPServer(("127.0.0.1", 0), ui.Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    conn = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    try:
        headers = {}
        body = None
        if payload is not None:
            body = json.dumps(payload)
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        raw = response.read()
        result = json.loads(raw) if raw else {}
        return response.status, result, missing_db
    finally:
        conn.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_knowledge_context_returns_503_without_creating_missing_db(monkeypatch, tmp_path):
    status, body, db_path = _request(
        monkeypatch,
        tmp_path,
        "POST",
        "/api/knowledge",
        {"action": "context", "query": "CWE-79"},
    )
    assert status == 503
    assert body["success"] is False
    assert body["blocked_by"] == "knowledge_runtime_gate"
    assert "does not exist" in body["error"]
    assert not db_path.exists()


def test_knowledge_health_returns_503_and_does_not_create_db(monkeypatch, tmp_path):
    status, body, db_path = _request(monkeypatch, tmp_path, "GET", "/api/knowledge/health")
    assert status == 503
    assert body["success"] is False
    assert body["overall"] == "BLOCKED"
    assert not db_path.exists()


def test_knowledge_status_reports_blocked_without_claiming_ready(monkeypatch, tmp_path):
    status, body, db_path = _request(monkeypatch, tmp_path, "GET", "/api/knowledge/status")
    assert status == 200
    assert body["ready"] is False
    assert body["state"] == "blocked"
    assert body["runtime_strict_mode"] is True
    assert not db_path.exists()


def test_strict_runtime_blocks_ingestion_mutations(monkeypatch, tmp_path):
    status, body, db_path = _request(
        monkeypatch,
        tmp_path,
        "POST",
        "/api/knowledge",
        {"action": "ingest", "path": "unused.jsonl"},
    )
    assert status == 503
    assert body["success"] is False
    assert body["blocked_by"] == "knowledge_runtime_gate"
    assert "ingestion is disabled" in body["error"]
    assert not db_path.exists()



def test_live_sampled_evaluation_api_fails_closed_without_published_db(monkeypatch, tmp_path):
    status, body, db_path = _request(
        monkeypatch,
        tmp_path,
        "POST",
        "/api/security-evaluation",
        {"mode": "live-sampled"},
    )
    assert status == 503
    assert body["success"] is False
    assert body["blocked_by"] == "knowledge_runtime_gate"
    assert "does not exist" in body["error"]
    assert not db_path.exists()
