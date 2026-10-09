"""Stage 5 integration tests for the evidence-backed RAG backend/API."""
from __future__ import annotations

import json
import threading
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from ai_cyber_os import ui
from ai_cyber_os.knowledge import ingest_file
from ai_cyber_os.runtime_intelligence import analyze


def _post_json(url: str, payload: dict):
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


def test_runtime_intelligence_returns_only_local_evidence(tmp_path):
    data = tmp_path / "evidence.jsonl"
    data.write_text(
        '{"id":"RAG-LOCAL-1","title":"Test alert","content":"Observed CVE-2026-1234 and CWE-79 in a controlled fixture","source":"local-fixture","validation_status":"fixture-validated"}\\n',
        encoding="utf-8",
    )
    db = tmp_path / "knowledge.db"
    ingest_file(data, db_path=db, dataset="fixture")

    result = analyze("CVE-2026-1234", db_path=db)

    assert result["success"] is True
    assert result["evidence_only"] is True
    assert result["answer"] is None
    assert result["answer_status"] == "not_generated"
    assert result["evidence"]
    assert result["evidence"][0]["record_id"] == "RAG-LOCAL-1"
    assert result["evidence"][0]["source"] == "local-fixture"
    assert result["evidence"][0]["content_sha256"]


def test_knowledge_context_api_retrieves_provenance_backed_evidence(tmp_path, monkeypatch):
    data = tmp_path / "evidence.jsonl"
    data.write_text(
        '{"id":"API-RAG-1","content":"local evidence confirms suspicious PowerShell activity","source":"api-fixture","validation_status":"fixture-validated"}\\n',
        encoding="utf-8",
    )
    db = tmp_path / "knowledge.db"
    ingest_file(data, db_path=db, dataset="fixture")
    monkeypatch.setattr(ui, "DEFAULT_DB", db)

    server = ThreadingHTTPServer(("127.0.0.1", 0), ui.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, payload = _post_json(
            f"http://127.0.0.1:{server.server_port}/api/knowledge",
            {"action": "context", "query": "PowerShell activity", "limit": 5},
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert status == 200
    assert payload["success"] is True
    assert payload["evidence_only"] is True
    assert payload["count"] == 1
    evidence = payload["evidence"][0]
    assert evidence["record_id"] == "API-RAG-1"
    assert evidence["source"] == "api-fixture"
    assert evidence["validation_status"] == "fixture-validated"
    assert len(evidence["content_sha256"]) == 64


@pytest.mark.parametrize(
    "payload",
    [
        {"action": "context", "query": "   "},
        {"action": "context", "query": "valid query", "limit": 0},
        {"action": "context", "query": "valid query", "limit": 51},
        {"action": "context", "query": "valid query", "limit": True},
        {"action": "context", "query": "valid query", "unknown": "blocked"},
    ],
)
def test_knowledge_context_api_rejects_invalid_requests(tmp_path, monkeypatch, payload):
    monkeypatch.setattr(ui, "DEFAULT_DB", tmp_path / "knowledge.db")
    server = ThreadingHTTPServer(("127.0.0.1", 0), ui.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, result = _post_json(
            f"http://127.0.0.1:{server.server_port}/api/knowledge", payload
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert status == 400
    assert result["success"] is False
    assert "error" in result
