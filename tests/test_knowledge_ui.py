from pathlib import Path
import json
from http.client import HTTPConnection
from threading import Thread

from ai_cyber_os import ui


def test_knowledge_status_endpoint(monkeypatch):
    monkeypatch.setattr(ui, "knowledge_status", lambda db_path: {"ready": True, "records": 0})
    server = ui.ThreadingHTTPServer(("127.0.0.1", 0), ui.Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        conn = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        conn.request("GET", "/api/knowledge/status")
        response = conn.getresponse()
        body = json.loads(response.read())
        assert response.status == 200
        assert body["ready"] is True
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_knowledge_search_endpoint(monkeypatch):
    monkeypatch.setattr(ui, "knowledge_search", lambda query, db_path, dataset=None, limit=10: [
        {"record_id": "CVE-TEST", "content": query, "source": "fixture"}
    ])
    server = ui.ThreadingHTTPServer(("127.0.0.1", 0), ui.Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        conn = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        conn.request("POST", "/api/knowledge",
                     body=json.dumps({"action": "search", "query": "CVE-TEST"}),
                     headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        body = json.loads(response.read())
        assert response.status == 200
        assert body["results"][0]["record_id"] == "CVE-TEST"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_knowledge_ingest_cannot_escape_project(monkeypatch):
    monkeypatch.setattr(ui, "PROJECT_ROOT", Path("/tmp/project"))
    server = ui.ThreadingHTTPServer(("127.0.0.1", 0), ui.Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        conn = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        conn.request("POST", "/api/knowledge",
                     body=json.dumps({"action": "ingest", "path": "../secret.jsonl"}),
                     headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        body = json.loads(response.read())
        assert response.status == 400
        assert "inside project" in body["error"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
