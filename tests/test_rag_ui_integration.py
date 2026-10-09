"""Stage 9: UI wiring for evidence-backed RAG context."""
from __future__ import annotations

import json
import threading
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from ai_cyber_os import ui
from ai_cyber_os.knowledge import ingest_file


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


def test_knowledge_panel_exposes_rag_context_action():
    html = ui.TEMPLATE
    assert 'onclick="kcontext()"' in html
    assert "async function kcontext()" in html
    assert 'JSON.stringify({action:"context",query:q,limit:8})' in html
    assert "answer generation disabled" in html
    assert "content_sha256" in html
    assert "validation_status" in html


def test_rag_context_ui_api_returns_evidence_records(tmp_path, monkeypatch):
    data = tmp_path / "fixture.jsonl"
    data.write_text(
        json.dumps({
            "id": "STAGE9-LOCAL-1",
            "title": "RAG UI fixture",
            "content": "Controlled evidence mentions CVE-2026-5678 and PowerShell activity.",
            "source": "stage9-fixture",
            "validation_status": "fixture-validated",
        }) + "\n",
        encoding="utf-8",
    )
    db = tmp_path / "knowledge.db"
    ingest_file(data, db_path=db, dataset="stage9-fixture")
    monkeypatch.setattr(ui, "DEFAULT_DB", db)

    server = ThreadingHTTPServer(("127.0.0.1", 0), ui.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, payload = _post_json(
            f"http://127.0.0.1:{server.server_port}/api/knowledge",
            {"action": "context", "query": "CVE-2026-5678", "limit": 8},
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert status == 200
    assert payload["success"] is True
    assert payload["evidence_only"] is True
    assert payload["count"] >= 1
    record = next(item for item in payload["evidence"] if item["record_id"] == "STAGE9-LOCAL-1")
    assert record["source"] == "stage9-fixture"
    assert record["validation_status"] == "fixture-validated"
    assert len(record["content_sha256"]) == 64
    assert "CVE-2026-5678" in record["content"]
    assert payload["answer_status"] if "answer_status" in payload else payload["evidence_only"] is True
