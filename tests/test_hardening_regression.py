from __future__ import annotations

import re
import sqlite3
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ai_cyber_os.api import SCHEMA_VERSION as API_SCHEMA_VERSION, create_app
from ai_cyber_os.backend import KnowledgeRAGBackend
from ai_cyber_os.commands import CommandSpec, ControlledCommandGateway
from ai_cyber_os.knowledge import KnowledgeStore
from ai_cyber_os.situation import SituationError, SituationStore, TelemetryEvent
from ai_cyber_os.ui import APP_JS, APP_CSS, INDEX_HTML, SCHEMA_VERSION as UI_SCHEMA_VERSION


def _record(record_id: str = "v1", related: list[str] | None = None) -> dict:
    return {
        "record_id": record_id,
        "family": "vulnerability",
        "title": "Hardening regression vulnerability",
        "description": "Deterministic evidence used by the hardening gate.",
        "cve_id": "CVE-2026-87654",
        "cwe_ids": ["CWE-79"],
        "capec_ids": [],
        "attack_ids": [],
        "cvss_score": 8.8,
        "cvss_vector": None,
        "severity": "HIGH",
        "evidence_refs": ["hardening:evidence:1"],
        "related_record_ids": related or [],
        "source_dataset": "hardening-test",
        "source_artifact": "regression.jsonl",
        "source_version": "1.0",
    }


def _event(**overrides) -> TelemetryEvent:
    payload = {
        "event_type": "alert",
        "observed_at": "2026-10-08T10:00:00Z",
        "source": "hardening-test",
        "severity": "HIGH",
        "subject_type": "asset",
        "subject_id": "host-1",
        "payload": {"signal": "observed"},
    }
    payload.update(overrides)
    return TelemetryEvent(**payload)


def _client(tmp_path: Path, *, gateway: ControlledCommandGateway | None = None):
    backend = KnowledgeRAGBackend(tmp_path / "knowledge.sqlite", tmp_path / "relationships.sqlite")
    situation = SituationStore(tmp_path / "situation.sqlite")
    return TestClient(
        create_app(
            backend=backend,
            situation=situation,
            command_gateway=gateway,
        )
    )


def test_http_security_headers_and_request_id_fail_closed(tmp_path: Path):
    with _client(tmp_path) as client:
        for path in ("/", "/health", "/ui", "/ui/assets/app.css", "/ui/assets/app.js"):
            response = client.get(path, headers={"X-Request-ID": "not a valid request id"})
            assert response.status_code == 200
            assert re.fullmatch(r"[0-9a-f]{32}", response.headers["X-Request-ID"])
            assert response.headers["X-AI-Cyber-Schema"] == API_SCHEMA_VERSION
            assert response.headers["X-AI-Cyber-UI-Schema"] == UI_SCHEMA_VERSION
            assert response.headers["X-Content-Type-Options"] == "nosniff"
            assert response.headers["Referrer-Policy"] == "no-referrer"
            assert response.headers["Cache-Control"] == "no-store"
            assert response.headers["Content-Security-Policy"].startswith("default-src 'self'")

def test_api_bounds_and_unknown_fields_fail_closed(tmp_path: Path):
    with _client(tmp_path) as client:
        invalid_queries = (
            {"q": "x", "top_k": 0},
            {"q": "x", "graph_depth": 9},
            {"q": "x", "graph_limit": 5001},
            {"q": "x", "max_context_chars": 255},
        )
        assert all(
            client.get("/v1/knowledge/query", params=params).status_code == 422
            for params in invalid_queries
        )

        telemetry = {
            "event_type": "alert",
            "observed_at": "2026-10-08T10:00:00Z",
            "source": "hardening-test",
            "payload": {},
            "unexpected": "reject-me",
        }
        assert client.post("/v1/telemetry/events", json=telemetry).status_code == 422

        batch = {
            "events": [
                {
                    "event_type": "alert",
                    "observed_at": "2026-10-08T10:00:00Z",
                    "source": "hardening-test",
                    "payload": {},
                }
            ] * 101
        }
        assert client.post("/v1/telemetry/events/batch", json=batch).status_code == 422

def test_telemetry_event_id_collision_cannot_overwrite_evidence(tmp_path: Path):
    store = SituationStore(tmp_path / "situation.sqlite")
    first = _event(event_id="fixed-event", payload={"value": "first"})
    second = _event(event_id="fixed-event", payload={"value": "second"})

    assert store.ingest(first) == "fixed-event"
    with pytest.raises(SituationError, match="collision"):
        store.ingest(second)

    assert store.count() == 1
    assert store.get("fixed-event")["payload"] == {"value": "first"}
    assert store.verify_integrity()["ok"] is True

def test_exact_start_end_time_window_is_exact(tmp_path: Path):
    store = SituationStore(tmp_path / "situation.sqlite")
    store.ingest(_event(event_id="at-window", observed_at="2026-10-08T10:00:00Z"))
    store.ingest(_event(event_id="after-window", observed_at="2026-10-08T10:00:01Z"))

    snapshot = store.situation(
        subject_type="asset",
        subject_id="host-1",
        start="2026-10-08T10:00:00Z",
        end="2026-10-08T10:00:00Z",
    )
    assert snapshot["event_count"] == 1
    assert snapshot["latest_event_at"] == "2026-10-08T10:00:00.000000Z"

def test_knowledge_limit_is_strictly_typed(tmp_path: Path):
    store = KnowledgeStore(tmp_path / "knowledge.sqlite")
    with pytest.raises(TypeError):
        store.search("anything", limit=1.5)
    with pytest.raises(TypeError):
        store.search("anything", limit="1")

def test_missing_command_executable_fails_and_is_audited(tmp_path: Path):
    situation = SituationStore(tmp_path / "situation.sqlite")
    gateway = ControlledCommandGateway(
        [
            CommandSpec(
                name="missing",
                executable="/definitely/not/a-real-ai-cyber-executable",
                allowed_argv=((),),
            )
        ],
        workspace_root=tmp_path,
        audit_store=situation,
    )

    result = gateway.execute("missing", ())
    assert result.status == "failed"
    assert result.ok is False
    assert result.returncode is None
    assert result.stderr
    assert result.audit_event_ids
    events = situation.query(event_types=["process"], limit=10)
    assert len(events) == 1
    assert events[0]["outcome"] == "failed"

def test_command_timeout_and_output_limits_remain_bounded(tmp_path: Path):
    situation = SituationStore(tmp_path / "situation.sqlite")
    timeout_gateway = ControlledCommandGateway(
        [
            CommandSpec(
                name="timeout",
                executable=sys.executable,
                allowed_argv=(("-c", "import time; time.sleep(2)"),),
                timeout_seconds=1,
            )
        ],
        workspace_root=tmp_path,
        audit_store=situation,
    )
    timed_out = timeout_gateway.execute("timeout", ("-c", "import time; time.sleep(2)"))
    assert timed_out.status == "timed_out"
    assert timed_out.timed_out is True
    assert timed_out.ok is False

    output_gateway = ControlledCommandGateway(
        [
            CommandSpec(
                name="output",
                executable=sys.executable,
                allowed_argv=(("-c", "print('x' * 2000)"),),
                max_output_bytes=256,
            )
        ],
        workspace_root=tmp_path,
        audit_store=situation,
    )
    output = output_gateway.execute("output", ("-c", "print('x' * 2000)"))
    assert output.status == "executed"
    assert output.ok is True
    assert output.stdout_truncated is True
    assert len(output.stdout.encode("utf-8")) <= 256

def test_backend_integrity_failure_surfaces_as_degraded_api_health(tmp_path: Path):
    backend = KnowledgeRAGBackend(tmp_path / "knowledge.sqlite", tmp_path / "relationships.sqlite")
    situation = SituationStore(tmp_path / "situation.sqlite")
    from ai_cyber_os.security_families import normalize_record

    backend.ingest_records([normalize_record(_record())])

    with sqlite3.connect(tmp_path / "knowledge.sqlite") as db:
        db.execute(
            "UPDATE knowledge_documents SET payload_json=? WHERE record_id=?",
            ('{"tampered":true}', "v1"),
        )

    assert backend.verify_integrity()["ok"] is False

    with TestClient(create_app(backend=backend, situation=situation)) as client:
        response = client.get("/health")
    assert response.status_code == 503
    detail = response.json()["detail"]
    assert detail["ok"] is False
    assert detail["backend"]["ok"] is False

def test_end_to_end_evidence_telemetry_command_path_stays_connected(tmp_path: Path):
    situation = SituationStore(tmp_path / "situation.sqlite")
    policy = CommandSpec(
        name="probe",
        executable=sys.executable,
        allowed_argv=(("-c", "print('hardening-green')"),),
    )
    gateway = ControlledCommandGateway(
        [policy],
        workspace_root=tmp_path,
        audit_store=situation,
    )

    with _client(tmp_path, gateway=gateway) as client:
        ingest = client.post("/v1/knowledge/records", json={"records": [_record()]})
        event = client.post(
            "/v1/telemetry/events",
            json={
                "event_type": "alert",
                "observed_at": "2026-10-08T10:00:00Z",
                "source": "hardening-test",
                "severity": "HIGH",
                "subject_type": "asset",
                "subject_id": "host-1",
                "payload": {"record_id": "v1", "signal": "observed"},
            },
        )
        knowledge = client.get("/v1/knowledge/query", params={"q": "CVE-2026-87654"})
        situation_view = client.get(
            "/v1/telemetry/situation",
            params={
                "subject_type": "asset",
                "subject_id": "host-1",
                "start": "2026-10-08T09:59:00Z",
                "end": "2026-10-08T10:01:00Z",
            },
        )
        command = client.post(
            "/v1/commands/execute",
            json={"command_name": "probe", "argv": ["-c", "print('hardening-green')"]},
        )
        health = client.get("/health")

    assert ingest.status_code == 201 and ingest.json()["integrity"]["ok"] is True
    assert event.status_code == 201
    assert knowledge.status_code == 200 and knowledge.json()["citations"]
    assert knowledge.json()["hits"][0]["record_id"] == "v1"
    assert situation_view.status_code == 200
    assert situation_view.json()["evidence_only"] is True
    assert situation_view.json()["event_count"] >= 1
    assert command.status_code == 200 and command.json()["ok"] is True
    assert command.json()["stdout"].strip() == "hardening-green"
    assert command.json()["audit_event_ids"]
    assert health.status_code == 200 and health.json()["ok"] is True

def test_ui_security_contract_survives_hardening():
    assert API_SCHEMA_VERSION == "ai_cyber_api.v1"
    assert UI_SCHEMA_VERSION == "ai_cyber_ui.v1"
    assert "https://" not in INDEX_HTML + APP_JS + APP_CSS
    assert "http://" not in INDEX_HTML + APP_JS + APP_CSS
    assert "innerHTML" not in APP_JS
    assert "outerHTML" not in APP_JS
    assert "document.write" not in APP_JS
    assert "eval(" not in APP_JS
    assert "new Function(" not in APP_JS
    for marker in (
        "/v1/knowledge/query",
        "/v1/telemetry/situation",
        "/v1/commands/execute",
        "textContent",
    ):
        assert marker in APP_JS
