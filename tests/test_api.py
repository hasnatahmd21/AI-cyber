from __future__ import annotations

import sys
from pathlib import Path

from fastapi.testclient import TestClient

from ai_cyber_os.api import SCHEMA_VERSION, create_app
from ai_cyber_os.backend import KnowledgeRAGBackend
from ai_cyber_os.commands import CommandSpec, ControlledCommandGateway
from ai_cyber_os.situation import SituationStore


def _record():
    return {
        "record_id": "v1",
        "family": "vulnerability",
        "title": "API test vulnerability",
        "description": "API integration evidence.",
        "cve_id": "CVE-2026-87654",
        "cwe_ids": ["CWE-79"],
        "capec_ids": [],
        "attack_ids": [],
        "cvss_score": 8.8,
        "cvss_vector": None,
        "severity": "HIGH",
        "evidence_refs": ["api-test:evidence"],
        "related_record_ids": [],
        "source_dataset": "api-test",
        "source_artifact": "records.jsonl",
        "source_version": "1.0",
    }


def _client(tmp_path: Path, *, with_gateway=True):
    backend = KnowledgeRAGBackend(tmp_path / "k.sqlite", tmp_path / "g.sqlite")
    situation = SituationStore(tmp_path / "s.sqlite")
    gateway = None
    if with_gateway:
        script = "print('api-gateway-green')"
        policy = CommandSpec(
            name="probe",
            executable=sys.executable,
            allowed_argv=(("-c", script),),
        )
        gateway = ControlledCommandGateway(
            [policy],
            workspace_root=tmp_path,
            audit_store=situation,
        )
    return TestClient(create_app(backend=backend, situation=situation, command_gateway=gateway))


def test_health_and_request_id(tmp_path: Path):
    with _client(tmp_path) as client:
        response = client.get("/health", headers={"X-Request-ID": "api-test-001"})
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["schema_version"] == SCHEMA_VERSION
    assert response.headers["X-Request-ID"] == "api-test-001"
    assert response.headers["X-AI-Cyber-Schema"] == SCHEMA_VERSION


def test_knowledge_ingest_then_query_is_real_backend_wiring(tmp_path: Path):
    with _client(tmp_path) as client:
        ingest = client.post("/v1/knowledge/records", json={"records": [_record()]})
        query = client.get("/v1/knowledge/query", params={"q": "CVE-2026-87654"})
    assert ingest.status_code == 201
    assert ingest.json()["integrity"]["ok"] is True
    assert query.status_code == 200
    body = query.json()
    assert body["lexical_hits"]
    assert body["citations"]
    assert body["hits"][0]["record_id"] == "v1"


def test_telemetry_single_batch_query_and_situation(tmp_path: Path):
    event = {
        "event_type": "alert",
        "observed_at": "2026-10-08T12:00:00Z",
        "source": "api-test",
        "severity": "HIGH",
        "subject_type": "asset",
        "subject_id": "host-api-1",
        "payload": {"signal": "observed"},
    }
    batch = {
        "events": [
            event,
            {**event, "external_id": "second", "observed_at": "2026-10-08T12:00:30Z", "severity": "CRITICAL"},
        ]
    }
    with _client(tmp_path) as client:
        single = client.post("/v1/telemetry/events", json=event)
        ingested = client.post("/v1/telemetry/events/batch", json=batch)
        queried = client.get(
            "/v1/telemetry/events",
            params=[("subject_type", "asset"), ("subject_id", "host-api-1")],
        )
        snapshot = client.get(
            "/v1/telemetry/situation",
            params={
                "subject_type": "asset",
                "subject_id": "host-api-1",
                "start": "2026-10-08T11:59:00Z",
                "end": "2026-10-08T12:02:00Z",
            },
        )
    assert single.status_code == 201
    assert ingested.status_code == 201 and ingested.json()["event_count"] == 2
    assert queried.status_code == 200 and queried.json()["count"] == 2
    assert snapshot.status_code == 200
    assert snapshot.json()["event_count"] == 2
    assert snapshot.json()["severity_counts"]["CRITICAL"] == 1
    assert snapshot.json()["evidence_only"] is True


def test_command_gateway_route_is_policy_bound_and_audited(tmp_path: Path):
    with _client(tmp_path) as client:
        listed = client.get("/v1/commands")
        allowed = client.post(
            "/v1/commands/execute",
            json={"command_name": "probe", "argv": ["-c", "print('api-gateway-green')"]},
        )
        denied = client.post(
            "/v1/commands/execute",
            json={"command_name": "probe", "argv": ["-c", "print('api-gateway-green');print('injected')"]},
        )
        audit = client.get("/v1/telemetry/events", params={"event_types": "process"})
    assert listed.status_code == 200
    assert listed.json()["enabled"] is True
    assert allowed.status_code == 200
    assert allowed.json()["ok"] is True
    assert allowed.json()["stdout"].strip() == "api-gateway-green"
    assert denied.status_code == 200
    assert denied.json()["status"] == "denied"
    assert audit.status_code == 200
    assert audit.json()["count"] == 1
    assert audit.json()["events"][0]["payload"]["request_id"] == allowed.json()["request_id"]


def test_command_route_disabled_without_injected_gateway(tmp_path: Path):
    with _client(tmp_path, with_gateway=False) as client:
        listed = client.get("/v1/commands")
        execute = client.post(
            "/v1/commands/execute",
            json={"command_name": "probe", "argv": []},
        )
    assert listed.json()["enabled"] is False
    assert execute.status_code == 503


def test_invalid_domain_input_returns_structured_400(tmp_path: Path):
    event = {
        "event_type": "alert",
        "observed_at": "2026-10-08T12:00:00Z",
        "source": "api-test",
        "severity": "URGENT",
        "payload": {},
    }
    with _client(tmp_path) as client:
        response = client.post("/v1/telemetry/events", json=event)
    assert response.status_code == 400
    detail = response.json()
    assert detail["error_type"] == "SituationError"
    assert detail["schema_version"] == SCHEMA_VERSION


def test_unknown_fields_are_rejected_by_api_models(tmp_path: Path):
    body = {**_record(), "unexpected": "must-not-pass"}
    with _client(tmp_path) as client:
        response = client.post("/v1/knowledge/records", json={"records": [body]})
    assert response.status_code == 422


def test_default_app_creates_local_first_stores(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("AI_CYBER_DATA_DIR", str(tmp_path))
    from ai_cyber_os.api import create_default_app

    with TestClient(create_default_app()) as client:
        response = client.get("/")
    assert response.status_code == 200
    assert (tmp_path / "knowledge.sqlite").is_file()
    assert (tmp_path / "relationships.sqlite").is_file()
    assert (tmp_path / "situation.sqlite").is_file()
