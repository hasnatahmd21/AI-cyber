"""Real HTTP/API boundary for the canonical AI-CYBER backend.

The API is an integration layer only. It delegates knowledge retrieval to the
#5 backend, telemetry to #6, and execution to the #7 controlled gateway.
No endpoint constructs or interprets shell commands itself.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from .backend import BackendIntegrationError, KnowledgeRAGBackend
from .commands import CommandGatewayError, ControlledCommandGateway
from .security_families import SecurityKnowledgeRecord, normalize_record
from .situation import SituationError, SituationStore, TelemetryEvent

SCHEMA_VERSION = "ai_cyber_api.v1"
_DEFAULT_DATA_DIR = Path(".ai_cyber") / "data"
_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


class APIErrorBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    error: str
    error_type: str
    request_id: str
    schema_version: str = SCHEMA_VERSION


class KnowledgeIngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    records: list[dict[str, Any]] = Field(min_length=1, max_length=100)


class TelemetryEventRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_type: str
    observed_at: str
    source: str
    payload: dict[str, Any]
    event_id: str | None = None
    external_id: str | None = None
    severity: str = "UNKNOWN"
    subject_type: str | None = None
    subject_id: str | None = None
    action: str | None = None
    outcome: str | None = None
    evidence_refs: list[str] = Field(default_factory=list, max_length=64)
    related_record_ids: list[str] = Field(default_factory=list, max_length=64)

    def to_event(self) -> TelemetryEvent:
        return TelemetryEvent(
            event_type=self.event_type,
            observed_at=self.observed_at,
            source=self.source,
            payload=self.payload,
            event_id=self.event_id,
            external_id=self.external_id,
            severity=self.severity,
            subject_type=self.subject_type,
            subject_id=self.subject_id,
            action=self.action,
            outcome=self.outcome,
            evidence_refs=tuple(self.evidence_refs),
            related_record_ids=tuple(self.related_record_ids),
        )


class TelemetryBatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    events: list[TelemetryEventRequest] = Field(min_length=1, max_length=100)


class CommandExecuteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command_name: str = Field(min_length=1, max_length=128)
    argv: list[str] = Field(default_factory=list, max_length=64)


def _error_response(exc: Exception, request_id: str) -> dict[str, Any]:
    return APIErrorBody(
        error=str(exc),
        error_type=type(exc).__name__,
        request_id=request_id,
    ).model_dump()


def _get_request_id(request: Request) -> str:
    value = request.headers.get("X-Request-ID", "")
    return value if _SAFE_REQUEST_ID.fullmatch(value) else uuid4().hex


def _raise_domain_error(exc: Exception, request: Request) -> HTTPException:
    return HTTPException(
        status_code=400,
        detail=_error_response(exc, getattr(request.state, "request_id", uuid4().hex)),
    )


def create_app(
    *,
    backend: KnowledgeRAGBackend,
    situation: SituationStore,
    command_gateway: ControlledCommandGateway | None = None,
    title: str = "AI-CYBER API",
) -> FastAPI:
    """Construct an API around already-created canonical component stores."""

    if not isinstance(backend, KnowledgeRAGBackend):
        raise TypeError("backend must be a KnowledgeRAGBackend")
    if not isinstance(situation, SituationStore):
        raise TypeError("situation must be a SituationStore")
    if command_gateway is not None and not isinstance(command_gateway, ControlledCommandGateway):
        raise TypeError("command_gateway must be a ControlledCommandGateway or None")

    app = FastAPI(
        title=title,
        version=SCHEMA_VERSION,
        docs_url="/docs",
        redoc_url="/redoc",
    )
    app.state.backend = backend
    app.state.situation = situation
    app.state.command_gateway = command_gateway

    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        request.state.request_id = _get_request_id(request)
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        response.headers["X-AI-Cyber-Schema"] = SCHEMA_VERSION
        return response

    @app.exception_handler(BackendIntegrationError)
    async def backend_error(request: Request, exc: BackendIntegrationError):
        return _json_domain_error(request, exc)

    @app.exception_handler(SituationError)
    async def situation_error(request: Request, exc: SituationError):
        return _json_domain_error(request, exc)

    @app.exception_handler(CommandGatewayError)
    async def command_error(request: Request, exc: CommandGatewayError):
        return _json_domain_error(request, exc)

    def _json_domain_error(request: Request, exc: Exception):
        from fastapi.responses import JSONResponse

        return JSONResponse(status_code=400, content=_error_response(exc, request.state.request_id))

    @app.get("/")
    def root(request: Request):
        return {
            "service": "ai-cyber",
            "schema_version": SCHEMA_VERSION,
            "request_id": request.state.request_id,
            "components": {
                "knowledge_rag": True,
                "situation_telemetry": True,
                "controlled_commands": command_gateway is not None,
            },
        }

    @app.get("/health")
    def health(request: Request):
        backend_health = backend.health()
        situation_health = situation.health()
        ok = bool(backend_health["ok"] and situation_health["ok"])
        body = {
            "ok": ok,
            "schema_version": SCHEMA_VERSION,
            "request_id": request.state.request_id,
            "backend": backend_health,
            "situation": situation_health,
            "command_gateway_enabled": command_gateway is not None,
        }
        if not ok:
            raise HTTPException(status_code=503, detail=body)
        return body

    @app.get("/v1/knowledge/query")
    def knowledge_query(
        request: Request,
        q: str = Query(min_length=1, max_length=4096),
        top_k: int = Query(default=5, ge=1, le=100),
        graph_depth: int = Query(default=3, ge=0, le=8),
        graph_limit: int = Query(default=100, ge=1, le=5000),
        max_context_chars: int = Query(default=12000, ge=256, le=1_000_000),
        dataset_id: str | None = Query(default=None, max_length=256),
        source: str | None = Query(default=None, max_length=256),
        version: str | None = Query(default=None, max_length=256),
    ):
        result = backend.query(
            q,
            top_k=top_k,
            graph_depth=graph_depth,
            graph_limit=graph_limit,
            max_context_chars=max_context_chars,
            dataset_id=dataset_id,
            source=source,
            version=version,
        )
        result["request_id"] = request.state.request_id
        return result

    @app.post("/v1/knowledge/records", status_code=201)
    def knowledge_ingest(request: Request, body: KnowledgeIngestRequest):
        records: list[SecurityKnowledgeRecord] = [
            normalize_record(item) for item in body.records
        ]
        result = backend.ingest_records(records)
        return {"request_id": request.state.request_id, **result}

    @app.get("/v1/commands")
    def command_catalog(request: Request):
        if command_gateway is None:
            return {
                "enabled": False,
                "commands": [],
                "schema_version": SCHEMA_VERSION,
                "request_id": request.state.request_id,
            }
        return {
            "enabled": True,
            "commands": command_gateway.describe(),
            "schema_version": SCHEMA_VERSION,
            "request_id": request.state.request_id,
        }

    @app.post("/v1/commands/execute")
    def command_execute(request: Request, body: CommandExecuteRequest):
        if command_gateway is None:
            raise HTTPException(
                status_code=503,
                detail={
                    "error": "command gateway is not configured",
                    "error_type": "CommandGatewayUnavailable",
                    "request_id": request.state.request_id,
                    "schema_version": SCHEMA_VERSION,
                },
            )
        result = command_gateway.execute(body.command_name, tuple(body.argv))
        return {"request_id": request.state.request_id, **result.as_dict()}

    @app.post("/v1/telemetry/events", status_code=201)
    def telemetry_ingest(request: Request, body: TelemetryEventRequest):
        event = body.to_event()
        event_id = situation.ingest(event)
        return {
            "request_id": request.state.request_id,
            "event_id": event_id,
            "event": situation.get(event_id),
        }

    @app.post("/v1/telemetry/events/batch", status_code=201)
    def telemetry_ingest_batch(request: Request, body: TelemetryBatchRequest):
        events = [item.to_event() for item in body.events]
        result = situation.ingest_many(events)
        return {"request_id": request.state.request_id, **result}

    @app.get("/v1/telemetry/events")
    def telemetry_query(
        request: Request,
        start: str | None = Query(default=None, max_length=64),
        end: str | None = Query(default=None, max_length=64),
        subject_type: str | None = Query(default=None, max_length=32),
        subject_id: str | None = Query(default=None, max_length=512),
        event_types: list[str] | None = Query(default=None, max_length=12),
        severities: list[str] | None = Query(default=None, max_length=5),
        source: str | None = Query(default=None, max_length=256),
        limit: int = Query(default=100, ge=1, le=5000),
    ):
        events = situation.query(
            start=start,
            end=end,
            subject_type=subject_type,
            subject_id=subject_id,
            event_types=event_types,
            severities=severities,
            source=source,
            limit=limit,
        )
        return {
            "schema_version": SCHEMA_VERSION,
            "request_id": request.state.request_id,
            "count": len(events),
            "events": events,
        }

    @app.get("/v1/telemetry/situation")
    def telemetry_situation(
        request: Request,
        subject_type: str = Query(min_length=1, max_length=32),
        subject_id: str = Query(min_length=1, max_length=512),
        start: str = Query(min_length=1, max_length=64),
        end: str = Query(min_length=1, max_length=64),
        limit: int = Query(default=500, ge=1, le=5000),
    ):
        snapshot = situation.situation(
            subject_type=subject_type,
            subject_id=subject_id,
            start=start,
            end=end,
            limit=limit,
        )
        snapshot["request_id"] = request.state.request_id
        return snapshot

    return app


def create_default_app() -> FastAPI:
    """Build a local-only-ready app using the configured data directory.

    Command execution is intentionally disabled here because command policies
    must be explicitly constructed and injected by the embedding application.
    """
    data_dir = Path(os.environ.get("AI_CYBER_DATA_DIR", str(_DEFAULT_DATA_DIR))).expanduser()
    data_dir.mkdir(parents=True, exist_ok=True)
    backend = KnowledgeRAGBackend(
        data_dir / "knowledge.sqlite",
        data_dir / "relationships.sqlite",
    )
    situation = SituationStore(data_dir / "situation.sqlite")
    return create_app(backend=backend, situation=situation)


__all__ = ["SCHEMA_VERSION", "create_app", "create_default_app"]
