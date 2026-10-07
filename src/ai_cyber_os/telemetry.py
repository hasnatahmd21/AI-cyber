"""Evidence-first runtime telemetry for the local AI-CYBER operational surface.

Telemetry is emitted only by real runtime/test operations. The UI must never
invent attack, detection, response, or verification events.
"""
from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
from threading import Condition, RLock
from typing import Any

_LOCK = RLock()
_CONDITION = Condition(_LOCK)
_EVENTS: deque[dict[str, Any]] = deque(maxlen=500)
_NEXT_ID = 1
_RUN: dict[str, Any] = {
    "active": False,
    "operation": None,
    "phase": None,
    "status": "IDLE",
    "started_at": None,
    "updated_at": None,
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def emit(
    event_type: str,
    message: str,
    *,
    operation: str | None = None,
    phase: str | None = None,
    status: str = "INFO",
    evidence: Any = None,
    source: str = "runtime",
    details: dict[str, Any] | None = None,
    keep_active: bool = False,
) -> dict[str, Any]:
    global _NEXT_ID
    with _CONDITION:
        timestamp = _now()
        event = {
            "id": _NEXT_ID,
            "timestamp": timestamp,
            "type": str(event_type),
            "message": str(message),
            "operation": operation,
            "phase": phase,
            "status": str(status),
            "source": str(source),
            "evidence": evidence,
            "details": details or {},
        }
        _NEXT_ID += 1
        _EVENTS.append(event)
        _RUN["updated_at"] = timestamp
        if operation is not None:
            _RUN["operation"] = operation
        if phase is not None:
            _RUN["phase"] = phase
        if status in {"RUNNING", "STARTED"}:
            _RUN["active"] = True
        elif status in {"PASS", "FAIL", "BLOCKED", "COMPLETE", "ERROR", "IDLE"} and event_type in {
            "operation_completed", "operation_error"
        }:
            if not keep_active:
                _RUN["active"] = False
            _RUN["status"] = status
        elif status in {"RUNNING", "STARTED"}:
            _RUN["status"] = status
        _CONDITION.notify_all()
        return dict(event)


def snapshot(since: int = 0, limit: int = 200) -> dict[str, Any]:
    with _LOCK:
        events = [e for e in _EVENTS if int(e["id"]) > int(since)][-max(1, min(limit, 500)):]
        return {
            "events": events,
            "next_id": _NEXT_ID - 1,
            "run": dict(_RUN),
        }


def begin(operation: str, *, phase: str | None = None, message: str | None = None) -> dict[str, Any]:
    with _LOCK:
        _RUN.update({
            "active": True,
            "operation": operation,
            "phase": phase,
            "status": "RUNNING",
            "started_at": _now(),
            "updated_at": _now(),
        })
    return emit(
        "operation_started",
        message or f"{operation} started",
        operation=operation,
        phase=phase,
        status="RUNNING",
    )


def complete(
    operation: str,
    *,
    success: bool,
    phase: str | None = None,
    message: str | None = None,
    evidence: Any = None,
    keep_active: bool = False,
) -> dict[str, Any]:
    status = "PASS" if success else "FAIL"
    with _LOCK:
        _RUN.update({"phase": phase, "status": status, "updated_at": _now()})
        if not keep_active:
            _RUN["active"] = False
    return emit(
        "operation_completed",
        message or f"{operation} {'completed' if success else 'failed'}",
        operation=operation,
        phase=phase,
        status=status,
        evidence=evidence,
        keep_active=keep_active,
    )


def error(operation: str, message: str, *, phase: str | None = None, details: dict[str, Any] | None = None) -> dict[str, Any]:
    with _LOCK:
        _RUN.update({"active": False, "phase": phase, "status": "ERROR", "updated_at": _now()})
    return emit(
        "operation_error",
        message,
        operation=operation,
        phase=phase,
        status="ERROR",
        details=details,
    )


def reset() -> None:
    global _NEXT_ID
    with _LOCK:
        _EVENTS.clear()
        _NEXT_ID = 1
        _RUN.update({
            "active": False,
            "operation": None,
            "phase": None,
            "status": "IDLE",
            "started_at": None,
            "updated_at": None,
        })
