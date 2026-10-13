"""
hydra_brain.bridge
==================

Duck-typed adapter between the HYDRA / NEXORA platform event model
(``CyberEvent``: event_id, event_type, tenant_id, timestamp, source,
causation_id, payload, ...) and ``HydraBrain.ingest``.

It does NOT import the platform. Anything with those attributes (or a
mapping with those keys) works, so the platform file and this package
stay independent.

    bridge = PlatformBridge(brain)
    bridge.subscribe_to(platform_event_bus)       # EventBus.subscribe(type, handler)
    # or call bridge.handle_event(event) yourself
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, List, Mapping, Optional

from .brain import HydraBrain, IngestResult


def _get(event: Any, name: str, default: Any = None) -> Any:
    if isinstance(event, Mapping):
        return event.get(name, default)
    return getattr(event, name, default)


def _parse_time(value: Any) -> Optional[datetime]:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


class PlatformBridge:
    def __init__(self, brain: HydraBrain) -> None:
        self.brain = brain
        self.results: List[IngestResult] = []
        self.errors: List[str] = []

    def handle_event(self, event: Any) -> Optional[IngestResult]:
        """Map one platform event onto ``brain.ingest``. Never raises."""
        try:
            event_id = _get(event, "event_id")
            tenant = _get(event, "tenant_id") or None
            source = (
                _get(event, "source")
                or _get(event, "actor_id")
                or "platform"
            )
            payload = dict(_get(event, "payload") or {})
            result = self.brain.ingest(
                source_id=str(source),
                payload=payload,
                telemetry_id=str(event_id) if event_id else None,
                scope_id=tenant,
                observed_at=_parse_time(_get(event, "timestamp")),
                causation_id=(_get(event, "causation_id") or None),
            )
            self.results.append(result)
            return result
        except Exception as exc:  # event handlers must not break the bus
            self.errors.append(f"{type(exc).__name__}: {exc}")
            return None

    def subscribe_to(self, bus: Any, event_type: str = "*") -> None:
        """Subscribe to an EventBus exposing ``subscribe(type, handler)``."""
        bus.subscribe(event_type, self.handle_event)
