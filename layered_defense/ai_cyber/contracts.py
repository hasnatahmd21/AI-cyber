"""Gate 0 - shared contracts and types. No other ai_cyber module is imported here
(prevents circular imports)."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Optional, Protocol, Tuple


class Decision(str, Enum):
    ALLOW = "allow"
    RESTRICT = "restrict"       # allowed only with reduced privileges
    ESCALATE = "escalate"       # needs a stronger layer / human approval
    BLOCK = "block"
    QUARANTINE = "quarantine"
    ERROR = "error"             # unknown / invalid state -> treated as NOT authorized


_SEVERITY = {Decision.ALLOW: 0, Decision.RESTRICT: 1, Decision.ESCALATE: 2,
             Decision.BLOCK: 3, Decision.QUARANTINE: 4, Decision.ERROR: 3}


def is_authorized(d: Decision) -> bool:
    """Only ALLOW and RESTRICT count as authorized. Everything else (incl. ERROR) is not."""
    return d in (Decision.ALLOW, Decision.RESTRICT)


def most_severe(*decisions: Decision) -> Decision:
    if not decisions:
        return Decision.ERROR  # undefined -> fail closed
    return max(decisions, key=lambda d: _SEVERITY[d])


class Sensitivity(str, Enum):
    NORMAL = "normal"
    CRITICAL = "critical"


class SecurityError(Exception):
    """Base error for all ai_cyber failures."""


class ContractViolation(SecurityError):
    pass


@dataclass(frozen=True)
class Request:
    request_id: str
    principal: str                      # claimed identity
    action: str                         # e.g. "read", "write", "delete"
    resource: str
    payload: Any = None
    credentials: Optional[str] = None   # opaque token, verified by trust_authority
    source: str = "external"
    sensitivity: Sensitivity = Sensitivity.NORMAL
    timestamp: float = field(default_factory=time.time)
    attributes: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Finding:
    layer: str
    code: str
    severity: int                      # 0..10
    detail: str = ""


@dataclass(frozen=True)
class LayerResult:
    layer: str
    decision: Decision
    findings: Tuple[Finding, ...] = ()
    reason: str = ""

    @property
    def max_severity(self) -> int:
        return max((f.severity for f in self.findings), default=0)


@dataclass(frozen=True)
class FinalResult:
    request_id: str
    decision: Decision
    layer_results: Tuple[LayerResult, ...]
    trace: Tuple[str, ...]
    reason: str = ""

    @property
    def authorized(self) -> bool:
        return is_authorized(self.decision)


class Layer(Protocol):
    name: str
    def evaluate(self, request: Request, prior: Tuple[LayerResult, ...]) -> LayerResult: ...


class AuditSink(Protocol):
    def record(self, event: str, **fields: Any) -> None: ...
