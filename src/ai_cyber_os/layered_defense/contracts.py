"""Shared fail-closed contracts for the layered defence runtime."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Optional, Protocol, Tuple


class Decision(str, Enum):
    ALLOW = "allow"
    RESTRICT = "restrict"
    ESCALATE = "escalate"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    ERROR = "error"


_SEVERITY = {
    Decision.ALLOW: 0, Decision.RESTRICT: 1, Decision.ESCALATE: 2,
    Decision.BLOCK: 3, Decision.QUARANTINE: 4, Decision.ERROR: 3,
}


def is_authorized(decision: Decision) -> bool:
    # The HYDRA launcher will require explicit ALLOW; RESTRICT is not enough
    # for privileged engine execution.
    return decision is Decision.ALLOW


def most_severe(*decisions: Decision) -> Decision:
    return max(decisions, key=lambda d: _SEVERITY[d]) if decisions else Decision.ERROR


class Sensitivity(str, Enum):
    NORMAL = "normal"
    CRITICAL = "critical"


class SecurityError(Exception):
    """Base error for layered-defence failures."""


class ContractViolation(SecurityError):
    pass


@dataclass(frozen=True)
class Request:
    request_id: str
    principal: str
    action: str
    resource: str
    payload: Any = None
    credentials: Optional[str] = None
    source: str = "external"
    sensitivity: Sensitivity = Sensitivity.NORMAL
    timestamp: float = field(default_factory=time.time)
    attributes: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Finding:
    layer: str
    code: str
    severity: int
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
        return self.decision is Decision.ALLOW


class Layer(Protocol):
    name: str
    def evaluate(self, request: Request, prior: Tuple[LayerResult, ...]) -> LayerResult: ...


class AuditSink(Protocol):
    def record(self, event: str, **fields: Any) -> None: ...
