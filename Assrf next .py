"""
HYDRA — Trust, Authority & Containment Control Plane (single-file edition)

Yeh ek complete, self-contained implementation hai jo 9 phases ko
ek file mein consolidate karti hai:

    § 1  Errors
    § 2  Enums
    § 3  Identifiers
    § 4  Clocks (logical + latency)
    § 5  Audit
    § 6  Config
    § 7  Trust
    § 8  Policy
    § 9  Authority
    §10  Subject & Session
    §11  Containment
    §12  Delegation
    §13  Telemetry
    §14  ControlPlane (end-to-end wiring)
    §15  Test infrastructure (shared)
    §16  Tests (per-phase grouped)

Design invariants:
  * Zero duplicate primitives — one Identifier family, one Clock
    protocol, one AuditEvent, one trust engine, one policy engine, etc.
  * Fail-closed at every security-relevant runtime error.
  * Contract violations raise; runtime failures fail closed.
  * No silent security failure: AuditSinkError propagates.
  * Full traceability: INPUT → EVIDENCE → ANALYSIS → POLICY → DECISION
    → AUTHORITY → ACTION → OBSERVATION → VERIFICATION → OUTCOME.

Purpose:
  Take an authorization request → evaluate trust → apply policy →
  optionally issue authority → enforce containment → support
  delegation → emit telemetry → remain auditable end-to-end.

Run:
    python hydra.py

Isse saare consolidated tests chalenge.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import io
import json
import math
import re
import secrets
import threading
import time
import traceback
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from types import MappingProxyType
from typing import (
    Any, Callable, Iterable, Mapping, Protocol, runtime_checkable,
)

__version__ = "1.0.0"


# ═════════════════════════════════════════════════════════════════════════
# §1  ERRORS
# ═════════════════════════════════════════════════════════════════════════

class HydraError(Exception):
    """Root of the HYDRA exception hierarchy."""


class AuditSinkError(HydraError):
    """Raised when an AuditSink cannot persist an event.

    MUST be raised (not swallowed) on failure.  Callers MUST treat it
    as security-relevant."""


class TrustEngineError(HydraError):
    """Base class for trust-domain errors."""


class TrustPolicyError(TrustEngineError):
    """Invalid trust policy construction."""


class PolicyError(HydraError):
    """Base class for policy-domain errors."""


class PolicyConstructionError(PolicyError):
    """Invalid Policy or PolicyRule construction."""


class DecisionError(HydraError):
    """Programmer error in decision handling."""


class AuthorityError(HydraError):
    """Base class for authority-domain errors."""


class AuthorityIssuanceError(AuthorityError):
    """Authority token could not be issued."""


class SubjectError(HydraError):
    """Base class for subject-domain errors."""


class DuplicateSubjectError(SubjectError):
    """Subject id already registered."""


class SubjectNotFoundError(SubjectError):
    """Subject id not in registry."""


class SessionError(HydraError):
    """Base class for session-domain errors."""


class SessionNotFoundError(SessionError):
    """Session id not in registry."""


class SessionCreationError(SessionError):
    """Invalid session parameters."""


class InvalidSessionTransitionError(SessionError):
    """Session state transition not permitted."""


class ContainmentError(HydraError):
    """Base class for containment-domain errors."""


class ContainmentPolicyError(ContainmentError):
    """Invalid containment policy."""


class ContainmentTransitionError(ContainmentError):
    """Containment transition not permitted."""


class ReviewError(ContainmentError):
    """Review-queue misuse."""


class DelegationError(HydraError):
    """Base class for delegation-domain errors."""


class DelegationPolicyError(DelegationError):
    """Invalid delegation policy."""


class DelegationIssuanceError(DelegationError):
    """Delegation could not be issued."""


class DelegationNotFoundError(DelegationError):
    """Delegation id not in broker."""


class TelemetryError(HydraError):
    """Base class for telemetry-domain errors."""


class TelemetryConfigError(TelemetryError):
    """Invalid telemetry config."""


class TraceError(TelemetryError):
    """Trace misuse."""


class MetricError(TelemetryError):
    """Metric misuse."""


class ControlPlaneError(HydraError):
    """Base class for control-plane errors."""


class ControlPlaneConfigError(ControlPlaneError):
    """Invalid control-plane config."""


class AuditError(HydraError):
    """Base class for audit-domain errors."""


# ═════════════════════════════════════════════════════════════════════════
# §2  ENUMS
# ═════════════════════════════════════════════════════════════════════════

class Environment(StrEnum):
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"


class IdentityKind(StrEnum):
    """Identity class.  Human vs non-human distinction is security-
    relevant (Standard #44): decision engines MUST NOT treat them
    interchangeably."""
    HUMAN = "human"
    SERVICE_ACCOUNT = "service_account"
    WORKLOAD = "workload"
    AI_AGENT = "ai_agent"
    DEVICE = "device"


class EventKind(StrEnum):
    """Kernel-level audit events."""
    CONFIG_LOADED = "config.loaded"
    CONFIG_REJECTED = "config.rejected"
    AUDIT_SINK_FAILURE = "audit.sink_failure"


class SessionState(StrEnum):
    CREATED = "created"
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class SessionEventKind(StrEnum):
    """Session-domain audit events (distinct category from EventKind)."""
    SUBJECT_REGISTERED = "subject.registered"
    SUBJECT_REGISTER_REJECTED = "subject.register_rejected"
    SESSION_CREATED = "session.created"
    SESSION_CREATE_REJECTED = "session.create_rejected"
    SESSION_ACTIVATED = "session.activated"
    SESSION_TOUCHED = "session.touched"
    SESSION_REVOKED = "session.revoked"
    SESSION_EXPIRED = "session.expired"
    SESSION_TRANSITION_REJECTED = "session.transition_rejected"


class TrustLevel(StrEnum):
    UNTRUSTED = "untrusted"   # [0.00, 0.20)
    LOW = "low"               # [0.20, 0.40)
    MEDIUM = "medium"         # [0.40, 0.60)
    HIGH = "high"             # [0.60, 0.80)
    FULL = "full"             # [0.80, 1.00]


class EvidencePolarity(StrEnum):
    POSITIVE = "positive"
    NEGATIVE = "negative"


class EvidenceKind(StrEnum):
    AUTHENTICATION = "authentication"
    ATTESTATION = "attestation"
    HISTORY = "history"
    MANUAL_VOUCH = "manual_vouch"
    NETWORK_CONTEXT = "network_context"


class TrustEventKind(StrEnum):
    TRUST_ASSESSED = "trust.assessed"
    TRUST_FAILED_CLOSED = "trust.failed_closed"
    TRUST_EVIDENCE_REJECTED = "trust.evidence_rejected"


class ActionKind(StrEnum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    ADMIN = "admin"
    DELEGATE = "delegate"
    CONTAIN = "contain"


class DecisionOutcome(StrEnum):
    """Deliberately no ABSTAIN.  Default-deny is the only safe default."""
    ALLOW = "allow"
    DENY = "deny"


class RuleOutcome(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class PolicyEventKind(StrEnum):
    POLICY_EVALUATED = "policy.evaluated"
    POLICY_EVALUATION_FAILED = "policy.evaluation_failed"


class AuthorityEventKind(StrEnum):
    AUTHORITY_ISSUED = "authority.issued"
    AUTHORITY_ISSUANCE_REJECTED = "authority.issuance_rejected"
    AUTHORITY_VALIDATED = "authority.validated"
    AUTHORITY_VALIDATION_REJECTED = "authority.validation_rejected"
    AUTHORITY_REVOKED = "authority.revoked"
    AUTHORITY_REVOKE_REJECTED = "authority.revoke_rejected"


class ContainmentLevel(StrEnum):
    """Ordered by strictness: NONE < MONITOR < RESTRICT < ISOLATE < TERMINATE."""
    NONE = "none"
    MONITOR = "monitor"
    RESTRICT = "restrict"
    ISOLATE = "isolate"
    TERMINATE = "terminate"


class ContainmentEventKind(StrEnum):
    CONTAINMENT_APPLIED = "containment.applied"
    CONTAINMENT_ESCALATED = "containment.escalated"
    CONTAINMENT_REINFORCED = "containment.reinforced"
    CONTAINMENT_RELEASED = "containment.released"
    CONTAINMENT_TRANSITION_REJECTED = "containment.transition_rejected"
    CONTAINMENT_FAILED_CLOSED = "containment.failed_closed"
    CONTAINMENT_AUTO_EXPIRED = "containment.auto_expired"


class ReviewState(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"


class ReviewDecision(StrEnum):
    APPROVE = "approve"
    DENY = "deny"


class ReviewEventKind(StrEnum):
    REVIEW_REQUESTED = "review.requested"
    REVIEW_RESOLVED = "review.resolved"
    REVIEW_RESOLUTION_REJECTED = "review.resolution_rejected"


class DelegationEventKind(StrEnum):
    DELEGATION_ISSUED = "delegation.issued"
    DELEGATION_ISSUANCE_REJECTED = "delegation.issuance_rejected"
    DELEGATION_VALIDATED = "delegation.validated"
    DELEGATION_VALIDATION_REJECTED = "delegation.validation_rejected"
    DELEGATION_REVOKED = "delegation.revoked"
    DELEGATION_REVOKE_REJECTED = "delegation.revoke_rejected"


class Stage(StrEnum):
    """Canonical pipeline stages (Standard #49).  Declaration order is
    the canonical order used by Trace.is_well_ordered()."""
    INPUT = "input"
    EVIDENCE = "evidence"
    ANALYSIS = "analysis"
    POLICY = "policy"
    DECISION = "decision"
    AUTHORITY = "authority"
    ACTION = "action"
    OBSERVATION = "observation"
    VERIFICATION = "verification"
    OUTCOME = "outcome"


class TelemetryEventKind(StrEnum):
    TRACE_CLOSED = "telemetry.trace_closed"
    TRACE_TRUNCATED = "telemetry.trace_truncated"
    TRACE_REJECTED = "telemetry.trace_rejected"


class ControlEventKind(StrEnum):
    AUTHORIZATION_GRANTED = "control.authorization_granted"
    AUTHORIZATION_DENIED = "control.authorization_denied"
    AUTHORIZATION_FAILED_CLOSED = "control.authorization_failed_closed"


class AuditSeverity(StrEnum):
    INFO = "info"
    WARN = "warn"
    CRITICAL = "critical"


class FindingCategory(StrEnum):
    DUPLICATION = "duplication"
    ADVERSARIAL = "adversarial"
    LEGITIMATE_USER = "legitimate_user"
    CONTRACT = "contract"
    INTEGRATION = "integration"


# Canonical ordinal tables — single source of truth per concept.
_TRUST_LEVEL_ORDER: tuple[TrustLevel, ...] = (
    TrustLevel.UNTRUSTED, TrustLevel.LOW, TrustLevel.MEDIUM,
    TrustLevel.HIGH, TrustLevel.FULL,
)
_TRUST_LEVEL_RANK: dict[TrustLevel, int] = {
    lvl: i for i, lvl in enumerate(_TRUST_LEVEL_ORDER)
}
_TRUST_LEVEL_THRESHOLDS: tuple[tuple[float, TrustLevel], ...] = (
    (0.80, TrustLevel.FULL), (0.60, TrustLevel.HIGH),
    (0.40, TrustLevel.MEDIUM), (0.20, TrustLevel.LOW),
    (0.00, TrustLevel.UNTRUSTED),
)
_CONTAINMENT_ORDER: tuple[ContainmentLevel, ...] = (
    ContainmentLevel.NONE, ContainmentLevel.MONITOR,
    ContainmentLevel.RESTRICT, ContainmentLevel.ISOLATE,
    ContainmentLevel.TERMINATE,
)
_CONTAINMENT_RANK: dict[ContainmentLevel, int] = {
    lvl: i for i, lvl in enumerate(_CONTAINMENT_ORDER)
}
_STAGE_RANK: dict[Stage, int] = {s: i for i, s in enumerate(Stage)}
_TERMINAL_SESSION_STATES: frozenset[SessionState] = frozenset(
    {SessionState.EXPIRED, SessionState.REVOKED}
)


def _trust_level_at_least(level: TrustLevel, minimum: TrustLevel) -> bool:
    return _TRUST_LEVEL_RANK[level] >= _TRUST_LEVEL_RANK[minimum]


def _score_to_level(score: float) -> TrustLevel:
    for threshold, level in _TRUST_LEVEL_THRESHOLDS:
        if score >= threshold:
            return level
    raise AssertionError(f"trust-level table misconfigured: score={score}")


def _max_containment(a: ContainmentLevel, b: ContainmentLevel) -> ContainmentLevel:
    return a if _CONTAINMENT_RANK[a] >= _CONTAINMENT_RANK[b] else b


# ═════════════════════════════════════════════════════════════════════════
# §3  IDENTIFIERS
# ═════════════════════════════════════════════════════════════════════════

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.\-:]{0,127}")


class Identifier:
    """Typed, validated, immutable identifier base.

    Subclasses MUST declare ``__slots__ = ()``.  Direct instantiation
    is forbidden."""

    __slots__ = ("_value",)
    _value: str

    def __init__(self, value: str) -> None:
        if type(self) is Identifier:
            raise TypeError(
                "Identifier is abstract; instantiate a concrete subtype."
            )
        if not isinstance(value, str):
            raise TypeError(
                f"{type(self).__name__}.value must be str, "
                f"got {type(value).__name__}"
            )
        if not value:
            raise ValueError(f"{type(self).__name__}.value must be non-empty")
        if not _ID_RE.fullmatch(value):
            raise ValueError(
                f"{type(self).__name__}.value {value!r} is not a valid "
                "identifier (expected [A-Za-z0-9][A-Za-z0-9_.\\-:]{0,127})"
            )
        object.__setattr__(self, "_value", value)

    @property
    def value(self) -> str:
        return self._value

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(f"{type(self).__name__} is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError(f"{type(self).__name__} is immutable")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Identifier):
            return NotImplemented
        return type(self) is type(other) and self._value == other._value

    def __hash__(self) -> int:
        return hash((type(self), self._value))

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self._value!r})"

    def __str__(self) -> str:
        return self._value


class SubjectId(Identifier): __slots__ = ()
class SessionId(Identifier): __slots__ = ()
class ResourceId(Identifier): __slots__ = ()
class AuthorityId(Identifier): __slots__ = ()
class PolicyId(Identifier): __slots__ = ()
class DecisionId(Identifier): __slots__ = ()
class EventId(Identifier): __slots__ = ()
class CorrelationId(Identifier): __slots__ = ()
class DelegationId(Identifier): __slots__ = ()
class ContainmentId(Identifier): __slots__ = ()
class EvidenceId(Identifier): __slots__ = ()
class ReviewRequestId(Identifier): __slots__ = ()


# ═════════════════════════════════════════════════════════════════════════
# §4  CLOCKS
# ═════════════════════════════════════════════════════════════════════════

@runtime_checkable
class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    __slots__ = ()
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


def _require_aware(value: datetime, *, context: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{context} expected datetime, got {type(value).__name__}")
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{context} requires a timezone-aware datetime")


class FrozenClock:
    __slots__ = ("_now",)
    def __init__(self, now: datetime) -> None:
        _require_aware(now, context="FrozenClock(now=...)")
        self._now = now
    def now(self) -> datetime:
        return self._now
    def advance(self, delta: timedelta) -> None:
        if not isinstance(delta, timedelta):
            raise TypeError(f"delta must be timedelta, got {type(delta).__name__}")
        self._now = self._now + delta
    def set(self, now: datetime) -> None:
        _require_aware(now, context="FrozenClock.set(now=...)")
        self._now = now


@runtime_checkable
class LatencyClock(Protocol):
    def now_ns(self) -> int: ...


class SystemLatencyClock:
    __slots__ = ()
    def now_ns(self) -> int:
        return time.perf_counter_ns()


class FrozenLatencyClock:
    __slots__ = ("_ns",)
    def __init__(self, start_ns: int = 0) -> None:
        if isinstance(start_ns, bool) or not isinstance(start_ns, int):
            raise TypeError("start_ns must be int")
        if start_ns < 0:
            raise ValueError("start_ns must be >= 0")
        self._ns = start_ns
    def now_ns(self) -> int:
        return self._ns
    def advance_ns(self, delta_ns: int) -> None:
        if isinstance(delta_ns, bool) or not isinstance(delta_ns, int):
            raise TypeError("delta_ns must be int")
        if delta_ns < 0:
            raise ValueError("delta_ns must be >= 0")
        self._ns += delta_ns


# ═════════════════════════════════════════════════════════════════════════
# §5  AUDIT
# ═════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True, slots=True)
class AuditEvent:
    """Immutable audit event.  Payload defensively copied + frozen."""
    event_id: EventId
    occurred_at: datetime
    kind: Any  # one of the StrEnum families; see module docstring
    payload: Mapping[str, Any] = field(default_factory=dict)
    correlation_id: CorrelationId | None = None
    actor: SubjectId | None = None

    def __post_init__(self) -> None:
        _require_aware(self.occurred_at, context="AuditEvent.occurred_at")
        object.__setattr__(self, "payload", MappingProxyType(dict(self.payload)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id.value,
            "occurred_at": self.occurred_at.isoformat(),
            "kind": str(self.kind),
            "correlation_id": self.correlation_id.value if self.correlation_id else None,
            "actor": self.actor.value if self.actor else None,
            "payload": dict(self.payload),
        }


@runtime_checkable
class AuditSink(Protocol):
    def emit(self, event: AuditEvent) -> None: ...


class InMemoryAuditSink:
    """Thread-safe in-memory audit sink (test/dev only)."""
    __slots__ = ("_events", "_lock")
    def __init__(self) -> None:
        self._events: list[AuditEvent] = []
        self._lock = threading.Lock()
    def emit(self, event: AuditEvent) -> None:
        if not isinstance(event, AuditEvent):
            raise TypeError(
                f"InMemoryAuditSink.emit expected AuditEvent, "
                f"got {type(event).__name__}"
            )
        with self._lock:
            self._events.append(event)
    def events(self) -> tuple[AuditEvent, ...]:
        with self._lock:
            return tuple(self._events)
    def clear(self) -> None:
        with self._lock:
            self._events.clear()
    def __len__(self) -> int:
        with self._lock:
            return len(self._events)


def _emit_event(
    audit: AuditSink,
    kind: Any,
    payload: Mapping[str, Any],
    *,
    actor: SubjectId | None = None,
    correlation_id: CorrelationId | None = None,
) -> None:
    """Shared audit-emission helper.

    Uses wall-clock time so a broken logical clock cannot suppress the
    audit trail.  Correlation id is optional and passed through."""
    audit.emit(AuditEvent(
        event_id=EventId(f"evt-{secrets.token_hex(8)}"),
        occurred_at=datetime.now(timezone.utc),
        kind=kind,
        payload=dict(payload),
        actor=actor,
        correlation_id=correlation_id,
    ))


# ═════════════════════════════════════════════════════════════════════════
# §6  CONFIG
# ═════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True, slots=True)
class KernelConfig:
    """Kernel config.  Safe defaults: production + audit on + fail-closed."""
    environment: Environment = Environment.PRODUCTION
    audit_enabled: bool = True
    fail_closed: bool = True

    @classmethod
    def testing(cls) -> "KernelConfig":
        return cls(environment=Environment.TESTING)
    @classmethod
    def development(cls) -> "KernelConfig":
        return cls(environment=Environment.DEVELOPMENT)


@dataclass(frozen=True, slots=True)
class TrustPolicy:
    """Immutable trust-evaluation policy."""
    name: str
    kind_weights: Mapping[EvidenceKind, float]
    half_life: timedelta
    min_evidence_for_full_trust: float

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise TrustPolicyError("TrustPolicy.name must be non-empty")
        if not isinstance(self.kind_weights, Mapping) or not self.kind_weights:
            raise TrustPolicyError("TrustPolicy.kind_weights must be a non-empty mapping")
        clean: dict[EvidenceKind, float] = {}
        for k, v in self.kind_weights.items():
            if not isinstance(k, EvidenceKind):
                raise TrustPolicyError("kind_weights keys must be EvidenceKind")
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                raise TrustPolicyError("kind_weights values must be numeric")
            fv = float(v)
            if not math.isfinite(fv) or fv < 0.0:
                raise TrustPolicyError("kind_weights values must be finite >= 0")
            clean[k] = fv
        object.__setattr__(self, "kind_weights", MappingProxyType(clean))
        if not isinstance(self.half_life, timedelta) or self.half_life <= timedelta(0):
            raise TrustPolicyError("half_life must be a positive timedelta")
        mv = self.min_evidence_for_full_trust
        if isinstance(mv, bool) or not isinstance(mv, (int, float)):
            raise TrustPolicyError("min_evidence_for_full_trust must be numeric")
        mvf = float(mv)
        if not math.isfinite(mvf) or mvf <= 0.0:
            raise TrustPolicyError("min_evidence_for_full_trust must be > 0")
        object.__setattr__(self, "min_evidence_for_full_trust", mvf)

    @classmethod
    def conservative_default(cls) -> "TrustPolicy":
        return cls(
            name="conservative-default@v1",
            kind_weights={
                EvidenceKind.AUTHENTICATION: 1.0,
                EvidenceKind.ATTESTATION: 0.7,
                EvidenceKind.MANUAL_VOUCH: 0.5,
                EvidenceKind.HISTORY: 0.3,
                EvidenceKind.NETWORK_CONTEXT: 0.2,
            },
            half_life=timedelta(hours=1),
            min_evidence_for_full_trust=2.0,
        )


@dataclass(frozen=True, slots=True)
class ContainmentPolicy:
    max_auto_release_level: ContainmentLevel = ContainmentLevel.RESTRICT
    require_review_for_levels: frozenset[ContainmentLevel] = field(
        default_factory=lambda: frozenset({ContainmentLevel.TERMINATE})
    )
    history_limit_per_subject: int = 32

    def __post_init__(self) -> None:
        if not isinstance(self.max_auto_release_level, ContainmentLevel):
            raise ContainmentPolicyError("max_auto_release_level must be ContainmentLevel")
        if not isinstance(self.require_review_for_levels, frozenset):
            raise ContainmentPolicyError("require_review_for_levels must be frozenset")
        for lvl in self.require_review_for_levels:
            if not isinstance(lvl, ContainmentLevel):
                raise ContainmentPolicyError("review levels must be ContainmentLevel")
        if isinstance(self.history_limit_per_subject, bool) or not isinstance(self.history_limit_per_subject, int):
            raise ContainmentPolicyError("history_limit_per_subject must be int")
        if self.history_limit_per_subject <= 0:
            raise ContainmentPolicyError("history_limit_per_subject must be > 0")

    @classmethod
    def default(cls) -> "ContainmentPolicy":
        return cls()


@dataclass(frozen=True, slots=True)
class DelegationPolicy:
    max_chain_depth: int = 3
    permitted_delegator_kinds: frozenset[IdentityKind] = frozenset({
        IdentityKind.HUMAN, IdentityKind.SERVICE_ACCOUNT,
    })
    permitted_delegatee_kinds: frozenset[IdentityKind] = frozenset({
        IdentityKind.HUMAN, IdentityKind.SERVICE_ACCOUNT,
        IdentityKind.WORKLOAD, IdentityKind.AI_AGENT, IdentityKind.DEVICE,
    })
    max_ttl: timedelta = timedelta(hours=24)

    def __post_init__(self) -> None:
        if isinstance(self.max_chain_depth, bool) or not isinstance(self.max_chain_depth, int):
            raise DelegationPolicyError("max_chain_depth must be int")
        if self.max_chain_depth < 0:
            raise DelegationPolicyError("max_chain_depth must be >= 0")
        for fname, kinds in (
            ("permitted_delegator_kinds", self.permitted_delegator_kinds),
            ("permitted_delegatee_kinds", self.permitted_delegatee_kinds),
        ):
            if not isinstance(kinds, frozenset):
                raise DelegationPolicyError(f"{fname} must be frozenset")
            for k in kinds:
                if not isinstance(k, IdentityKind):
                    raise DelegationPolicyError(f"{fname} elements must be IdentityKind")
        if not isinstance(self.max_ttl, timedelta) or self.max_ttl <= timedelta(0):
            raise DelegationPolicyError("max_ttl must be a positive timedelta")

    @classmethod
    def default(cls) -> "DelegationPolicy":
        return cls()


@dataclass(frozen=True, slots=True)
class TelemetryConfig:
    max_traces: int = 1024
    max_steps_per_trace: int = 64

    def __post_init__(self) -> None:
        for name, value in (
            ("max_traces", self.max_traces),
            ("max_steps_per_trace", self.max_steps_per_trace),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TelemetryConfigError(f"{name} must be int")
            if value <= 0:
                raise TelemetryConfigError(f"{name} must be > 0")

    @classmethod
    def default(cls) -> "TelemetryConfig":
        return cls()


@dataclass(frozen=True, slots=True)
class ControlPlaneConfig:
    require_session: bool = True
    require_authority_ttl: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.require_session, bool):
            raise ControlPlaneConfigError("require_session must be bool")
        if not isinstance(self.require_authority_ttl, bool):
            raise ControlPlaneConfigError("require_authority_ttl must be bool")

    @classmethod
    def default(cls) -> "ControlPlaneConfig":
        return cls()


# ═════════════════════════════════════════════════════════════════════════
# §7  TRUST
# ═════════════════════════════════════════════════════════════════════════

class TrustScore:
    """Immutable, validated score in [0.0, 1.0]."""
    __slots__ = ("_value",)
    _value: float

    def __init__(self, value: float) -> None:
        if isinstance(value, bool):
            raise TypeError("TrustScore must not be bool")
        if not isinstance(value, (int, float)):
            raise TypeError(f"TrustScore must be numeric, got {type(value).__name__}")
        v = float(value)
        if not math.isfinite(v):
            raise ValueError(f"TrustScore must be finite, got {value!r}")
        if not (0.0 <= v <= 1.0):
            raise ValueError(f"TrustScore must be in [0.0, 1.0], got {value!r}")
        object.__setattr__(self, "_value", v)

    @property
    def value(self) -> float:
        return self._value

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("TrustScore is immutable")
    def __delattr__(self, name: str) -> None:
        raise AttributeError("TrustScore is immutable")

    def _cmp(self, other: object, op: Callable[[float, float], bool]) -> Any:
        if isinstance(other, TrustScore):
            return op(self._value, other._value)
        return NotImplemented

    def __eq__(self, o: object) -> bool: return self._cmp(o, lambda a, b: a == b)
    def __lt__(self, o: object) -> bool: return self._cmp(o, lambda a, b: a < b)
    def __le__(self, o: object) -> bool: return self._cmp(o, lambda a, b: a <= b)
    def __gt__(self, o: object) -> bool: return self._cmp(o, lambda a, b: a > b)
    def __ge__(self, o: object) -> bool: return self._cmp(o, lambda a, b: a >= b)
    def __hash__(self) -> int: return hash(self._value)
    def __repr__(self) -> str: return f"TrustScore({self._value!r})"
    def __str__(self) -> str: return f"{self._value:.6f}"


@dataclass(frozen=True, slots=True)
class Evidence:
    """One observation.  Immutable, validated, subject-bound."""
    evidence_id: EvidenceId
    subject_id: SubjectId
    kind: EvidenceKind
    polarity: EvidencePolarity
    strength: TrustScore
    observed_at: datetime
    source: str

    def __post_init__(self) -> None:
        if not isinstance(self.evidence_id, EvidenceId):
            raise TypeError("Evidence.evidence_id must be EvidenceId")
        if not isinstance(self.subject_id, SubjectId):
            raise TypeError("Evidence.subject_id must be SubjectId")
        if not isinstance(self.kind, EvidenceKind):
            raise TypeError("Evidence.kind must be EvidenceKind")
        if not isinstance(self.polarity, EvidencePolarity):
            raise TypeError("Evidence.polarity must be EvidencePolarity")
        if not isinstance(self.strength, TrustScore):
            raise TypeError("Evidence.strength must be TrustScore")
        _require_aware(self.observed_at, context="Evidence.observed_at")
        if not isinstance(self.source, str) or not self.source.strip():
            raise ValueError("Evidence.source must be a non-empty string")


@dataclass(frozen=True, slots=True)
class Contribution:
    evidence_id: EvidenceId
    kind: EvidenceKind
    polarity: EvidencePolarity
    strength: float
    weight: float
    decay: float
    mass: float


@dataclass(frozen=True, slots=True)
class Rejection:
    evidence_id: EvidenceId
    reason: str


@dataclass(frozen=True, slots=True)
class TrustAssessment:
    """Immutable result of trust evaluation."""
    subject_id: SubjectId
    score: TrustScore
    level: TrustLevel
    computed_at: datetime
    policy_name: str
    contributions: tuple[Contribution, ...] = ()
    rejections: tuple[Rejection, ...] = ()
    failed_closed: bool = False
    failure_reason: str | None = None

    def __post_init__(self) -> None:
        _require_aware(self.computed_at, context="TrustAssessment.computed_at")
        if self.failed_closed and self.failure_reason is None:
            raise ValueError("failed_closed=True requires failure_reason")
        if not self.failed_closed and self.failure_reason is not None:
            raise ValueError("failure_reason only valid when failed_closed=True")

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject_id": self.subject_id.value,
            "score": self.score.value,
            "level": self.level.value,
            "computed_at": self.computed_at.isoformat(),
            "policy_name": self.policy_name,
            "failed_closed": self.failed_closed,
            "failure_reason": self.failure_reason,
            "contributions": [
                {
                    "evidence_id": c.evidence_id.value, "kind": c.kind.value,
                    "polarity": c.polarity.value, "strength": c.strength,
                    "weight": c.weight, "decay": c.decay, "mass": c.mass,
                } for c in self.contributions
            ],
            "rejections": [
                {"evidence_id": r.evidence_id.value, "reason": r.reason}
                for r in self.rejections
            ],
        }


class StandardTrustEngine:
    """Default trust engine.

    Failure model:
      * Contract violations raise (TypeError/ValueError).
      * Runtime errors fail closed with a flagged TrustAssessment.
      * AuditSinkError always propagates.
    """
    __slots__ = ("_clock", "_audit")

    def __init__(self, clock: Clock, audit: AuditSink) -> None:
        if not isinstance(clock, Clock):
            raise TypeError("clock must satisfy Clock protocol")
        if not isinstance(audit, AuditSink):
            raise TypeError("audit must satisfy AuditSink protocol")
        self._clock = clock
        self._audit = audit

    def assess(
        self,
        subject_id: SubjectId,
        evidence: Iterable[Evidence],
        policy: TrustPolicy,
    ) -> TrustAssessment:
        if not isinstance(subject_id, SubjectId):
            raise TypeError("subject_id must be SubjectId")
        if not isinstance(policy, TrustPolicy):
            raise TypeError("policy must be TrustPolicy")
        if isinstance(evidence, (str, bytes)):
            raise TypeError("evidence must be iterable of Evidence")
        try:
            evidence_tuple = tuple(evidence)
        except TypeError as exc:
            raise TypeError("evidence must be iterable") from exc
        for e in evidence_tuple:
            if not isinstance(e, Evidence):
                raise TypeError(f"evidence items must be Evidence, got {type(e).__name__}")

        try:
            now = self._clock.now()
        except Exception as exc:
            return self._fail_closed(subject_id, policy, exc, datetime.now(timezone.utc))

        try:
            return self._evaluate(subject_id, evidence_tuple, policy, now)
        except AuditSinkError:
            raise
        except Exception as exc:
            return self._fail_closed(subject_id, policy, exc, now)

    def _evaluate(self, subject_id, evidence, policy, now) -> TrustAssessment:
        ordered = sorted(evidence, key=lambda e: e.evidence_id.value)
        seen: set[str] = set()
        contributions: list[Contribution] = []
        rejections: list[Rejection] = []
        half_life_s = policy.half_life.total_seconds()

        for e in ordered:
            if e.subject_id != subject_id:
                rejections.append(Rejection(e.evidence_id, "subject_mismatch"))
                _emit_event(self._audit, TrustEventKind.TRUST_EVIDENCE_REJECTED,
                            {"evidence_id": e.evidence_id.value,
                             "reason": "subject_mismatch",
                             "expected_subject": subject_id.value,
                             "actual_subject": e.subject_id.value},
                            actor=subject_id)
                continue
            if e.evidence_id.value in seen:
                rejections.append(Rejection(e.evidence_id, "duplicate_id"))
                _emit_event(self._audit, TrustEventKind.TRUST_EVIDENCE_REJECTED,
                            {"evidence_id": e.evidence_id.value,
                             "reason": "duplicate_id"},
                            actor=subject_id)
                continue
            seen.add(e.evidence_id.value)

            weight = float(policy.kind_weights.get(e.kind, 0.0))
            age_s = (now - e.observed_at).total_seconds()
            if age_s < 0.0:
                age_s = 0.0
            decay = math.pow(0.5, age_s / half_life_s)
            decay = min(1.0, max(0.0, decay))
            mass = weight * decay * e.strength.value
            contributions.append(Contribution(
                evidence_id=e.evidence_id, kind=e.kind, polarity=e.polarity,
                strength=e.strength.value, weight=weight, decay=decay, mass=mass,
            ))

        pos_mass = sum(c.mass for c in contributions
                       if c.polarity is EvidencePolarity.POSITIVE)
        neg_mass = sum(c.mass for c in contributions
                       if c.polarity is EvidencePolarity.NEGATIVE)
        denom = policy.min_evidence_for_full_trust
        pos_ratio = min(pos_mass / denom, 1.0)
        neg_ratio = min(neg_mass / denom, 1.0)
        raw = min(1.0, max(0.0, pos_ratio * (1.0 - neg_ratio)))

        assessment = TrustAssessment(
            subject_id=subject_id, score=TrustScore(raw),
            level=_score_to_level(raw), computed_at=now,
            policy_name=policy.name,
            contributions=tuple(contributions),
            rejections=tuple(rejections),
        )
        _emit_event(self._audit, TrustEventKind.TRUST_ASSESSED,
                    {"subject_id": subject_id.value,
                     "policy_name": policy.name,
                     "score": assessment.score.value,
                     "level": assessment.level.value,
                     "accepted": len(contributions),
                     "rejected": len(rejections)},
                    actor=subject_id)
        return assessment

    def _fail_closed(self, subject_id, policy, exc, now) -> TrustAssessment:
        reason = f"{type(exc).__name__}: {exc}"
        _emit_event(self._audit, TrustEventKind.TRUST_FAILED_CLOSED,
                    {"subject_id": subject_id.value,
                     "policy_name": policy.name, "reason": reason},
                    actor=subject_id)
        return TrustAssessment(
            subject_id=subject_id, score=TrustScore(0.0),
            level=TrustLevel.UNTRUSTED, computed_at=now,
            policy_name=policy.name, failed_closed=True, failure_reason=reason,
        )


# ═════════════════════════════════════════════════════════════════════════
# §8  POLICY
# ═════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True, slots=True)
class PolicyRule:
    name: str
    outcome: RuleOutcome
    min_trust_level: TrustLevel = TrustLevel.UNTRUSTED
    action_kinds: frozenset[ActionKind] = field(default_factory=frozenset)
    resource_ids: frozenset[ResourceId] = field(default_factory=frozenset)
    required_attributes: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise PolicyConstructionError("PolicyRule.name must be non-empty")
        if not isinstance(self.outcome, RuleOutcome):
            raise PolicyConstructionError("PolicyRule.outcome must be RuleOutcome")
        if not isinstance(self.min_trust_level, TrustLevel):
            raise PolicyConstructionError("min_trust_level must be TrustLevel")
        if not isinstance(self.action_kinds, frozenset):
            raise PolicyConstructionError("action_kinds must be frozenset")
        for a in self.action_kinds:
            if not isinstance(a, ActionKind):
                raise PolicyConstructionError("action_kinds elements must be ActionKind")
        if not isinstance(self.resource_ids, frozenset):
            raise PolicyConstructionError("resource_ids must be frozenset")
        for r in self.resource_ids:
            if not isinstance(r, ResourceId):
                raise PolicyConstructionError("resource_ids elements must be ResourceId")
        for k, v in self.required_attributes.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise PolicyConstructionError("required_attributes must map str->str")
        object.__setattr__(self, "required_attributes",
                           MappingProxyType(dict(self.required_attributes)))

    def matches(self, *, subject, resource_id, action, trust_level) -> bool:
        if self.action_kinds and action not in self.action_kinds:
            return False
        if self.resource_ids and resource_id not in self.resource_ids:
            return False
        if not _trust_level_at_least(trust_level, self.min_trust_level):
            return False
        for k, v in self.required_attributes.items():
            if subject.attributes.get(k) != v:
                return False
        return True


@dataclass(frozen=True, slots=True)
class Policy:
    name: str
    rules: tuple[PolicyRule, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise PolicyConstructionError("Policy.name must be non-empty")
        if not isinstance(self.rules, tuple):
            raise PolicyConstructionError("Policy.rules must be a tuple")
        for r in self.rules:
            if not isinstance(r, PolicyRule):
                raise PolicyConstructionError("Policy.rules elements must be PolicyRule")
        names = [r.name for r in self.rules]
        if len(names) != len(set(names)):
            raise PolicyConstructionError("Policy.rules must have unique names")


@dataclass(frozen=True, slots=True)
class Decision:
    """Immutable decision.  Embeds the driving TrustAssessment so the
    full chain is reconstructible from one object."""
    decision_id: DecisionId
    subject_id: SubjectId
    session_id: SessionId | None
    resource_id: ResourceId
    action: ActionKind
    outcome: DecisionOutcome
    policy_name: str
    matched_rule_names: tuple[str, ...]
    reason: str
    decided_at: datetime
    assessment: TrustAssessment
    failed_closed: bool = False
    failure_reason: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.decision_id, DecisionId):
            raise DecisionError("decision_id must be DecisionId")
        if not isinstance(self.subject_id, SubjectId):
            raise DecisionError("subject_id must be SubjectId")
        if self.session_id is not None and not isinstance(self.session_id, SessionId):
            raise DecisionError("session_id must be SessionId or None")
        if not isinstance(self.resource_id, ResourceId):
            raise DecisionError("resource_id must be ResourceId")
        if not isinstance(self.action, ActionKind):
            raise DecisionError("action must be ActionKind")
        if not isinstance(self.outcome, DecisionOutcome):
            raise DecisionError("outcome must be DecisionOutcome")
        _require_aware(self.decided_at, context="Decision.decided_at")
        if not isinstance(self.policy_name, str) or not self.policy_name.strip():
            raise DecisionError("policy_name must be non-empty")
        if not isinstance(self.matched_rule_names, tuple):
            raise DecisionError("matched_rule_names must be a tuple")
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise DecisionError("reason must be non-empty")
        if not isinstance(self.assessment, TrustAssessment):
            raise DecisionError("assessment must be TrustAssessment")
        if self.assessment.subject_id != self.subject_id:
            raise DecisionError("assessment.subject_id must match decision.subject_id")
        if self.failed_closed and self.failure_reason is None:
            raise DecisionError("failed_closed=True requires failure_reason")
        if not self.failed_closed and self.failure_reason is not None:
            raise DecisionError("failure_reason only valid when failed_closed=True")
        if self.failed_closed and self.outcome is not DecisionOutcome.DENY:
            raise DecisionError("failed_closed=True must have outcome=DENY")

    def is_authorizable(self) -> bool:
        return self.outcome is DecisionOutcome.ALLOW and not self.failed_closed

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id.value,
            "subject_id": self.subject_id.value,
            "session_id": self.session_id.value if self.session_id else None,
            "resource_id": self.resource_id.value,
            "action": self.action.value,
            "outcome": self.outcome.value,
            "policy_name": self.policy_name,
            "matched_rule_names": list(self.matched_rule_names),
            "reason": self.reason,
            "decided_at": self.decided_at.isoformat(),
            "failed_closed": self.failed_closed,
            "failure_reason": self.failure_reason,
            "assessment": self.assessment.to_dict(),
        }


class PolicyEngine:
    """Default policy engine.  Deny-overrides; default-deny.

    Failure model mirrors trust engine: contract violations raise;
    runtime errors fail closed to DENY; AuditSinkError propagates."""
    __slots__ = ("_clock", "_audit")

    def __init__(self, clock: Clock, audit: AuditSink) -> None:
        if not isinstance(clock, Clock):
            raise TypeError("clock must satisfy Clock protocol")
        if not isinstance(audit, AuditSink):
            raise TypeError("audit must satisfy AuditSink protocol")
        self._clock = clock
        self._audit = audit

    def evaluate(
        self, *, subject, session_id, resource_id, action,
        assessment, policy,
    ) -> Decision:
        # contract validation
        if not isinstance(subject, Subject):
            raise TypeError("subject must be Subject")
        if session_id is not None and not isinstance(session_id, SessionId):
            raise TypeError("session_id must be SessionId or None")
        if not isinstance(resource_id, ResourceId):
            raise TypeError("resource_id must be ResourceId")
        if not isinstance(action, ActionKind):
            raise TypeError("action must be ActionKind")
        if not isinstance(assessment, TrustAssessment):
            raise TypeError("assessment must be TrustAssessment")
        if not isinstance(policy, Policy):
            raise TypeError("policy must be Policy")
        if assessment.subject_id != subject.subject_id:
            raise DecisionError(
                "assessment.subject_id must match subject.subject_id"
            )

        try:
            now = self._clock.now()
        except Exception as exc:
            return self._fail_closed(subject, session_id, resource_id, action,
                                     assessment, policy, exc,
                                     datetime.now(timezone.utc))
        try:
            return self._evaluate(subject, session_id, resource_id, action,
                                  assessment, policy, now)
        except AuditSinkError:
            raise
        except Exception as exc:
            return self._fail_closed(subject, session_id, resource_id, action,
                                     assessment, policy, exc, now)

    def _evaluate(self, subject, session_id, resource_id, action,
                  assessment, policy, now) -> Decision:
        if assessment.failed_closed:
            d = Decision(
                decision_id=DecisionId(f"dec-{secrets.token_hex(8)}"),
                subject_id=subject.subject_id, session_id=session_id,
                resource_id=resource_id, action=action,
                outcome=DecisionOutcome.DENY, policy_name=policy.name,
                matched_rule_names=(), reason="trust_assessment_failed_closed",
                decided_at=now, assessment=assessment,
                failed_closed=True,
                failure_reason="trust_assessment_failed_closed",
            )
            self._emit(d)
            return d

        matched_allow: list[PolicyRule] = []
        matched_deny: list[PolicyRule] = []
        for rule in policy.rules:
            if rule.matches(subject=subject, resource_id=resource_id,
                            action=action, trust_level=assessment.level):
                (matched_allow if rule.outcome is RuleOutcome.ALLOW
                 else matched_deny).append(rule)

        if matched_deny:
            outcome, names, reason = DecisionOutcome.DENY, \
                tuple(r.name for r in matched_deny), "deny_rule_matched"
        elif matched_allow:
            outcome, names, reason = DecisionOutcome.ALLOW, \
                tuple(r.name for r in matched_allow), "allow_rule_matched"
        else:
            outcome, names, reason = DecisionOutcome.DENY, (), "no_matching_rule"

        d = Decision(
            decision_id=DecisionId(f"dec-{secrets.token_hex(8)}"),
            subject_id=subject.subject_id, session_id=session_id,
            resource_id=resource_id, action=action, outcome=outcome,
            policy_name=policy.name, matched_rule_names=names,
            reason=reason, decided_at=now, assessment=assessment,
        )
        self._emit(d)
        return d

    def _emit(self, d: Decision) -> None:
        _emit_event(self._audit, PolicyEventKind.POLICY_EVALUATED, {
            "decision_id": d.decision_id.value,
            "subject_id": d.subject_id.value,
            "resource_id": d.resource_id.value,
            "action": d.action.value,
            "outcome": d.outcome.value,
            "reason": d.reason,
            "policy_name": d.policy_name,
            "trust_level": d.assessment.level.value,
            "trust_score": d.assessment.score.value,
            "matched_rule_names": list(d.matched_rule_names),
        }, actor=d.subject_id)

    def _fail_closed(self, subject, session_id, resource_id, action,
                     assessment, policy, exc, now) -> Decision:
        reason = f"{type(exc).__name__}: {exc}"
        d = Decision(
            decision_id=DecisionId(f"dec-{secrets.token_hex(8)}"),
            subject_id=subject.subject_id, session_id=session_id,
            resource_id=resource_id, action=action,
            outcome=DecisionOutcome.DENY, policy_name=policy.name,
            matched_rule_names=(), reason="evaluation_failed",
            decided_at=now, assessment=assessment,
            failed_closed=True, failure_reason=reason,
        )
        _emit_event(self._audit, PolicyEventKind.POLICY_EVALUATION_FAILED, {
            "decision_id": d.decision_id.value,
            "subject_id": d.subject_id.value,
            "policy_name": d.policy_name,
            "reason": d.failure_reason,
        }, actor=d.subject_id)
        return d


# ═════════════════════════════════════════════════════════════════════════
# §9  AUTHORITY
# ═════════════════════════════════════════════════════════════════════════

_MIN_KEY_BYTES = 32


def _authority_canonical_bytes(
    *, authority_id, subject_id, session_id, resource_ids,
    action_kinds, issued_at, expires_at, issuer, single_use,
) -> bytes:
    """Canonical, NUL-separated, version-tagged encoding of signed fields."""
    return b"\x00".join([
        b"hydra.authority.v1",
        authority_id.value.encode("utf-8"),
        subject_id.value.encode("utf-8"),
        session_id.value.encode("utf-8") if session_id else b"",
        b"|".join(sorted(r.value.encode("utf-8") for r in resource_ids)),
        b"|".join(sorted(a.value.encode("utf-8") for a in action_kinds)),
        issued_at.isoformat().encode("utf-8"),
        expires_at.isoformat().encode("utf-8"),
        issuer.encode("utf-8"),
        b"1" if single_use else b"0",
    ])


@dataclass(frozen=True, slots=True)
class Authority:
    """Immutable, self-contained authority token."""
    authority_id: AuthorityId
    subject_id: SubjectId
    session_id: SessionId | None
    resource_ids: frozenset[ResourceId]
    action_kinds: frozenset[ActionKind]
    issued_at: datetime
    expires_at: datetime
    issuer: str
    single_use: bool
    signature: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.authority_id, AuthorityId):
            raise AuthorityError("authority_id must be AuthorityId")
        if not isinstance(self.subject_id, SubjectId):
            raise AuthorityError("subject_id must be SubjectId")
        if self.session_id is not None and not isinstance(self.session_id, SessionId):
            raise AuthorityError("session_id must be SessionId or None")
        if not isinstance(self.resource_ids, frozenset) or not self.resource_ids:
            raise AuthorityError("resource_ids must be non-empty frozenset")
        if not isinstance(self.action_kinds, frozenset) or not self.action_kinds:
            raise AuthorityError("action_kinds must be non-empty frozenset")
        _require_aware(self.issued_at, context="Authority.issued_at")
        _require_aware(self.expires_at, context="Authority.expires_at")
        if self.expires_at <= self.issued_at:
            raise AuthorityError("expires_at must be after issued_at")
        if not isinstance(self.issuer, str) or not self.issuer.strip():
            raise AuthorityError("issuer must be non-empty")
        if not isinstance(self.single_use, bool):
            raise AuthorityError("single_use must be bool")
        if not isinstance(self.signature, bytes) or len(self.signature) != 32:
            raise AuthorityError("signature must be 32 bytes (SHA-256 HMAC)")

    def canonical_bytes(self) -> bytes:
        return _authority_canonical_bytes(
            authority_id=self.authority_id, subject_id=self.subject_id,
            session_id=self.session_id, resource_ids=self.resource_ids,
            action_kinds=self.action_kinds, issued_at=self.issued_at,
            expires_at=self.expires_at, issuer=self.issuer,
            single_use=self.single_use,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "authority_id": self.authority_id.value,
            "subject_id": self.subject_id.value,
            "session_id": self.session_id.value if self.session_id else None,
            "resource_ids": sorted(r.value for r in self.resource_ids),
            "action_kinds": sorted(a.value for a in self.action_kinds),
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "issuer": self.issuer,
            "single_use": self.single_use,
            "signature_hex": self.signature.hex(),
        }


@dataclass(frozen=True, slots=True)
class AuthorityValidation:
    authority_id: AuthorityId
    valid: bool
    reason: str
    checked_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.authority_id, AuthorityId):
            raise AuthorityError("authority_id must be AuthorityId")
        if not isinstance(self.valid, bool):
            raise AuthorityError("valid must be bool")
        if not isinstance(self.reason, str) or not self.reason:
            raise AuthorityError("reason must be non-empty")
        _require_aware(self.checked_at, context="AuthorityValidation.checked_at")

    def to_dict(self) -> dict[str, Any]:
        return {
            "authority_id": self.authority_id.value,
            "valid": self.valid,
            "reason": self.reason,
            "checked_at": self.checked_at.isoformat(),
        }


class AuthorityEngine:
    """Signs, validates, and revokes authority tokens.

    Key management is out of scope (KMS/HSM); the HMAC key is a
    constructor argument.
    """
    __slots__ = ("_key", "_clock", "_audit", "_revoked", "_used", "_lock")

    def __init__(self, key: bytes, clock: Clock, audit: AuditSink) -> None:
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError(f"key must be bytes, got {type(key).__name__}")
        kb = bytes(key)
        if len(kb) < _MIN_KEY_BYTES:
            raise ValueError(f"HMAC key must be >= {_MIN_KEY_BYTES} bytes, got {len(kb)}")
        if not isinstance(clock, Clock):
            raise TypeError("clock must satisfy Clock protocol")
        if not isinstance(audit, AuditSink):
            raise TypeError("audit must satisfy AuditSink protocol")
        self._key = kb
        self._clock = clock
        self._audit = audit
        self._revoked: set[AuthorityId] = set()
        self._used: set[AuthorityId] = set()
        self._lock = threading.Lock()

    def issue(
        self, decision: Decision, *, ttl: timedelta, issuer: str,
        single_use: bool = False,
    ) -> Authority:
        if not isinstance(decision, Decision):
            raise TypeError("decision must be Decision")
        if not isinstance(ttl, timedelta) or ttl <= timedelta(0):
            raise AuthorityIssuanceError("ttl must be positive")
        if not isinstance(issuer, str) or not issuer.strip():
            raise AuthorityIssuanceError("issuer must be non-empty")
        if not isinstance(single_use, bool):
            raise AuthorityIssuanceError("single_use must be bool")

        if decision.outcome is not DecisionOutcome.ALLOW:
            _emit_event(self._audit, AuthorityEventKind.AUTHORITY_ISSUANCE_REJECTED,
                        {"decision_id": decision.decision_id.value,
                         "subject_id": decision.subject_id.value,
                         "reason": f"decision_outcome_{decision.outcome.value}"},
                        actor=decision.subject_id)
            raise AuthorityIssuanceError(
                f"cannot issue from decision with outcome {decision.outcome.value}"
            )
        if decision.failed_closed:
            _emit_event(self._audit, AuthorityEventKind.AUTHORITY_ISSUANCE_REJECTED,
                        {"decision_id": decision.decision_id.value,
                         "subject_id": decision.subject_id.value,
                         "reason": "decision_failed_closed"},
                        actor=decision.subject_id)
            raise AuthorityIssuanceError("cannot issue from failed-closed decision")

        now = self._clock.now()
        expires_at = now + ttl
        auth_id = AuthorityId(f"auth-{secrets.token_hex(16)}")
        resources = frozenset({decision.resource_id})
        actions = frozenset({decision.action})
        payload = _authority_canonical_bytes(
            authority_id=auth_id, subject_id=decision.subject_id,
            session_id=decision.session_id, resource_ids=resources,
            action_kinds=actions, issued_at=now, expires_at=expires_at,
            issuer=issuer, single_use=single_use,
        )
        signature = hmac.new(self._key, payload, hashlib.sha256).digest()
        a = Authority(
            authority_id=auth_id, subject_id=decision.subject_id,
            session_id=decision.session_id, resource_ids=resources,
            action_kinds=actions, issued_at=now, expires_at=expires_at,
            issuer=issuer, single_use=single_use, signature=signature,
        )
        _emit_event(self._audit, AuthorityEventKind.AUTHORITY_ISSUED, {
            "authority_id": auth_id.value,
            "subject_id": decision.subject_id.value,
            "session_id": decision.session_id.value if decision.session_id else None,
            "resource_ids": sorted(r.value for r in resources),
            "action_kinds": sorted(x.value for x in actions),
            "expires_at": expires_at.isoformat(),
            "issuer": issuer, "single_use": single_use,
            "decision_id": decision.decision_id.value,
        }, actor=decision.subject_id)
        return a

    def validate(
        self, authority: Authority, *, expected_subject: SubjectId,
        expected_resource: ResourceId, expected_action: ActionKind,
    ) -> AuthorityValidation:
        if not isinstance(authority, Authority):
            raise TypeError("authority must be Authority")
        if not isinstance(expected_subject, SubjectId):
            raise TypeError("expected_subject must be SubjectId")
        if not isinstance(expected_resource, ResourceId):
            raise TypeError("expected_resource must be ResourceId")
        if not isinstance(expected_action, ActionKind):
            raise TypeError("expected_action must be ActionKind")

        now = self._clock.now()
        expected_sig = hmac.new(
            self._key, authority.canonical_bytes(), hashlib.sha256,
        ).digest()
        reason: str | None = None
        if not hmac.compare_digest(expected_sig, authority.signature):
            reason = "signature_mismatch"
        elif authority.subject_id != expected_subject:
            reason = "subject_mismatch"
        elif expected_resource not in authority.resource_ids:
            reason = "resource_out_of_scope"
        elif expected_action not in authority.action_kinds:
            reason = "action_out_of_scope"
        elif now >= authority.expires_at:
            reason = "expired"

        if reason is None:
            with self._lock:
                if authority.authority_id in self._revoked:
                    reason = "revoked"
                elif authority.single_use:
                    if authority.authority_id in self._used:
                        reason = "already_used"
                    else:
                        self._used.add(authority.authority_id)

        if reason is not None:
            _emit_event(self._audit, AuthorityEventKind.AUTHORITY_VALIDATION_REJECTED, {
                "authority_id": authority.authority_id.value,
                "subject_id": expected_subject.value,
                "resource_id": expected_resource.value,
                "action": expected_action.value,
                "reason": reason,
            }, actor=expected_subject)
            return AuthorityValidation(authority.authority_id, False, reason, now)

        _emit_event(self._audit, AuthorityEventKind.AUTHORITY_VALIDATED, {
            "authority_id": authority.authority_id.value,
            "subject_id": expected_subject.value,
            "resource_id": expected_resource.value,
            "action": expected_action.value,
        }, actor=expected_subject)
        return AuthorityValidation(authority.authority_id, True, "ok", now)

    def revoke(self, authority_id: AuthorityId, reason: str) -> None:
        if not isinstance(authority_id, AuthorityId):
            raise TypeError("authority_id must be AuthorityId")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("revoke reason must be non-empty")
        with self._lock:
            already = authority_id in self._revoked
            self._revoked.add(authority_id)
        if already:
            _emit_event(self._audit, AuthorityEventKind.AUTHORITY_REVOKE_REJECTED,
                        {"authority_id": authority_id.value,
                         "reason": "already_revoked"})
            return
        _emit_event(self._audit, AuthorityEventKind.AUTHORITY_REVOKED,
                    {"authority_id": authority_id.value, "reason": reason})


# ═════════════════════════════════════════════════════════════════════════
# §10  SUBJECT & SESSION
# ═════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True, slots=True)
class Subject:
    subject_id: SubjectId
    identity_kind: IdentityKind
    display_name: str
    attributes: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.subject_id, SubjectId):
            raise TypeError("Subject.subject_id must be SubjectId")
        if not isinstance(self.identity_kind, IdentityKind):
            raise TypeError("Subject.identity_kind must be IdentityKind")
        if not isinstance(self.display_name, str) or not self.display_name.strip():
            raise ValueError("Subject.display_name must be non-empty")
        for k, v in self.attributes.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise TypeError("Subject.attributes must map str->str")
        object.__setattr__(self, "attributes", MappingProxyType(dict(self.attributes)))


class SubjectRegistry:
    """Thread-safe subject registry.  Duplicate registration rejected."""
    __slots__ = ("_clock", "_audit", "_subjects", "_lock")

    def __init__(self, clock: Clock, audit: AuditSink) -> None:
        if not isinstance(clock, Clock):
            raise TypeError("clock must satisfy Clock protocol")
        if not isinstance(audit, AuditSink):
            raise TypeError("audit must satisfy AuditSink protocol")
        self._clock = clock
        self._audit = audit
        self._subjects: dict[SubjectId, Subject] = {}
        self._lock = threading.Lock()

    def register(self, subject: Subject) -> None:
        if not isinstance(subject, Subject):
            raise TypeError("register expected Subject")
        with self._lock:
            if subject.subject_id in self._subjects:
                _emit_event(self._audit, SessionEventKind.SUBJECT_REGISTER_REJECTED,
                            {"subject_id": subject.subject_id.value},
                            actor=subject.subject_id)
                raise DuplicateSubjectError(
                    f"subject {subject.subject_id.value!r} already registered"
                )
            self._subjects[subject.subject_id] = subject
            _emit_event(self._audit, SessionEventKind.SUBJECT_REGISTERED,
                        {"subject_id": subject.subject_id.value,
                         "identity_kind": subject.identity_kind.value},
                        actor=subject.subject_id)

    def get(self, subject_id: SubjectId) -> Subject | None:
        if not isinstance(subject_id, SubjectId):
            raise TypeError("subject_id must be SubjectId")
        with self._lock:
            return self._subjects.get(subject_id)

    def require(self, subject_id: SubjectId) -> Subject:
        s = self.get(subject_id)
        if s is None:
            raise SubjectNotFoundError(f"subject {subject_id.value!r} not registered")
        return s

    def __len__(self) -> int:
        with self._lock:
            return len(self._subjects)

    def __contains__(self, subject_id: object) -> bool:
        with self._lock:
            return subject_id in self._subjects


@dataclass(frozen=True, slots=True)
class Session:
    session_id: SessionId
    subject_id: SubjectId
    state: SessionState
    created_at: datetime
    last_activity_at: datetime
    expires_at: datetime
    idle_timeout: timedelta
    ended_at: datetime | None = None
    ended_reason: str | None = None

    def __post_init__(self) -> None:
        for name, value in (
            ("created_at", self.created_at),
            ("last_activity_at", self.last_activity_at),
            ("expires_at", self.expires_at),
        ):
            _require_aware(value, context=f"Session.{name}")
        if self.expires_at < self.created_at:
            raise ValueError("expires_at must be >= created_at")
        if self.last_activity_at < self.created_at:
            raise ValueError("last_activity_at must be >= created_at")
        if self.idle_timeout <= timedelta(0):
            raise ValueError("idle_timeout must be positive")
        if (self.ended_at is None) != (self.ended_reason is None):
            raise ValueError("ended_at and ended_reason must both be set or both None")
        if self.ended_at is not None:
            _require_aware(self.ended_at, context="Session.ended_at")
        if self.state in _TERMINAL_SESSION_STATES and self.ended_at is None:
            raise ValueError(f"terminal state {self.state.value} requires ended_at")
        if self.state not in _TERMINAL_SESSION_STATES and self.ended_at is not None:
            raise ValueError(f"non-terminal state {self.state.value} must not have ended_at")

    def is_terminal(self) -> bool:
        return self.state in _TERMINAL_SESSION_STATES

    def is_hard_expired(self, now: datetime) -> bool:
        return now >= self.expires_at

    def is_idle_expired(self, now: datetime) -> bool:
        return (now - self.last_activity_at) > self.idle_timeout

    def is_valid(self, now: datetime) -> bool:
        if self.state is not SessionState.ACTIVE:
            return False
        if self.is_hard_expired(now):
            return False
        if self.is_idle_expired(now):
            return False
        return True


class SessionRegistry:
    """Thread-safe session lifecycle manager."""
    __slots__ = ("_clock", "_audit", "_subjects", "_sessions", "_lock")

    def __init__(self, clock: Clock, audit: AuditSink,
                 subjects: SubjectRegistry) -> None:
        if not isinstance(clock, Clock):
            raise TypeError("clock must satisfy Clock protocol")
        if not isinstance(audit, AuditSink):
            raise TypeError("audit must satisfy AuditSink protocol")
        if not isinstance(subjects, SubjectRegistry):
            raise TypeError("subjects must be SubjectRegistry")
        self._clock = clock
        self._audit = audit
        self._subjects = subjects
        self._sessions: dict[SessionId, Session] = {}
        self._lock = threading.Lock()

    def create(
        self, subject_id: SubjectId, ttl: timedelta, idle_timeout: timedelta,
        session_id: SessionId | None = None,
    ) -> Session:
        if not isinstance(subject_id, SubjectId):
            raise TypeError("subject_id must be SubjectId")
        if not isinstance(ttl, timedelta) or ttl <= timedelta(0):
            raise SessionCreationError("ttl must be positive")
        if not isinstance(idle_timeout, timedelta) or idle_timeout <= timedelta(0):
            raise SessionCreationError("idle_timeout must be positive")
        if session_id is not None and not isinstance(session_id, SessionId):
            raise TypeError("session_id must be SessionId or None")

        with self._lock:
            if subject_id not in self._subjects:
                _emit_event(self._audit, SessionEventKind.SESSION_CREATE_REJECTED,
                            {"subject_id": subject_id.value,
                             "reason": "subject_not_registered"})
                raise SubjectNotFoundError(
                    f"cannot create session: subject {subject_id.value!r} not registered"
                )
            if session_id is None:
                session_id = SessionId(f"sess-{secrets.token_hex(16)}")
            if session_id in self._sessions:
                _emit_event(self._audit, SessionEventKind.SESSION_CREATE_REJECTED,
                            {"session_id": session_id.value,
                             "reason": "session_id_collision"})
                raise SessionCreationError(f"session id {session_id.value!r} exists")
            now = self._clock.now()
            s = Session(
                session_id=session_id, subject_id=subject_id,
                state=SessionState.CREATED, created_at=now,
                last_activity_at=now, expires_at=now + ttl,
                idle_timeout=idle_timeout,
            )
            self._sessions[session_id] = s
            _emit_event(self._audit, SessionEventKind.SESSION_CREATED, {
                "session_id": session_id.value, "subject_id": subject_id.value,
                "ttl_seconds": ttl.total_seconds(),
                "idle_timeout_seconds": idle_timeout.total_seconds(),
            }, actor=subject_id)
            return s

    def get(self, session_id: SessionId) -> Session | None:
        if not isinstance(session_id, SessionId):
            raise TypeError("session_id must be SessionId")
        with self._lock:
            return self._sessions.get(session_id)

    def _require(self, session_id: SessionId) -> Session:
        if not isinstance(session_id, SessionId):
            raise TypeError("session_id must be SessionId")
        s = self._sessions.get(session_id)
        if s is None:
            raise SessionNotFoundError(f"session {session_id.value!r} not found")
        return s

    def _reject_if_not_active(self, session: Session, now: datetime) -> None:
        if session.state in _TERMINAL_SESSION_STATES:
            _emit_event(self._audit, SessionEventKind.SESSION_TRANSITION_REJECTED,
                        {"session_id": session.session_id.value,
                         "from": session.state.value, "reason": "terminal_state"},
                        actor=session.subject_id)
            raise InvalidSessionTransitionError(
                f"session {session.session_id.value!r} is {session.state.value}"
            )
        if session.is_hard_expired(now):
            _emit_event(self._audit, SessionEventKind.SESSION_TRANSITION_REJECTED,
                        {"session_id": session.session_id.value,
                         "from": session.state.value, "reason": "hard_expired"},
                        actor=session.subject_id)
            raise InvalidSessionTransitionError(
                f"session {session.session_id.value!r} is hard-expired"
            )
        if session.is_idle_expired(now):
            _emit_event(self._audit, SessionEventKind.SESSION_TRANSITION_REJECTED,
                        {"session_id": session.session_id.value,
                         "from": session.state.value, "reason": "idle_expired"},
                        actor=session.subject_id)
            raise InvalidSessionTransitionError(
                f"session {session.session_id.value!r} is idle-expired"
            )

    def activate(self, session_id: SessionId) -> Session:
        with self._lock:
            s = self._require(session_id)
            now = self._clock.now()
            if s.state is not SessionState.CREATED:
                _emit_event(self._audit, SessionEventKind.SESSION_TRANSITION_REJECTED,
                            {"session_id": session_id.value,
                             "from": s.state.value, "to": "active",
                             "reason": "state_not_allowed"},
                            actor=s.subject_id)
                raise InvalidSessionTransitionError(
                    f"cannot transition {s.state.value} -> active"
                )
            self._reject_if_not_active(s, now)
            updated = replace(s, state=SessionState.ACTIVE, last_activity_at=now)
            self._sessions[session_id] = updated
            _emit_event(self._audit, SessionEventKind.SESSION_ACTIVATED,
                        {"session_id": session_id.value}, actor=s.subject_id)
            return updated

    def touch(self, session_id: SessionId) -> Session:
        with self._lock:
            s = self._require(session_id)
            now = self._clock.now()
            if s.state is not SessionState.ACTIVE:
                _emit_event(self._audit, SessionEventKind.SESSION_TRANSITION_REJECTED,
                            {"session_id": session_id.value,
                             "from": s.state.value, "reason": "not_active"},
                            actor=s.subject_id)
                raise InvalidSessionTransitionError(
                    f"cannot touch session in state {s.state.value}"
                )
            self._reject_if_not_active(s, now)
            updated = replace(s, last_activity_at=now)
            self._sessions[session_id] = updated
            _emit_event(self._audit, SessionEventKind.SESSION_TOUCHED,
                        {"session_id": session_id.value}, actor=s.subject_id)
            return updated

    def _terminate(self, session_id: SessionId, new_state: SessionState,
                   reason: str, event_kind) -> Session:
        with self._lock:
            s = self._require(session_id)
            now = self._clock.now()
            if s.state in _TERMINAL_SESSION_STATES:
                _emit_event(self._audit, SessionEventKind.SESSION_TRANSITION_REJECTED,
                            {"session_id": session_id.value,
                             "from": s.state.value, "reason": "already_terminal"},
                            actor=s.subject_id)
                raise InvalidSessionTransitionError(
                    f"session {session_id.value!r} already {s.state.value}"
                )
            updated = replace(s, state=new_state, ended_at=now, ended_reason=reason)
            self._sessions[session_id] = updated
            _emit_event(self._audit, event_kind,
                        {"session_id": session_id.value, "reason": reason},
                        actor=s.subject_id)
            return updated

    def revoke(self, session_id: SessionId, reason: str) -> Session:
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("revoke reason must be non-empty")
        return self._terminate(session_id, SessionState.REVOKED, reason,
                               SessionEventKind.SESSION_REVOKED)

    def expire(self, session_id: SessionId, reason: str) -> Session:
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("expire reason must be non-empty")
        return self._terminate(session_id, SessionState.EXPIRED, reason,
                               SessionEventKind.SESSION_EXPIRED)

    def sweep(self) -> tuple[SessionId, ...]:
        now = self._clock.now()
        transitioned: list[SessionId] = []
        with self._lock:
            for sid, s in list(self._sessions.items()):
                if s.state in _TERMINAL_SESSION_STATES:
                    continue
                reason: str | None = None
                if s.is_hard_expired(now):
                    reason = "hard_expiry"
                elif s.is_idle_expired(now):
                    reason = "idle_timeout"
                if reason is None:
                    continue
                expired = replace(s, state=SessionState.EXPIRED,
                                  ended_at=now, ended_reason=reason)
                self._sessions[sid] = expired
                transitioned.append(sid)
                _emit_event(self._audit, SessionEventKind.SESSION_EXPIRED,
                            {"session_id": sid.value, "reason": reason,
                             "via": "sweep"},
                            actor=s.subject_id)
        return tuple(transitioned)

    def is_valid(self, session_id: SessionId) -> bool:
        with self._lock:
            s = self._sessions.get(session_id)
        if s is None:
            return False
        return s.is_valid(self._clock.now())

    def list_for_subject(self, subject_id: SubjectId) -> tuple[Session, ...]:
        if not isinstance(subject_id, SubjectId):
            raise TypeError("subject_id must be SubjectId")
        with self._lock:
            return tuple(s for s in self._sessions.values()
                         if s.subject_id == subject_id)

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions)


# ═════════════════════════════════════════════════════════════════════════
# §11  CONTAINMENT
# ═════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True, slots=True)
class ContainmentRecord:
    containment_id: ContainmentId
    subject_id: SubjectId
    level: ContainmentLevel
    previous_level: ContainmentLevel
    applied_at: datetime
    reason: str
    initiated_by: SubjectId
    expires_at: datetime | None
    subject_registered: bool
    failed_closed: bool = False
    failure_reason: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.containment_id, ContainmentId):
            raise ContainmentError("containment_id must be ContainmentId")
        if not isinstance(self.subject_id, SubjectId):
            raise ContainmentError("subject_id must be SubjectId")
        if not isinstance(self.level, ContainmentLevel):
            raise ContainmentError("level must be ContainmentLevel")
        if not isinstance(self.previous_level, ContainmentLevel):
            raise ContainmentError("previous_level must be ContainmentLevel")
        _require_aware(self.applied_at, context="ContainmentRecord.applied_at")
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ContainmentError("reason must be non-empty")
        if not isinstance(self.initiated_by, SubjectId):
            raise ContainmentError("initiated_by must be SubjectId")
        if self.expires_at is not None:
            _require_aware(self.expires_at, context="ContainmentRecord.expires_at")
            if self.expires_at <= self.applied_at:
                raise ContainmentError("expires_at must be after applied_at")
        if self.level is ContainmentLevel.NONE and self.expires_at is not None:
            raise ContainmentError("level=NONE cannot carry expires_at")
        if self.failed_closed and self.failure_reason is None:
            raise ContainmentError("failed_closed=True requires failure_reason")
        if not self.failed_closed and self.failure_reason is not None:
            raise ContainmentError("failure_reason only valid when failed_closed=True")

    def is_active(self) -> bool:
        return self.level is not ContainmentLevel.NONE

    def to_dict(self) -> dict[str, Any]:
        return {
            "containment_id": self.containment_id.value,
            "subject_id": self.subject_id.value,
            "level": self.level.value,
            "previous_level": self.previous_level.value,
            "applied_at": self.applied_at.isoformat(),
            "reason": self.reason,
            "initiated_by": self.initiated_by.value,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "subject_registered": self.subject_registered,
            "failed_closed": self.failed_closed,
            "failure_reason": self.failure_reason,
        }


@dataclass(frozen=True, slots=True)
class BlastRadiusReport:
    subject_id: SubjectId
    subject_registered: bool
    affected_session_ids: frozenset[SessionId]
    computed_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.subject_id, SubjectId):
            raise ContainmentError("subject_id must be SubjectId")
        if not isinstance(self.subject_registered, bool):
            raise ContainmentError("subject_registered must be bool")
        if not isinstance(self.affected_session_ids, frozenset):
            raise ContainmentError("affected_session_ids must be frozenset")
        _require_aware(self.computed_at, context="BlastRadiusReport.computed_at")

    @property
    def affected_session_count(self) -> int:
        return len(self.affected_session_ids)

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject_id": self.subject_id.value,
            "subject_registered": self.subject_registered,
            "affected_session_ids": sorted(s.value for s in self.affected_session_ids),
            "affected_session_count": self.affected_session_count,
            "computed_at": self.computed_at.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class ReviewRequest:
    review_id: ReviewRequestId
    subject_id: SubjectId
    requested_level: ContainmentLevel
    reason: str
    requested_by: SubjectId
    requested_at: datetime
    state: ReviewState = ReviewState.PENDING
    resolved_at: datetime | None = None
    resolved_by: SubjectId | None = None
    resolution_reason: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.review_id, ReviewRequestId):
            raise ReviewError("review_id must be ReviewRequestId")
        if not isinstance(self.subject_id, SubjectId):
            raise ReviewError("subject_id must be SubjectId")
        if not isinstance(self.requested_level, ContainmentLevel):
            raise ReviewError("requested_level must be ContainmentLevel")
        if self.requested_level is ContainmentLevel.NONE:
            raise ReviewError("requested_level=NONE is meaningless")
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ReviewError("reason must be non-empty")
        if not isinstance(self.requested_by, SubjectId):
            raise ReviewError("requested_by must be SubjectId")
        _require_aware(self.requested_at, context="ReviewRequest.requested_at")
        if not isinstance(self.state, ReviewState):
            raise ReviewError("state must be ReviewState")
        if self.state is ReviewState.PENDING:
            if self.resolved_at is not None or self.resolved_by is not None:
                raise ReviewError("PENDING review must not have resolution")
        else:
            if self.resolved_at is None or self.resolved_by is None:
                raise ReviewError("resolved review requires resolved_at/by")
            _require_aware(self.resolved_at, context="ReviewRequest.resolved_at")

    def to_dict(self) -> dict[str, Any]:
        return {
            "review_id": self.review_id.value,
            "subject_id": self.subject_id.value,
            "requested_level": self.requested_level.value,
            "reason": self.reason,
            "requested_by": self.requested_by.value,
            "requested_at": self.requested_at.isoformat(),
            "state": self.state.value,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "resolved_by": self.resolved_by.value if self.resolved_by else None,
            "resolution_reason": self.resolution_reason,
        }


class ManualReviewQueue:
    __slots__ = ("_clock", "_audit", "_requests", "_lock")

    def __init__(self, clock: Clock, audit: AuditSink) -> None:
        self._clock = clock
        self._audit = audit
        self._requests: dict[ReviewRequestId, ReviewRequest] = {}
        self._lock = threading.Lock()

    def submit(self, subject_id, requested_level, reason, requested_by) -> ReviewRequest:
        if not isinstance(subject_id, SubjectId):
            raise TypeError("subject_id must be SubjectId")
        if not isinstance(requested_level, ContainmentLevel):
            raise TypeError("requested_level must be ContainmentLevel")
        if requested_level is ContainmentLevel.NONE:
            raise ReviewError("requested_level=NONE is meaningless")
        if not isinstance(reason, str) or not reason.strip():
            raise ReviewError("reason must be non-empty")
        if not isinstance(requested_by, SubjectId):
            raise TypeError("requested_by must be SubjectId")
        now = self._clock.now()
        req = ReviewRequest(
            review_id=ReviewRequestId(f"rev-{secrets.token_hex(8)}"),
            subject_id=subject_id, requested_level=requested_level,
            reason=reason, requested_by=requested_by, requested_at=now,
        )
        with self._lock:
            self._requests[req.review_id] = req
        _emit_event(self._audit, ReviewEventKind.REVIEW_REQUESTED, {
            "review_id": req.review_id.value, "subject_id": subject_id.value,
            "requested_level": requested_level.value,
            "requested_by": requested_by.value,
        }, actor=requested_by)
        return req

    def get(self, review_id: ReviewRequestId) -> ReviewRequest | None:
        if not isinstance(review_id, ReviewRequestId):
            raise TypeError("review_id must be ReviewRequestId")
        with self._lock:
            return self._requests.get(review_id)

    def pending(self) -> tuple[ReviewRequest, ...]:
        with self._lock:
            return tuple(r for r in self._requests.values()
                         if r.state is ReviewState.PENDING)

    def mark_resolved(self, review_id, *, decision, resolved_by, reason) -> ReviewRequest:
        if not isinstance(review_id, ReviewRequestId):
            raise TypeError("review_id must be ReviewRequestId")
        if not isinstance(decision, ReviewDecision):
            raise TypeError("decision must be ReviewDecision")
        if not isinstance(resolved_by, SubjectId):
            raise TypeError("resolved_by must be SubjectId")
        if not isinstance(reason, str) or not reason.strip():
            raise ReviewError("resolution reason must be non-empty")
        with self._lock:
            current = self._requests.get(review_id)
            if current is None:
                raise ReviewError(f"unknown review {review_id.value!r}")
            if current.state is not ReviewState.PENDING:
                raise ReviewError(
                    f"review {review_id.value!r} already {current.state.value}"
                )
            now = self._clock.now()
            new_state = (ReviewState.APPROVED
                         if decision is ReviewDecision.APPROVE
                         else ReviewState.DENIED)
            updated = replace(
                current, state=new_state, resolved_at=now,
                resolved_by=resolved_by, resolution_reason=reason,
            )
            self._requests[review_id] = updated
        _emit_event(self._audit, ReviewEventKind.REVIEW_RESOLVED, {
            "review_id": review_id.value, "subject_id": updated.subject_id.value,
            "requested_level": updated.requested_level.value,
            "state": new_state.value, "resolved_by": resolved_by.value,
        }, actor=resolved_by)
        return updated

    def __len__(self) -> int:
        with self._lock:
            return len(self._requests)


class ContainmentEngine:
    """Monotone containment with review-gated TERMINATE, ttl-bounded
    auto-release at low levels, and fail-safe on broken clock."""
    __slots__ = (
        "_clock", "_audit", "_subjects", "_sessions", "_policy",
        "_reviews", "_current", "_history", "_lock",
    )

    def __init__(self, clock, audit, subjects, sessions, policy=None) -> None:
        if not isinstance(clock, Clock):
            raise TypeError("clock must satisfy Clock protocol")
        if not isinstance(audit, AuditSink):
            raise TypeError("audit must satisfy AuditSink protocol")
        if not isinstance(subjects, SubjectRegistry):
            raise TypeError("subjects must be SubjectRegistry")
        if not isinstance(sessions, SessionRegistry):
            raise TypeError("sessions must be SessionRegistry")
        if policy is None:
            policy = ContainmentPolicy.default()
        if not isinstance(policy, ContainmentPolicy):
            raise TypeError("policy must be ContainmentPolicy")
        self._clock = clock
        self._audit = audit
        self._subjects = subjects
        self._sessions = sessions
        self._policy = policy
        self._reviews = ManualReviewQueue(clock, audit)
        self._current: dict[SubjectId, ContainmentRecord] = {}
        self._history: dict[SubjectId, list[ContainmentRecord]] = {}
        self._lock = threading.Lock()

    @property
    def policy(self) -> ContainmentPolicy:
        return self._policy

    @property
    def reviews(self) -> ManualReviewQueue:
        return self._reviews

    def _try_now(self):
        try:
            return self._clock.now(), False, None
        except Exception as exc:
            return (datetime.now(timezone.utc), True,
                    f"{type(exc).__name__}: {exc}")

    def _store(self, record: ContainmentRecord) -> None:
        self._current[record.subject_id] = record
        hist = self._history.setdefault(record.subject_id, [])
        hist.append(record)
        limit = self._policy.history_limit_per_subject
        if len(hist) > limit:
            del hist[:len(hist) - limit]

    def contain(self, subject_id, level, reason, *, initiated_by, ttl=None):
        if not isinstance(subject_id, SubjectId):
            raise TypeError("subject_id must be SubjectId")
        if not isinstance(level, ContainmentLevel):
            raise TypeError("level must be ContainmentLevel")
        if level is ContainmentLevel.NONE:
            raise ContainmentTransitionError(
                "contain(level=NONE) is meaningless; use release()"
            )
        if not isinstance(reason, str) or not reason.strip():
            raise ContainmentError("reason must be non-empty")
        if not isinstance(initiated_by, SubjectId):
            raise TypeError("initiated_by must be SubjectId")
        if ttl is not None:
            if not isinstance(ttl, timedelta):
                raise TypeError("ttl must be timedelta or None")
            if ttl <= timedelta(0):
                raise ContainmentError("ttl must be positive")

        now, clock_failed, clock_error = self._try_now()

        if clock_failed:
            with self._lock:
                current = self._current.get(subject_id)
                current_level = current.level if current else ContainmentLevel.NONE
                effective = _max_containment(current_level, level)
                record = ContainmentRecord(
                    containment_id=ContainmentId(f"cnt-{secrets.token_hex(8)}"),
                    subject_id=subject_id, level=effective,
                    previous_level=current_level, applied_at=now,
                    reason=reason, initiated_by=initiated_by,
                    expires_at=None,
                    subject_registered=self._subjects.get(subject_id) is not None,
                    failed_closed=True,
                    failure_reason=f"clock_failure: {clock_error}",
                )
                self._store(record)
            _emit_event(self._audit, ContainmentEventKind.CONTAINMENT_FAILED_CLOSED,
                        {"subject_id": subject_id.value, "level": level.value,
                         "reason": reason, "failure_reason": record.failure_reason},
                        actor=initiated_by)
            return record

        with self._lock:
            current = self._current.get(subject_id)
            current_level = current.level if current else ContainmentLevel.NONE

            if _CONTAINMENT_RANK[level] < _CONTAINMENT_RANK[current_level]:
                _emit_event(self._audit, ContainmentEventKind.CONTAINMENT_TRANSITION_REJECTED,
                            {"subject_id": subject_id.value,
                             "reason": f"would_de_escalate:{current_level.value}->{level.value}"},
                            actor=initiated_by)
                raise ContainmentTransitionError(
                    f"cannot contain at {level.value} below current "
                    f"{current_level.value}; use release()"
                )
            if level in self._policy.require_review_for_levels:
                _emit_event(self._audit, ContainmentEventKind.CONTAINMENT_TRANSITION_REJECTED,
                            {"subject_id": subject_id.value,
                             "reason": f"requires_review:{level.value}"},
                            actor=initiated_by)
                raise ContainmentTransitionError(
                    f"level {level.value} requires manual review"
                )
            if ttl is not None and _CONTAINMENT_RANK[level] > _CONTAINMENT_RANK[
                self._policy.max_auto_release_level
            ]:
                _emit_event(self._audit, ContainmentEventKind.CONTAINMENT_TRANSITION_REJECTED,
                            {"subject_id": subject_id.value,
                             "reason": f"ttl_not_permitted:{level.value}"},
                            actor=initiated_by)
                raise ContainmentTransitionError(
                    f"ttl not permitted for {level.value}"
                )
            expires_at = (now + ttl) if ttl is not None else None
            record = ContainmentRecord(
                containment_id=ContainmentId(f"cnt-{secrets.token_hex(8)}"),
                subject_id=subject_id, level=level, previous_level=current_level,
                applied_at=now, reason=reason, initiated_by=initiated_by,
                expires_at=expires_at,
                subject_registered=self._subjects.get(subject_id) is not None,
            )
            self._store(record)

        if current_level is ContainmentLevel.NONE:
            kind = ContainmentEventKind.CONTAINMENT_APPLIED
        elif _CONTAINMENT_RANK[level] > _CONTAINMENT_RANK[current_level]:
            kind = ContainmentEventKind.CONTAINMENT_ESCALATED
        else:
            kind = ContainmentEventKind.CONTAINMENT_REINFORCED

        _emit_event(self._audit, kind, {
            "containment_id": record.containment_id.value,
            "subject_id": subject_id.value,
            "previous_level": current_level.value, "level": level.value,
            "reason": reason, "initiated_by": initiated_by.value,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "subject_registered": record.subject_registered,
        }, actor=initiated_by)
        return record

    def release(self, subject_id, reason, *, released_by,
                new_level=ContainmentLevel.NONE) -> ContainmentRecord:
        if not isinstance(subject_id, SubjectId):
            raise TypeError("subject_id must be SubjectId")
        if not isinstance(reason, str) or not reason.strip():
            raise ContainmentError("reason must be non-empty")
        if not isinstance(released_by, SubjectId):
            raise TypeError("released_by must be SubjectId")
        if not isinstance(new_level, ContainmentLevel):
            raise TypeError("new_level must be ContainmentLevel")
        now, clock_failed, clock_error = self._try_now()
        if clock_failed:
            raise ContainmentError(f"clock failure during release: {clock_error}")
        with self._lock:
            current = self._current.get(subject_id)
            if current is None or current.level is ContainmentLevel.NONE:
                _emit_event(self._audit, ContainmentEventKind.CONTAINMENT_TRANSITION_REJECTED,
                            {"subject_id": subject_id.value,
                             "reason": "already_released"},
                            actor=released_by)
                raise ContainmentTransitionError(
                    f"subject {subject_id.value!r} is not contained"
                )
            if _CONTAINMENT_RANK[new_level] >= _CONTAINMENT_RANK[current.level]:
                _emit_event(self._audit, ContainmentEventKind.CONTAINMENT_TRANSITION_REJECTED,
                            {"subject_id": subject_id.value,
                             "reason": f"release_must_lower:{current.level.value}->{new_level.value}"},
                            actor=released_by)
                raise ContainmentTransitionError(
                    f"release target {new_level.value} not below current {current.level.value}"
                )
            record = ContainmentRecord(
                containment_id=ContainmentId(f"cnt-{secrets.token_hex(8)}"),
                subject_id=subject_id, level=new_level,
                previous_level=current.level, applied_at=now,
                reason=reason, initiated_by=released_by,
                expires_at=None,
                subject_registered=self._subjects.get(subject_id) is not None,
            )
            self._store(record)
        _emit_event(self._audit, ContainmentEventKind.CONTAINMENT_RELEASED, {
            "containment_id": record.containment_id.value,
            "subject_id": subject_id.value,
            "previous_level": current.level.value,
            "new_level": new_level.value, "reason": reason,
            "released_by": released_by.value,
        }, actor=released_by)
        return record

    def current_level(self, subject_id: SubjectId) -> ContainmentLevel:
        if not isinstance(subject_id, SubjectId):
            raise TypeError("subject_id must be SubjectId")
        with self._lock:
            rec = self._current.get(subject_id)
            return rec.level if rec else ContainmentLevel.NONE

    def is_contained(self, subject_id, *,
                     at_least=ContainmentLevel.MONITOR) -> bool:
        if not isinstance(at_least, ContainmentLevel):
            raise TypeError("at_least must be ContainmentLevel")
        return _CONTAINMENT_RANK[self.current_level(subject_id)] >= \
            _CONTAINMENT_RANK[at_least]

    def current_record(self, subject_id) -> ContainmentRecord | None:
        if not isinstance(subject_id, SubjectId):
            raise TypeError("subject_id must be SubjectId")
        with self._lock:
            return self._current.get(subject_id)

    def history(self, subject_id) -> tuple[ContainmentRecord, ...]:
        if not isinstance(subject_id, SubjectId):
            raise TypeError("subject_id must be SubjectId")
        with self._lock:
            return tuple(self._history.get(subject_id, ()))

    def active_containments(self) -> tuple[ContainmentRecord, ...]:
        with self._lock:
            return tuple(r for r in self._current.values() if r.is_active())

    def blast_radius(self, subject_id: SubjectId) -> BlastRadiusReport:
        if not isinstance(subject_id, SubjectId):
            raise TypeError("subject_id must be SubjectId")
        now, clock_failed, clock_error = self._try_now()
        if clock_failed:
            raise ContainmentError(f"clock failure computing blast radius: {clock_error}")
        registered = self._subjects.get(subject_id) is not None
        sessions = self._sessions.list_for_subject(subject_id)
        affected = frozenset(
            s.session_id for s in sessions
            if not s.is_terminal() and not s.is_hard_expired(now)
        )
        return BlastRadiusReport(
            subject_id=subject_id, subject_registered=registered,
            affected_session_ids=affected, computed_at=now,
        )

     def sweep(self) -> tuple[ContainmentRecord, ...]:
        """Expire time-bounded containments and return the resulting records.

        Expiry is monotonic: a sweep never promotes a containment level and
        records each release through the normal containment store/audit path.
        """
        now, clock_failed, clock_error = self._try_now()
        if clock_failed:
            raise ContainmentError(f"clock failure sweeping containments: {clock_error}")

        expired: list[ContainmentRecord] = []
        with self._lock:
            current_items = tuple(self._current.items())

        for subject_id, current in current_items:
            if current.level is ContainmentLevel.NONE:
                continue
            if current.expires_at is None or current.expires_at > now:
                continue
            record = ContainmentRecord(
                containment_id=ContainmentId(f"cnt-{secrets.token_hex(8)}"),
                subject_id=subject_id,
                level=ContainmentLevel.NONE,
                previous_level=current.level,
                applied_at=now,
                reason="containment TTL expired",
                initiated_by=current.initiated_by,
                expires_at=None,
                subject_registered=self._subjects.get(subject_id) is not None,
            )
            with self._lock:
                latest = self._current.get(subject_id)
                if latest is None or latest.containment_id != current.containment_id:
                    continue
                self._store(record)
            _emit_event(
                self._audit,
                ContainmentEventKind.CONTAINMENT_RELEASED,
                {
                    "containment_id": record.containment_id.value,
                    "subject_id": subject_id.value,
                    "previous_level": current.level.value,
                    "new_level": ContainmentLevel.NONE.value,
                    "reason": record.reason,
                    "released_by": current.initiated_by.value,
                    "via": "sweep",
                },
                actor=current.initiated_by,
            )
            expired.append(record)

        return tuple(expired)
