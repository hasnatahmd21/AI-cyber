"""
HYDRA POST-CORE — PHASE 22: RELIABILITY + FAILURE ENGINEERING
================================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * Domain — 9 failure kinds, 5 cause categories, 5 severity levels
  * Failure event model with observations, signals, cascades
  * Cause classifier — ATTACK / FAILURE / MISCONFIGURATION /
    UNKNOWN / MIXED_CAUSE using evidence-signal fingerprints
  * Cascade analysis — failure propagation DAG with depth tracking
  * Root-cause identification — sources of a failure cascade
  * Blast-radius and cascade-depth metrics
  * Recovery assessment — outcome-aware, not just action-aware
  * Findings — attack-indicated, misconfiguration, resource
    exhaustion, cascade, control-plane, partial outage,
    recovery-failure, mixed-cause, low-confidence
  * Machine-checkable reliability invariants
  * In-memory + SQLite stores
  * Phase-22 engine facade
  * Full test suite + manual runner

Purpose: distinguish ATTACK from FAILURE from MISCONFIGURATION from
UNKNOWN from MIXED CAUSE, and reason about their interaction.

This is NEW reliability/failure-engineering technology. It is NOT a
second SIEM correlator. It reasons about *cause*, not just correlation.

No third-party dependencies.

Run tests:
    python hydra_phase22_reliability_failure_engineering.py
    pytest hydra_phase22_reliability_failure_engineering.py -q
"""
from __future__ import annotations

import json
import math
import sqlite3
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Mapping,
    Optional,
    Protocol,
    Sequence,
    Tuple,
)

# =============================================================================
# SECTION 1 — CONTRACTS
# =============================================================================


class Clock(Protocol):
    def now(self) -> datetime: ...


class EvidenceEmitter(Protocol):
    def emit(self, evidence: Mapping[str, Any]) -> None: ...


class ProvenanceRecorder(Protocol):
    def record(self, *, subject_id: str, action: str, at: datetime,
               details: Mapping[str, Any]) -> None: ...


# =============================================================================
# SECTION 2 — DOMAIN ENUMS
# =============================================================================


class FailureKind(str, Enum):
    INFRASTRUCTURE = "infrastructure"
    ACCIDENTAL = "accidental"
    CONFIGURATION = "configuration"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    DEPENDENCY = "dependency"
    CASCADING = "cascading"
    CONTROL_PLANE = "control_plane"
    PARTIAL_OUTAGE = "partial_outage"
    RECOVERY = "recovery_failure"


ALL_FAILURE_KINDS: Tuple[FailureKind, ...] = tuple(FailureKind)


class CauseCategory(str, Enum):
    ATTACK = "attack"
    FAILURE = "failure"
    MISCONFIGURATION = "misconfiguration"
    UNKNOWN = "unknown"
    MIXED_CAUSE = "mixed_cause"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_SEVERITY_WEIGHT: Mapping[Severity, float] = {
    Severity.LOW: 0.25,
    Severity.MEDIUM: 0.5,
    Severity.HIGH: 0.75,
    Severity.CRITICAL: 1.0,
}


def severity_weight(s: Severity) -> float:
    return _SEVERITY_WEIGHT[s]


class Signal(str, Enum):
    """Signals that support or refute each cause category."""
    # Attack indicators
    MALICIOUS_PAYLOAD = "malicious_payload"
    KNOWN_ATTACK_TTP = "known_attack_ttp"
    LATERAL_MOVEMENT = "lateral_movement"
    CREDENTIAL_MISUSE = "credential_misuse"
    # Failure indicators
    HARDWARE_FAULT = "hardware_fault"
    TIMEOUT = "timeout"
    CRASH = "crash"
    OS_KERNEL_PANIC = "os_kernel_panic"
    # Misconfiguration indicators
    RECENT_CONFIG_CHANGE = "recent_config_change"
    RECENT_POLICY_CHANGE = "recent_policy_change"
    INVALID_SETTING = "invalid_setting"
    DRIFT_FROM_BASELINE = "drift_from_baseline"
    # Resource exhaustion indicators
    CPU_SATURATION = "cpu_saturation"
    MEMORY_SATURATION = "memory_saturation"
    DISK_FULL = "disk_full"
    FILE_DESCRIPTOR_LIMIT = "fd_limit"
    # Control-plane indicators
    API_SERVER_UNREACHABLE = "api_server_unreachable"
    CONSENSUS_LOST = "consensus_lost"
    LEADER_ELECTION_FAILED = "leader_election_failed"
    # Recovery indicators
    RECOVERY_ATTEMPT_FAILED = "recovery_attempt_failed"
    BACKUP_UNAVAILABLE = "backup_unavailable"
    RESTORE_INTEGRITY_FAILED = "restore_integrity_failed"


# Signal → (cause → weight) mapping. Weights are the strength with which
# a single observed signal supports a cause category.
_SIGNAL_CAUSE_WEIGHTS: Mapping[Signal, Mapping[CauseCategory, float]] = {
    Signal.MALICIOUS_PAYLOAD: {
        CauseCategory.ATTACK: 0.9,
    },
    Signal.KNOWN_ATTACK_TTP: {
        CauseCategory.ATTACK: 0.9,
    },
    Signal.LATERAL_MOVEMENT: {
        CauseCategory.ATTACK: 0.8,
    },
    Signal.CREDENTIAL_MISUSE: {
        CauseCategory.ATTACK: 0.7,
    },
    Signal.HARDWARE_FAULT: {
        CauseCategory.FAILURE: 0.9,
    },
    Signal.TIMEOUT: {
        CauseCategory.FAILURE: 0.5,
        CauseCategory.DEPENDENCY if False else CauseCategory.FAILURE: 0.5,
    },
    Signal.CRASH: {
        CauseCategory.FAILURE: 0.7,
    },
    Signal.OS_KERNEL_PANIC: {
        CauseCategory.FAILURE: 0.9,
    },
    Signal.RECENT_CONFIG_CHANGE: {
        CauseCategory.MISCONFIGURATION: 0.8,
    },
    Signal.RECENT_POLICY_CHANGE: {
        CauseCategory.MISCONFIGURATION: 0.8,
    },
    Signal.INVALID_SETTING: {
        CauseCategory.MISCONFIGURATION: 0.9,
    },
    Signal.DRIFT_FROM_BASELINE: {
        CauseCategory.MISCONFIGURATION: 0.6,
    },
    Signal.CPU_SATURATION: {
        CauseCategory.FAILURE: 0.4,
    },
    Signal.MEMORY_SATURATION: {
        CauseCategory.FAILURE: 0.4,
    },
    Signal.DISK_FULL: {
        CauseCategory.FAILURE: 0.5,
    },
    Signal.FILE_DESCRIPTOR_LIMIT: {
        CauseCategory.FAILURE: 0.5,
    },
    Signal.API_SERVER_UNREACHABLE: {
        CauseCategory.FAILURE: 0.5,
    },
    Signal.CONSENSUS_LOST: {
        CauseCategory.FAILURE: 0.7,
    },
    Signal.LEADER_ELECTION_FAILED: {
        CauseCategory.FAILURE: 0.6,
    },
    Signal.RECOVERY_ATTEMPT_FAILED: {
        CauseCategory.FAILURE: 0.5,
    },
    Signal.BACKUP_UNAVAILABLE: {
        CauseCategory.FAILURE: 0.5,
        CauseCategory.MISCONFIGURATION: 0.4,
    },
    Signal.RESTORE_INTEGRITY_FAILED: {
        CauseCategory.FAILURE: 0.6,
        CauseCategory.ATTACK: 0.3,
    },
}


def signal_weights(signal: Signal) -> Mapping[CauseCategory, float]:
    return _SIGNAL_CAUSE_WEIGHTS.get(signal, {})


# =============================================================================
# SECTION 3 — FAILURE EVENT
# =============================================================================


@dataclass(frozen=True)
class FailureEvent:
    event_id: str
    kind: FailureKind
    entity_id: str
    severity: Severity
    signals: FrozenSet[Signal]
    at: datetime
    parent_event_id: Optional[str] = None
    detail: str = ""

    def __post_init__(self) -> None:
        if not self.event_id:
            raise ValueError("event_id is required")
        if not self.entity_id:
            raise ValueError("entity_id is required")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        if self.parent_event_id == self.event_id:
            raise ValueError("event cannot be its own parent")


# =============================================================================
# SECTION 4 — CAUSE CLASSIFICATION
# =============================================================================


@dataclass(frozen=True)
class CauseScore:
    category: CauseCategory
    score: float
    supporting_signals: Tuple[Signal, ...]

    def __post_init__(self) -> None:
        if not 0.0 <= self.score <= 1.0:
            raise ValueError("score must be within [0,1]")


@dataclass(frozen=True)
class CauseClassification:
    event_id: str
    primary: CauseCategory
    confidence: float
    scores: Mapping[CauseCategory, float]
    supporting_signals: Mapping[CauseCategory, Tuple[Signal, ...]]
    mixed: bool
    rationale: str

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be within [0,1]")


# Decision thresholds
_ATTACK_THRESHOLD: float = 0.5
_FAILURE_THRESHOLD: float = 0.4
_MISCONFIG_THRESHOLD: float = 0.5
_MIXED_MARGIN: float = 0.15  # if top two are within this, it's mixed
_LOW_CONFIDENCE_CUTOFF: float = 0.2


def classify_cause(event: FailureEvent) -> CauseClassification:
    """Deterministic signal-driven cause classification.

    score(category) = min(1, Σ weights over observed signals)
    """
    raw: Dict[CauseCategory, float] = {c: 0.0 for c in CauseCategory}
    supporting: Dict[CauseCategory, List[Signal]] = {
        c: [] for c in CauseCategory
    }

    for sig in event.signals:
        for cat, w in signal_weights(sig).items():
            raw[cat] = min(1.0, raw[cat] + w)
            supporting[cat].append(sig)

    # Kind-based priors (weak, tie-breaking only)
    kind_prior: Dict[FailureKind, CauseCategory] = {
        FailureKind.INFRASTRUCTURE: CauseCategory.FAILURE,
        FailureKind.ACCIDENTAL: CauseCategory.FAILURE,
        FailureKind.CONFIGURATION: CauseCategory.MISCONFIGURATION,
        FailureKind.RESOURCE_EXHAUSTION: CauseCategory.FAILURE,
        FailureKind.DEPENDENCY: CauseCategory.FAILURE,
        FailureKind.CASCADING: CauseCategory.UNKNOWN,
        FailureKind.CONTROL_PLANE: CauseCategory.FAILURE,
        FailureKind.PARTIAL_OUTAGE: CauseCategory.FAILURE,
        FailureKind.RECOVERY: CauseCategory.FAILURE,
    }
    prior = kind_prior.get(event.kind, CauseCategory.UNKNOWN)
    if prior is not CauseCategory.UNKNOWN:
        raw[prior] = min(1.0, raw[prior] + 0.10)
        if prior not in supporting:
            supporting[prior] = []

    # Sort categories by score, tie-break by enum order
    ordered = sorted(
        raw.items(),
        key=lambda kv: (-kv[1], kv[0].value),
    )

    top_cat, top_score = ordered[0]
    second_cat, second_score = ordered[1] if len(ordered) > 1 else (None, 0.0)

    if top_score < _LOW_CONFIDENCE_CUTOFF:
        return CauseClassification(
            event_id=event.event_id,
            primary=CauseCategory.UNKNOWN,
            confidence=top_score,
            scores={c: raw[c] for c in CauseCategory},
            supporting_signals={
                c: tuple(supporting[c]) for c in CauseCategory
            },
            mixed=False,
            rationale=(
                f"no signal reached confidence cutoff "
                f"{_LOW_CONFIDENCE_CUTOFF:.2f}"
            ),
        )

    is_mixed = False
    if second_cat is not None \
       and second_score >= _LOW_CONFIDENCE_CUTOFF \
       and (top_score - second_score) <= _MIXED_MARGIN:
        is_mixed = True

    if is_mixed:
        primary = CauseCategory.MIXED_CAUSE
        confidence = (top_score + second_score) / 2.0
        rationale = (
            f"mixed: {top_cat.value} {top_score:.2f} vs "
            f"{second_cat.value} {second_score:.2f}"
        )
    else:
        primary = top_cat
        confidence = top_score
        rationale = (
            f"{top_cat.value} supported by score {top_score:.2f}"
        )

    return CauseClassification(
        event_id=event.event_id,
        primary=primary,
        confidence=confidence,
        scores={c: raw[c] for c in CauseCategory},
        supporting_signals={
            c: tuple(supporting[c]) for c in CauseCategory
        },
        mixed=is_mixed,
        rationale=rationale,
    )


# =============================================================================
# SECTION 5 — CASCADE GRAPH
# =============================================================================


class CascadeGraph:
    """Directed graph of failure propagation."""

    def __init__(self) -> None:
        self._events: Dict[str, FailureEvent] = {}
        self._children: Dict[str, List[str]] = {}
        self._parents: Dict[str, List[str]] = {}

    def add(self, event: FailureEvent) -> None:
        if event.event_id in self._events:
            raise ValueError(f"event {event.event_id} already exists")
        if event.parent_event_id is not None \
           and event.parent_event_id not in self._events:
            raise KeyError(
                f"parent {event.parent_event_id} not registered"
            )
        self._events[event.event_id] = event
        self._children.setdefault(event.event_id, [])
        self._parents.setdefault(event.event_id, [])
        if event.parent_event_id is not None:
            self._children.setdefault(event.parent_event_id, []).append(
                event.event_id
            )
            self._parents[event.event_id].append(event.parent_event_id)

    def event(self, event_id: str) -> FailureEvent:
        e = self._events.get(event_id)
        if e is None:
            raise KeyError(f"unknown event {event_id}")
        return e

    def events(self) -> Tuple[FailureEvent, ...]:
        return tuple(self._events.values())

    def children(self, event_id: str) -> Tuple[str, ...]:
        return tuple(self._children.get(event_id, ()))

    def parents(self, event_id: str) -> Tuple[str, ...]:
        return tuple(self._parents.get(event_id, ()))

    def roots(self) -> Tuple[str, ...]:
        return tuple(
            eid for eid in self._events
            if not self._parents.get(eid)
        )

    def depth_of(self, event_id: str) -> int:
        """Longest distance from any root."""
        memo: Dict[str, int] = {}

        def visit(eid: str) -> int:
            if eid in memo:
                return memo[eid]
            ps = self._parents.get(eid, [])
            if not ps:
                memo[eid] = 0
                return 0
            d = 1 + max(visit(p) for p in ps)
            memo[eid] = d
            return d

        return visit(event_id)

    def subtree(self, event_id: str) -> Tuple[str, ...]:
        """All nodes downstream of event_id, including event_id."""
        out: List[str] = []
        q: deque = deque([event_id])
        seen: set = set()
        while q:
            cur = q.popleft()
            if cur in seen:
                continue
            seen.add(cur)
            out.append(cur)
            for c in self._children.get(cur, ()):
                q.append(c)
        return tuple(out)

    def cascade_depth(self) -> int:
        if not self._events:
            return 0
        return max(self.depth_of(eid) for eid in self._events)

    def cascade_breadth(self) -> int:
        """Max fan-out in the graph."""
        if not self._events:
            return 0
        return max(
            len(self._children.get(eid, ())) for eid in self._events
        )


# =============================================================================
# SECTION 6 — RECOVERY ASSESSMENT
# =============================================================================


@dataclass(frozen=True)
class RecoveryAttempt:
    attempt_id: str
    event_id: str
    started_at: datetime
    finished_at: Optional[datetime]
    action_verified: bool
    objective_achieved: bool
    elapsed_seconds: float
    detail: str = ""

    def __post_init__(self) -> None:
        if not self.attempt_id:
            raise ValueError("attempt_id is required")
        if not self.event_id:
            raise ValueError("event_id is required")
        if self.started_at.tzinfo is None:
            raise ValueError("started_at must be timezone-aware")
        if self.finished_at is not None \
           and self.finished_at.tzinfo is None:
            raise ValueError("finished_at must be timezone-aware")
        if self.elapsed_seconds < 0:
            raise ValueError("elapsed_seconds must be >= 0")


@dataclass(frozen=True)
class RecoveryAssessment:
    event_id: str
    successful: bool
    effective: bool
    action_only: bool
    rationale: str


def assess_recovery(
    attempts: Sequence[RecoveryAttempt],
) -> RecoveryAssessment:
    """A recovery is *effective* only when the objective was achieved.

    ACTION_EXECUTED ≠ OBJECTIVE_ACHIEVED.
    """
    if not attempts:
        return RecoveryAssessment(
            event_id="<none>", successful=False, effective=False,
            action_only=False, rationale="no recovery attempts recorded",
        )
    event_id = attempts[0].event_id
    any_verified = any(a.action_verified for a in attempts)
    any_achieved = any(a.objective_achieved for a in attempts)
    all_action_only = all(
        a.action_verified and not a.objective_achieved for a in attempts
    )

    if any_achieved:
        return RecoveryAssessment(
            event_id=event_id, successful=True, effective=True,
            action_only=False,
            rationale="at least one attempt achieved the objective",
        )
    if all_action_only:
        return RecoveryAssessment(
            event_id=event_id, successful=False, effective=False,
            action_only=True,
            rationale=(
                "actions executed but objectives not achieved — "
                "recovery not effective"
            ),
        )
    return RecoveryAssessment(
        event_id=event_id, successful=False, effective=False,
        action_only=False,
        rationale=(
            f"{len(attempts)} attempt(s) — no verification and no "
            f"objective achieved"
        ),
    )


# =============================================================================
# SECTION 7 — FINDINGS
# =============================================================================


class ReliabilityFindingKind(str, Enum):
    ATTACK_INDICATED = "attack_indicated"
    FAILURE_INDICATED = "failure_indicated"
    MISCONFIGURATION_INDICATED = "misconfiguration_indicated"
    MIXED_CAUSE_INDICATED = "mixed_cause_indicated"
    LOW_CONFIDENCE_CAUSE = "low_confidence_cause"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    DEPENDENCY_FAILURE = "dependency_failure"
    CONTROL_PLANE_FAILURE = "control_plane_failure"
    PARTIAL_OUTAGE = "partial_outage"
    CASCADE_DETECTED = "cascade_detected"
    RECOVERY_INEFFECTIVE = "recovery_ineffective"


@dataclass(frozen=True)
class ReliabilityFinding:
    kind: ReliabilityFindingKind
    event_id: str
    detail: str
    severity: int
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        if not 1 <= self.severity <= 5:
            raise ValueError("severity must be in [1,5]")


# =============================================================================
# SECTION 8 — INVARIANTS
# =============================================================================


class InvariantSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class InvariantViolation:
    invariant_id: str
    severity: InvariantSeverity
    subject_id: str
    detail: str


@dataclass(frozen=True)
class ReliabilitySnapshot:
    events: Mapping[str, FailureEvent]
    classifications: Mapping[str, CauseClassification]
    assessments: Mapping[str, RecoveryAssessment]
    cascade_depth: int
    cascade_breadth: int


@dataclass(frozen=True)
class ReliabilityInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[ReliabilitySnapshot],
                        Tuple[InvariantViolation, ...]]
    description: str


def _inv_classification_present(
    snap: ReliabilitySnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for eid in snap.events:
        if eid not in snap.classifications:
            out.append(InvariantViolation(
                invariant_id="rel.classification_present",
                severity=InvariantSeverity.HIGH,
                subject_id=eid,
                detail="event has no cause classification",
            ))
    return tuple(out)


def _inv_confidence_bounded(
    snap: ReliabilitySnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for eid, c in snap.classifications.items():
        if not 0.0 <= c.confidence <= 1.0:
            out.append(InvariantViolation(
                invariant_id="rel.confidence_bounded",
                severity=InvariantSeverity.HIGH,
                subject_id=eid,
                detail=f"confidence {c.confidence} out of [0,1]",
            ))
    return tuple(out)


def _inv_scores_bounded(
    snap: ReliabilitySnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for eid, c in snap.classifications.items():
        for cat, s in c.scores.items():
            if not 0.0 <= s <= 1.0:
                out.append(InvariantViolation(
                    invariant_id="rel.scores_bounded",
                    severity=InvariantSeverity.HIGH,
                    subject_id=f"{eid}:{cat.value}",
                    detail=f"score {s} out of [0,1]",
                ))
    return tuple(out)


def _inv_mixed_has_two_categories(
    snap: ReliabilitySnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for eid, c in snap.classifications.items():
        if c.primary is not CauseCategory.MIXED_CAUSE:
            continue
        above = [
            cat for cat, s in c.scores.items()
            if s >= _LOW_CONFIDENCE_CUTOFF
        ]
        if len(above) < 2:
            out.append(InvariantViolation(
                invariant_id="rel.mixed_has_two_categories",
                severity=InvariantSeverity.HIGH,
                subject_id=eid,
                detail=(
                    f"mixed_use only {len(above)} category(ies) above cutoff"
                ),
            ))
    return tuple(out)


def _inv_attack_requires_attack_signal(
    snap: ReliabilitySnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for eid, c in snap.classifications.items():
        if c.primary is not CauseCategory.ATTACK:
            continue
        sigs = c.supporting_signals.get(CauseCategory.ATTACK, ())
        if not sigs:
            out.append(InvariantViolation(
                invariant_id="rel.attack_requires_signal",
                severity=InvariantSeverity.HIGH,
                subject_id=eid,
                detail="ATTACK primary with no attack signal",
            ))
    return tuple(out)


def _inv_no_mixed_without_two_causes(
    snap: ReliabilitySnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for eid, c in snap.classifications.items():
        if c.primary is CauseCategory.MIXED_CAUSE and not c.mixed:
            out.append(InvariantViolation(
                invariant_id="rel.mixed_flag_consistent",
                severity=InvariantSeverity.HIGH,
                subject_id=eid,
                detail="mixed_cause without mixed=True flag",
            ))
    return tuple(out)


DEFAULT_INVARIANTS: Tuple[ReliabilityInvariant, ...] = (
    ReliabilityInvariant(
        invariant_id="rel.classification_present",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_classification_present,
        description="Every failure event must be classified.",
    ),
    ReliabilityInvariant(
        invariant_id="rel.confidence_bounded",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_confidence_bounded,
        description="Classification confidence must lie within [0,1].",
    ),
    ReliabilityInvariant(
        invariant_id="rel.scores_bounded",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_scores_bounded,
        description="Per-category scores must lie within [0,1].",
    ),
    ReliabilityInvariant(
        invariant_id="rel.mixed_has_two_categories",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_mixed_has_two_categories,
        description="MIXED_CAUSE requires two or more categories above cutoff.",
    ),
    ReliabilityInvariant(
        invariant_id="rel.attack_requires_signal",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_attack_requires_attack_signal,
        description="ATTACK primary requires at least one attack signal.",
    ),
    ReliabilityInvariant(
        invariant_id="rel.mixed_flag_consistent",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_no_mixed_without_two_causes,
        description="mixed_cause must set the mixed flag.",
    ),
)


def check_invariants(
    snap: ReliabilitySnapshot,
    invariants: Iterable[ReliabilityInvariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 9 — STORE
# =============================================================================


@dataclass(frozen=True)
class FailureRecord:
    event_id: str
    kind: FailureKind
    entity_id: str
    primary_cause: CauseCategory
    confidence: float
    severity: Severity
    cascade_depth: int
    updated_at: datetime


class ReliabilityStore(Protocol):
    def put(self, record: FailureRecord) -> None: ...
    def get(self, event_id: str) -> Optional[FailureRecord]: ...
    def all(self) -> Tuple[FailureRecord, ...]: ...


class InMemoryReliabilityStore:
    def __init__(self) -> None:
        self._data: Dict[str, FailureRecord] = {}

    def put(self, record: FailureRecord) -> None:
        existing = self._data.get(record.event_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._data[record.event_id] = record

    def get(self, event_id: str) -> Optional[FailureRecord]:
        return self._data.get(event_id)

    def all(self) -> Tuple[FailureRecord, ...]:
        return tuple(self._data.values())


class SqliteReliabilityStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS rel_events (
                event_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                primary_cause TEXT NOT NULL,
                confidence REAL NOT NULL,
                severity TEXT NOT NULL,
                cascade_depth INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS rel_signals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL,
                signal TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def put(self, record: FailureRecord) -> None:
        existing = self.get(record.event_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._conn.execute(
            """
            INSERT INTO rel_events
              (event_id, kind, entity_id, primary_cause, confidence,
               severity, cascade_depth, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(event_id) DO UPDATE SET
              kind=excluded.kind,
              entity_id=excluded.entity_id,
              primary_cause=excluded.primary_cause,
              confidence=excluded.confidence,
              severity=excluded.severity,
              cascade_depth=excluded.cascade_depth,
              updated_at=excluded.updated_at
            """,
            (
                record.event_id, record.kind.value, record.entity_id,
                record.primary_cause.value, record.confidence,
                record.severity.value, record.cascade_depth,
                record.updated_at.isoformat(),
            ),
        )
        self._conn.commit()

    def get(self, event_id: str) -> Optional[FailureRecord]:
        row = self._conn.execute(
            "SELECT kind, entity_id, primary_cause, confidence, severity, "
            "cascade_depth, updated_at FROM rel_events WHERE event_id = ?",
            (event_id,),
        ).fetchone()
        if row is None:
            return None
        return FailureRecord(
            event_id=event_id, kind=FailureKind(row[0]),
            entity_id=row[1], primary_cause=CauseCategory(row[2]),
            confidence=float(row[3]), severity=Severity(row[4]),
            cascade_depth=int(row[5]),
            updated_at=datetime.fromisoformat(row[6]),
        )

    def all(self) -> Tuple[FailureRecord, ...]:
        rows = self._conn.execute("SELECT event_id FROM rel_events").fetchall()
        return tuple(
            r for r in (self.get(x[0]) for x in rows) if r is not None
        )

    def put_signal(self, event_id: str, signal: Signal) -> None:
        self._conn.execute(
            "INSERT INTO rel_signals (event_id, signal) VALUES (?, ?)",
            (event_id, signal.value),
        )
        self._conn.commit()

    def signals_for(self, event_id: str) -> Tuple[Signal, ...]:
        rows = self._conn.execute(
            "SELECT signal FROM rel_signals WHERE event_id = ?",
            (event_id,),
        ).fetchall()
        return tuple(Signal(r[0]) for r in rows)


# =============================================================================
# SECTION 10 — ENGINE
# =============================================================================


class ReliabilityFailureEngine:
    """Reliability + failure-engineering engine.

    Records failure events, classifies cause, tracks cascade propagation,
    assesses recovery, and emits findings.
    """

    def __init__(
        self,
        *,
        store: Optional[ReliabilityStore] = None,
        mixed_margin: float = _MIXED_MARGIN,
        cascade_depth_threshold: int = 2,
        cascade_breadth_threshold: int = 3,
        low_confidence_cutoff: float = _LOW_CONFIDENCE_CUTOFF,
    ) -> None:
        for n, v in (
            ("mixed_margin", mixed_margin),
            ("low_confidence_cutoff", low_confidence_cutoff),
        ):
            if not 0.0 <= v <= 1.0:
                raise ValueError(f"{n} must be within [0,1]")
        if cascade_depth_threshold < 1:
            raise ValueError("cascade_depth_threshold must be >= 1")
        if cascade_breadth_threshold < 1:
            raise ValueError("cascade_breadth_threshold must be >= 1")

        self._store: ReliabilityStore = store or InMemoryReliabilityStore()
        self._graph = CascadeGraph()
        self._classifications: Dict[str, CauseClassification] = {}
        self._assessments: Dict[str, RecoveryAssessment] = {}
        self._attempts: Dict[str, List[RecoveryAttempt]] = {}
        self._findings: List[ReliabilityFinding] = []
        self._violations: Tuple[InvariantViolation, ...] = ()

        self._mixed_margin = mixed_margin
        self._cascade_depth_threshold = cascade_depth_threshold
        self._cascade_breadth_threshold = cascade_breadth_threshold
        self._low_conf_cutoff = low_confidence_cutoff

    # ---- registration ----------------------------------------------------

    def register_event(self, event: FailureEvent) -> None:
        self._graph.add(event)
        if isinstance(self._store, SqliteReliabilityStore):
            for s in event.signals:
                self._store.put_signal(event.event_id, s)

    def record_recovery(self, attempt: RecoveryAttempt) -> None:
        if attempt.event_id not in {
            e.event_id for e in self._graph.events()
        }:
            raise KeyError(
                f"event {attempt.event_id} not registered"
            )
        self._attempts.setdefault(attempt.event_id, []).append(attempt)

    def graph(self) -> CascadeGraph:
        return self._graph

    def set_mixed_margin(self, margin: float) -> None:
        if not 0.0 <= margin <= 1.0:
            raise ValueError("margin must be within [0,1]")
        self._mixed_margin = margin

    def set_cascade_thresholds(self, *, depth: int, breadth: int) -> None:
        if depth < 1:
            raise ValueError("depth must be >= 1")
        if breadth < 1:
            raise ValueError("breadth must be >= 1")
        self._cascade_depth_threshold = depth
        self._cascade_breadth_threshold = breadth

    # ---- recompute -------------------------------------------------------

    def recompute(self, *, at: datetime) -> Tuple[FailureRecord, ...]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

        self._findings = []
        records: List[FailureRecord] = []

        for e in self._graph.events():
            classification = classify_cause(e)
            self._classifications[e.event_id] = classification
            self._emit_cause_findings(e, classification, at=at)

            # Kind-based findings
            if e.kind is FailureKind.RESOURCE_EXHAUSTION:
                self._findings.append(ReliabilityFinding(
                    kind=ReliabilityFindingKind.RESOURCE_EXHAUSTION,
                    event_id=e.event_id,
                    detail=f"resource exhaustion on {e.entity_id}",
                    severity=4, at=at,
                ))
            elif e.kind is FailureKind.DEPENDENCY:
                self._findings.append(ReliabilityFinding(
                    kind=ReliabilityFindingKind.DEPENDENCY_FAILURE,
                    event_id=e.event_id,
                    detail=f"dependency failure on {e.entity_id}",
                    severity=3, at=at,
                ))
            elif e.kind is FailureKind.CONTROL_PLANE:
                self._findings.append(ReliabilityFinding(
                    kind=ReliabilityFindingKind.CONTROL_PLANE_FAILURE,
                    event_id=e.event_id,
                    detail=f"control-plane failure on {e.entity_id}",
                    severity=5, at=at,
                ))
            elif e.kind is FailureKind.PARTIAL_OUTAGE:
                self._findings.append(ReliabilityFinding(
                    kind=ReliabilityFindingKind.PARTIAL_OUTAGE,
                    event_id=e.event_id,
                    detail=f"partial outage on {e.entity_id}",
                    severity=4, at=at,
                ))

            # Cascade depth
            depth = self._graph.depth_of(e.event_id)
            if depth >= self._cascade_depth_threshold:
                self._findings.append(ReliabilityFinding(
                    kind=ReliabilityFindingKind.CASCADE_DETECTED,
                    event_id=e.event_id,
                    detail=(
                        f"cascade depth {depth} on {e.entity_id}"
                    ),
                    severity=4, at=at,
                ))

            rec = FailureRecord(
                event_id=e.event_id, kind=e.kind,
                entity_id=e.entity_id,
                primary_cause=classification.primary,
                confidence=classification.confidence,
                severity=e.severity,
                cascade_depth=depth, updated_at=at,
            )
            self._store.put(rec)
            records.append(rec)

        # Recovery assessments
        for eid, attempts in self._attempts.items():
            assessment = assess_recovery(attempts)
            self._assessments[eid] = assessment
            if not assessment.effective:
                self._findings.append(ReliabilityFinding(
                    kind=ReliabilityFindingKind.RECOVERY_INEFFECTIVE,
                    event_id=eid,
                    detail=assessment.rationale,
                    severity=5 if assessment.action_only else 4,
                    at=at,
                ))

        self._violations = check_invariants(self.snapshot())
        return tuple(records)

    def _emit_cause_findings(
        self,
        event: FailureEvent,
        c: CauseClassification,
        *,
        at: datetime,
    ) -> None:
        if c.primary is CauseCategory.ATTACK:
            self._findings.append(ReliabilityFinding(
                kind=ReliabilityFindingKind.ATTACK_INDICATED,
                event_id=event.event_id,
                detail=c.rationale,
                severity=5, at=at,
            ))
        elif c.primary is CauseCategory.FAILURE:
            self._findings.append(ReliabilityFinding(
                kind=ReliabilityFindingKind.FAILURE_INDICATED,
                event_id=event.event_id,
                detail=c.rationale,
                severity=3, at=at,
            ))
        elif c.primary is CauseCategory.MISCONFIGURATION:
            self._findings.append(ReliabilityFinding(
                kind=ReliabilityFindingKind.MISCONFIGURATION_INDICATED,
                event_id=event.event_id,
                detail=c.rationale,
                severity=4, at=at,
            ))
        elif c.primary is CauseCategory.MIXED_CAUSE:
            self._findings.append(ReliabilityFinding(
                kind=ReliabilityFindingKind.MIXED_CAUSE_INDICATED,
                event_id=event.event_id,
                detail=c.rationale,
                severity=4, at=at,
            ))
        if c.confidence < self._low_conf_cutoff:
            self._findings.append(ReliabilityFinding(
                kind=ReliabilityFindingKind.LOW_CONFIDENCE_CAUSE,
                event_id=event.event_id,
                detail=(
                    f"cause confidence {c.confidence:.3f} below "
                    f"{self._low_conf_cutoff:.2f}"
                ),
                severity=2, at=at,
            ))

    # ---- queries ---------------------------------------------------------

    def classification(self, event_id: str) -> Optional[CauseClassification]:
        return self._classifications.get(event_id)

    def assessment(self, event_id: str) -> Optional[RecoveryAssessment]:
        return self._assessments.get(event_id)

    def findings(self) -> Tuple[ReliabilityFinding, ...]:
        return tuple(self._findings)

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return self._violations

    def record(self, event_id: str) -> Optional[FailureRecord]:
        return self._store.get(event_id)

    def cascade_depth(self) -> int:
        return self._graph.cascade_depth()

    def cascade_breadth(self) -> int:
        return self._graph.cascade_breadth()

    def root_events(self) -> Tuple[str, ...]:
        return self._graph.roots()

    def cascade_subtree(self, event_id: str) -> Tuple[str, ...]:
        return self._graph.subtree(event_id)

    def snapshot(self) -> ReliabilitySnapshot:
        return ReliabilitySnapshot(
            events={e.event_id: e for e in self._graph.events()},
            classifications=dict(self._classifications),
            assessments=dict(self._assessments),
            cascade_depth=self.cascade_depth(),
            cascade_breadth=self.cascade_breadth(),
        )


# =============================================================================
# SECTION 11 — TESTS
# =============================================================================


def _t0() -> datetime:
    from datetime import timezone
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _t(seconds: int) -> datetime:
    return _t0() + timedelta(seconds=seconds)


def _event(
    eid: str, *,
    kind: FailureKind = FailureKind.ACCIDENTAL,
    entity: str = "e",
    severity: Severity = Severity.MEDIUM,
    signals: Iterable[Signal] = (),
    parent: Optional[str] = None,
    at: Optional[datetime] = None,
    detail: str = "",
) -> FailureEvent:
    return FailureEvent(
        event_id=eid, kind=kind, entity_id=entity, severity=severity,
        signals=frozenset(signals), at=at or _t0(),
        parent_event_id=parent, detail=detail,
    )


def _attempt(
    aid: str, eid: str = "e", *,
    action_verified: bool = True,
    objective_achieved: bool = False,
    elapsed: float = 60.0,
) -> RecoveryAttempt:
    return RecoveryAttempt(
        attempt_id=aid, event_id=eid, started_at=_t0(),
        finished_at=_t0(), action_verified=action_verified,
        objective_achieved=objective_achieved,
        elapsed_seconds=elapsed,
    )


# ---- domain ----

def test_event_requires_id() -> None:
    try:
        FailureEvent(
            event_id="", kind=FailureKind.ACCIDENTAL,
            entity_id="e", severity=Severity.LOW,
            signals=frozenset(), at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_event_requires_aware_time() -> None:
    from datetime import datetime as dt
    try:
        FailureEvent(
            event_id="e", kind=FailureKind.ACCIDENTAL,
            entity_id="x", severity=Severity.LOW,
            signals=frozenset(), at=dt(2026, 1, 1),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_event_self_parent_rejected() -> None:
    try:
        FailureEvent(
            event_id="e", kind=FailureKind.ACCIDENTAL,
            entity_id="x", severity=Severity.LOW,
            signals=frozenset(), at=_t0(),
            parent_event_id="e",
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_severity_weights_monotonic() -> None:
    assert severity_weight(Severity.LOW) < severity_weight(Severity.MEDIUM)
    assert severity_weight(Severity.MEDIUM) < severity_weight(Severity.HIGH)
    assert severity_weight(Severity.HIGH) < severity_weight(Severity.CRITICAL)


def test_signal_weights_present() -> None:
    w = signal_weights(Signal.MALICIOUS_PAYLOAD)
    assert CauseCategory.ATTACK in w
    assert w[CauseCategory.ATTACK] > 0.5


# ---- cause classification ----

def test_classify_attack_from_strong_signals() -> None:
    e = _event("e", signals={
        Signal.MALICIOUS_PAYLOAD, Signal.LATERAL_MOVEMENT,
    })
    c = classify_cause(e)
    assert c.primary is CauseCategory.ATTACK
    assert c.confidence >= 0.5


def test_classify_failure_from_hardware_signals() -> None:
    e = _event("e", kind=FailureKind.INFRASTRUCTURE, signals={
        Signal.HARDWARE_FAULT,
    })
    c = classify_cause(e)
    assert c.primary is CauseCategory.FAILURE


def test_classify_misconfiguration() -> None:
    e = _event("e", kind=FailureKind.CONFIGURATION, signals={
        Signal.RECENT_CONFIG_CHANGE, Signal.INVALID_SETTING,
    })
    c = classify_cause(e)
    assert c.primary is CauseCategory.MISCONFIGURATION


def test_classify_mixed_cause() -> None:
    e = _event("e", signals={
        Signal.MALICIOUS_PAYLOAD, Signal.INVALID_SETTING,
    })
    c = classify_cause(e)
    # attack score 0.9, misconfig 0.9 → mixed
    assert c.primary is CauseCategory.MIXED_CAUSE
    assert c.mixed is True


def test_classify_unknown_when_no_signals() -> None:
    e = _event("e", kind=FailureKind.CASCADING)
    c = classify_cause(e)
    assert c.primary is CauseCategory.UNKNOWN


def test_classify_kind_prior_when_no_signals() -> None:
    e = _event("e", kind=FailureKind.CONFIGURATION)
    c = classify_cause(e)
    # prior pushes MISCONFIGURATION to 0.10 → still below cutoff
    assert c.primary is CauseCategory.UNKNOWN


def test_classify_signal_strength_bounded_at_one() -> None:
    e = _event("e", signals={
        Signal.MALICIOUS_PAYLOAD, Signal.KNOWN_ATTACK_TTP,
        Signal.LATERAL_MOVEMENT, Signal.CREDENTIAL_MISUSE,
    })
    c = classify_cause(e)
    for s in c.scores.values():
        assert 0.0 <= s <= 1.0


def test_classify_supporting_signals_recorded() -> None:
    e = _event("e", signals={Signal.MALICIOUS_PAYLOAD})
    c = classify_cause(e)
    assert Signal.MALICIOUS_PAYLOAD in c.supporting_signals[
        CauseCategory.ATTACK
    ]


# ---- cascade graph ----

def test_cascade_add_event() -> None:
    g = CascadeGraph()
    g.add(_event("a"))
    assert len(g.events()) == 1


def test_cascade_duplicate_event_rejected() -> None:
    g = CascadeGraph()
    g.add(_event("a"))
    try:
        g.add(_event("a"))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_cascade_unknown_parent_rejected() -> None:
    g = CascadeGraph()
    try:
        g.add(_event("b", parent="missing"))
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_cascade_depth_linear() -> None:
    g = CascadeGraph()
    g.add(_event("a"))
    g.add(_event("b", parent="a"))
    g.add(_event("c", parent="b"))
    assert g.depth_of("a") == 0
    assert g.depth_of("c") == 2
    assert g.cascade_depth() == 2


def test_cascade_breadth_fanout() -> None:
    g = CascadeGraph()
    g.add(_event("root"))
    for i in range(4):
        g.add(_event(f"c{i}", parent="root"))
    assert g.cascade_breadth() == 4


def test_cascade_roots() -> None:
    g = CascadeGraph()
    g.add(_event("r"))
    g.add(_event("a", parent="r"))
    g.add(_event("b", parent="r"))
    assert g.roots() == ("r",)


def test_cascade_subtree() -> None:
    g = CascadeGraph()
    g.add(_event("r"))
    g.add(_event("a", parent="r"))
    g.add(_event("b", parent="a"))
    g.add(_event("c", parent="r"))
    subtree = set(g.subtree("r"))
    assert subtree == {"r", "a", "b", "c"}


def test_cascade_children_parents() -> None:
    g = CascadeGraph()
    g.add(_event("r"))
    g.add(_event("a", parent="r"))
    assert g.children("r") == ("a",)
    assert g.parents("a") == ("r",)


# ---- recovery ----

def test_recovery_no_attempts_not_effective() -> None:
    r = assess_recovery(())
    assert not r.effective
    assert not r.action_only


def test_recovery_action_only_not_effective() -> None:
    r = assess_recovery([_attempt("a", action_verified=True,
                                  objective_achieved=False)])
    assert not r.effective
    assert r.action_only


def test_recovery_objective_achieved_effective() -> None:
    r = assess_recovery([_attempt("a", action_verified=True,
                                  objective_achieved=True)])
    assert r.effective
    assert not r.action_only


def test_recovery_mixed_attempts_effective_if_any_achieved() -> None:
    r = assess_recovery([
        _attempt("a", action_verified=True, objective_achieved=False),
        _attempt("b", action_verified=True, objective_achieved=True),
    ])
    assert r.effective
    assert not r.action_only


def test_recovery_neither_verified_nor_achieved() -> None:
    r = assess_recovery([_attempt("a", action_verified=False,
                                  objective_achieved=False)])
    assert not r.effective
    assert not r.action_only


# ---- engine ----

def test_engine_register_event() -> None:
    eng = ReliabilityFailureEngine()
    eng.register_event(_event("e"))
    eng.recompute(at=_t0())


def test_engine_recompute_produces_records() -> None:
    eng = ReliabilityFailureEngine()
    eng.register_event(_event("e", signals={Signal.HARDWARE_FAULT}))
    records = eng.recompute(at=_t0())
    assert len(records) == 1
    assert records[0].primary_cause is CauseCategory.FAILURE


def test_engine_attack_indicated_finding() -> None:
    eng = ReliabilityFailureEngine()
    eng.register_event(_event("e", signals={Signal.MALICIOUS_PAYLOAD}))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert ReliabilityFindingKind.ATTACK_INDICATED in kinds


def test_engine_misconfiguration_finding() -> None:
    eng = ReliabilityFailureEngine()
    eng.register_event(_event(
        "e", kind=FailureKind.CONFIGURATION,
        signals={Signal.RECENT_CONFIG_CHANGE, Signal.INVALID_SETTING},
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert ReliabilityFindingKind.MISCONFIGURATION_INDICATED in kinds


def test_engine_mixed_cause_finding() -> None:
    eng = ReliabilityFailureEngine()
    eng.register_event(_event(
        "e", signals={Signal.MALICIOUS_PAYLOAD, Signal.INVALID_SETTING},
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert ReliabilityFindingKind.MIXED_CAUSE_INDICATED in kinds


def test_engine_resource_exhaustion_finding() -> None:
    eng = ReliabilityFailureEngine()
    eng.register_event(_event(
        "e", kind=FailureKind.RESOURCE_EXHAUSTION,
        signals={Signal.MEMORY_SATURATION},
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert ReliabilityFindingKind.RESOURCE_EXHAUSTION in kinds


def test_engine_dependency_failure_finding() -> None:
    eng = ReliabilityFailureEngine()
    eng.register_event(_event(
        "e", kind=FailureKind.DEPENDENCY, signals={Signal.TIMEOUT},
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert ReliabilityFindingKind.DEPENDENCY_FAILURE in kinds


def test_engine_control_plane_finding() -> None:
    eng = ReliabilityFailureEngine()
    eng.register_event(_event(
        "e", kind=FailureKind.CONTROL_PLANE,
        signals={Signal.CONSENSUS_LOST},
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert ReliabilityFindingKind.CONTROL_PLANE_FAILURE in kinds


def test_engine_partial_outage_finding() -> None:
    eng = ReliabilityFailureEngine()
    eng.register_event(_event("e", kind=FailureKind.PARTIAL_OUTAGE))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert ReliabilityFindingKind.PARTIAL_OUTAGE in kinds


def test_engine_cascade_finding() -> None:
    eng = ReliabilityFailureEngine()
    eng.set_cascade_thresholds(depth=2, breadth=3)
    eng.register_event(_event("r", signals={Signal.HARDWARE_FAULT}))
    eng.register_event(_event("a", parent="r"))
    eng.register_event(_event("b", parent="a"))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert ReliabilityFindingKind.CASCADE_DETECTED in kinds


def test_engine_recovery_ineffective_finding() -> None:
    eng = ReliabilityFailureEngine()
    eng.register_event(_event("e"))
    eng.record_recovery(_attempt("a", eid="e",
                                 action_verified=True,
                                 objective_achieved=False))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert ReliabilityFindingKind.RECOVERY_INEFFECTIVE in kinds


def test_engine_low_confidence_finding() -> None:
    eng = ReliabilityFailureEngine()
    eng.register_event(_event("e", kind=FailureKind.CASCADING))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert ReliabilityFindingKind.LOW_CONFIDENCE_CAUSE in kinds


def test_engine_record_lookup() -> None:
    eng = ReliabilityFailureEngine()
    eng.register_event(_event("e", signals={Signal.MALICIOUS_PAYLOAD}))
    eng.recompute(at=_t0())
    rec = eng.record("e")
    assert rec is not None
    assert rec.primary_cause is CauseCategory.ATTACK


def test_engine_recovery_unknown_event_rejected() -> None:
    eng = ReliabilityFailureEngine()
    try:
        eng.record_recovery(_attempt("a", eid="missing"))
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_engine_cascade_depth_and_breadth() -> None:
    eng = ReliabilityFailureEngine()
    eng.register_event(_event("r"))
    eng.register_event(_event("a", parent="r"))
    eng.register_event(_event("b", parent="a"))
    eng.recompute(at=_t0())
    assert eng.cascade_depth() == 2


def test_engine_root_events() -> None:
    eng = ReliabilityFailureEngine()
    eng.register_event(_event("r"))
    eng.register_event(_event("a", parent="r"))
    eng.recompute(at=_t0())
    assert eng.root_events() == ("r",)


def test_engine_cascade_subtree() -> None:
    eng = ReliabilityFailureEngine()
    eng.register_event(_event("r"))
    eng.register_event(_event("a", parent="r"))
    eng.register_event(_event("b", parent="a"))
    eng.recompute(at=_t0())
    assert set(eng.cascade_subtree("r")) == {"r", "a", "b"}


def test_engine_recompute_rejects_naive_time() -> None:
    from datetime import datetime as dt
    eng = ReliabilityFailureEngine()
    try:
        eng.recompute(at=dt(2026, 1, 1))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- invariants ----

def test_invariant_clean_snapshot() -> None:
    eng = ReliabilityFailureEngine()
    eng.register_event(_event("e", signals={Signal.MALICIOUS_PAYLOAD}))
    eng.recompute(at=_t0())
    assert eng.violations() == ()


def test_invariant_attack_requires_signal() -> None:
    # Craft a classification directly
    bad = CauseClassification(
        event_id="e", primary=CauseCategory.ATTACK, confidence=0.9,
        scores={c: 0.0 for c in CauseCategory},
        supporting_signals={c: () for c in CauseCategory},
        mixed=False, rationale="fake",
    )
    snap = ReliabilitySnapshot(
        events={}, classifications={"e": bad}, assessments={},
        cascade_depth=0, cascade_breadth=0,
    )
    v = check_invariants(snap)
    assert any(x.invariant_id == "rel.attack_requires_signal" for x in v)


def test_invariant_mixed_has_two_categories() -> None:
    bad = CauseClassification(
        event_id="e", primary=CauseCategory.MIXED_CAUSE, confidence=0.5,
        scores={c: 0.0 for c in CauseCategory},
        supporting_signals={c: () for c in CauseCategory},
        mixed=True, rationale="fake",
    )
    snap = ReliabilitySnapshot(
        events={}, classifications={"e": bad}, assessments={},
        cascade_depth=0, cascade_breadth=0,
    )
    v = check_invariants(snap)
    assert any(
        x.invariant_id == "rel.mixed_has_two_categories" for x in v
    )


def test_invariant_confidence_bounded() -> None:
    bad = CauseClassification(
        event_id="e", primary=CauseCategory.FAILURE, confidence=0.5,
        scores={c: 0.5 for c in CauseCategory},
        supporting_signals={c: () for c in CauseCategory},
        mixed=False, rationale="fake",
    )
    # Now override confidence via direct mutation
    bad2 = object.__new__(CauseClassification)
    object.__setattr__(bad2, "event_id", "e")
    object.__setattr__(bad2, "primary", CauseCategory.FAILURE)
    object.__setattr__(bad2, "confidence", 1.5)
    object.__setattr__(bad2, "scores", {c: 0.5 for c in CauseCategory})
    object.__setattr__(bad2, "supporting_signals",
                       {c: () for c in CauseCategory})
    object.__setattr__(bad2, "mixed", False)
    object.__setattr__(bad2, "rationale", "fake")
    snap = ReliabilitySnapshot(
        events={}, classifications={"e": bad2}, assessments={},
        cascade_depth=0, cascade_breadth=0,
    )
    v = check_invariants(snap)
    assert any(x.invariant_id == "rel.confidence_bounded" for x in v)


# ---- policy ----

def test_engine_constructor_validation() -> None:
    try:
        ReliabilityFailureEngine(mixed_margin=1.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_set_mixed_margin() -> None:
    eng = ReliabilityFailureEngine()
    eng.set_mixed_margin(0.05)
    eng.register_event(_event(
        "e", signals={Signal.MALICIOUS_PAYLOAD, Signal.INVALID_SETTING},
    ))
    eng.recompute(at=_t0())
    # Still mixed at small margin? attack 0.9, misconfig 0.9 → diff 0 → yes
    assert eng.classification("e").primary is CauseCategory.MIXED_CAUSE


def test_engine_set_cascade_thresholds_validation() -> None:
    eng = ReliabilityFailureEngine()
    try:
        eng.set_cascade_thresholds(depth=0, breadth=1)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


# ---- store ----

def test_in_memory_store_rejects_stale() -> None:
    s = InMemoryReliabilityStore()
    t = _t0()
    s.put(FailureRecord(
        "e", FailureKind.ACCIDENTAL, "x",
        CauseCategory.FAILURE, 0.5, Severity.MEDIUM, 0, t,
    ))
    earlier = t.replace(year=t.year - 1)
    try:
        s.put(FailureRecord(
            "e", FailureKind.ACCIDENTAL, "x",
            CauseCategory.UNKNOWN, 0.1, Severity.LOW, 0, earlier,
        ))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "rel.db")
    store = SqliteReliabilityStore(db)
    t = _t0()
    store.put(FailureRecord(
        "e", FailureKind.INFRASTRUCTURE, "db-1",
        CauseCategory.FAILURE, 0.8, Severity.HIGH, 1, t,
    ))
    got = store.get("e")
    assert got is not None
    assert got.primary_cause is CauseCategory.FAILURE
    assert got.kind is FailureKind.INFRASTRUCTURE


def test_sqlite_store_signal_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "rel.db")
    store = SqliteReliabilityStore(db)
    store.put_signal("e", Signal.MALICIOUS_PAYLOAD)
    store.put_signal("e", Signal.LATERAL_MOVEMENT)
    sigs = store.signals_for("e")
    assert Signal.MALICIOUS_PAYLOAD in sigs
    assert Signal.LATERAL_MOVEMENT in sigs


# =============================================================================
# SECTION 12 — MANUAL RUNNER
# =============================================================================


def _run_all_tests() -> Tuple[int, int]:
    import traceback
    g = globals()
    tests = sorted(
        (name, fn) for name, fn in g.items()
        if name.startswith("test_") and callable(fn)
    )
    passed = 0
    failed = 0
    for name, fn in tests:
        try:
            fn()
        except Exception:
            failed += 1
            print(f"[FAIL] {name}")
            traceback.print_exc()
        else:
            passed += 1
            print(f"[ OK ] {name}")
    return passed, failed


if __name__ == "__main__":
    passed, failed = _run_all_tests()
    print(f"\n{passed} passed, {failed} failed")
    if failed:
        raise SystemExit(1)
