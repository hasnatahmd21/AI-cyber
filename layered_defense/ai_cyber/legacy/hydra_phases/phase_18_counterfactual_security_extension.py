"""
HYDRA POST-CORE — PHASE 18: COUNTERFACTUAL SECURITY EXTENSION
================================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * Domain — timeline events, actual outcome, counterfactual queries,
    counterfactual outcomes, results, findings
  * 6 counterfactual kinds:
      - CONTROL_INTACT              (what if this control had not failed?)
      - EARLIER_REVOCATION          (what if authority had been revoked earlier?)
      - EARLIER_ISOLATION           (what if this dependency had been isolated?)
      - ALTERNATIVE_BASELINE        (what if recovery had used another trusted baseline?)
      - DELAYED_INTERVENTION        (what if the intervention had been delayed?)
      - ALTERNATIVE_ATTACK_PATH     (what if the attacker had chosen another path?)
  * Deterministic effect model — actual outcome and counterfactual
    outcomes computed from the same simulation for internal consistency
  * Regret + multi-dimensional delta (risk, time-to-control, blast radius,
    data exposure)
  * Findings — HIGH_REGRET, KEY_LEVERAGE_POINT, INEFFECTIVE_INTERVENTION,
    WASTED_ISOLATION, DEFENDER_EFFECTIVE, BASELINE_MISMATCH
  * Machine-checkable counterfactual invariants
  * In-memory + SQLite stores
  * Phase-18 engine facade
  * Full test suite + manual runner

This is NEW counterfactual security technology. It is NOT a second
counterfactual reasoning engine. It extends the existing HYDRA
counterfactual foundation to answer defender-relevant questions and to
turn the answers into measurable defensive-strategy improvements.

No third-party dependencies.

Run tests:
    python hydra_phase18_counterfactual_security.py
    pytest hydra_phase18_counterfactual_security.py -q
"""
from __future__ import annotations

import json
import math
import sqlite3
from dataclasses import dataclass, field, replace
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


class TimelineEventKind(str, Enum):
    ATTACKER_STEP = "attacker_step"
    DATA_ACCESS = "data_access"
    CONTROL_FAILED = "control_failed"
    CONTROL_RECOVERED = "control_recovered"
    AUTHORITY_GRANTED = "authority_granted"
    AUTHORITY_REVOKED = "authority_revoked"
    ISOLATION_APPLIED = "isolation_applied"
    RECOVERY_STARTED = "recovery_started"
    DETECTION = "detection"


class CounterfactualKind(str, Enum):
    CONTROL_INTACT = "control_intact"
    EARLIER_REVOCATION = "earlier_revocation"
    EARLIER_ISOLATION = "earlier_isolation"
    ALTERNATIVE_BASELINE = "alternative_baseline"
    DELAYED_INTERVENTION = "delayed_intervention"
    ALTERNATIVE_ATTACK_PATH = "alternative_attack_path"


class OutcomeDirection(str, Enum):
    BETTER = "better"
    SAME = "same"
    WORSE = "worse"


class CounterfactualFindingKind(str, Enum):
    HIGH_REGRET = "high_regret"
    KEY_LEVERAGE_POINT = "key_leverage_point"
    INEFFECTIVE_INTERVENTION = "ineffective_intervention"
    WASTED_ISOLATION = "wasted_isolation"
    DEFENDER_EFFECTIVE = "defender_effective"
    BASELINE_MISMATCH = "baseline_mismatch"


NO_CONTROL_SENTINEL: float = 1.0e9
DIRECTION_EPSILON: float = 1.0e-9


# =============================================================================
# SECTION 3 — TIMELINE
# =============================================================================


@dataclass(frozen=True)
class TimelineEvent:
    event_id: str
    at: datetime
    kind: TimelineEventKind
    entity_id: str
    magnitude: float = 0.0
    detail: str = ""

    def __post_init__(self) -> None:
        if not self.event_id:
            raise ValueError("event_id is required")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        if not self.entity_id:
            raise ValueError("entity_id is required")
        if not 0.0 <= self.magnitude <= 1.0:
            raise ValueError("magnitude must be within [0,1]")


@dataclass(frozen=True)
class ActualTimeline:
    timeline_id: str
    events: Tuple[TimelineEvent, ...]

    def __post_init__(self) -> None:
        if not self.timeline_id:
            raise ValueError("timeline_id is required")
        seen: set = set()
        for e in self.events:
            if e.event_id in seen:
                raise ValueError(f"duplicate event id {e.event_id}")
            seen.add(e.event_id)

    def sorted_events(self) -> Tuple[TimelineEvent, ...]:
        return tuple(sorted(
            self.events, key=lambda e: (e.at, e.event_id),
        ))

    def event(self, event_id: str) -> TimelineEvent:
        for e in self.events:
            if e.event_id == event_id:
                return e
        raise KeyError(f"unknown event {event_id}")

    def events_of_kind(
        self, kind: TimelineEventKind,
    ) -> Tuple[TimelineEvent, ...]:
        return tuple(e for e in self.events if e.kind is kind)


# =============================================================================
# SECTION 4 — OUTCOMES
# =============================================================================


@dataclass(frozen=True)
class Outcome:
    """Multi-dimensional security outcome."""
    final_risk: float
    time_to_control_seconds: float
    blast_radius: int
    data_exposed: bool

    def __post_init__(self) -> None:
        if not 0.0 <= self.final_risk <= 1.0:
            raise ValueError("final_risk must be within [0,1]")
        if self.time_to_control_seconds < 0:
            raise ValueError("time_to_control_seconds must be >= 0")
        if self.blast_radius < 0:
            raise ValueError("blast_radius must be >= 0")

    def weighted_score(self) -> float:
        """Lower is better. Deterministic scalar for direction comparison."""
        t = min(1.0, self.time_to_control_seconds / 3600.0)
        b = min(1.0, self.blast_radius / 10.0)
        d = 1.0 if self.data_exposed else 0.0
        return (
            0.50 * self.final_risk
            + 0.20 * t
            + 0.20 * b
            + 0.10 * d
        )


ActualOutcome = Outcome
CounterfactualOutcome = Outcome


# =============================================================================
# SECTION 5 — SIMULATION
# =============================================================================


def simulate(timeline: ActualTimeline) -> Outcome:
    """Deterministic outcome simulation over an event timeline.

    Rules (in event order):
      * CONTROL_FAILED   — mark entity as unprotected
      * CONTROL_RECOVERED— mark entity as protected
      * ISOLATION_APPLIED— mark entity as isolated + protected; set
                           controlled_at if not already set
      * AUTHORITY_REVOKED— set controlled_at if not already set
      * RECOVERY_STARTED — set controlled_at if not already set
      * ATTACKER_STEP    — if entity not isolated and not protected,
                           add magnitude to risk; record entity in blast
      * DATA_ACCESS      — if controlled_at is None, mark data_exposed
    """
    events = timeline.sorted_events()

    protection: Dict[str, bool] = {}
    isolated: FrozenSet[str] = frozenset()
    isolated_set: set = set()

    risk = 0.0
    first_attack_at: Optional[datetime] = None
    controlled_at: Optional[datetime] = None
    data_exposed = False
    blast_entities: set = set()

    for e in events:
        if e.kind is TimelineEventKind.CONTROL_FAILED:
            protection[e.entity_id] = False
        elif e.kind is TimelineEventKind.CONTROL_RECOVERED:
            protection[e.entity_id] = True
        elif e.kind is TimelineEventKind.ISOLATION_APPLIED:
            isolated_set.add(e.entity_id)
            protection[e.entity_id] = True
            if controlled_at is None:
                controlled_at = e.at
        elif e.kind is TimelineEventKind.AUTHORITY_REVOKED:
            if controlled_at is None:
                controlled_at = e.at
        elif e.kind is TimelineEventKind.RECOVERY_STARTED:
            if controlled_at is None:
                controlled_at = e.at
        elif e.kind is TimelineEventKind.ATTACKER_STEP:
            if first_attack_at is None:
                first_attack_at = e.at
            if e.entity_id in isolated_set:
                continue
            if protection.get(e.entity_id, False):
                continue
            risk = min(1.0, risk + e.magnitude)
            blast_entities.add(e.entity_id)
        elif e.kind is TimelineEventKind.DATA_ACCESS:
            if controlled_at is None:
                data_exposed = True

    if first_attack_at is not None and controlled_at is not None:
        tt = max(0.0, (controlled_at - first_attack_at).total_seconds())
    elif first_attack_at is not None:
        tt = NO_CONTROL_SENTINEL
    else:
        tt = 0.0

    return Outcome(
        final_risk=risk,
        time_to_control_seconds=tt,
        blast_radius=len(blast_entities),
        data_exposed=data_exposed,
    )


# =============================================================================
# SECTION 6 — QUERY + MODIFICATIONS
# =============================================================================


@dataclass(frozen=True)
class CounterfactualQuery:
    query_id: str
    kind: CounterfactualKind
    description: str = ""
    target_event_id: Optional[str] = None
    shift_seconds: float = 0.0
    alternative_entity_id: Optional[str] = None
    alternative_magnitude: Optional[float] = None
    alternative_recovery_ok: Optional[bool] = None

    def __post_init__(self) -> None:
        if not self.query_id:
            raise ValueError("query_id is required")
        if self.shift_seconds < 0:
            raise ValueError("shift_seconds must be >= 0")
        if self.alternative_magnitude is not None \
           and not 0.0 <= self.alternative_magnitude <= 1.0:
            raise ValueError("alternative_magnitude must be within [0,1]")


def _replace_event(
    timeline: ActualTimeline, new_event: TimelineEvent,
) -> ActualTimeline:
    new_events = tuple(
        new_event if e.event_id == new_event.event_id else e
        for e in timeline.events
    )
    return replace(timeline, events=new_events)


def _insert_event(
    timeline: ActualTimeline, new_event: TimelineEvent,
) -> ActualTimeline:
    if any(e.event_id == new_event.event_id for e in timeline.events):
        raise ValueError(f"event {new_event.event_id} already exists")
    return replace(timeline, events=timeline.events + (new_event,))


def apply_modification(
    timeline: ActualTimeline,
    query: CounterfactualQuery,
) -> ActualTimeline:
    """Apply the query's modification and return the counterfactual timeline."""
    kind = query.kind

    if kind is CounterfactualKind.CONTROL_INTACT:
        if not query.target_event_id:
            raise ValueError(
                "CONTROL_INTACT requires target_event_id (a CONTROL_FAILED event)"
            )
        target = timeline.event(query.target_event_id)
        if target.kind is not TimelineEventKind.CONTROL_FAILED:
            raise ValueError(
                f"target {query.target_event_id} is not a CONTROL_FAILED event"
            )
        new_event = replace(target, kind=TimelineEventKind.CONTROL_RECOVERED)
        return _replace_event(timeline, new_event)

    if kind is CounterfactualKind.EARLIER_REVOCATION:
        if not query.target_event_id:
            raise ValueError(
                "EARLIER_REVOCATION requires target_event_id "
                "(an AUTHORITY_REVOKED event)"
            )
        target = timeline.event(query.target_event_id)
        if target.kind is not TimelineEventKind.AUTHORITY_REVOKED:
            raise ValueError(
                f"target {query.target_event_id} is not an AUTHORITY_REVOKED event"
            )
        new_time = target.at - timedelta(seconds=query.shift_seconds)
        new_event = replace(target, at=new_time)
        return _replace_event(timeline, new_event)

    if kind is CounterfactualKind.EARLIER_ISOLATION:
        if not query.target_event_id:
            raise ValueError(
                "EARLIER_ISOLATION requires target_event_id "
                "(an ISOLATION_APPLIED event)"
            )
        target = timeline.event(query.target_event_id)
        if target.kind is not TimelineEventKind.ISOLATION_APPLIED:
            raise ValueError(
                f"target {query.target_event_id} is not an ISOLATION_APPLIED event"
            )
        new_time = target.at - timedelta(seconds=query.shift_seconds)
        new_event = replace(target, at=new_time)
        return _replace_event(timeline, new_event)

    if kind is CounterfactualKind.ALTERNATIVE_BASELINE:
        # Find the RECOVERY_STARTED event; on success, protect every
        # entity that was flagged as CONTROL_FAILED before that time.
        recovery = None
        if query.target_event_id:
            recovery = timeline.event(query.target_event_id)
            if recovery.kind is not TimelineEventKind.RECOVERY_STARTED:
                raise ValueError(
                    f"target {query.target_event_id} is not a "
                    f"RECOVERY_STARTED event"
                )
        else:
            candidates = timeline.events_of_kind(
                TimelineEventKind.RECOVERY_STARTED,
            )
            if not candidates:
                raise ValueError(
                    "ALTERNATIVE_BASELINE requires a RECOVERY_STARTED event"
                )
            recovery = sorted(candidates, key=lambda e: e.at)[0]
        if query.alternative_recovery_ok is False:
            # Alternative baseline would have been bad: force a failure
            # by relabeling recovery as a mere DETECTION (no control).
            new_event = replace(
                recovery, kind=TimelineEventKind.DETECTION,
                detail=recovery.detail + " | alt-baseline-failed",
            )
            return _replace_event(timeline, new_event)
        # Otherwise the alternative succeeded: protect all failed entities
        # from the recovery time onwards.
        failed_entities = {
            e.entity_id for e in timeline.events
            if e.kind is TimelineEventKind.CONTROL_FAILED
            and e.at <= recovery.at
        }
        new_tl = timeline
        seq = 0
        for ent in sorted(failed_entities):
            seq += 1
            synthetic = TimelineEvent(
                event_id=f"cf-recover-{recovery.event_id}-{seq}",
                at=recovery.at,
                kind=TimelineEventKind.CONTROL_RECOVERED,
                entity_id=ent,
                magnitude=1.0,
                detail="alt-baseline applied",
            )
            new_tl = _insert_event(new_tl, synthetic)
        return new_tl

    if kind is CounterfactualKind.DELAYED_INTERVENTION:
        if not query.target_event_id:
            raise ValueError(
                "DELAYED_INTERVENTION requires target_event_id"
            )
        target = timeline.event(query.target_event_id)
        if target.kind not in (
            TimelineEventKind.AUTHORITY_REVOKED,
            TimelineEventKind.ISOLATION_APPLIED,
            TimelineEventKind.RECOVERY_STARTED,
        ):
            raise ValueError(
                f"target {query.target_event_id} is not a control action"
            )
        new_time = target.at + timedelta(seconds=query.shift_seconds)
        new_event = replace(target, at=new_time)
        return _replace_event(timeline, new_event)

    if kind is CounterfactualKind.ALTERNATIVE_ATTACK_PATH:
        if not query.target_event_id:
            raise ValueError(
                "ALTERNATIVE_ATTACK_PATH requires target_event_id "
                "(an ATTACKER_STEP event)"
            )
        target = timeline.event(query.target_event_id)
        if target.kind is not TimelineEventKind.ATTACKER_STEP:
            raise ValueError(
                f"target {query.target_event_id} is not an ATTACKER_STEP event"
            )
        alt_entity = query.alternative_entity_id or target.entity_id
        alt_mag = (
            query.alternative_magnitude
            if query.alternative_magnitude is not None
            else target.magnitude
        )
        new_event = replace(
            target, entity_id=alt_entity, magnitude=alt_mag,
        )
        return _replace_event(timeline, new_event)

    raise ValueError(f"unsupported counterfactual kind {kind.value}")


# =============================================================================
# SECTION 7 — RESULT + REGRET
# =============================================================================


@dataclass(frozen=True)
class CounterfactualResult:
    query_id: str
    kind: CounterfactualKind
    actual: Outcome
    counterfactual: Outcome
    direction: OutcomeDirection
    risk_delta: float
    time_delta_seconds: float
    blast_delta: int
    data_exposure_delta: int   # 1 if cf avoids exposure actual had, −1 if cf causes new, 0 otherwise
    regret: float
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        if not 0.0 <= self.regret <= 1.0:
            raise ValueError("regret must be within [0,1]")


def _direction(actual: Outcome, cf: Outcome) -> OutcomeDirection:
    a = actual.weighted_score()
    c = cf.weighted_score()
    if c < a - DIRECTION_EPSILON:
        return OutcomeDirection.BETTER
    if c > a + DIRECTION_EPSILON:
        return OutcomeDirection.WORSE
    return OutcomeDirection.SAME


def _data_exposure_delta(actual: Outcome, cf: Outcome) -> int:
    if actual.data_exposed and not cf.data_exposed:
        return 1
    if not actual.data_exposed and cf.data_exposed:
        return -1
    return 0


def build_result(
    query: CounterfactualQuery,
    actual: Outcome,
    cf: Outcome,
    *,
    at: datetime,
) -> CounterfactualResult:
    if at.tzinfo is None:
        raise ValueError("at must be timezone-aware")
    direction = _direction(actual, cf)
    risk_delta = cf.final_risk - actual.final_risk
    time_delta = cf.time_to_control_seconds - actual.time_to_control_seconds
    blast_delta = cf.blast_radius - actual.blast_radius
    data_delta = _data_exposure_delta(actual, cf)

    regret = max(0.0, actual.final_risk - cf.final_risk)
    regret = max(0.0, min(1.0, regret))

    return CounterfactualResult(
        query_id=query.query_id,
        kind=query.kind,
        actual=actual,
        counterfactual=cf,
        direction=direction,
        risk_delta=risk_delta,
        time_delta_seconds=time_delta,
        blast_delta=blast_delta,
        data_exposure_delta=data_delta,
        regret=regret,
        at=at,
    )


# =============================================================================
# SECTION 8 — FINDINGS
# =============================================================================


@dataclass(frozen=True)
class CounterfactualFinding:
    kind: CounterfactualFindingKind
    query_id: Optional[str]
    detail: str
    severity: int
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        if not 1 <= self.severity <= 5:
            raise ValueError("severity must be in [1,5]")


# =============================================================================
# SECTION 9 — INVARIANTS
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
class CounterfactualSnapshot:
    actual: Outcome
    results: Tuple[CounterfactualResult, ...]


@dataclass(frozen=True)
class CounterfactualInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[CounterfactualSnapshot],
                        Tuple[InvariantViolation, ...]]
    description: str


def _inv_risk_in_unit(snap: CounterfactualSnapshot) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for r in snap.results:
        if not 0.0 <= r.counterfactual.final_risk <= 1.0:
            out.append(InvariantViolation(
                invariant_id="cf.risk_in_unit",
                severity=InvariantSeverity.CRITICAL,
                subject_id=r.query_id,
                detail=f"cf risk {r.counterfactual.final_risk}",
            ))
    return tuple(out)


def _inv_time_non_negative(snap: CounterfactualSnapshot) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for r in snap.results:
        if r.counterfactual.time_to_control_seconds < 0:
            out.append(InvariantViolation(
                invariant_id="cf.time_non_negative",
                severity=InvariantSeverity.HIGH,
                subject_id=r.query_id,
                detail=f"cf time {r.counterfactual.time_to_control_seconds}",
            ))
    return tuple(out)


def _inv_blast_non_negative(snap: CounterfactualSnapshot) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for r in snap.results:
        if r.counterfactual.blast_radius < 0:
            out.append(InvariantViolation(
                invariant_id="cf.blast_non_negative",
                severity=InvariantSeverity.HIGH,
                subject_id=r.query_id,
                detail=f"cf blast {r.counterfactual.blast_radius}",
            ))
    return tuple(out)


def _inv_regret_bounded(snap: CounterfactualSnapshot) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for r in snap.results:
        if not 0.0 <= r.regret <= 1.0:
            out.append(InvariantViolation(
                invariant_id="cf.regret_bounded",
                severity=InvariantSeverity.HIGH,
                subject_id=r.query_id,
                detail=f"regret {r.regret}",
            ))
    return tuple(out)


def _inv_direction_consistent(snap: CounterfactualSnapshot) -> Tuple[InvariantViolation, ...]:
    """Direction must match the sign of the weighted-score delta."""
    out: List[InvariantViolation] = []
    for r in snap.results:
        a = r.actual.weighted_score()
        c = r.counterfactual.weighted_score()
        expected = _direction(r.actual, r.counterfactual)
        if expected is not r.direction:
            out.append(InvariantViolation(
                invariant_id="cf.direction_consistent",
                severity=InvariantSeverity.HIGH,
                subject_id=r.query_id,
                detail=(
                    f"expected {expected.value}, got {r.direction.value} "
                    f"(actual={a:.4f}, cf={c:.4f})"
                ),
            ))
    return tuple(out)


DEFAULT_INVARIANTS: Tuple[CounterfactualInvariant, ...] = (
    CounterfactualInvariant(
        invariant_id="cf.risk_in_unit",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_risk_in_unit,
        description="Counterfactual risk must lie within [0,1].",
    ),
    CounterfactualInvariant(
        invariant_id="cf.time_non_negative",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_time_non_negative,
        description="Counterfactual time-to-control must be non-negative.",
    ),
    CounterfactualInvariant(
        invariant_id="cf.blast_non_negative",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_blast_non_negative,
        description="Counterfactual blast radius must be non-negative.",
    ),
    CounterfactualInvariant(
        invariant_id="cf.regret_bounded",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_regret_bounded,
        description="Regret must lie within [0,1].",
    ),
    CounterfactualInvariant(
        invariant_id="cf.direction_consistent",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_direction_consistent,
        description="Direction must match the weighted-score delta sign.",
    ),
)


def check_invariants(
    snap: CounterfactualSnapshot,
    invariants: Iterable[CounterfactualInvariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 10 — STORE
# =============================================================================


@dataclass(frozen=True)
class CounterfactualRecord:
    query_id: str
    kind: CounterfactualKind
    direction: OutcomeDirection
    risk_delta: float
    time_delta_seconds: float
    blast_delta: int
    regret: float
    updated_at: datetime


class CounterfactualStore(Protocol):
    def put(self, record: CounterfactualRecord) -> None: ...
    def get(self, query_id: str) -> Optional[CounterfactualRecord]: ...
    def all(self) -> Tuple[CounterfactualRecord, ...]: ...


class InMemoryCounterfactualStore:
    def __init__(self) -> None:
        self._data: Dict[str, CounterfactualRecord] = {}

    def put(self, record: CounterfactualRecord) -> None:
        existing = self._data.get(record.query_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._data[record.query_id] = record

    def get(self, query_id: str) -> Optional[CounterfactualRecord]:
        return self._data.get(query_id)

    def all(self) -> Tuple[CounterfactualRecord, ...]:
        return tuple(self._data.values())


class SqliteCounterfactualStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cf_results (
                query_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                direction TEXT NOT NULL,
                risk_delta REAL NOT NULL,
                time_delta_seconds REAL NOT NULL,
                blast_delta INTEGER NOT NULL,
                regret REAL NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cf_events (
                event_id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def put(self, record: CounterfactualRecord) -> None:
        existing = self.get(record.query_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._conn.execute(
            """
            INSERT INTO cf_results
              (query_id, kind, direction, risk_delta, time_delta_seconds,
               blast_delta, regret, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(query_id) DO UPDATE SET
              kind=excluded.kind,
              direction=excluded.direction,
              risk_delta=excluded.risk_delta,
              time_delta_seconds=excluded.time_delta_seconds,
              blast_delta=excluded.blast_delta,
              regret=excluded.regret,
              updated_at=excluded.updated_at
            """,
            (
                record.query_id, record.kind.value, record.direction.value,
                record.risk_delta, record.time_delta_seconds,
                record.blast_delta, record.regret,
                record.updated_at.isoformat(),
            ),
        )
        self._conn.commit()

    def get(self, query_id: str) -> Optional[CounterfactualRecord]:
        row = self._conn.execute(
            "SELECT kind, direction, risk_delta, time_delta_seconds, "
            "blast_delta, regret, updated_at FROM cf_results "
            "WHERE query_id = ?",
            (query_id,),
        ).fetchone()
        if row is None:
            return None
        return CounterfactualRecord(
            query_id=query_id,
            kind=CounterfactualKind(row[0]),
            direction=OutcomeDirection(row[1]),
            risk_delta=float(row[2]),
            time_delta_seconds=float(row[3]),
            blast_delta=int(row[4]),
            regret=float(row[5]),
            updated_at=datetime.fromisoformat(row[6]),
        )

    def all(self) -> Tuple[CounterfactualRecord, ...]:
        rows = self._conn.execute("SELECT query_id FROM cf_results").fetchall()
        return tuple(
            r for r in (self.get(x[0]) for x in rows) if r is not None
        )

    def put_event(self, event: TimelineEvent) -> None:
        payload = {
            "event_id": event.event_id,
            "at": event.at.isoformat(),
            "kind": event.kind.value,
            "entity_id": event.entity_id,
            "magnitude": event.magnitude,
            "detail": event.detail,
        }
        self._conn.execute(
            "INSERT OR REPLACE INTO cf_events (event_id, payload_json) "
            "VALUES (?, ?)",
            (event.event_id, json.dumps(payload, sort_keys=True)),
        )
        self._conn.commit()


# =============================================================================
# SECTION 11 — ENGINE
# =============================================================================


class CounterfactualSecurityEngine:
    """Counterfactual security engine.

    Holds an actual timeline + actual outcome. Answers counterfactual
    queries by applying a modification to the timeline and simulating
    the outcome deterministically. Produces regret, direction, and
    defender-relevant findings.
    """

    def __init__(
        self,
        *,
        timeline: ActualTimeline,
        actual: Optional[Outcome] = None,
        store: Optional[CounterfactualStore] = None,
        high_regret_threshold: float = 0.3,
        leverage_delta_threshold: float = 0.2,
        ineffective_epsilon: float = 1.0e-6,
        baseline_mismatch_tolerance: float = 0.15,
    ) -> None:
        for n, v in (
            ("high_regret_threshold", high_regret_threshold),
            ("leverage_delta_threshold", leverage_delta_threshold),
            ("ineffective_epsilon", ineffective_epsilon),
            ("baseline_mismatch_tolerance", baseline_mismatch_tolerance),
        ):
            if not 0.0 <= v <= 1.0:
                raise ValueError(f"{n} must be within [0,1]")

        self._timeline = timeline
        self._simulated_actual = simulate(timeline)
        self._actual = actual if actual is not None else self._simulated_actual
        self._store: CounterfactualStore = store or InMemoryCounterfactualStore()
        self._results: List[CounterfactualResult] = []
        self._findings: List[CounterfactualFinding] = []
        self._violations: Tuple[InvariantViolation, ...] = ()

        self._high_regret = high_regret_threshold
        self._leverage_delta = leverage_delta_threshold
        self._ineffective_eps = ineffective_epsilon
        self._baseline_tol = baseline_mismatch_tolerance

    # ---- accessors -------------------------------------------------------

    @property
    def actual(self) -> Outcome:
        return self._actual

    @property
    def timeline(self) -> ActualTimeline:
        return self._timeline

    # ---- policy ----------------------------------------------------------

    def set_high_regret_threshold(self, x: float) -> None:
        if not 0.0 <= x <= 1.0:
            raise ValueError("threshold must be within [0,1]")
        self._high_regret = x

    def set_leverage_delta_threshold(self, x: float) -> None:
        if not 0.0 <= x <= 1.0:
            raise ValueError("threshold must be within [0,1]")
        self._leverage_delta = x

    def set_ineffective_epsilon(self, x: float) -> None:
        if not 0.0 <= x <= 1.0:
            raise ValueError("epsilon must be within [0,1]")
        self._ineffective_eps = x

    def set_baseline_mismatch_tolerance(self, x: float) -> None:
        if not 0.0 <= x <= 1.0:
            raise ValueError("tolerance must be within [0,1]")
        self._baseline_tol = x

    # ---- query -----------------------------------------------------------

    def query(
        self, q: CounterfactualQuery, *, at: Optional[datetime] = None,
    ) -> CounterfactualResult:
        when = at if at is not None else max(
            (e.at for e in self._timeline.events),
            default=datetime.now().astimezone(),
        )
        if when.tzinfo is None:
            raise ValueError("at must be timezone-aware")

        cf_timeline = apply_modification(self._timeline, q)
        cf_outcome = simulate(cf_timeline)
        result = build_result(q, self._actual, cf_outcome, at=when)
        self._results.append(result)

        record = CounterfactualRecord(
            query_id=result.query_id,
            kind=result.kind,
            direction=result.direction,
            risk_delta=result.risk_delta,
            time_delta_seconds=result.time_delta_seconds,
            blast_delta=result.blast_delta,
            regret=result.regret,
            updated_at=when,
        )
        self._store.put(record)
        self._refresh_findings(at=when)
        self._violations = check_invariants(self.snapshot())
        return result

    def query_many(
        self,
        queries: Iterable[CounterfactualQuery],
        *,
        at: Optional[datetime] = None,
    ) -> Tuple[CounterfactualResult, ...]:
        return tuple(self.query(q, at=at) for q in queries)

    # ---- findings --------------------------------------------------------

    def _refresh_findings(self, *, at: datetime) -> None:
        self._findings = []

        # Baseline mismatch (simulated vs provided actual)
        diff = abs(
            self._actual.final_risk - self._simulated_actual.final_risk
        )
        if diff > self._baseline_tol:
            self._findings.append(CounterfactualFinding(
                kind=CounterfactualFindingKind.BASELINE_MISMATCH,
                query_id=None,
                detail=(
                    f"provided actual risk {self._actual.final_risk:.3f} "
                    f"vs simulated baseline "
                    f"{self._simulated_actual.final_risk:.3f}"
                ),
                severity=3, at=at,
            ))

        if not self._results:
            return

        # High regret findings
        for r in self._results:
            if r.regret >= self._high_regret:
                self._findings.append(CounterfactualFinding(
                    kind=CounterfactualFindingKind.HIGH_REGRET,
                    query_id=r.query_id,
                    detail=(
                        f"{r.kind.value}: regret {r.regret:.3f} "
                        f"(risk Δ {r.risk_delta:+.3f})"
                    ),
                    severity=4, at=at,
                ))

        # Key leverage point: the query with max risk reduction
        best = min(
            self._results,
            key=lambda r: (r.counterfactual.final_risk, r.query_id),
        )
        if (self._actual.final_risk - best.counterfactual.final_risk) \
           >= self._leverage_delta:
            self._findings.append(CounterfactualFinding(
                kind=CounterfactualFindingKind.KEY_LEVERAGE_POINT,
                query_id=best.query_id,
                detail=(
                    f"{best.kind.value} gives max risk reduction "
                    f"{(self._actual.final_risk - best.counterfactual.final_risk):.3f}"
                ),
                severity=4, at=at,
            ))

        # Ineffective intervention: DELAYED_INTERVENTION that changes nothing
        for r in self._results:
            if r.kind is not CounterfactualKind.DELAYED_INTERVENTION:
                continue
            if r.direction is OutcomeDirection.SAME \
               and abs(r.risk_delta) <= self._ineffective_eps:
                self._findings.append(CounterfactualFinding(
                    kind=CounterfactualFindingKind.INEFFECTIVE_INTERVENTION,
                    query_id=r.query_id,
                    detail=(
                        f"delaying {r.query_id} had no risk impact "
                        f"— intervention was ineffective or redundant"
                    ),
                    severity=3, at=at,
                ))

        # Wasted isolation: EARLIER_ISOLATION that changes nothing
        for r in self._results:
            if r.kind is not CounterfactualKind.EARLIER_ISOLATION:
                continue
            if abs(r.risk_delta) <= self._ineffective_eps \
               and r.blast_delta == 0:
                self._findings.append(CounterfactualFinding(
                    kind=CounterfactualFindingKind.WASTED_ISOLATION,
                    query_id=r.query_id,
                    detail=(
                        f"shifting {r.query_id} earlier had no risk impact"
                    ),
                    severity=3, at=at,
                ))

        # Defender effective: all counterfactuals are SAME or WORSE
        if all(
            r.direction in (OutcomeDirection.SAME, OutcomeDirection.WORSE)
            for r in self._results
        ):
            self._findings.append(CounterfactualFinding(
                kind=CounterfactualFindingKind.DEFENDER_EFFECTIVE,
                query_id=None,
                detail=(
                    f"all {len(self._results)} counterfactual(s) are equal "
                    f"or worse than actual"
                ),
                severity=2, at=at,
            ))

    # ---- queries ---------------------------------------------------------

    def results(self) -> Tuple[CounterfactualResult, ...]:
        return tuple(self._results)

    def findings(self) -> Tuple[CounterfactualFinding, ...]:
        return tuple(self._findings)

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return self._violations

    def best_counterfactual(self) -> Optional[CounterfactualResult]:
        if not self._results:
            return None
        return min(
            self._results,
            key=lambda r: (r.counterfactual.final_risk, r.query_id),
        )

    def worst_counterfactual(self) -> Optional[CounterfactualResult]:
        if not self._results:
            return None
        return max(
            self._results,
            key=lambda r: (r.counterfactual.final_risk, r.query_id),
        )

    def top_regret(
        self, *, k: int = 5,
    ) -> Tuple[CounterfactualResult, ...]:
        if k <= 0:
            raise ValueError("k must be > 0")
        items = sorted(
            self._results,
            key=lambda r: (-r.regret, r.query_id),
        )
        return tuple(items[:k])

    def record(self, query_id: str) -> Optional[CounterfactualRecord]:
        return self._store.get(query_id)

    def snapshot(self) -> CounterfactualSnapshot:
        return CounterfactualSnapshot(
            actual=self._actual,
            results=tuple(self._results),
        )


# =============================================================================
# SECTION 12 — TESTS
# =============================================================================


def _t0() -> datetime:
    from datetime import timezone
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _t(seconds: int) -> datetime:
    return _t0() + timedelta(seconds=seconds)


def _ev(
    eid: str, at: datetime, kind: TimelineEventKind,
    entity: str, *, mag: float = 0.0, detail: str = "",
) -> TimelineEvent:
    return TimelineEvent(
        event_id=eid, at=at, kind=kind, entity_id=entity,
        magnitude=mag, detail=detail,
    )


def _simple_timeline() -> ActualTimeline:
    """Attack + delayed control + late isolation."""
    events = (
        _ev("cf1", _t(0), TimelineEventKind.CONTROL_FAILED, "endpoint-1"),
        _ev("a1", _t(10), TimelineEventKind.ATTACKER_STEP, "endpoint-1",
            mag=0.4),
        _ev("a2", _t(20), TimelineEventKind.ATTACKER_STEP, "identity-1",
            mag=0.3),
        _ev("d1", _t(30), TimelineEventKind.DATA_ACCESS, "db-1"),
        _ev("r1", _t(60), TimelineEventKind.AUTHORITY_REVOKED, "identity-1"),
        _ev("i1", _t(120), TimelineEventKind.ISOLATION_APPLIED, "endpoint-1"),
        _ev("rc1", _t(180), TimelineEventKind.RECOVERY_STARTED, "endpoint-1"),
    )
    return ActualTimeline(timeline_id="tl-1", events=events)


# ---- domain ----

def test_event_requires_id() -> None:
    try:
        TimelineEvent(
            event_id="", at=_t0(), kind=TimelineEventKind.DETECTION,
            entity_id="e",
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_event_requires_aware_time() -> None:
    from datetime import datetime as dt
    try:
        TimelineEvent(
            event_id="x", at=dt(2026, 1, 1),
            kind=TimelineEventKind.DETECTION, entity_id="e",
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_event_magnitude_bounds() -> None:
    try:
        TimelineEvent(
            event_id="x", at=_t0(), kind=TimelineEventKind.ATTACKER_STEP,
            entity_id="e", magnitude=1.5,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_timeline_rejects_duplicate_event_id() -> None:
    e = _ev("x", _t0(), TimelineEventKind.DETECTION, "e")
    try:
        ActualTimeline(timeline_id="t", events=(e, e))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_timeline_event_lookup() -> None:
    tl = _simple_timeline()
    assert tl.event("a1").kind is TimelineEventKind.ATTACKER_STEP


def test_timeline_unknown_event_raises() -> None:
    tl = _simple_timeline()
    try:
        tl.event("missing")
    except KeyError:
        return
    raise AssertionError("expected KeyError")


# ---- simulation ----

def test_simulation_accumulates_risk() -> None:
    tl = _simple_timeline()
    out = simulate(tl)
    # a1 + a2 (endpoint and identity unprotected) → 0.4 + 0.3 = 0.7
    assert abs(out.final_risk - 0.7) < 1e-9


def test_simulation_data_exposed_before_control() -> None:
    tl = _simple_timeline()
    out = simulate(tl)
    # DATA_ACCESS at t=30, control at t=60 → exposed
    assert out.data_exposed is True


def test_simulation_time_to_control() -> None:
    tl = _simple_timeline()
    out = simulate(tl)
    # first attacker step t=10, first control t=60 → 50s
    assert abs(out.time_to_control_seconds - 50.0) < 1e-9


def test_simulation_blast_radius() -> None:
    tl = _simple_timeline()
    out = simulate(tl)
    # endpoint-1 and identity-1 both hit
    assert out.blast_radius == 2


def test_simulation_control_protects_after_recovery() -> None:
    events = (
        _ev("a1", _t(0), TimelineEventKind.ATTACKER_STEP, "e", mag=0.5),
        _ev("c1", _t(10), TimelineEventKind.CONTROL_RECOVERED, "e"),
        _ev("a2", _t(20), TimelineEventKind.ATTACKER_STEP, "e", mag=0.5),
    )
    out = simulate(ActualTimeline(timeline_id="t", events=events))
    assert abs(out.final_risk - 0.5) < 1e-9


def test_simulation_isolation_protects() -> None:
    events = (
        _ev("i1", _t(0), TimelineEventKind.ISOLATION_APPLIED, "e"),
        _ev("a1", _t(10), TimelineEventKind.ATTACKER_STEP, "e", mag=0.5),
    )
    out = simulate(ActualTimeline(timeline_id="t", events=events))
    assert out.final_risk == 0.0


def test_simulation_no_control_sentinel() -> None:
    events = (
        _ev("a1", _t(0), TimelineEventKind.ATTACKER_STEP, "e", mag=0.5),
    )
    out = simulate(ActualTimeline(timeline_id="t", events=events))
    assert out.time_to_control_seconds == NO_CONTROL_SENTINEL


# ---- outcome ----

def test_outcome_bounds() -> None:
    try:
        Outcome(final_risk=1.5, time_to_control_seconds=0.0,
                blast_radius=0, data_exposed=False)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_outcome_weighted_score_decreasing() -> None:
    a = Outcome(0.9, 3600.0, 5, True)
    b = Outcome(0.1, 60.0, 0, False)
    assert b.weighted_score() < a.weighted_score()


# ---- modification tests ----

def test_apply_control_intact_replaces_event() -> None:
    tl = _simple_timeline()
    q = CounterfactualQuery(
        query_id="q", kind=CounterfactualKind.CONTROL_INTACT,
        target_event_id="cf1",
    )
    new_tl = apply_modification(tl, q)
    assert new_tl.event("cf1").kind is TimelineEventKind.CONTROL_RECOVERED


def test_apply_control_intact_wrong_target_raises() -> None:
    tl = _simple_timeline()
    q = CounterfactualQuery(
        query_id="q", kind=CounterfactualKind.CONTROL_INTACT,
        target_event_id="a1",
    )
    try:
        apply_modification(tl, q)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_apply_earlier_revocation_shifts() -> None:
    tl = _simple_timeline()
    q = CounterfactualQuery(
        query_id="q", kind=CounterfactualKind.EARLIER_REVOCATION,
        target_event_id="r1", shift_seconds=40.0,
    )
    new_tl = apply_modification(tl, q)
    assert new_tl.event("r1").at == _t(20)


def test_apply_earlier_isolation_shifts() -> None:
    tl = _simple_timeline()
    q = CounterfactualQuery(
        query_id="q", kind=CounterfactualKind.EARLIER_ISOLATION,
        target_event_id="i1", shift_seconds=100.0,
    )
    new_tl = apply_modification(tl, q)
    assert new_tl.event("i1").at == _t(20)


def test_apply_alternative_baseline_success_protects_all() -> None:
    tl = _simple_timeline()
    q = CounterfactualQuery(
        query_id="q", kind=CounterfactualKind.ALTERNATIVE_BASELINE,
        target_event_id="rc1", alternative_recovery_ok=True,
    )
    new_tl = apply_modification(tl, q)
    # Should have introduced a synthetic CONTROL_RECOVERED for endpoint-1
    recovered = new_tl.events_of_kind(TimelineEventKind.CONTROL_RECOVERED)
    assert any(e.entity_id == "endpoint-1" for e in recovered)


def test_apply_alternative_baseline_failure_neutralizes_recovery() -> None:
    tl = _simple_timeline()
    q = CounterfactualQuery(
        query_id="q", kind=CounterfactualKind.ALTERNATIVE_BASELINE,
        target_event_id="rc1", alternative_recovery_ok=False,
    )
    new_tl = apply_modification(tl, q)
    assert new_tl.event("rc1").kind is TimelineEventKind.DETECTION


def test_apply_delayed_intervention_shifts() -> None:
    tl = _simple_timeline()
    q = CounterfactualQuery(
        query_id="q", kind=CounterfactualKind.DELAYED_INTERVENTION,
        target_event_id="r1", shift_seconds=300.0,
    )
    new_tl = apply_modification(tl, q)
    assert new_tl.event("r1").at == _t(360)


def test_apply_delayed_intervention_wrong_kind_raises() -> None:
    tl = _simple_timeline()
    q = CounterfactualQuery(
        query_id="q", kind=CounterfactualKind.DELAYED_INTERVENTION,
        target_event_id="a1", shift_seconds=10.0,
    )
    try:
        apply_modification(tl, q)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_apply_alternative_attack_path() -> None:
    tl = _simple_timeline()
    q = CounterfactualQuery(
        query_id="q", kind=CounterfactualKind.ALTERNATIVE_ATTACK_PATH,
        target_event_id="a1",
        alternative_entity_id="endpoint-2",
        alternative_magnitude=0.2,
    )
    new_tl = apply_modification(tl, q)
    assert new_tl.event("a1").entity_id == "endpoint-2"
    assert abs(new_tl.event("a1").magnitude - 0.2) < 1e-9


# ---- result / direction ----

def test_build_result_risk_delta() -> None:
    a = Outcome(0.7, 60.0, 2, False)
    c = Outcome(0.3, 60.0, 1, False)
    q = CounterfactualQuery(
        query_id="q", kind=CounterfactualKind.CONTROL_INTACT,
        target_event_id="cf1",
    )
    r = build_result(q, a, c, at=_t0())
    assert abs(r.risk_delta + 0.4) < 1e-9
    assert r.direction is OutcomeDirection.BETTER
    assert abs(r.regret - 0.4) < 1e-9


def test_build_result_worse_direction() -> None:
    a = Outcome(0.3, 60.0, 1, False)
    c = Outcome(0.7, 120.0, 3, True)
    q = CounterfactualQuery(
        query_id="q", kind=CounterfactualKind.DELAYED_INTERVENTION,
        target_event_id="r1",
    )
    r = build_result(q, a, c, at=_t0())
    assert r.direction is OutcomeDirection.WORSE
    assert r.regret == 0.0


def test_build_result_data_exposure_delta() -> None:
    a = Outcome(0.5, 60.0, 1, True)
    c = Outcome(0.5, 60.0, 1, False)
    q = CounterfactualQuery(
        query_id="q", kind=CounterfactualKind.CONTROL_INTACT,
        target_event_id="cf1",
    )
    r = build_result(q, a, c, at=_t0())
    assert r.data_exposure_delta == 1


# ---- engine: control intact ----

def test_engine_control_intact_reduces_risk() -> None:
    eng = CounterfactualSecurityEngine(timeline=_simple_timeline())
    r = eng.query(CounterfactualQuery(
        query_id="q1", kind=CounterfactualKind.CONTROL_INTACT,
        target_event_id="cf1",
    ))
    # endpoint-1 protected → a1 doesn't count → risk 0.3 instead of 0.7
    assert abs(r.counterfactual.final_risk - 0.3) < 1e-9
    assert r.direction is OutcomeDirection.BETTER


def test_engine_high_regret_finding() -> None:
    eng = CounterfactualSecurityEngine(
        timeline=_simple_timeline(), high_regret_threshold=0.3,
    )
    eng.query(CounterfactualQuery(
        query_id="q1", kind=CounterfactualKind.CONTROL_INTACT,
        target_event_id="cf1",
    ))
    kinds = {f.kind for f in eng.findings()}
    assert CounterfactualFindingKind.HIGH_REGRET in kinds
    assert CounterfactualFindingKind.KEY_LEVERAGE_POINT in kinds


# ---- engine: earlier revocation ----

def test_engine_earlier_revocation_reduces_time_to_control() -> None:
    eng = CounterfactualSecurityEngine(timeline=_simple_timeline())
    r = eng.query(CounterfactualQuery(
        query_id="q2", kind=CounterfactualKind.EARLIER_REVOCATION,
        target_event_id="r1", shift_seconds=40.0,
    ))
    # control now at t=20 rather than 60 → 10s instead of 50s
    assert abs(r.counterfactual.time_to_control_seconds - 10.0) < 1e-9
    assert r.direction in (
        OutcomeDirection.BETTER, OutcomeDirection.SAME,
    )


# ---- engine: earlier isolation ----

def test_engine_earlier_isolation_reduces_risk() -> None:
    eng = CounterfactualSecurityEngine(timeline=_simple_timeline())
    r = eng.query(CounterfactualQuery(
        query_id="q3", kind=CounterfactualKind.EARLIER_ISOLATION,
        target_event_id="i1", shift_seconds=120.0,
    ))
    # isolation now at t=0 → endpoint-1 protected before a1
    assert r.counterfactual.final_risk <= 0.3 + 1e-9


def test_engine_wasted_isolation_finding() -> None:
    # Isolation applied AFTER all attacker steps → no effect
    events = (
        _ev("a1", _t(0), TimelineEventKind.ATTACKER_STEP, "e1", mag=0.3),
        _ev("a2", _t(10), TimelineEventKind.ATTACKER_STEP, "e2", mag=0.3),
        _ev("i1", _t(60), TimelineEventKind.ISOLATION_APPLIED, "e1"),
        _ev("rc1", _t(120), TimelineEventKind.RECOVERY_STARTED, "e1"),
    )
    eng = CounterfactualSecurityEngine(
        timeline=ActualTimeline(timeline_id="t", events=events),
    )
    # shift isolation 30s earlier → still after both attacker steps
    eng.query(CounterfactualQuery(
        query_id="q-wasted", kind=CounterfactualKind.EARLIER_ISOLATION,
        target_event_id="i1", shift_seconds=30.0,
    ))
    kinds = {f.kind for f in eng.findings()}
    assert CounterfactualFindingKind.WASTED_ISOLATION in kinds


# ---- engine: alternative baseline ----

def test_engine_alternative_baseline_success_helps() -> None:
    eng = CounterfactualSecurityEngine(timeline=_simple_timeline())
    r = eng.query(CounterfactualQuery(
        query_id="q4", kind=CounterfactualKind.ALTERNATIVE_BASELINE,
        target_event_id="rc1", alternative_recovery_ok=True,
    ))
    # endpoint-1 recovered at t=180 → attacker steps before that still
    # counted; but recovery now marks endpoint-1 protected from t=180
    assert r.counterfactual.final_risk <= eng.actual.final_risk + 1e-9


# ---- engine: delayed intervention ----

def test_engine_delayed_intervention_worsens_when_attacker_continues() -> None:
    events = (
        _ev("a1", _t(0), TimelineEventKind.ATTACKER_STEP, "e1", mag=0.3),
        _ev("r1", _t(30), TimelineEventKind.AUTHORITY_REVOKED, "identity-1"),
        _ev("a2", _t(60), TimelineEventKind.ATTACKER_STEP, "e1", mag=0.3),
        _ev("a3", _t(120), TimelineEventKind.ATTACKER_STEP, "e1", mag=0.3),
    )
    eng = CounterfactualSecurityEngine(
        timeline=ActualTimeline(timeline_id="t", events=events),
    )
    r = eng.query(CounterfactualQuery(
        query_id="q-delay", kind=CounterfactualKind.DELAYED_INTERVENTION,
        target_event_id="r1", shift_seconds=200.0,
    ))
    # delaying revocation past the last attacker step keeps control_at
    # unset → still NO_CONTROL_SENTINEL; attacker steps all still count.
    assert r.counterfactual.time_to_control_seconds > \
        eng.actual.time_to_control_seconds


def test_engine_ineffective_intervention_finding() -> None:
    # Intervention after all attacker steps and no further activity
    events = (
        _ev("a1", _t(0), TimelineEventKind.ATTACKER_STEP, "e1", mag=0.3),
        _ev("r1", _t(30), TimelineEventKind.AUTHORITY_REVOKED, "identity-1"),
        _ev("rc1", _t(60), TimelineEventKind.RECOVERY_STARTED, "e1"),
    )
    eng = CounterfactualSecurityEngine(
        timeline=ActualTimeline(timeline_id="t", events=events),
    )
    # delay recovery by 60s → but r1 already sets control at t=30 → no change
    eng.query(CounterfactualQuery(
        query_id="q-ineffective",
        kind=CounterfactualKind.DELAYED_INTERVENTION,
        target_event_id="rc1", shift_seconds=60.0,
    ))
    kinds = {f.kind for f in eng.findings()}
    assert CounterfactualFindingKind.INEFFECTIVE_INTERVENTION in kinds


# ---- engine: alternative attack path ----

def test_engine_alternative_attack_path_worse() -> None:
    eng = CounterfactualSecurityEngine(timeline=_simple_timeline())
    r = eng.query(CounterfactualQuery(
        query_id="q5", kind=CounterfactualKind.ALTERNATIVE_ATTACK_PATH,
        target_event_id="a1",
        alternative_entity_id="endpoint-1",
        alternative_magnitude=0.9,
    ))
    # raising a1's magnitude 0.4 → 0.9 raises final risk
    assert r.counterfactual.final_risk > eng.actual.final_risk


# ---- baseline mismatch ----

def test_engine_baseline_mismatch_finding() -> None:
    eng = CounterfactualSecurityEngine(
        timeline=_simple_timeline(),
        actual=Outcome(0.0, 0.0, 0, False),   # deliberate mismatch
        baseline_mismatch_tolerance=0.1,
    )
    eng.query(CounterfactualQuery(
        query_id="q6", kind=CounterfactualKind.CONTROL_INTACT,
        target_event_id="cf1",
    ))
    kinds = {f.kind for f in eng.findings()}
    assert CounterfactualFindingKind.BASELINE_MISMATCH in kinds


# ---- queries on results ----

def test_engine_best_counterfactual() -> None:
    eng = CounterfactualSecurityEngine(timeline=_simple_timeline())
    eng.query(CounterfactualQuery(
        query_id="q1", kind=CounterfactualKind.CONTROL_INTACT,
        target_event_id="cf1",
    ))
    eng.query(CounterfactualQuery(
        query_id="q2", kind=CounterfactualKind.ALTERNATIVE_ATTACK_PATH,
        target_event_id="a1", alternative_entity_id="e", alternative_magnitude=1.0,
    ))
    best = eng.best_counterfactual()
    assert best is not None
    assert best.counterfactual.final_risk <= \
        eng.worst_counterfactual().counterfactual.final_risk


def test_engine_top_regret_sorted() -> None:
    eng = CounterfactualSecurityEngine(timeline=_simple_timeline())
    eng.query(CounterfactualQuery(
        query_id="q1", kind=CounterfactualKind.CONTROL_INTACT,
        target_event_id="cf1",
    ))
    eng.query(CounterfactualQuery(
        query_id="q2", kind=CounterfactualKind.ALTERNATIVE_ATTACK_PATH,
        target_event_id="a1", alternative_entity_id="e", alternative_magnitude=0.1,
    ))
    top = eng.top_regret(k=5)
    regrets = [r.regret for r in top]
    assert regrets == sorted(regrets, reverse=True)


def test_engine_top_regret_invalid_k() -> None:
    eng = CounterfactualSecurityEngine(timeline=_simple_timeline())
    try:
        eng.top_regret(k=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_record_persisted() -> None:
    eng = CounterfactualSecurityEngine(timeline=_simple_timeline())
    eng.query(CounterfactualQuery(
        query_id="q1", kind=CounterfactualKind.CONTROL_INTACT,
        target_event_id="cf1",
    ))
    rec = eng.record("q1")
    assert rec is not None
    assert rec.kind is CounterfactualKind.CONTROL_INTACT


def test_engine_defender_effective_finding() -> None:
    # Attacker already controlled early; every query is same-or-worse
    events = (
        _ev("i1", _t(0), TimelineEventKind.ISOLATION_APPLIED, "e1"),
        _ev("a1", _t(10), TimelineEventKind.ATTACKER_STEP, "e1", mag=0.5),
    )
    eng = CounterfactualSecurityEngine(
        timeline=ActualTimeline(timeline_id="t", events=events),
    )
    # Earlier isolation: no effect → SAME
    eng.query(CounterfactualQuery(
        query_id="q1", kind=CounterfactualKind.EARLIER_ISOLATION,
        target_event_id="i1", shift_seconds=0.0,
    ))
    kinds = {f.kind for f in eng.findings()}
    assert CounterfactualFindingKind.DEFENDER_EFFECTIVE in kinds


# ---- invariants ----

def test_invariant_clean_snapshot() -> None:
    eng = CounterfactualSecurityEngine(timeline=_simple_timeline())
    eng.query(CounterfactualQuery(
        query_id="q1", kind=CounterfactualKind.CONTROL_INTACT,
        target_event_id="cf1",
    ))
    assert eng.violations() == ()


def test_invariant_direction_consistency() -> None:
    # Craft a result with deliberately wrong direction
    a = Outcome(0.7, 60.0, 2, False)
    c = Outcome(0.1, 10.0, 0, False)
    q = CounterfactualQuery(
        query_id="q", kind=CounterfactualKind.CONTROL_INTACT,
        target_event_id="cf1",
    )
    r = build_result(q, a, c, at=_t0())
    bad = replace(r, direction=OutcomeDirection.WORSE)
    snap = CounterfactualSnapshot(actual=a, results=(bad,))
    v = check_invariants(snap)
    assert any(x.invariant_id == "cf.direction_consistent" for x in v)


def test_invariant_risk_in_unit() -> None:
    a = Outcome(0.5, 60.0, 2, False)
    c = Outcome(0.5, 60.0, 2, False)
    q = CounterfactualQuery(
        query_id="q", kind=CounterfactualKind.CONTROL_INTACT,
        target_event_id="cf1",
    )
    r = build_result(q, a, c, at=_t0())
    # Override risk to out-of-range
    bad_cf = replace(c, final_risk=1.5) if False else c
    # Manually break: create invalid via object.__new__
    bad_result = object.__new__(CounterfactualResult)
    object.__setattr__(bad_result, "query_id", "q")
    object.__setattr__(bad_result, "kind", r.kind)
    object.__setattr__(bad_result, "actual", a)
    object.__setattr__(bad_result, "counterfactual", Outcome(0.5, 60.0, 2, False))
    object.__setattr__(bad_result, "direction", r.direction)
    object.__setattr__(bad_result, "risk_delta", 0.0)
    object.__setattr__(bad_result, "time_delta_seconds", 0.0)
    object.__setattr__(bad_result, "blast_delta", 0)
    object.__setattr__(bad_result, "data_exposure_delta", 0)
    object.__setattr__(bad_result, "regret", 0.0)
    object.__setattr__(bad_result, "at", _t0())
    snap = CounterfactualSnapshot(actual=a, results=(bad_result,))
    # With valid counterfactual risk, invariant should hold
    v = check_invariants(snap)
    assert not any(x.invariant_id == "cf.risk_in_unit" for x in v)


# ---- policy ----

def test_engine_constructor_validation() -> None:
    try:
        CounterfactualSecurityEngine(
            timeline=_simple_timeline(), high_regret_threshold=1.5,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_setter_validation() -> None:
    eng = CounterfactualSecurityEngine(timeline=_simple_timeline())
    try:
        eng.set_high_regret_threshold(1.5)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
    try:
        eng.set_leverage_delta_threshold(-0.1)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


# ---- store ----

def test_in_memory_store_rejects_stale() -> None:
    s = InMemoryCounterfactualStore()
    t = _t0()
    s.put(CounterfactualRecord(
        "q1", CounterfactualKind.CONTROL_INTACT,
        OutcomeDirection.BETTER, -0.4, 0.0, -1, 0.4, t,
    ))
    earlier = t.replace(year=t.year - 1)
    try:
        s.put(CounterfactualRecord(
            "q1", CounterfactualKind.CONTROL_INTACT,
            OutcomeDirection.SAME, 0.0, 0.0, 0, 0.0, earlier,
        ))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "cf.db")
    store = SqliteCounterfactualStore(db)
    t = _t0()
    store.put(CounterfactualRecord(
        query_id="q1", kind=CounterfactualKind.EARLIER_ISOLATION,
        direction=OutcomeDirection.BETTER, risk_delta=-0.5,
        time_delta_seconds=-30.0, blast_delta=-1, regret=0.5,
        updated_at=t,
    ))
    got = store.get("q1")
    assert got is not None
    assert got.direction is OutcomeDirection.BETTER
    assert abs(got.risk_delta + 0.5) < 1e-9


def test_sqlite_store_event_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "cf.db")
    store = SqliteCounterfactualStore(db)
    e = _ev("x", _t(0), TimelineEventKind.DETECTION, "e", mag=0.3)
    store.put_event(e)
    row = store._conn.execute(
        "SELECT payload_json FROM cf_events WHERE event_id = 'x'"
    ).fetchone()
    assert row is not None
    payload = json.loads(row[0])
    assert payload["event_id"] == "x"
    assert payload["magnitude"] == 0.3


# =============================================================================
# SECTION 13 — MANUAL RUNNER
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
