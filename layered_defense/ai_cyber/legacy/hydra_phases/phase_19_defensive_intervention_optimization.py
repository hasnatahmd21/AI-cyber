"""
HYDRA POST-CORE — PHASE 19: DEFENSIVE INTERVENTION OPTIMIZATION
==================================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * Domain — 9 intervention kinds
    (OBSERVE / WARN / RESTRICT / DEGRADE / ISOLATE / BLOCK /
     RECOVER / REBUILD / ESCALATE)
  * Multi-dimensional intervention cost model:
      risk_reduction, blast_radius, business_impact, recovery_cost,
      reversibility, confidence, time_to_effect, future_risk,
      authority_required
  * Cost-aware + constraint-aware intervention optimizer
    (authority gate, approval gate, reversibility floor, verification
     gate, business-impact cap, confidence floor)
  * Score components (expected value, weighted cost, net benefit)
  * Findings — RECOMMENDED, BLOCKED, REQUIRE_APPROVAL,
    LOW_CONFIDENCE, HIGH_IMPACT_UNVERIFIED, NO_VIABLE_OPTION
  * Machine-checkable intervention invariants
  * In-memory + SQLite stores
  * Phase-19 engine facade
  * Full test suite + manual runner

This is NEW defensive-intervention optimization technology. It is NOT
a second decision engine. It is a layer that the existing HYDRA
decision-intelligence consumes to select and justify defensive actions.

No third-party dependencies.

Run tests:
    python hydra_phase19_defensive_intervention_optimization.py
    pytest hydra_phase19_defensive_intervention_optimization.py -q
"""
from __future__ import annotations

import json
import math
import sqlite3
from dataclasses import dataclass, field, replace
from datetime import datetime
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


class InterventionKind(str, Enum):
    OBSERVE = "observe"
    WARN = "warn"
    RESTRICT = "restrict"
    DEGRADE = "degrade"
    ISOLATE = "isolate"
    BLOCK = "block"
    RECOVER = "recover"
    REBUILD = "rebuild"
    ESCALATE = "escalate"


ALL_INTERVENTIONS: Tuple[InterventionKind, ...] = tuple(InterventionKind)


# Intrinsic "aggressiveness" ordering used for authority and approval
# gating. Higher = more aggressive.
_AGGRESSIVENESS: Mapping[InterventionKind, int] = {
    InterventionKind.OBSERVE: 0,
    InterventionKind.WARN: 1,
    InterventionKind.RESTRICT: 2,
    InterventionKind.DEGRADE: 3,
    InterventionKind.ISOLATE: 4,
    InterventionKind.BLOCK: 5,
    InterventionKind.RECOVER: 3,
    InterventionKind.REBUILD: 4,
    InterventionKind.ESCALATE: 5,
}


def aggressiveness(kind: InterventionKind) -> int:
    return _AGGRESSIVENESS[kind]


class AuthorityLevel(str, Enum):
    READ_ONLY = "read_only"
    OPERATOR = "operator"
    SENIOR = "senior"
    ADMIN = "admin"
    BREAK_GLASS = "break_glass"


_AUTHORITY_RANK: Mapping[AuthorityLevel, int] = {
    AuthorityLevel.READ_ONLY: 0,
    AuthorityLevel.OPERATOR: 1,
    AuthorityLevel.SENIOR: 2,
    AuthorityLevel.ADMIN: 3,
    AuthorityLevel.BREAK_GLASS: 4,
}


def authority_rank(level: AuthorityLevel) -> int:
    return _AUTHORITY_RANK[level]


class DecisionOutcome(str, Enum):
    RECOMMENDED = "recommended"
    REQUIRE_APPROVAL = "require_approval"
    BLOCKED = "blocked"
    NO_VIABLE_OPTION = "no_viable_option"


class InterventionFindingKind(str, Enum):
    RECOMMENDED = "recommended"
    BLOCKED = "blocked"
    REQUIRE_APPROVAL = "require_approval"
    LOW_CONFIDENCE = "low_confidence"
    HIGH_IMPACT_UNVERIFIED = "high_impact_unverified"
    NO_VIABLE_OPTION = "no_viable_option"
    REVERSIBILITY_FLOOR_VIOLATED = "reversibility_floor_violated"


@dataclass(frozen=True)
class InterventionFinding:
    kind: InterventionFindingKind
    entity_id: str
    intervention_id: Optional[str]
    detail: str
    severity: int
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        if not 1 <= self.severity <= 5:
            raise ValueError("severity must be in [1,5]")


# =============================================================================
# SECTION 3 — CANDIDATE
# =============================================================================


@dataclass(frozen=True)
class InterventionCandidate:
    """A concrete intervention option on a specific entity.

    All numeric fields are in [0,1] except time_to_effect_seconds,
    business_hours_lost, and recovery_cost_units which are normalized
    inside weighted_cost().
    """
    intervention_id: str
    entity_id: str
    kind: InterventionKind
    risk_reduction: float
    blast_radius: int
    business_impact: float
    recovery_cost_units: float
    reversibility: float
    confidence: float
    time_to_effect_seconds: float
    future_risk: float
    requires_approval: bool = False
    is_verified: bool = True
    # optional authority explicitly required by the candidate
    minimum_authority: AuthorityLevel = AuthorityLevel.OPERATOR

    def __post_init__(self) -> None:
        if not self.intervention_id:
            raise ValueError("intervention_id is required")
        if not self.entity_id:
            raise ValueError("entity_id is required")
        for n, v in (
            ("risk_reduction", self.risk_reduction),
            ("business_impact", self.business_impact),
            ("reversibility", self.reversibility),
            ("confidence", self.confidence),
            ("future_risk", self.future_risk),
        ):
            if not 0.0 <= v <= 1.0:
                raise ValueError(f"{n} must be within [0,1]")
        if self.blast_radius < 0:
            raise ValueError("blast_radius must be >= 0")
        if self.recovery_cost_units < 0:
            raise ValueError("recovery_cost_units must be >= 0")
        if self.time_to_effect_seconds < 0:
            raise ValueError("time_to_effect_seconds must be >= 0")


# =============================================================================
# SECTION 4 — SCORING
# =============================================================================


@dataclass(frozen=True)
class ScoringWeights:
    """Weights used to compute the total weighted cost.

    Weights must sum to 1.0.
    """
    blast_radius: float = 0.15
    business_impact: float = 0.20
    recovery_cost: float = 0.10
    irreversibility: float = 0.15
    time_to_effect: float = 0.10
    future_risk: float = 0.10
    unconfidence: float = 0.20

    def __post_init__(self) -> None:
        total = (
            self.blast_radius + self.business_impact
            + self.recovery_cost + self.irreversibility
            + self.time_to_effect + self.future_risk
            + self.unconfidence
        )
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"weights must sum to 1.0 (got {total})")
        for n, v in (
            ("blast_radius", self.blast_radius),
            ("business_impact", self.business_impact),
            ("recovery_cost", self.recovery_cost),
            ("irreversibility", self.irreversibility),
            ("time_to_effect", self.time_to_effect),
            ("future_risk", self.future_risk),
            ("unconfidence", self.unconfidence),
        ):
            if not 0.0 <= v <= 1.0:
                raise ValueError(f"{n} must be within [0,1]")


# Time-to-effect normalization: 15 minutes = full penalty.
TIME_NORM_SECONDS: float = 900.0
# Blast radius normalization: 10 entities = full penalty.
BLAST_NORM: float = 10.0
# Recovery cost normalization: 10 units = full penalty.
RECOVERY_NORM: float = 10.0


@dataclass(frozen=True)
class InterventionScore:
    intervention_id: str
    entity_id: str
    kind: InterventionKind
    expected_risk_reduction: float
    weighted_cost: float
    net_benefit: float
    components: Mapping[str, float]

    def __post_init__(self) -> None:
        for n, v in (
            ("expected_risk_reduction", self.expected_risk_reduction),
            ("weighted_cost", self.weighted_cost),
            ("net_benefit", self.net_benefit),
        ):
            if not -1.0 - 1e-9 <= v <= 1.0 + 1e-9:
                raise ValueError(f"{n} must be within [-1,1]")


def _clip01(x: float) -> float:
    return max(0.0, min(1.0, x))


def score_intervention(
    cand: InterventionCandidate,
    *,
    weights: ScoringWeights = ScoringWeights(),
) -> InterventionScore:
    blast_norm = _clip01(cand.blast_radius / BLAST_NORM)
    biz = _clip01(cand.business_impact)
    rec = _clip01(cand.recovery_cost_units / RECOVERY_NORM)
    irrev = _clip01(1.0 - cand.reversibility)
    time_norm = _clip01(cand.time_to_effect_seconds / TIME_NORM_SECONDS)
    future = _clip01(cand.future_risk)
    unconf = _clip01(1.0 - cand.confidence)

    weighted = (
        weights.blast_radius * blast_norm
        + weights.business_impact * biz
        + weights.recovery_cost * rec
        + weights.irreversibility * irrev
        + weights.time_to_effect * time_norm
        + weights.future_risk * future
        + weights.unconfidence * unconf
    )
    weighted = _clip01(weighted)

    expected = _clip01(cand.risk_reduction * cand.confidence)
    net = _clip01(expected - weighted) if expected >= weighted else \
        -_clip01(weighted - expected)

    return InterventionScore(
        intervention_id=cand.intervention_id,
        entity_id=cand.entity_id,
        kind=cand.kind,
        expected_risk_reduction=expected,
        weighted_cost=weighted,
        net_benefit=net,
        components={
            "blast_radius": blast_norm,
            "business_impact": biz,
            "recovery_cost": rec,
            "irreversibility": irrev,
            "time_to_effect": time_norm,
            "future_risk": future,
            "unconfidence": unconf,
        },
    )


# =============================================================================
# SECTION 5 — CONSTRAINTS
# =============================================================================


@dataclass(frozen=True)
class OptimizationConstraints:
    min_confidence: float = 0.3
    min_reversibility: float = 0.0
    max_business_impact: float = 1.0
    max_blast_radius: int = 100
    require_verified_for_high_impact: bool = True
    high_impact_aggressiveness: int = 4
    require_approval_aggressiveness: int = 3

    def __post_init__(self) -> None:
        for n, v in (
            ("min_confidence", self.min_confidence),
            ("min_reversibility", self.min_reversibility),
            ("max_business_impact", self.max_business_impact),
        ):
            if not 0.0 <= v <= 1.0:
                raise ValueError(f"{n} must be within [0,1]")
        if self.max_blast_radius < 0:
            raise ValueError("max_blast_radius must be >= 0")
        if self.high_impact_aggressiveness < 0:
            raise ValueError("high_impact_aggressiveness must be >= 0")
        if self.require_approval_aggressiveness < 0:
            raise ValueError(
                "require_approval_aggressiveness must be >= 0"
            )


@dataclass(frozen=True)
class ConstraintResult:
    eligible: bool
    requires_approval: bool
    rationale: str
    reasons: Tuple[str, ...] = ()


def evaluate_constraints(
    cand: InterventionCandidate,
    *,
    authority: AuthorityLevel,
    constraints: OptimizationConstraints,
) -> ConstraintResult:
    reasons: List[str] = []

    if cand.confidence < constraints.min_confidence:
        reasons.append(
            f"confidence {cand.confidence:.3f} below min "
            f"{constraints.min_confidence:.2f}"
        )
    if cand.reversibility < constraints.min_reversibility:
        reasons.append(
            f"reversibility {cand.reversibility:.3f} below min "
            f"{constraints.min_reversibility:.2f}"
        )
    if cand.business_impact > constraints.max_business_impact:
        reasons.append(
            f"business impact {cand.business_impact:.3f} above max "
            f"{constraints.max_business_impact:.2f}"
        )
    if cand.blast_radius > constraints.max_blast_radius:
        reasons.append(
            f"blast radius {cand.blast_radius} above max "
            f"{constraints.max_blast_radius}"
        )

    authority_gap = authority_rank(cand.minimum_authority) - authority_rank(authority)
    if authority_gap >= 2:
        reasons.append(
            f"authority {authority.value} far below required "
            f"{cand.minimum_authority.value}"
        )

    if reasons:
        return ConstraintResult(
            eligible=False, requires_approval=False,
            rationale="; ".join(reasons), reasons=tuple(reasons),
        )

    requires_approval = cand.requires_approval
    if aggressiveness(cand.kind) >= constraints.require_approval_aggressiveness:
        requires_approval = True
    if authority_gap == 1:
        requires_approval = True

    if constraints.require_verified_for_high_impact \
       and aggressiveness(cand.kind) >= constraints.high_impact_aggressiveness \
       and not cand.is_verified:
        reasons.append(
            "high-impact intervention requires verification"
        )
        return ConstraintResult(
            eligible=False, requires_approval=requires_approval,
            rationale="; ".join(reasons), reasons=tuple(reasons),
        )

    return ConstraintResult(
        eligible=True, requires_approval=requires_approval,
        rationale="eligible" if not requires_approval
        else "eligible but requires approval",
    )


# =============================================================================
# SECTION 6 — OPTIMIZATION RESULT
# =============================================================================


@dataclass(frozen=True)
class InterventionDecision:
    entity_id: str
    outcome: DecisionOutcome
    recommended: Optional[InterventionScore]
    alternatives: Tuple[InterventionScore, ...]
    blocked: Tuple[Tuple[str, str], ...]        # (intervention_id, reason)
    approval_required: Tuple[str, ...]
    rationale: str
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


def optimize_interventions(
    *,
    entity_id: str,
    candidates: Sequence[InterventionCandidate],
    authority: AuthorityLevel,
    constraints: OptimizationConstraints = OptimizationConstraints(),
    weights: ScoringWeights = ScoringWeights(),
    at: datetime,
) -> InterventionDecision:
    if at.tzinfo is None:
        raise ValueError("at must be timezone-aware")
    if not entity_id:
        raise ValueError("entity_id is required")

    scored: List[InterventionScore] = []
    blocked: List[Tuple[str, str]] = []
    approval_required: List[str] = []

    for c in candidates:
        if c.entity_id != entity_id:
            raise ValueError(
                f"candidate {c.intervention_id} belongs to a different "
                f"entity {c.entity_id}"
            )
        cr = evaluate_constraints(c, authority=authority, constraints=constraints)
        if not cr.eligible:
            blocked.append((c.intervention_id, cr.rationale))
            continue
        score = score_intervention(c, weights=weights)
        if cr.requires_approval:
            approval_required.append(c.intervention_id)
        scored.append(score)

    if not scored:
        return InterventionDecision(
            entity_id=entity_id,
            outcome=DecisionOutcome.NO_VIABLE_OPTION,
            recommended=None,
            alternatives=(),
            blocked=tuple(blocked),
            approval_required=(),
            rationale="no eligible interventions after constraints",
            at=at,
        )

    # Rank by net_benefit desc, tie-break by aggressiveness ascending
    # (prefer less aggressive on ties) then intervention_id.
    scored.sort(
        key=lambda s: (-s.net_benefit, aggressiveness(s.kind),
                       s.intervention_id),
    )
    best = scored[0]

    if best.net_benefit < 0.0:
        return InterventionDecision(
            entity_id=entity_id,
            outcome=DecisionOutcome.NO_VIABLE_OPTION,
            recommended=None,
            alternatives=tuple(scored),
            blocked=tuple(blocked),
            approval_required=tuple(approval_required),
            rationale=(
                f"best net benefit {best.net_benefit:.3f} is negative"
            ),
            at=at,
        )

    if best.intervention_id in approval_required:
        return InterventionDecision(
            entity_id=entity_id,
            outcome=DecisionOutcome.REQUIRE_APPROVAL,
            recommended=best,
            alternatives=tuple(scored),
            blocked=tuple(blocked),
            approval_required=tuple(approval_required),
            rationale=(
                f"best candidate {best.intervention_id} "
                f"({best.kind.value}) requires approval"
            ),
            at=at,
        )

    return InterventionDecision(
        entity_id=entity_id,
        outcome=DecisionOutcome.RECOMMENDED,
        recommended=best,
        alternatives=tuple(scored),
        blocked=tuple(blocked),
        approval_required=tuple(approval_required),
        rationale=(
            f"recommended {best.intervention_id} ({best.kind.value}) "
            f"with net benefit {best.net_benefit:.3f}"
        ),
        at=at,
    )


# =============================================================================
# SECTION 7 — INVARIANTS
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
class OptimizationSnapshot:
    decisions: Mapping[str, InterventionDecision]
    constraints: OptimizationConstraints
    weights: ScoringWeights


@dataclass(frozen=True)
class OptimizationInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[OptimizationSnapshot],
                        Tuple[InvariantViolation, ...]]
    description: str


def _inv_recommended_in_alternatives(
    snap: OptimizationSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for eid, d in snap.decisions.items():
        if d.recommended is None:
            continue
        alt_ids = {s.intervention_id for s in d.alternatives}
        if d.recommended.intervention_id not in alt_ids:
            out.append(InvariantViolation(
                invariant_id="opt.recommended_in_alternatives",
                severity=InvariantSeverity.HIGH,
                subject_id=eid,
                detail=(
                    f"recommended {d.recommended.intervention_id} not in "
                    f"alternatives"
                ),
            ))
    return tuple(out)


def _inv_net_benefit_bounded(
    snap: OptimizationSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for eid, d in snap.decisions.items():
        if d.recommended is None:
            continue
        nb = d.recommended.net_benefit
        if not -1.0 - 1e-9 <= nb <= 1.0 + 1e-9:
            out.append(InvariantViolation(
                invariant_id="opt.net_benefit_bounded",
                severity=InvariantSeverity.HIGH,
                subject_id=eid,
                detail=f"net benefit {nb}",
            ))
    return tuple(out)


def _inv_blocked_not_recommended(
    snap: OptimizationSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for eid, d in snap.decisions.items():
        if d.recommended is None:
            continue
        blocked_ids = {iid for iid, _ in d.blocked}
        if d.recommended.intervention_id in blocked_ids:
            out.append(InvariantViolation(
                invariant_id="opt.blocked_not_recommended",
                severity=InvariantSeverity.CRITICAL,
                subject_id=eid,
                detail=(
                    f"recommended {d.recommended.intervention_id} is "
                    f"also blocked"
                ),
            ))
    return tuple(out)


def _inv_approval_only_if_required(
    snap: OptimizationSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for eid, d in snap.decisions.items():
        if d.outcome is DecisionOutcome.REQUIRE_APPROVAL:
            if d.recommended is None:
                out.append(InvariantViolation(
                    invariant_id="opt.approval_requires_candidate",
                    severity=InvariantSeverity.HIGH,
                    subject_id=eid,
                    detail="REQUIRE_APPROVAL with no recommended candidate",
                ))
            elif d.recommended.intervention_id not in d.approval_required:
                out.append(InvariantViolation(
                    invariant_id="opt.approval_requires_candidate",
                    severity=InvariantSeverity.HIGH,
                    subject_id=eid,
                    detail=(
                        f"recommended {d.recommended.intervention_id} "
                        f"not in approval_required"
                    ),
                ))
    return tuple(out)


def _inv_no_viable_has_no_recommendation(
    snap: OptimizationSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for eid, d in snap.decisions.items():
        if d.outcome is DecisionOutcome.NO_VIABLE_OPTION \
           and d.recommended is not None:
            out.append(InvariantViolation(
                invariant_id="opt.no_viable_has_no_recommendation",
                severity=InvariantSeverity.HIGH,
                subject_id=eid,
                detail="NO_VIABLE_OPTION with recommended candidate",
            ))
    return tuple(out)


DEFAULT_INVARIANTS: Tuple[OptimizationInvariant, ...] = (
    OptimizationInvariant(
        invariant_id="opt.recommended_in_alternatives",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_recommended_in_alternatives,
        description="Recommended candidate must be among the alternatives.",
    ),
    OptimizationInvariant(
        invariant_id="opt.net_benefit_bounded",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_net_benefit_bounded,
        description="Net benefit must lie within [-1,1].",
    ),
    OptimizationInvariant(
        invariant_id="opt.blocked_not_recommended",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_blocked_not_recommended,
        description="Blocked candidates must not be recommended.",
    ),
    OptimizationInvariant(
        invariant_id="opt.approval_requires_candidate",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_approval_only_if_required,
        description="REQUIRE_APPROVAL must reference the recommended candidate.",
    ),
    OptimizationInvariant(
        invariant_id="opt.no_viable_has_no_recommendation",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_no_viable_has_no_recommendation,
        description="NO_VIABLE_OPTION must not carry a recommendation.",
    ),
)


def check_invariants(
    snap: OptimizationSnapshot,
    invariants: Iterable[OptimizationInvariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 8 — STORE
# =============================================================================


@dataclass(frozen=True)
class DecisionRecord:
    entity_id: str
    outcome: DecisionOutcome
    recommended_id: Optional[str]
    recommended_kind: Optional[InterventionKind]
    net_benefit: Optional[float]
    blocked_count: int
    approval_required_count: int
    updated_at: datetime


class InterventionStore(Protocol):
    def put(self, record: DecisionRecord) -> None: ...
    def get(self, entity_id: str) -> Optional[DecisionRecord]: ...
    def all(self) -> Tuple[DecisionRecord, ...]: ...


class InMemoryInterventionStore:
    def __init__(self) -> None:
        self._data: Dict[str, DecisionRecord] = {}

    def put(self, record: DecisionRecord) -> None:
        existing = self._data.get(record.entity_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._data[record.entity_id] = record

    def get(self, entity_id: str) -> Optional[DecisionRecord]:
        return self._data.get(entity_id)

    def all(self) -> Tuple[DecisionRecord, ...]:
        return tuple(self._data.values())


class SqliteInterventionStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS opt_decisions (
                entity_id TEXT PRIMARY KEY,
                outcome TEXT NOT NULL,
                recommended_id TEXT,
                recommended_kind TEXT,
                net_benefit REAL,
                blocked_count INTEGER NOT NULL,
                approval_required_count INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS opt_candidates (
                intervention_id TEXT PRIMARY KEY,
                entity_id TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def put(self, record: DecisionRecord) -> None:
        existing = self.get(record.entity_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._conn.execute(
            """
            INSERT INTO opt_decisions
              (entity_id, outcome, recommended_id, recommended_kind,
               net_benefit, blocked_count, approval_required_count,
               updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(entity_id) DO UPDATE SET
              outcome=excluded.outcome,
              recommended_id=excluded.recommended_id,
              recommended_kind=excluded.recommended_kind,
              net_benefit=excluded.net_benefit,
              blocked_count=excluded.blocked_count,
              approval_required_count=excluded.approval_required_count,
              updated_at=excluded.updated_at
            """,
            (
                record.entity_id, record.outcome.value,
                record.recommended_id,
                record.recommended_kind.value if record.recommended_kind else None,
                record.net_benefit, record.blocked_count,
                record.approval_required_count,
                record.updated_at.isoformat(),
            ),
        )
        self._conn.commit()

    def get(self, entity_id: str) -> Optional[DecisionRecord]:
        row = self._conn.execute(
            "SELECT outcome, recommended_id, recommended_kind, "
            "net_benefit, blocked_count, approval_required_count, "
            "updated_at FROM opt_decisions WHERE entity_id = ?",
            (entity_id,),
        ).fetchone()
        if row is None:
            return None
        return DecisionRecord(
            entity_id=entity_id,
            outcome=DecisionOutcome(row[0]),
            recommended_id=row[1],
            recommended_kind=InterventionKind(row[2]) if row[2] else None,
            net_benefit=float(row[3]) if row[3] is not None else None,
            blocked_count=int(row[4]),
            approval_required_count=int(row[5]),
            updated_at=datetime.fromisoformat(row[6]),
        )

    def all(self) -> Tuple[DecisionRecord, ...]:
        rows = self._conn.execute(
            "SELECT entity_id FROM opt_decisions"
        ).fetchall()
        return tuple(
            r for r in (self.get(x[0]) for x in rows) if r is not None
        )

    def put_candidate(self, cand: InterventionCandidate) -> None:
        payload = {
            "intervention_id": cand.intervention_id,
            "entity_id": cand.entity_id,
            "kind": cand.kind.value,
            "risk_reduction": cand.risk_reduction,
            "blast_radius": cand.blast_radius,
            "business_impact": cand.business_impact,
            "recovery_cost_units": cand.recovery_cost_units,
            "reversibility": cand.reversibility,
            "confidence": cand.confidence,
            "time_to_effect_seconds": cand.time_to_effect_seconds,
            "future_risk": cand.future_risk,
            "requires_approval": cand.requires_approval,
            "is_verified": cand.is_verified,
            "minimum_authority": cand.minimum_authority.value,
        }
        self._conn.execute(
            "INSERT OR REPLACE INTO opt_candidates "
            "(intervention_id, entity_id, payload_json) VALUES (?, ?, ?)",
            (cand.intervention_id, cand.entity_id,
             json.dumps(payload, sort_keys=True)),
        )
        self._conn.commit()


# =============================================================================
# SECTION 9 — ENGINE
# =============================================================================


class DefensiveInterventionEngine:
    """Defensive intervention optimizer.

    Collects candidate interventions per entity, filters by authority
    and constraints, scores by multi-dimensional cost/benefit, and
    emits a decision per entity with findings.
    """

    def __init__(
        self,
        *,
        store: Optional[InterventionStore] = None,
        constraints: Optional[OptimizationConstraints] = None,
        weights: Optional[ScoringWeights] = None,
    ) -> None:
        self._store: InterventionStore = store or InMemoryInterventionStore()
        self._constraints = constraints or OptimizationConstraints()
        self._weights = weights or ScoringWeights()
        self._candidates: Dict[str, List[InterventionCandidate]] = {}
        self._decisions: Dict[str, InterventionDecision] = {}
        self._findings: List[InterventionFinding] = []
        self._violations: Tuple[InvariantViolation, ...] = ()

    # ---- registration ----------------------------------------------------

    def register_candidate(self, cand: InterventionCandidate) -> None:
        bucket = self._candidates.setdefault(cand.entity_id, [])
        if any(c.intervention_id == cand.intervention_id for c in bucket):
            raise ValueError(
                f"candidate {cand.intervention_id} already registered "
                f"for entity {cand.entity_id}"
            )
        bucket.append(cand)
        if isinstance(self._store, SqliteInterventionStore):
            self._store.put_candidate(cand)

    def register_entity(self, entity_id: str) -> None:
        if not entity_id:
            raise ValueError("entity_id is required")
        self._candidates.setdefault(entity_id, [])

    def candidates(self, entity_id: str) -> Tuple[InterventionCandidate, ...]:
        return tuple(self._candidates.get(entity_id, ()))

    def set_constraints(self, constraints: OptimizationConstraints) -> None:
        self._constraints = constraints

    def set_weights(self, weights: ScoringWeights) -> None:
        self._weights = weights

    def constraints(self) -> OptimizationConstraints:
        return self._constraints

    def weights(self) -> ScoringWeights:
        return self._weights

    # ---- recompute -------------------------------------------------------

    def recompute(
        self,
        *,
        at: datetime,
        authority: Optional[Mapping[str, AuthorityLevel]] = None,
        default_authority: AuthorityLevel = AuthorityLevel.OPERATOR,
    ) -> Tuple[DecisionRecord, ...]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        auth_map = dict(authority or {})

        self._findings = []
        records: List[DecisionRecord] = []

        for eid, cands in self._candidates.items():
            if not cands:
                decision = InterventionDecision(
                    entity_id=eid,
                    outcome=DecisionOutcome.NO_VIABLE_OPTION,
                    recommended=None,
                    alternatives=(),
                    blocked=(),
                    approval_required=(),
                    rationale="no candidates registered",
                    at=at,
                )
            else:
                decision = optimize_interventions(
                    entity_id=eid,
                    candidates=tuple(cands),
                    authority=auth_map.get(eid, default_authority),
                    constraints=self._constraints,
                    weights=self._weights,
                    at=at,
                )

            self._decisions[eid] = decision
            self._emit_findings(decision, at=at)

            record = DecisionRecord(
                entity_id=eid,
                outcome=decision.outcome,
                recommended_id=(
                    decision.recommended.intervention_id
                    if decision.recommended else None
                ),
                recommended_kind=(
                    decision.recommended.kind
                    if decision.recommended else None
                ),
                net_benefit=(
                    decision.recommended.net_benefit
                    if decision.recommended else None
                ),
                blocked_count=len(decision.blocked),
                approval_required_count=len(decision.approval_required),
                updated_at=at,
            )
            self._store.put(record)
            records.append(record)

        self._violations = check_invariants(self.snapshot())
        return tuple(records)

    def _emit_findings(
        self, d: InterventionDecision, *, at: datetime,
    ) -> None:
        if d.outcome is DecisionOutcome.NO_VIABLE_OPTION:
            self._findings.append(InterventionFinding(
                kind=InterventionFindingKind.NO_VIABLE_OPTION,
                entity_id=d.entity_id, intervention_id=None,
                detail=d.rationale, severity=4, at=at,
            ))

        if d.outcome is DecisionOutcome.RECOMMENDED and d.recommended:
            self._findings.append(InterventionFinding(
                kind=InterventionFindingKind.RECOMMENDED,
                entity_id=d.entity_id,
                intervention_id=d.recommended.intervention_id,
                detail=d.rationale, severity=2, at=at,
            ))
        if d.outcome is DecisionOutcome.REQUIRE_APPROVAL and d.recommended:
            self._findings.append(InterventionFinding(
                kind=InterventionFindingKind.REQUIRE_APPROVAL,
                entity_id=d.entity_id,
                intervention_id=d.recommended.intervention_id,
                detail=d.rationale, severity=3, at=at,
            ))

        for iid, reason in d.blocked:
            self._findings.append(InterventionFinding(
                kind=InterventionFindingKind.BLOCKED,
                entity_id=d.entity_id, intervention_id=iid,
                detail=reason, severity=2, at=at,
            ))

        if d.recommended and d.recommended.components:
            comp = d.recommended.components
            if comp.get("unconfidence", 0.0) > 0.6:
                self._findings.append(InterventionFinding(
                    kind=InterventionFindingKind.LOW_CONFIDENCE,
                    entity_id=d.entity_id,
                    intervention_id=d.recommended.intervention_id,
                    detail=(
                        f"unconfidence {comp['unconfidence']:.3f} — "
                        f"recommendation is weakly supported"
                    ),
                    severity=3, at=at,
                ))

        # High-impact unverified candidates (if they would otherwise be
        # eligible but were blocked by the verification gate).
        for iid, reason in d.blocked:
            if "requires verification" in reason:
                self._findings.append(InterventionFinding(
                    kind=InterventionFindingKind.HIGH_IMPACT_UNVERIFIED,
                    entity_id=d.entity_id, intervention_id=iid,
                    detail=reason, severity=4, at=at,
                ))

    # ---- queries ---------------------------------------------------------

    def decision(self, entity_id: str) -> Optional[InterventionDecision]:
        return self._decisions.get(entity_id)

    def record(self, entity_id: str) -> Optional[DecisionRecord]:
        return self._store.get(entity_id)

    def findings(self) -> Tuple[InterventionFinding, ...]:
        return tuple(self._findings)

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return self._violations

    def top_recommendations(
        self, *, k: int = 10,
    ) -> Tuple[Tuple[str, InterventionScore], ...]:
        if k <= 0:
            raise ValueError("k must be > 0")
        items: List[Tuple[str, InterventionScore]] = []
        for eid, d in self._decisions.items():
            if d.recommended is None:
                continue
            items.append((eid, d.recommended))
        items.sort(key=lambda x: (-x[1].net_benefit, x[0]))
        return tuple(items[:k])

    def snapshot(self) -> OptimizationSnapshot:
        return OptimizationSnapshot(
            decisions=dict(self._decisions),
            constraints=self._constraints,
            weights=self._weights,
        )


# =============================================================================
# SECTION 10 — TESTS
# =============================================================================


def _t0() -> datetime:
    from datetime import timezone
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _cand(
    iid: str, eid: str = "e1", *,
    kind: InterventionKind = InterventionKind.WARN,
    risk_reduction: float = 0.6,
    blast_radius: int = 1,
    business_impact: float = 0.1,
    recovery_cost_units: float = 0.5,
    reversibility: float = 0.9,
    confidence: float = 0.9,
    time_to_effect_seconds: float = 30.0,
    future_risk: float = 0.1,
    requires_approval: bool = False,
    is_verified: bool = True,
    minimum_authority: AuthorityLevel = AuthorityLevel.OPERATOR,
) -> InterventionCandidate:
    return InterventionCandidate(
        intervention_id=iid, entity_id=eid, kind=kind,
        risk_reduction=risk_reduction, blast_radius=blast_radius,
        business_impact=business_impact,
        recovery_cost_units=recovery_cost_units,
        reversibility=reversibility, confidence=confidence,
        time_to_effect_seconds=time_to_effect_seconds,
        future_risk=future_risk,
        requires_approval=requires_approval,
        is_verified=is_verified,
        minimum_authority=minimum_authority,
    )


# ---- domain ----

def test_candidate_requires_id() -> None:
    try:
        InterventionCandidate(
            intervention_id="", entity_id="e",
            kind=InterventionKind.WARN,
            risk_reduction=0.5, blast_radius=1, business_impact=0.1,
            recovery_cost_units=0.5, reversibility=0.9, confidence=0.9,
            time_to_effect_seconds=30.0, future_risk=0.1,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_candidate_bounds() -> None:
    try:
        _cand("i1", risk_reduction=1.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_candidate_non_negative_blast() -> None:
    try:
        _cand("i1", blast_radius=-1)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_aggressiveness_ordering() -> None:
    assert aggressiveness(InterventionKind.OBSERVE) < \
        aggressiveness(InterventionKind.WARN)
    assert aggressiveness(InterventionKind.WARN) < \
        aggressiveness(InterventionKind.BLOCK)
    assert aggressiveness(InterventionKind.BLOCK) == \
        aggressiveness(InterventionKind.ESCALATE)


def test_authority_rank_ordering() -> None:
    assert authority_rank(AuthorityLevel.READ_ONLY) < \
        authority_rank(AuthorityLevel.OPERATOR)
    assert authority_rank(AuthorityLevel.OPERATOR) < \
        authority_rank(AuthorityLevel.SENIOR)
    assert authority_rank(AuthorityLevel.BREAK_GLASS) == 4


# ---- scoring ----

def test_scoring_weights_sum_to_one() -> None:
    try:
        ScoringWeights(
            blast_radius=0.9, business_impact=0.9, recovery_cost=0.9,
            irreversibility=0.9, time_to_effect=0.9, future_risk=0.9,
            unconfidence=0.9,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_score_zero_cost_full_reduction() -> None:
    c = _cand(
        "i1", risk_reduction=1.0, blast_radius=0, business_impact=0.0,
        recovery_cost_units=0.0, reversibility=1.0, confidence=1.0,
        time_to_effect_seconds=0.0, future_risk=0.0,
    )
    s = score_intervention(c)
    assert s.expected_risk_reduction == 1.0
    assert s.weighted_cost == 0.0
    assert s.net_benefit == 1.0


def test_score_high_cost_negative_net() -> None:
    c = _cand(
        "i1", risk_reduction=0.1, blast_radius=10, business_impact=1.0,
        recovery_cost_units=10.0, reversibility=0.0, confidence=0.1,
        time_to_effect_seconds=900.0, future_risk=1.0,
    )
    s = score_intervention(c)
    assert s.net_benefit < 0.0


def test_score_expected_value_uses_confidence() -> None:
    c = _cand("i1", risk_reduction=0.8, confidence=0.5)
    s = score_intervention(c)
    assert abs(s.expected_risk_reduction - 0.4) < 1e-9


def test_score_components_present() -> None:
    c = _cand("i1")
    s = score_intervention(c)
    for k in (
        "blast_radius", "business_impact", "recovery_cost",
        "irreversibility", "time_to_effect", "future_risk", "unconfidence",
    ):
        assert k in s.components


def test_score_irreversibility_mirrors_reversibility() -> None:
    c = _cand("i1", reversibility=0.3)
    s = score_intervention(c)
    assert abs(s.components["irreversibility"] - 0.7) < 1e-9


# ---- constraints ----

def test_constraint_low_confidence_blocked() -> None:
    c = _cand("i1", confidence=0.1)
    r = evaluate_constraints(
        c, authority=AuthorityLevel.ADMIN,
        constraints=OptimizationConstraints(min_confidence=0.3),
    )
    assert not r.eligible


def test_constraint_insufficient_authority() -> None:
    c = _cand("i1", minimum_authority=AuthorityLevel.ADMIN)
    r = evaluate_constraints(
        c, authority=AuthorityLevel.OPERATOR,
        constraints=OptimizationConstraints(),
    )
    assert not r.eligible
    assert "authority" in r.rationale


def test_constraint_high_impact_unverified_blocked() -> None:
    c = _cand(
        "i1", kind=InterventionKind.BLOCK, is_verified=False,
        minimum_authority=AuthorityLevel.SENIOR,
    )
    r = evaluate_constraints(
        c, authority=AuthorityLevel.ADMIN,
        constraints=OptimizationConstraints(),
    )
    assert not r.eligible
    assert "verification" in r.rationale


def test_constraint_high_impact_verified_requires_approval() -> None:
    c = _cand(
        "i1", kind=InterventionKind.ISOLATE, is_verified=True,
        minimum_authority=AuthorityLevel.SENIOR,
    )
    r = evaluate_constraints(
        c, authority=AuthorityLevel.ADMIN,
        constraints=OptimizationConstraints(),
    )
    assert r.eligible
    assert r.requires_approval


def test_constraint_business_impact_cap() -> None:
    c = _cand("i1", business_impact=0.9)
    r = evaluate_constraints(
        c, authority=AuthorityLevel.ADMIN,
        constraints=OptimizationConstraints(max_business_impact=0.5),
    )
    assert not r.eligible


def test_constraint_blast_radius_cap() -> None:
    c = _cand("i1", blast_radius=50)
    r = evaluate_constraints(
        c, authority=AuthorityLevel.ADMIN,
        constraints=OptimizationConstraints(max_blast_radius=10),
    )
    assert not r.eligible


def test_constraint_reversibility_floor() -> None:
    c = _cand("i1", reversibility=0.1)
    r = evaluate_constraints(
        c, authority=AuthorityLevel.ADMIN,
        constraints=OptimizationConstraints(min_reversibility=0.5),
    )
    assert not r.eligible


def test_constraint_explicit_approval_flag() -> None:
    c = _cand("i1", kind=InterventionKind.WARN, requires_approval=True)
    r = evaluate_constraints(
        c, authority=AuthorityLevel.ADMIN,
        constraints=OptimizationConstraints(),
    )
    assert r.eligible
    assert r.requires_approval


# ---- optimize ----

def test_optimize_recommends_best() -> None:
    cands = (
        _cand("i-low", risk_reduction=0.3),
        _cand("i-high", risk_reduction=0.9),
    )
    d = optimize_interventions(
        entity_id="e1", candidates=cands,
        authority=AuthorityLevel.OPERATOR, at=_t0(),
    )
    assert d.outcome is DecisionOutcome.RECOMMENDED
    assert d.recommended is not None
    assert d.recommended.intervention_id == "i-high"


def test_optimize_entity_mismatch_rejected() -> None:
    cands = (_cand("i1", eid="other"),)
    try:
        optimize_interventions(
            entity_id="e1", candidates=cands,
            authority=AuthorityLevel.OPERATOR, at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_optimize_no_candidates_returns_no_viable() -> None:
    d = optimize_interventions(
        entity_id="e1", candidates=(),
        authority=AuthorityLevel.OPERATOR, at=_t0(),
    )
    assert d.outcome is DecisionOutcome.NO_VIABLE_OPTION
    assert d.recommended is None


def test_optimize_all_blocked_returns_no_viable() -> None:
    cands = (_cand("i1", confidence=0.05),)
    d = optimize_interventions(
        entity_id="e1", candidates=cands,
        authority=AuthorityLevel.OPERATOR, at=_t0(),
    )
    assert d.outcome is DecisionOutcome.NO_VIABLE_OPTION
    assert any(iid == "i1" for iid, _ in d.blocked)


def test_optimize_negative_net_benefit_no_viable() -> None:
    cands = (_cand(
        "i1", risk_reduction=0.05, blast_radius=10,
        business_impact=1.0, recovery_cost_units=10.0,
        reversibility=0.0, confidence=0.9,
        time_to_effect_seconds=900.0, future_risk=1.0,
    ),)
    d = optimize_interventions(
        entity_id="e1", candidates=cands,
        authority=AuthorityLevel.ADMIN, at=_t0(),
    )
    assert d.outcome is DecisionOutcome.NO_VIABLE_OPTION


def test_optimize_high_impact_requires_approval() -> None:
    cands = (_cand(
        "i1", kind=InterventionKind.ISOLATE, is_verified=True,
        minimum_authority=AuthorityLevel.SENIOR,
    ),)
    d = optimize_interventions(
        entity_id="e1", candidates=cands,
        authority=AuthorityLevel.ADMIN, at=_t0(),
    )
    assert d.outcome is DecisionOutcome.REQUIRE_APPROVAL
    assert "i1" in d.approval_required


def test_optimize_tie_break_prefers_less_aggressive() -> None:
    cands = (
        _cand("i-warn", kind=InterventionKind.WARN, risk_reduction=0.6),
        _cand("i-block", kind=InterventionKind.BLOCK, risk_reduction=0.6),
    )
    d = optimize_interventions(
        entity_id="e1", candidates=cands,
        authority=AuthorityLevel.ADMIN, at=_t0(),
    )
    assert d.recommended is not None
    assert d.recommended.intervention_id == "i-warn"


def test_optimize_at_requires_timezone() -> None:
    from datetime import datetime as dt
    try:
        optimize_interventions(
            entity_id="e1", candidates=(),
            authority=AuthorityLevel.OPERATOR, at=dt(2026, 1, 1),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- engine ----

def test_engine_register_and_recompute() -> None:
    eng = DefensiveInterventionEngine()
    eng.register_candidate(_cand("i1", "e1"))
    eng.register_candidate(_cand("i2", "e2", risk_reduction=0.8))
    records = eng.recompute(at=_t0())
    assert len(records) == 2


def test_engine_rejects_duplicate_candidate() -> None:
    eng = DefensiveInterventionEngine()
    eng.register_candidate(_cand("i1", "e1"))
    try:
        eng.register_candidate(_cand("i1", "e1"))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_record_lookup() -> None:
    eng = DefensiveInterventionEngine()
    eng.register_candidate(_cand("i1", "e1"))
    eng.recompute(at=_t0())
    rec = eng.record("e1")
    assert rec is not None
    assert rec.recommended_id == "i1"


def test_engine_finding_recommended() -> None:
    eng = DefensiveInterventionEngine()
    eng.register_candidate(_cand("i1", "e1"))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert InterventionFindingKind.RECOMMENDED in kinds


def test_engine_finding_require_approval() -> None:
    eng = DefensiveInterventionEngine()
    eng.register_candidate(_cand(
        "i1", "e1", kind=InterventionKind.ISOLATE,
        minimum_authority=AuthorityLevel.SENIOR,
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert InterventionFindingKind.REQUIRE_APPROVAL in kinds


def test_engine_finding_blocked() -> None:
    eng = DefensiveInterventionEngine()
    eng.register_candidate(_cand("i1", "e1", confidence=0.05))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert InterventionFindingKind.BLOCKED in kinds


def test_engine_finding_no_viable_option() -> None:
    eng = DefensiveInterventionEngine()
    eng.register_candidate(_cand("i1", "e1", confidence=0.05))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert InterventionFindingKind.NO_VIABLE_OPTION in kinds


def test_engine_finding_high_impact_unverified() -> None:
    eng = DefensiveInterventionEngine()
    eng.register_candidate(_cand(
        "i1", "e1", kind=InterventionKind.BLOCK, is_verified=False,
        minimum_authority=AuthorityLevel.SENIOR,
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert InterventionFindingKind.HIGH_IMPACT_UNVERIFIED in kinds


def test_engine_finding_low_confidence() -> None:
    eng = DefensiveInterventionEngine()
    eng.register_candidate(_cand(
        "i1", "e1", confidence=0.35, risk_reduction=0.9,
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert InterventionFindingKind.LOW_CONFIDENCE in kinds


def test_engine_authority_map_used() -> None:
    eng = DefensiveInterventionEngine()
    eng.register_candidate(_cand(
        "i1", "e1", minimum_authority=AuthorityLevel.ADMIN,
        risk_reduction=0.9,
    ))
    # Without admin → blocked
    eng.recompute(at=_t0())
    assert eng.decision("e1").outcome is DecisionOutcome.NO_VIABLE_OPTION
    # With admin → recommended
    eng.recompute(at=_t0(), authority={"e1": AuthorityLevel.ADMIN})
    assert eng.decision("e1").outcome is DecisionOutcome.RECOMMENDED


def test_engine_top_recommendations_sorted() -> None:
    eng = DefensiveInterventionEngine()
    eng.register_candidate(_cand("i1", "e1", risk_reduction=0.9))
    eng.register_candidate(_cand("i2", "e2", risk_reduction=0.4))
    eng.recompute(at=_t0())
    top = eng.top_recommendations(k=5)
    assert len(top) == 2
    assert top[0][1].net_benefit >= top[1][1].net_benefit


def test_engine_top_recommendations_invalid_k() -> None:
    eng = DefensiveInterventionEngine()
    try:
        eng.top_recommendations(k=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_set_weights() -> None:
    eng = DefensiveInterventionEngine()
    custom = ScoringWeights(
        blast_radius=0.20, business_impact=0.20, recovery_cost=0.10,
        irreversibility=0.15, time_to_effect=0.05,
        future_risk=0.10, unconfidence=0.20,
    )
    eng.set_weights(custom)
    assert eng.weights() is custom


def test_engine_set_constraints() -> None:
    eng = DefensiveInterventionEngine()
    custom = OptimizationConstraints(min_confidence=0.7)
    eng.set_constraints(custom)
    assert eng.constraints() is custom


def test_engine_no_candidates_no_viable() -> None:
    eng = DefensiveInterventionEngine()
    eng.register_entity("empty")
    records = eng.recompute(at=_t0())
    assert len(records) == 1
    assert records[0].outcome is DecisionOutcome.NO_VIABLE_OPTION


# ---- invariants ----

def test_invariant_clean_snapshot() -> None:
    eng = DefensiveInterventionEngine()
    eng.register_candidate(_cand("i1", "e1"))
    eng.recompute(at=_t0())
    assert eng.violations() == ()


def test_invariant_blocked_not_recommended() -> None:
    # Craft a decision where recommended is also blocked
    good_cand = _cand("i1", "e1")
    score = score_intervention(good_cand)
    bad_decision = InterventionDecision(
        entity_id="e1", outcome=DecisionOutcome.RECOMMENDED,
        recommended=score, alternatives=(score,),
        blocked=(("i1", "fake block"),),
        approval_required=(), rationale="fake", at=_t0(),
    )
    snap = OptimizationSnapshot(
        decisions={"e1": bad_decision},
        constraints=OptimizationConstraints(),
        weights=ScoringWeights(),
    )
    v = check_invariants(snap)
    assert any(x.invariant_id == "opt.blocked_not_recommended" for x in v)


def test_invariant_no_viable_has_no_recommendation() -> None:
    good_cand = _cand("i1", "e1")
    score = score_intervention(good_cand)
    bad = InterventionDecision(
        entity_id="e1", outcome=DecisionOutcome.NO_VIABLE_OPTION,
        recommended=score, alternatives=(score,), blocked=(),
        approval_required=(), rationale="fake", at=_t0(),
    )
    snap = OptimizationSnapshot(
        decisions={"e1": bad},
        constraints=OptimizationConstraints(),
        weights=ScoringWeights(),
    )
    v = check_invariants(snap)
    assert any(
        x.invariant_id == "opt.no_viable_has_no_recommendation"
        for x in v
    )


def test_invariant_approval_requires_candidate() -> None:
    bad = InterventionDecision(
        entity_id="e1", outcome=DecisionOutcome.REQUIRE_APPROVAL,
        recommended=None, alternatives=(), blocked=(),
        approval_required=("i1",), rationale="fake", at=_t0(),
    )
    snap = OptimizationSnapshot(
        decisions={"e1": bad},
        constraints=OptimizationConstraints(),
        weights=ScoringWeights(),
    )
    v = check_invariants(snap)
    assert any(
        x.invariant_id == "opt.approval_requires_candidate" for x in v
    )


# ---- policy ----

def test_engine_constructor_defaults() -> None:
    eng = DefensiveInterventionEngine()
    assert isinstance(eng.constraints(), OptimizationConstraints)
    assert isinstance(eng.weights(), ScoringWeights)


def test_engine_custom_weights() -> None:
    w = ScoringWeights(
        blast_radius=0.10, business_impact=0.20, recovery_cost=0.10,
        irreversibility=0.20, time_to_effect=0.10,
        future_risk=0.10, unconfidence=0.20,
    )
    eng = DefensiveInterventionEngine(weights=w)
    assert eng.weights() is w


def test_engine_custom_constraints() -> None:
    c = OptimizationConstraints(min_confidence=0.6)
    eng = DefensiveInterventionEngine(constraints=c)
    assert eng.constraints() is c


# ---- store ----

def test_in_memory_store_rejects_stale() -> None:
    s = InMemoryInterventionStore()
    t = _t0()
    s.put(DecisionRecord(
        "e1", DecisionOutcome.RECOMMENDED, "i1",
        InterventionKind.WARN, 0.5, 0, 0, t,
    ))
    earlier = t.replace(year=t.year - 1)
    try:
        s.put(DecisionRecord(
            "e1", DecisionOutcome.NO_VIABLE_OPTION, None, None, None,
            0, 0, earlier,
        ))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_decision_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "opt.db")
    store = SqliteInterventionStore(db)
    t = _t0()
    store.put(DecisionRecord(
        entity_id="e1", outcome=DecisionOutcome.RECOMMENDED,
        recommended_id="i1", recommended_kind=InterventionKind.WARN,
        net_benefit=0.55, blocked_count=1, approval_required_count=0,
        updated_at=t,
    ))
    got = store.get("e1")
    assert got is not None
    assert got.recommended_id == "i1"
    assert got.recommended_kind is InterventionKind.WARN
    assert abs(got.net_benefit - 0.55) < 1e-9


def test_sqlite_store_candidate_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "opt.db")
    store = SqliteInterventionStore(db)
    c = _cand("i1", "e1")
    store.put_candidate(c)
    row = store._conn.execute(
        "SELECT payload_json FROM opt_candidates "
        "WHERE intervention_id = 'i1'"
    ).fetchone()
    assert row is not None
    payload = json.loads(row[0])
    assert payload["intervention_id"] == "i1"
    assert payload["kind"] == "warn"


# =============================================================================
# SECTION 11 — MANUAL RUNNER
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
