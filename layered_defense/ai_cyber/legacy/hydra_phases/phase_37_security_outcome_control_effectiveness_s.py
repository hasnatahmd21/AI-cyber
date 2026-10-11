"""
HYDRA POST-CORE — PHASE 37: SECURITY OUTCOME / CONTROL EFFECTIVENESS SCIENCE
===============================================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * Domain — 6 outcome kinds, 5 control effectiveness tiers,
    5 detection quality tiers, 5 decision quality tiers,
    5 recovery quality tiers, 4 cost classes, 12 finding kinds
  * Outcome recording — pre/post security state per defensive decision
  * Effectiveness computations across 12 orthogonal dimensions:
      1.  threat_reduction
      2.  control_effectiveness
      3.  residual_risk
      4.  false_positive_cost
      5.  false_negative_cost
      6.  intervention_cost
      7.  recovery_quality
      8.  detection_quality
      9.  decision_quality
     10.  time_to_control_seconds
     11.  time_to_recovery_seconds
     12.  blast_radius_reduction
     13.  security_state_improvement
  * Per-control effectiveness aggregation
  * Per-detector detection quality aggregation (confusion-matrix-based)
  * Per-intervention decision quality aggregation
  * Global scorecard
  * Findings — 12 kinds
  * Machine-checkable outcome invariants
  * In-memory + SQLite stores
  * Phase-37 engine facade
  * Full test suite + manual runner

Doctrine: this measures *what actually happened after a defensive
decision*, not what was expected. Every outcome carries its own
pre-state and post-state, and every metric is computed from those.

No third-party dependencies.

Run tests:
    python hydra_phase37_outcome_effectiveness_science.py
    pytest hydra_phase37_outcome_effectiveness_science.py -q
"""
from __future__ import annotations

import json
import math
import sqlite3
from dataclasses import dataclass, field
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


class OutcomeKind(str, Enum):
    DETECTION = "detection"
    INTERVENTION = "intervention"
    RECOVERY = "recovery"
    VERIFICATION = "verification"
    LEARNING = "learning"
    NO_ACTION = "no_action"


ALL_OUTCOME_KINDS: Tuple[OutcomeKind, ...] = tuple(OutcomeKind)


class ControlEffectivenessTier(str, Enum):
    NEGATIVE = "negative"          # made things worse
    INEFFECTIVE = "ineffective"
    MARGINAL = "marginal"
    EFFECTIVE = "effective"
    HIGHLY_EFFECTIVE = "highly_effective"


class DetectionQualityTier(str, Enum):
    POOR = "poor"
    LIMITED = "limited"
    ACCEPTABLE = "acceptable"
    GOOD = "good"
    EXCELLENT = "excellent"


class DecisionQualityTier(str, Enum):
    HARMFUL = "harmful"
    SUBOPTIMAL = "suboptimal"
    ACCEPTABLE = "decision_acceptable"
    GOOD = "good"
    OPTIMAL = "optimal"


class RecoveryQualityTier(str, Enum):
    FAILED = "failed"
    PARTIAL = "partial"
    ACCEPTABLE = "recovery_acceptable"
    GOOD = "good"
    COMPLETE = "complete"


class CostClass(str, Enum):
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"
    INTERVENTION = "intervention"
    RECOVERY = "recovery"


class FindingKind(str, Enum):
    CONTROL_EFFECTIVE = "control_effective"
    CONTROL_INEFFECTIVE = "control_ineffective"
    CONTROL_NEGATIVE = "control_negative"
    DETECTION_DEGRADED = "detection_degraded"
    DETECTION_EXCELLENT = "detection_excellent"
    DECISION_HARMFUL = "decision_harmful"
    DECISION_OPTIMAL = "decision_optimal"
    RECOVERY_FAILED = "recovery_failed"
    RESIDUAL_RISK_HIGH = "residual_risk_high"
    BLAST_RADIUS_INCREASED = "blast_radius_increased"
    STATE_IMPROVED = "state_improved"
    STATE_WORSENED = "state_worsened"


@dataclass(frozen=True)
class OutcomeFinding:
    kind: FindingKind
    subject_id: str
    detail: str
    severity: int
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        if not 1 <= self.severity <= 5:
            raise ValueError("severity must be in [1,5]")


# =============================================================================
# SECTION 3 — STATE MODEL
# =============================================================================


@dataclass(frozen=True)
class StateVector:
    """A snapshot of the security-relevant state of an entity at a
    moment in time. Higher is better for `trust`, `integrity`,
    `availability`, `confidentiality`; higher is worse for `risk`,
    `exposure`, `blast_radius`."""
    trust: float
    integrity: float
    availability: float
    confidentiality: float
    risk: float
    exposure: float
    blast_radius: int

    def __post_init__(self) -> None:
        for n, v in (
            ("trust", self.trust),
            ("integrity", self.integrity),
            ("availability", self.availability),
            ("confidentiality", self.confidentiality),
            ("risk", self.risk),
            ("exposure", self.exposure),
        ):
            if not 0.0 <= v <= 1.0:
                raise ValueError(f"{n} must be within [0,1]")
        if self.blast_radius < 0:
            raise ValueError("blast_radius must be >= 0")

    def composite_goodness(self) -> float:
        """Higher is better. Risk and exposure are inverted."""
        positive = (
            self.trust + self.integrity + self.availability
            + self.confidentiality
        ) / 4.0
        negative = (self.risk + self.exposure) / 2.0
        br = min(1.0, self.blast_radius / 10.0)
        return max(0.0, min(1.0, 0.6 * positive + 0.25 * (1 - negative)
                             + 0.15 * (1 - br)))


# =============================================================================
# SECTION 4 — COST MODEL
# =============================================================================


@dataclass(frozen=True)
class CostBudget:
    false_positive_unit: float = 1.0
    false_negative_unit: float = 5.0
    intervention_unit: float = 2.0
    recovery_unit: float = 3.0

    def __post_init__(self) -> None:
        for n, v in (
            ("false_positive_unit", self.false_positive_unit),
            ("false_negative_unit", self.false_negative_unit),
            ("intervention_unit", self.intervention_unit),
            ("recovery_unit", self.recovery_unit),
        ):
            if v < 0:
                raise ValueError(f"{n} must be >= 0")


# =============================================================================
# SECTION 5 — OUTCOME RECORD
# =============================================================================


@dataclass(frozen=True)
class OutcomeRecord:
    """What actually happened after a defensive decision."""
    outcome_id: str
    entity_id: str
    kind: OutcomeKind

    # Identity of the decision/component under test
    detector_id: Optional[str]
    control_id: Optional[str]
    intervention_id: Optional[str]

    # State before and after
    pre_state: StateVector
    post_state: StateVector

    # Detection flags (used for confusion matrix)
    ground_truth_positive: bool
    alert_fired: bool

    # Timing
    decision_at: datetime
    controlled_at: Optional[datetime]
    recovered_at: Optional[datetime]

    # Costs
    false_positive_count: int = 0
    false_negative_count: int = 0
    intervention_cost_units: float = 0.0
    recovery_cost_units: float = 0.0

    # Verification / outcome flags
    action_verified: bool = True
    objective_achieved: bool = True

    tags: FrozenSet[str] = frozenset()

    def __post_init__(self) -> None:
        if not self.outcome_id:
            raise ValueError("outcome_id is required")
        if not self.entity_id:
            raise ValueError("entity_id is required")
        if self.decision_at.tzinfo is None:
            raise ValueError("decision_at must be timezone-aware")
        for n, t in (
            ("controlled_at", self.controlled_at),
            ("recovered_at", self.recovered_at),
        ):
            if t is not None and t.tzinfo is None:
                raise ValueError(f"{n} must be timezone-aware")
        if self.false_positive_count < 0:
            raise ValueError("false_positive_count must be >= 0")
        if self.false_negative_count < 0:
            raise ValueError("false_negative_count must be >= 0")
        if self.intervention_cost_units < 0:
            raise ValueError("intervention_cost_units must be >= 0")
        if self.recovery_cost_units < 0:
            raise ValueError("recovery_cost_units must be >= 0")

    # ---- computed outcome metrics ---------------------------------------

    @property
    def threat_reduction(self) -> float:
        """Fraction of pre-state risk that was eliminated."""
        before = self.pre_state.risk
        after = self.post_state.risk
        if before <= 0.0:
            return 0.0
        return max(0.0, min(1.0, (before - after) / before))

    @property
    def residual_risk(self) -> float:
        return self.post_state.risk

    @property
    def state_improvement(self) -> float:
        """Composite goodness delta ∈ [-1,1]."""
        return self.post_state.composite_goodness() - \
            self.pre_state.composite_goodness()

    @property
    def blast_radius_reduction(self) -> int:
        return self.pre_state.blast_radius - self.post_state.blast_radius

    @property
    def time_to_control_seconds(self) -> Optional[float]:
        if self.controlled_at is None:
            return None
        return (self.controlled_at - self.decision_at).total_seconds()

    @property
    def time_to_recovery_seconds(self) -> Optional[float]:
        if self.recovered_at is None:
            return None
        return (self.recovered_at - self.decision_at).total_seconds()

    def detection_outcome(self) -> str:
        """TP / FP / TN / FN."""
        if self.ground_truth_positive and self.alert_fired:
            return "TP"
        if not self.ground_truth_positive and self.alert_fired:
            return "FP"
        if not self.ground_truth_positive and not self.alert_fired:
            return "TN"
        return "FN"


# =============================================================================
# SECTION 6 — QUALITY TIER MAPPERS
# =============================================================================


def _control_effectiveness_tier(x: float) -> ControlEffectivenessTier:
    if not -1.0 <= x <= 1.0:
        raise ValueError("effectiveness score must be in [-1,1]")
    if x < 0.0:
        return ControlEffectivenessTier.NEGATIVE
    if x < 0.25:
        return ControlEffectivenessTier.INEFFECTIVE
    if x < 0.5:
        return ControlEffectivenessTier.MARGINAL
    if x < 0.8:
        return ControlEffectivenessTier.EFFECTIVE
    return ControlEffectivenessTier.HIGHLY_EFFECTIVE


def _detection_quality_tier(f1: float) -> DetectionQualityTier:
    if not 0.0 <= f1 <= 1.0:
        raise ValueError("f1 must be in [0,1]")
    if f1 < 0.3:
        return DetectionQualityTier.POOR
    if f1 < 0.5:
        return DetectionQualityTier.LIMITED
    if f1 < 0.7:
        return DetectionQualityTier.ACCEPTABLE
    if f1 < 0.9:
        return DetectionQualityTier.GOOD
    return DetectionQualityTier.EXCELLENT


def _decision_quality_tier(x: float) -> DecisionQualityTier:
    if not -1.0 <= x <= 1.0:
        raise ValueError("decision quality score must be in [-1,1]")
    if x < 0.0:
        return DecisionQualityTier.HARMFUL
    if x < 0.3:
        return DecisionQualityTier.SUBOPTIMAL
    if x < 0.55:
        return DecisionQualityTier.ACCEPTABLE
    if x < 0.8:
        return DecisionQualityTier.GOOD
    return DecisionQualityTier.OPTIMAL


def _recovery_quality_tier(
    action_verified: bool,
    objective_achieved: bool,
    state_improvement: float,
) -> RecoveryQualityTier:
    if not action_verified:
        return RecoveryQualityTier.FAILED
    if not objective_achieved:
        return RecoveryQualityTier.PARTIAL
    if state_improvement <= 0.0:
        return RecoveryQualityTier.PARTIAL
    if state_improvement < 0.3:
        return RecoveryQualityTier.ACCEPTABLE
    if state_improvement < 0.6:
        return RecoveryQualityTier.GOOD
    return RecoveryQualityTier.COMPLETE


# =============================================================================
# SECTION 7 — PER-COMPONENT AGGREGATES
# =============================================================================


@dataclass(frozen=True)
class ControlEffectivenessReport:
    control_id: str
    samples: int
    mean_effectiveness: float
    tier: ControlEffectivenessTier
    total_fp_cost: float
    total_fn_cost: float
    mean_residual_risk: float
    mean_state_improvement: float

    def __post_init__(self) -> None:
        if self.samples < 0:
            raise ValueError("samples must be >= 0")


@dataclass(frozen=True)
class DetectionQualityReport:
    detector_id: str
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float
    f1: float
    tier: DetectionQualityTier

    def __post_init__(self) -> None:
        for n, v in (
            ("tp", self.tp), ("fp", self.fp),
            ("tn", self.tn), ("fn", self.fn),
        ):
            if v < 0:
                raise ValueError(f"{n} must be >= 0")

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn


@dataclass(frozen=True)
class DecisionQualityReport:
    intervention_id: str
    samples: int
    mean_state_improvement: float
    mean_residual_risk: float
    mean_time_to_control_seconds: Optional[float]
    tier: DecisionQualityTier

    def __post_init__(self) -> None:
        if self.samples < 0:
            raise ValueError("samples must be >= 0")


@dataclass(frozen=True)
class RecoveryQualityReport:
    recovery_context: str
    samples: int
    mean_time_to_recovery_seconds: Optional[float]
    mean_state_improvement: float
    tier_counts: Mapping[RecoveryQualityTier, int]

    def __post_init__(self) -> None:
        if self.samples < 0:
            raise ValueError("samples must be >= 0")


@dataclass(frozen=True)
class GlobalScorecard:
    total_outcomes: int
    mean_threat_reduction: float
    mean_residual_risk: float
    mean_state_improvement: float
    mean_blast_radius_reduction: float
    mean_time_to_control_seconds: Optional[float]
    mean_time_to_recovery_seconds: Optional[float]
    detection_quality: float             # mean F1 across detectors
    decision_quality: float              # mean tier score
    recovery_quality: float              # mean tier score
    total_false_positive_cost: float
    total_false_negative_cost: float
    total_intervention_cost: float
    total_recovery_cost: float

    def __post_init__(self) -> None:
        if self.total_outcomes < 0:
            raise ValueError("total_outcomes must be >= 0")


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
class OutcomeSnapshot:
    outcomes: Tuple[OutcomeRecord, ...]
    controls: Mapping[str, ControlEffectivenessReport]
    detectors: Mapping[str, DetectionQualityReport]
    decisions: Mapping[str, DecisionQualityReport]
    recoveries: Mapping[str, RecoveryQualityReport]
    scorecard: GlobalScorecard
    findings: Tuple[OutcomeFinding, ...]


@dataclass(frozen=True)
class OutcomeInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[OutcomeSnapshot],
                        Tuple[InvariantViolation, ...]]
    description: str


def _inv_state_improvement_bounded(
    snap: OutcomeSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for o in snap.outcomes:
        d = o.state_improvement
        if not -1.0 - 1e-9 <= d <= 1.0 + 1e-9:
            out.append(InvariantViolation(
                invariant_id="out.state_improvement_bounded",
                severity=InvariantSeverity.HIGH,
                subject_id=o.outcome_id,
                detail=f"state_improvement {d}",
            ))
    return tuple(out)


def _inv_threat_reduction_bounded(
    snap: OutcomeSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for o in snap.outcomes:
        x = o.threat_reduction
        if not 0.0 - 1e-9 <= x <= 1.0 + 1e-9:
            out.append(InvariantViolation(
                invariant_id="out.threat_reduction_bounded",
                severity=InvariantSeverity.HIGH,
                subject_id=o.outcome_id,
                detail=f"threat_reduction {x}",
            ))
    return tuple(out)


def _inv_confusion_counts_consistent(
    snap: OutcomeSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for o in snap.outcomes:
        co = o.detection_outcome()
        if co == "FP" and o.ground_truth_positive:
            out.append(InvariantViolation(
                invariant_id="out.confusion_consistent",
                severity=InvariantSeverity.CRITICAL,
                subject_id=o.outcome_id,
                detail="FP with ground_truth_positive=True",
            ))
        if co == "FN" and not o.ground_truth_positive:
            out.append(InvariantViolation(
                invariant_id="out.confusion_consistent",
                severity=InvariantSeverity.CRITICAL,
                subject_id=o.outcome_id,
                detail="FN with ground_truth_positive=False",
            ))
    return tuple(out)


def _inv_time_ordering(
    snap: OutcomeSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for o in snap.outcomes:
        if o.controlled_at is not None and o.controlled_at < o.decision_at:
            out.append(InvariantViolation(
                invariant_id="out.time_ordering",
                severity=InvariantSeverity.HIGH,
                subject_id=o.outcome_id,
                detail="controlled_at < decision_at",
            ))
        if o.recovered_at is not None and o.recovered_at < o.decision_at:
            out.append(InvariantViolation(
                invariant_id="out.time_ordering",
                severity=InvariantSeverity.HIGH,
                subject_id=o.outcome_id,
                detail="recovered_at < decision_at",
            ))
    return tuple(out)


def _inv_scorecard_bounded(
    snap: OutcomeSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    sc = snap.scorecard
    for n, v in (
        ("mean_threat_reduction", sc.mean_threat_reduction),
        ("mean_residual_risk", sc.mean_residual_risk),
        ("detection_quality", sc.detection_quality),
    ):
        if not 0.0 - 1e-9 <= v <= 1.0 + 1e-9:
            out.append(InvariantViolation(
                invariant_id="out.scorecard_bounded",
                severity=InvariantSeverity.HIGH,
                subject_id="scorecard",
                detail=f"{n}={v}",
            ))
    return tuple(out)


DEFAULT_INVARIANTS: Tuple[OutcomeInvariant, ...] = (
    OutcomeInvariant(
        invariant_id="out.state_improvement_bounded",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_state_improvement_bounded,
        description="State improvement must lie within [-1,1].",
    ),
    OutcomeInvariant(
        invariant_id="out.threat_reduction_bounded",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_threat_reduction_bounded,
        description="Threat reduction must lie within [0,1].",
    ),
    OutcomeInvariant(
        invariant_id="out.confusion_consistent",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_confusion_counts_consistent,
        description="Confusion outcomes must be internally consistent.",
    ),
    OutcomeInvariant(
        invariant_id="out.time_ordering",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_time_ordering,
        description="Controlled/recovered timestamps cannot precede decision.",
    ),
    OutcomeInvariant(
        invariant_id="out.scorecard_bounded",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_scorecard_bounded,
        description="Scorecard aggregates must lie within [0,1].",
    ),
)


def check_invariants(
    snap: OutcomeSnapshot,
    invariants: Iterable[OutcomeInvariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 9 — AGGREGATION
# =============================================================================


def _mean(xs: Iterable[float]) -> Optional[float]:
    ys = list(xs)
    if not ys:
        return None
    return sum(ys) / len(ys)


def _mean_or_zero(xs: Iterable[float]) -> float:
    m = _mean(xs)
    return m if m is not None else 0.0


def aggregate_control(
    control_id: str,
    outcomes: Sequence[OutcomeRecord],
    *,
    budget: CostBudget,
) -> ControlEffectivenessReport:
    rel = [o for o in outcomes if o.control_id == control_id]
    if not rel:
        return ControlEffectivenessReport(
            control_id=control_id, samples=0,
            mean_effectiveness=0.0,
            tier=ControlEffectivenessTier.INEFFECTIVE,
            total_fp_cost=0.0, total_fn_cost=0.0,
            mean_residual_risk=0.0, mean_state_improvement=0.0,
        )
    effs = [o.threat_reduction for o in rel]
    mean_eff = _mean_or_zero(effs)
    # Signed adjustment: if state worsened substantially, push into
    # negative territory.
    mean_state = _mean_or_zero(o.state_improvement for o in rel)
    effectiveness = mean_eff * 0.7 + mean_state * 0.3
    tier = _control_effectiveness_tier(effectiveness)

    total_fp = sum(
        o.false_positive_count * budget.false_positive_unit for o in rel
    )
    total_fn = sum(
        o.false_negative_count * budget.false_negative_unit for o in rel
    )
    return ControlEffectivenessReport(
        control_id=control_id, samples=len(rel),
        mean_effectiveness=effectiveness, tier=tier,
        total_fp_cost=total_fp, total_fn_cost=total_fn,
        mean_residual_risk=_mean_or_zero(o.residual_risk for o in rel),
        mean_state_improvement=mean_state,
    )


def aggregate_detector(
    detector_id: str,
    outcomes: Sequence[OutcomeRecord],
) -> DetectionQualityReport:
    rel = [o for o in outcomes if o.detector_id == detector_id]
    tp = sum(1 for o in rel if o.detection_outcome() == "TP")
    fp = sum(1 for o in rel if o.detection_outcome() == "FP")
    tn = sum(1 for o in rel if o.detection_outcome() == "TN")
    fn = sum(1 for o in rel if o.detection_outcome() == "FN")

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0 else 0.0
    )
    return DetectionQualityReport(
        detector_id=detector_id, tp=tp, fp=fp, tn=tn, fn=fn,
        precision=precision, recall=recall, f1=f1,
        tier=_detection_quality_tier(f1),
    )


def aggregate_decision(
    intervention_id: str,
    outcomes: Sequence[OutcomeRecord],
) -> DecisionQualityReport:
    rel = [o for o in outcomes
           if o.intervention_id == intervention_id]
    if not rel:
        return DecisionQualityReport(
            intervention_id=intervention_id, samples=0,
            mean_state_improvement=0.0, mean_residual_risk=0.0,
            mean_time_to_control_seconds=None,
            tier=DecisionQualityTier.SUBOPTIMAL,
        )
    mean_imp = _mean_or_zero(o.state_improvement for o in rel)
    mean_res = _mean_or_zero(o.residual_risk for o in rel)
    ttc = _mean(
        o.time_to_control_seconds for o in rel
        if o.time_to_control_seconds is not None
    )
    # score = improvement − residual_risk (bounded)
    score = max(-1.0, min(1.0, mean_imp - 0.5 * mean_res))
    return DecisionQualityReport(
        intervention_id=intervention_id, samples=len(rel),
        mean_state_improvement=mean_imp,
        mean_residual_risk=mean_res,
        mean_time_to_control_seconds=ttc,
        tier=_decision_quality_tier(score),
    )


def aggregate_recovery(
    recovery_context: str,
    outcomes: Sequence[OutcomeRecord],
) -> RecoveryQualityReport:
    rel = [o for o in outcomes if o.kind is OutcomeKind.RECOVERY
           or o.recovered_at is not None]
    # For context scoping we filter by tag equality when provided
    if recovery_context != "*":
        rel = [o for o in rel if recovery_context in o.tags]
    if not rel:
        return RecoveryQualityReport(
            recovery_context=recovery_context, samples=0,
            mean_time_to_recovery_seconds=None,
            mean_state_improvement=0.0,
            tier_counts={},
        )
    ttr = _mean(
        o.time_to_recovery_seconds for o in rel
        if o.time_to_recovery_seconds is not None
    )
    mean_imp = _mean_or_zero(o.state_improvement for o in rel)
    counts: Dict[RecoveryQualityTier, int] = {t: 0 for t in RecoveryQualityTier}
    for o in rel:
        tier = _recovery_quality_tier(
            o.action_verified, o.objective_achieved,
            o.state_improvement,
        )
        counts[tier] += 1
    # Best representative tier: complete > good > acceptable > partial
    # > failed — we choose based on the mode.
    best = max(
        (t for t in counts if counts[t] > 0),
        key=lambda t: counts[t],
        default=RecoveryQualityTier.FAILED,
    )
    return RecoveryQualityReport(
        recovery_context=recovery_context, samples=len(rel),
        mean_time_to_recovery_seconds=ttr,
        mean_state_improvement=mean_imp,
        tier_counts=counts,
    )


_TIER_SCORE: Mapping[Any, float] = {
    DetectionQualityTier.POOR: 0.1,
    DetectionQualityTier.LIMITED: 0.3,
    DetectionQualityTier.ACCEPTABLE: 0.5,
    DetectionQualityTier.GOOD: 0.75,
    DetectionQualityTier.EXCELLENT: 1.0,
    DecisionQualityTier.HARMFUL: 0.0,
    DecisionQualityTier.SUBOPTIMAL: 0.25,
    DecisionQualityTier.ACCEPTABLE: 0.5,
    DecisionQualityTier.GOOD: 0.75,
    DecisionQualityTier.OPTIMAL: 1.0,
    RecoveryQualityTier.FAILED: 0.0,
    RecoveryQualityTier.PARTIAL: 0.3,
    RecoveryQualityTier.ACCEPTABLE: 0.55,
    RecoveryQualityTier.GOOD: 0.8,
    RecoveryQualityTier.COMPLETE: 1.0,
}


def _tier_score(t: Any) -> float:
    return _TIER_SCORE.get(t, 0.0)


# =============================================================================
# SECTION 10 — STORE
# =============================================================================


@dataclass(frozen=True)
class OutcomeStateRecord:
    outcome_id: str
    entity_id: str
    kind: OutcomeKind
    threat_reduction: float
    residual_risk: float
    state_improvement: float
    updated_at: datetime


class OutcomeStore(Protocol):
    def put(self, record: OutcomeStateRecord) -> None: ...
    def get(self, outcome_id: str) -> Optional[OutcomeStateRecord]: ...
    def all(self) -> Tuple[OutcomeStateRecord, ...]: ...


class InMemoryOutcomeStore:
    def __init__(self) -> None:
        self._data: Dict[str, OutcomeStateRecord] = {}

    def put(self, record: OutcomeStateRecord) -> None:
        existing = self._data.get(record.outcome_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._data[record.outcome_id] = record

    def get(self, outcome_id: str) -> Optional[OutcomeStateRecord]:
        return self._data.get(outcome_id)

    def all(self) -> Tuple[OutcomeStateRecord, ...]:
        return tuple(self._data.values())


class SqliteOutcomeStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS outcome_records (
                outcome_id TEXT PRIMARY KEY,
                entity_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                threat_reduction REAL NOT NULL,
                residual_risk REAL NOT NULL,
                state_improvement REAL NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS outcome_findings (
                finding_id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def put(self, record: OutcomeStateRecord) -> None:
        existing = self.get(record.outcome_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._conn.execute(
            """
            INSERT INTO outcome_records
              (outcome_id, entity_id, kind, threat_reduction,
               residual_risk, state_improvement, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(outcome_id) DO UPDATE SET
              entity_id=excluded.entity_id,
              kind=excluded.kind,
              threat_reduction=excluded.threat_reduction,
              residual_risk=excluded.residual_risk,
              state_improvement=excluded.state_improvement,
              updated_at=excluded.updated_at
            """,
            (
                record.outcome_id, record.entity_id, record.kind.value,
                record.threat_reduction, record.residual_risk,
                record.state_improvement,
                record.updated_at.isoformat(),
            ),
        )
        self._conn.commit()

    def get(self, outcome_id: str) -> Optional[OutcomeStateRecord]:
        row = self._conn.execute(
            "SELECT entity_id, kind, threat_reduction, residual_risk, "
            "state_improvement, updated_at FROM outcome_records "
            "WHERE outcome_id = ?",
            (outcome_id,),
        ).fetchone()
        if row is None:
            return None
        return OutcomeStateRecord(
            outcome_id=outcome_id, entity_id=row[0],
            kind=OutcomeKind(row[1]),
            threat_reduction=float(row[2]),
            residual_risk=float(row[3]),
            state_improvement=float(row[4]),
            updated_at=datetime.fromisoformat(row[5]),
        )

    def all(self) -> Tuple[OutcomeStateRecord, ...]:
        rows = self._conn.execute(
            "SELECT outcome_id FROM outcome_records"
        ).fetchall()
        return tuple(
            r for r in (self.get(x[0]) for x in rows)
            if r is not None
        )

    def put_finding(self, finding_id: str, f: OutcomeFinding) -> None:
        payload = {
            "finding_id": finding_id,
            "kind": f.kind.value,
            "subject_id": f.subject_id,
            "detail": f.detail,
            "severity": f.severity,
            "at": f.at.isoformat(),
        }
        self._conn.execute(
            "INSERT OR REPLACE INTO outcome_findings "
            "(finding_id, payload_json) VALUES (?, ?)",
            (finding_id, json.dumps(payload, sort_keys=True)),
        )
        self._conn.commit()


# =============================================================================
# SECTION 11 — ENGINE
# =============================================================================


@dataclass(frozen=True)
class OutcomeConfig:
    high_residual_risk: float = 0.6
    low_threat_reduction: float = 0.3
    negative_state_improvement: float = -0.05
    positive_state_improvement: float = 0.15
    max_findings: int = 5000

    def __post_init__(self) -> None:
        if not 0.0 <= self.high_residual_risk <= 1.0:
            raise ValueError("high_residual_risk must be within [0,1]")
        if not 0.0 <= self.low_threat_reduction <= 1.0:
            raise ValueError("low_threat_reduction must be within [0,1]")
        if not -1.0 <= self.negative_state_improvement <= 1.0:
            raise ValueError(
                "negative_state_improvement must be within [-1,1]"
            )
        if not -1.0 <= self.positive_state_improvement <= 1.0:
            raise ValueError(
                "positive_state_improvement must be within [-1,1]"
            )
        if self.max_findings < 1:
            raise ValueError("max_findings must be >= 1")


class SecurityOutcomeScienceEngine:
    """Security outcome / control effectiveness engine."""

    def __init__(
        self,
        *,
        store: Optional[OutcomeStore] = None,
        budget: Optional[CostBudget] = None,
        config: Optional[OutcomeConfig] = None,
    ) -> None:
        self._store: OutcomeStore = store or InMemoryOutcomeStore()
        self._budget = budget or CostBudget()
        self._config = config or OutcomeConfig()
        self._outcomes: List[OutcomeRecord] = []
        self._controls: Dict[str, ControlEffectivenessReport] = {}
        self._detectors: Dict[str, DetectionQualityReport] = {}
        self._decisions: Dict[str, DecisionQualityReport] = {}
        self._recoveries: Dict[str, RecoveryQualityReport] = {}
        self._scorecard: Optional[GlobalScorecard] = None
        self._findings: List[OutcomeFinding] = []
        self._violations: Tuple[InvariantViolation, ...] = ()

    # ---- config ----------------------------------------------------------

    def budget(self) -> CostBudget:
        return self._budget

    def set_budget(self, b: CostBudget) -> None:
        self._budget = b

    def config(self) -> OutcomeConfig:
        return self._config

    def set_config(self, c: OutcomeConfig) -> None:
        self._config = c

    # ---- ingestion -------------------------------------------------------

    def record_outcome(self, o: OutcomeRecord) -> None:
        self._outcomes.append(o)

    def outcomes(self) -> Tuple[OutcomeRecord, ...]:
        return tuple(self._outcomes)

    def outcome(self, oid: str) -> Optional[OutcomeRecord]:
        for o in self._outcomes:
            if o.outcome_id == oid:
                return o
        return None

    # ---- recompute -------------------------------------------------------

    def recompute(self, *, at: datetime) -> Tuple[OutcomeStateRecord, ...]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        cfg = self._config
        budget = self._budget
        self._findings = []

        # Per-control aggregates
        controls: Dict[str, ControlEffectivenessReport] = {}
        control_ids = sorted({
            o.control_id for o in self._outcomes if o.control_id
        })
        for cid in control_ids:
            r = aggregate_control(cid, self._outcomes, budget=budget)
            controls[cid] = r
            if r.tier is ControlEffectivenessTier.NEGATIVE:
                self._findings.append(OutcomeFinding(
                    kind=FindingKind.CONTROL_NEGATIVE,
                    subject_id=cid,
                    detail=(
                        f"control {cid} reduced security "
                        f"(effectiveness {r.mean_effectiveness:.2f})"
                    ),
                    severity=5, at=at,
                ))
            elif r.tier is ControlEffectivenessTier.INEFFECTIVE:
                self._findings.append(OutcomeFinding(
                    kind=FindingKind.CONTROL_INEFFECTIVE,
                    subject_id=cid,
                    detail=(
                        f"effectiveness {r.mean_effectiveness:.2f} "
                        f"below marginal"
                    ),
                    severity=3, at=at,
                ))
            elif r.tier in (
                ControlEffectivenessTier.EFFECTIVE,
                ControlEffectivenessTier.HIGHLY_EFFECTIVE,
            ):
                self._findings.append(OutcomeFinding(
                    kind=FindingKind.CONTROL_EFFECTIVE,
                    subject_id=cid,
                    detail=(
                        f"effectiveness {r.mean_effectiveness:.2f} "
                        f"({r.tier.value})"
                    ),
                    severity=2, at=at,
                ))
        self._controls = controls

        # Per-detector aggregates
        detectors: Dict[str, DetectionQualityReport] = {}
        detector_ids = sorted({
            o.detector_id for o in self._outcomes if o.detector_id
        })
        for did in detector_ids:
            r = aggregate_detector(did, self._outcomes)
            detectors[did] = r
            if r.tier is DetectionQualityTier.POOR:
                self._findings.append(OutcomeFinding(
                    kind=FindingKind.DETECTION_DEGRADED,
                    subject_id=did,
                    detail=(
                        f"F1 {r.f1:.2f} — poor (TP={r.tp} FP={r.fp} "
                        f"FN={r.fn})"
                    ),
                    severity=4, at=at,
                ))
            elif r.tier is DetectionQualityTier.EXCELLENT:
                self._findings.append(OutcomeFinding(
                    kind=FindingKind.DETECTION_EXCELLENT,
                    subject_id=did,
                    detail=f"F1 {r.f1:.2f}",
                    severity=1, at=at,
                ))
        self._detectors = detectors

        # Per-intervention aggregates
        decisions: Dict[str, DecisionQualityReport] = {}
        decision_ids = sorted({
            o.intervention_id for o in self._outcomes
            if o.intervention_id
        })
        for iid in decision_ids:
            r = aggregate_decision(iid, self._outcomes)
            decisions[iid] = r
            if r.tier is DecisionQualityTier.HARMFUL:
                self._findings.append(OutcomeFinding(
                    kind=FindingKind.DECISION_HARMFUL,
                    subject_id=iid,
                    detail=(
                        f"decision {iid} degraded state "
                        f"(improvement {r.mean_state_improvement:.2f})"
                    ),
                    severity=5, at=at,
                ))
            elif r.tier is DecisionQualityTier.OPTIMAL:
                self._findings.append(OutcomeFinding(
                    kind=FindingKind.DECISION_OPTIMAL,
                    subject_id=iid,
                    detail=(
                        f"improvement "
                        f"{r.mean_state_improvement:.2f}"
                    ),
                    severity=2, at=at,
                ))
        self._decisions = decisions

        # Per-recovery aggregates (by tag contexts)
        recovery_contexts = sorted({
            tag for o in self._outcomes for tag in o.tags
        } | {"*"})
        recoveries: Dict[str, RecoveryQualityReport] = {}
        for ctx in recovery_contexts:
            r = aggregate_recovery(ctx, self._outcomes)
            if r.samples == 0:
                continue
            recoveries[ctx] = r
            failed = r.tier_counts.get(RecoveryQualityTier.FAILED, 0)
            if failed > 0 and failed == r.samples:
                self._findings.append(OutcomeFinding(
                    kind=FindingKind.RECOVERY_FAILED,
                    subject_id=ctx,
                    detail=(
                        f"all {r.samples} recovery attempt(s) failed"
                    ),
                    severity=5, at=at,
                ))
        self._recoveries = recoveries

        # Per-outcome findings
        for o in self._outcomes:
            if o.residual_risk >= cfg.high_residual_risk:
                self._findings.append(OutcomeFinding(
                    kind=FindingKind.RESIDUAL_RISK_HIGH,
                    subject_id=o.outcome_id,
                    detail=(
                        f"residual risk {o.residual_risk:.2f} >= "
                        f"{cfg.high_residual_risk:.2f}"
                    ),
                    severity=4, at=at,
                ))
            if o.blast_radius_reduction < 0:
                self._findings.append(OutcomeFinding(
                    kind=FindingKind.BLAST_RADIUS_INCREASED,
                    subject_id=o.outcome_id,
                    detail=(
                        f"blast radius increased by "
                        f"{abs(o.blast_radius_reduction)}"
                    ),
                    severity=4, at=at,
                ))
            if o.state_improvement >= cfg.positive_state_improvement:
                self._findings.append(OutcomeFinding(
                    kind=FindingKind.STATE_IMPROVED,
                    subject_id=o.outcome_id,
                    detail=(
                        f"state improved by "
                        f"{o.state_improvement:+.2f}"
                    ),
                    severity=1, at=at,
                ))
            elif o.state_improvement <= cfg.negative_state_improvement:
                self._findings.append(OutcomeFinding(
                    kind=FindingKind.STATE_WORSENED,
                    subject_id=o.outcome_id,
                    detail=(
                        f"state worsened by "
                        f"{abs(o.state_improvement):.2f}"
                    ),
                    severity=4, at=at,
                ))

        if len(self._findings) > cfg.max_findings:
            self._findings = self._findings[: cfg.max_findings]

        # Scorecard
        self._scorecard = self._build_scorecard(at=at)

        # Persist
        records: List[OutcomeStateRecord] = []
        for o in self._outcomes:
            rec = OutcomeStateRecord(
                outcome_id=o.outcome_id, entity_id=o.entity_id,
                kind=o.kind, threat_reduction=o.threat_reduction,
                residual_risk=o.residual_risk,
                state_improvement=o.state_improvement,
                updated_at=at,
            )
            self._store.put(rec)
            records.append(rec)

        if isinstance(self._store, SqliteOutcomeStore):
            for i, f in enumerate(self._findings):
                self._store.put_finding(
                    f"f-{i:08d}-{f.kind.value}", f,
                )

        self._violations = check_invariants(self.snapshot())
        return tuple(records)

    # ---- scorecard -------------------------------------------------------

    def _build_scorecard(self, *, at: datetime) -> GlobalScorecard:
        total = len(self._outcomes)
        if total == 0:
            return GlobalScorecard(
                total_outcomes=0,
                mean_threat_reduction=0.0,
                mean_residual_risk=0.0,
                mean_state_improvement=0.0,
                mean_blast_radius_reduction=0.0,
                mean_time_to_control_seconds=None,
                mean_time_to_recovery_seconds=None,
                detection_quality=0.0,
                decision_quality=0.0,
                recovery_quality=0.0,
                total_false_positive_cost=0.0,
                total_false_negative_cost=0.0,
                total_intervention_cost=0.0,
                total_recovery_cost=0.0,
            )
        mean_tr = _mean_or_zero(o.threat_reduction for o in self._outcomes)
        mean_rr = _mean_or_zero(o.residual_risk for o in self._outcomes)
        mean_si = _mean_or_zero(o.state_improvement for o in self._outcomes)
        mean_br = _mean_or_zero(
            o.blast_radius_reduction for o in self._outcomes
        )
        ttc = _mean(
            o.time_to_control_seconds for o in self._outcomes
            if o.time_to_control_seconds is not None
        )
        ttr = _mean(
            o.time_to_recovery_seconds for o in self._outcomes
            if o.time_to_recovery_seconds is not None
        )
        dq = _mean_or_zero(
            _tier_score(r.tier) for r in self._detectors.values()
        )
        decq = _mean_or_zero(
            _tier_score(r.tier) for r in self._decisions.values()
        )
        # Recovery quality mean across all recovery outcomes
        rec_scores = [
            _tier_score(_recovery_quality_tier(
                o.action_verified, o.objective_achieved,
                o.state_improvement,
            ))
            for o in self._outcomes
            if o.kind is OutcomeKind.RECOVERY or o.recovered_at is not None
        ]
        recq = _mean_or_zero(rec_scores)

        fp_cost = sum(
            o.false_positive_count * self._budget.false_positive_unit
            for o in self._outcomes
        )
        fn_cost = sum(
            o.false_negative_count * self._budget.false_negative_unit
            for o in self._outcomes
        )
        int_cost = sum(
            o.intervention_cost_units for o in self._outcomes
        )
        rec_cost = sum(
            o.recovery_cost_units for o in self._outcomes
        )
        return GlobalScorecard(
            total_outcomes=total,
            mean_threat_reduction=mean_tr,
            mean_residual_risk=mean_rr,
            mean_state_improvement=mean_si,
            mean_blast_radius_reduction=mean_br,
            mean_time_to_control_seconds=ttc,
            mean_time_to_recovery_seconds=ttr,
            detection_quality=dq,
            decision_quality=decq,
            recovery_quality=recq,
            total_false_positive_cost=fp_cost,
            total_false_negative_cost=fn_cost,
            total_intervention_cost=int_cost,
            total_recovery_cost=rec_cost,
        )

    # ---- queries ---------------------------------------------------------

    def control_report(
        self, control_id: str,
    ) -> Optional[ControlEffectivenessReport]:
        return self._controls.get(control_id)

    def detector_report(
        self, detector_id: str,
    ) -> Optional[DetectionQualityReport]:
        return self._detectors.get(detector_id)

    def decision_report(
        self, intervention_id: str,
    ) -> Optional[DecisionQualityReport]:
        return self._decisions.get(intervention_id)

    def recovery_report(
        self, context: str,
    ) -> Optional[RecoveryQualityReport]:
        return self._recoveries.get(context)

    def scorecard(self) -> Optional[GlobalScorecard]:
        return self._scorecard

    def findings(self) -> Tuple[OutcomeFinding, ...]:
        return tuple(self._findings)

    def findings_by_kind(self) -> Mapping[FindingKind, int]:
        out: Dict[FindingKind, int] = {k: 0 for k in FindingKind}
        for f in self._findings:
            out[f.kind] += 1
        return out

    def top_findings(
        self, *, k: int = 10,
    ) -> Tuple[OutcomeFinding, ...]:
        if k <= 0:
            raise ValueError("k must be > 0")
        ordered = sorted(
            self._findings,
            key=lambda f: (-f.severity, f.kind.value, f.subject_id),
        )
        return tuple(ordered[:k])

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return self._violations

    def record(self, outcome_id: str) -> Optional[OutcomeStateRecord]:
        return self._store.get(outcome_id)

    def snapshot(self) -> OutcomeSnapshot:
        sc = self._scorecard or GlobalScorecard(
            total_outcomes=0, mean_threat_reduction=0.0,
            mean_residual_risk=0.0, mean_state_improvement=0.0,
            mean_blast_radius_reduction=0.0,
            mean_time_to_control_seconds=None,
            mean_time_to_recovery_seconds=None,
            detection_quality=0.0, decision_quality=0.0,
            recovery_quality=0.0,
            total_false_positive_cost=0.0,
            total_false_negative_cost=0.0,
            total_intervention_cost=0.0,
            total_recovery_cost=0.0,
        )
        return OutcomeSnapshot(
            outcomes=tuple(self._outcomes),
            controls=dict(self._controls),
            detectors=dict(self._detectors),
            decisions=dict(self._decisions),
            recoveries=dict(self._recoveries),
            scorecard=sc,
            findings=tuple(self._findings),
        )


# =============================================================================
# SECTION 12 — TESTS
# =============================================================================


def _t0() -> datetime:
    from datetime import timezone
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _t(seconds: int) -> datetime:
    return _t0() + timedelta(seconds=seconds)


from datetime import timedelta  # noqa: E402


def _state(
    *, trust: float = 0.8, integrity: float = 0.9,
    availability: float = 0.95, confidentiality: float = 0.9,
    risk: float = 0.4, exposure: float = 0.3,
    blast: int = 2,
) -> StateVector:
    return StateVector(
        trust=trust, integrity=integrity,
        availability=availability, confidentiality=confidentiality,
        risk=risk, exposure=exposure, blast_radius=blast,
    )


def _outcome(
    oid: str = "o1", *,
    entity: str = "e1",
    kind: OutcomeKind = OutcomeKind.INTERVENTION,
    detector_id: Optional[str] = "det-1",
    control_id: Optional[str] = "ctl-1",
    intervention_id: Optional[str] = "int-1",
    pre: Optional[StateVector] = None,
    post: Optional[StateVector] = None,
    gt_positive: bool = True,
    alert: bool = True,
    decision_at: Optional[datetime] = None,
    controlled_at: Optional[datetime] = None,
    recovered_at: Optional[datetime] = None,
    fp_count: int = 0, fn_count: int = 0,
    intervention_cost: float = 0.0,
    recovery_cost: float = 0.0,
    action_verified: bool = True,
    objective_achieved: bool = True,
    tags: Iterable[str] = (),
) -> OutcomeRecord:
    return OutcomeRecord(
        outcome_id=oid, entity_id=entity, kind=kind,
        detector_id=detector_id, control_id=control_id,
        intervention_id=intervention_id,
        pre_state=pre or _state(risk=0.8, exposure=0.6, blast=5),
        post_state=post or _state(risk=0.2, exposure=0.2, blast=1),
        ground_truth_positive=gt_positive, alert_fired=alert,
        decision_at=decision_at or _t0(),
        controlled_at=controlled_at,
        recovered_at=recovered_at,
        false_positive_count=fp_count,
        false_negative_count=fn_count,
        intervention_cost_units=intervention_cost,
        recovery_cost_units=recovery_cost,
        action_verified=action_verified,
        objective_achieved=objective_achieved,
        tags=frozenset(tags),
    )


# ---- domain ----

def test_state_vector_bounds() -> None:
    try:
        _state(trust=1.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_state_vector_blast_nonneg() -> None:
    try:
        _state(blast=-1)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_state_vector_composite_bounded() -> None:
    s = _state()
    assert 0.0 <= s.composite_goodness() <= 1.0


def test_outcome_requires_id() -> None:
    try:
        OutcomeRecord(
            outcome_id="", entity_id="e",
            kind=OutcomeKind.INTERVENTION,
            detector_id=None, control_id=None, intervention_id=None,
            pre_state=_state(), post_state=_state(),
            ground_truth_positive=True, alert_fired=True,
            decision_at=_t0(), controlled_at=None, recovered_at=None,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_outcome_requires_aware_time() -> None:
    from datetime import datetime as dt
    try:
        OutcomeRecord(
            outcome_id="o", entity_id="e",
            kind=OutcomeKind.INTERVENTION,
            detector_id=None, control_id=None, intervention_id=None,
            pre_state=_state(), post_state=_state(),
            ground_truth_positive=True, alert_fired=True,
            decision_at=dt(2026, 1, 1),
            controlled_at=None, recovered_at=None,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_outcome_threat_reduction() -> None:
    o = _outcome(
        pre=_state(risk=0.8),
        post=_state(risk=0.2),
    )
    assert abs(o.threat_reduction - 0.75) < 1e-9


def test_outcome_threat_reduction_zero_pre() -> None:
    o = _outcome(pre=_state(risk=0.0), post=_state(risk=0.0))
    assert o.threat_reduction == 0.0


def test_outcome_detection_outcome_tp() -> None:
    o = _outcome(gt_positive=True, alert=True)
    assert o.detection_outcome() == "TP"


def test_outcome_detection_outcome_fp() -> None:
    o = _outcome(gt_positive=False, alert=True)
    assert o.detection_outcome() == "FP"


def test_outcome_detection_outcome_tn() -> None:
    o = _outcome(gt_positive=False, alert=False)
    assert o.detection_outcome() == "TN"


def test_outcome_detection_outcome_fn() -> None:
    o = _outcome(gt_positive=True, alert=False)
    assert o.detection_outcome() == "FN"


def test_outcome_time_to_control() -> None:
    o = _outcome(decision_at=_t(0), controlled_at=_t(30))
    assert o.time_to_control_seconds == 30.0


def test_outcome_time_to_control_none() -> None:
    o = _outcome(decision_at=_t(0), controlled_at=None)
    assert o.time_to_control_seconds is None


def test_outcome_blast_radius_reduction() -> None:
    o = _outcome(
        pre=_state(blast=5), post=_state(blast=1),
    )
    assert o.blast_radius_reduction == 4


def test_outcome_blast_radius_increase_negative() -> None:
    o = _outcome(
        pre=_state(blast=1), post=_state(blast=5),
    )
    assert o.blast_radius_reduction == -4


def test_outcome_state_improvement_positive() -> None:
    o = _outcome(
        pre=_state(risk=0.8, exposure=0.6, blast=5),
        post=_state(risk=0.2, exposure=0.2, blast=1),
    )
    assert o.state_improvement > 0


# ---- quality tiers ----

def test_control_effectiveness_tier_ordering() -> None:
    assert _control_effectiveness_tier(-0.1) is \
        ControlEffectivenessTier.NEGATIVE
    assert _control_effectiveness_tier(0.1) is \
        ControlEffectivenessTier.INEFFECTIVE
    assert _control_effectiveness_tier(0.4) is \
        ControlEffectivenessTier.MARGINAL
    assert _control_effectiveness_tier(0.6) is \
        ControlEffectivenessTier.EFFECTIVE
    assert _control_effectiveness_tier(0.9) is \
        ControlEffectivenessTier.HIGHLY_EFFECTIVE


def test_detection_quality_tier_ordering() -> None:
    assert _detection_quality_tier(0.1) is DetectionQualityTier.POOR
    assert _detection_quality_tier(0.4) is DetectionQualityTier.LIMITED
    assert _detection_quality_tier(0.6) is DetectionQualityTier.ACCEPTABLE
    assert _detection_quality_tier(0.8) is DetectionQualityTier.GOOD
    assert _detection_quality_tier(0.95) is DetectionQualityTier.EXCELLENT


def test_decision_quality_tier_ordering() -> None:
    assert _decision_quality_tier(-0.1) is DecisionQualityTier.HARMFUL
    assert _decision_quality_tier(0.1) is DecisionQualityTier.SUBOPTIMAL
    assert _decision_quality_tier(0.4) is DecisionQualityTier.ACCEPTABLE
    assert _decision_quality_tier(0.6) is DecisionQualityTier.GOOD
    assert _decision_quality_tier(0.9) is DecisionQualityTier.OPTIMAL


def test_recovery_quality_tier_failed() -> None:
    assert _recovery_quality_tier(False, True, 0.5) is \
        RecoveryQualityTier.FAILED


def test_recovery_quality_tier_partial() -> None:
    assert _recovery_quality_tier(True, False, 0.5) is \
        RecoveryQualityTier.PARTIAL


def test_recovery_quality_tier_complete() -> None:
    assert _recovery_quality_tier(True, True, 0.7) is \
        RecoveryQualityTier.COMPLETE


# ---- aggregation ----

def test_aggregate_control_effective() -> None:
    outs = [
        _outcome(f"o{i}", control_id="c1",
                 pre=_state(risk=0.8), post=_state(risk=0.2))
        for i in range(3)
    ]
    r = aggregate_control("c1", outs, budget=CostBudget())
    assert r.samples == 3
    assert r.tier in (
        ControlEffectivenessTier.EFFECTIVE,
        ControlEffectivenessTier.HIGHLY_EFFECTIVE,
    )


def test_aggregate_control_ineffective() -> None:
    outs = [
        _outcome(f"o{i}", control_id="c1",
                 pre=_state(risk=0.8), post=_state(risk=0.78))
        for i in range(3)
    ]
    r = aggregate_control("c1", outs, budget=CostBudget())
    assert r.tier in (
        ControlEffectivenessTier.INEFFECTIVE,
        ControlEffectivenessTier.MARGINAL,
    )


def test_aggregate_control_negative_when_state_worsens() -> None:
    outs = [
        _outcome(
            f"o{i}", control_id="c1",
            pre=_state(risk=0.5, exposure=0.3, blast=2),
            post=_state(risk=0.9, exposure=0.9, blast=8),
        )
        for i in range(3)
    ]
    r = aggregate_control("c1", outs, budget=CostBudget())
    assert r.tier is ControlEffectivenessTier.NEGATIVE


def test_aggregate_control_empty() -> None:
    r = aggregate_control("c1", [], budget=CostBudget())
    assert r.samples == 0


def test_aggregate_detector_perfect() -> None:
    outs = [
        _outcome(f"tp{i}", detector_id="d", gt_positive=True, alert=True)
        for i in range(3)
    ] + [
        _outcome(f"tn{i}", detector_id="d",
                 gt_positive=False, alert=False)
        for i in range(3)
    ]
    r = aggregate_detector("d", outs)
    assert r.precision == 1.0
    assert r.recall == 1.0
    assert r.f1 == 1.0
    assert r.tier is DetectionQualityTier.EXCELLENT


def test_aggregate_detector_mixed() -> None:
    outs = [
        _outcome("a", detector_id="d", gt_positive=True, alert=True),
        _outcome("b", detector_id="d", gt_positive=False, alert=True),
        _outcome("c", detector_id="d", gt_positive=True, alert=False),
    ]
    r = aggregate_detector("d", outs)
    assert r.tp == 1 and r.fp == 1 and r.fn == 1


def test_aggregate_detector_empty() -> None:
    r = aggregate_detector("d", [])
    assert r.total == 0


def test_aggregate_decision_optimal() -> None:
    outs = [
        _outcome(f"o{i}", intervention_id="i1",
                 pre=_state(trust=0.1, integrity=0.2, availability=0.4,
                            confidentiality=0.2, risk=0.8, exposure=0.6,
                            blast=8),
                 post=_state(trust=0.95, integrity=0.95,
                             availability=0.95, confidentiality=0.95,
                             risk=0.1, exposure=0.1, blast=0))
        for i in range(3)
    ]
    r = aggregate_decision("i1", outs)
    assert r.tier in (
        DecisionQualityTier.GOOD, DecisionQualityTier.OPTIMAL,
    )


def test_aggregate_decision_harmful() -> None:
    outs = [
        _outcome(f"o{i}", intervention_id="i1",
                 pre=_state(risk=0.2),
                 post=_state(risk=0.9))
        for i in range(3)
    ]
    r = aggregate_decision("i1", outs)
    assert r.tier is DecisionQualityTier.HARMFUL


def test_aggregate_recovery_complete() -> None:
    outs = [
        _outcome(
            f"r{i}", kind=OutcomeKind.RECOVERY,
            pre=_state(trust=0.1, integrity=0.2, availability=0.4,
                       confidentiality=0.2, risk=0.9, exposure=0.7,
                       blast=8),
            post=_state(trust=0.95, integrity=0.95, availability=0.95,
                        confidentiality=0.95, risk=0.1, exposure=0.1,
                        blast=0),
            recovered_at=_t(60),
            tags=("ctx-1",),
        )
        for i in range(2)
    ]
    r = aggregate_recovery("ctx-1", outs)
    assert r.samples == 2
    assert r.tier_counts.get(RecoveryQualityTier.COMPLETE, 0) == 2


def test_aggregate_recovery_failed() -> None:
    outs = [
        _outcome(
            f"r{i}", kind=OutcomeKind.RECOVERY,
            action_verified=False,
            recovered_at=_t(60),
            tags=("ctx-1",),
        )
        for i in range(2)
    ]
    r = aggregate_recovery("ctx-1", outs)
    assert r.tier_counts.get(RecoveryQualityTier.FAILED, 0) == 2


def test_aggregate_recovery_empty() -> None:
    r = aggregate_recovery("ctx-1", [])
    assert r.samples == 0


# ---- engine ----

def test_engine_record_outcome() -> None:
    eng = SecurityOutcomeScienceEngine()
    eng.record_outcome(_outcome("o1"))
    assert eng.outcome("o1") is not None


def test_engine_recompute_requires_aware_time() -> None:
    from datetime import datetime as dt
    eng = SecurityOutcomeScienceEngine()
    try:
        eng.recompute(at=dt(2026, 1, 1))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_recompute_returns_records() -> None:
    eng = SecurityOutcomeScienceEngine()
    eng.record_outcome(_outcome("o1"))
    records = eng.recompute(at=_t0())
    assert len(records) == 1
    assert records[0].outcome_id == "o1"


def test_engine_scorecard_empty() -> None:
    eng = SecurityOutcomeScienceEngine()
    eng.recompute(at=_t0())
    sc = eng.scorecard()
    assert sc is not None
    assert sc.total_outcomes == 0


def test_engine_scorecard_basic() -> None:
    eng = SecurityOutcomeScienceEngine()
    for i in range(3):
        eng.record_outcome(_outcome(
            f"o{i}",
            pre=_state(risk=0.8, exposure=0.6, blast=5),
            post=_state(risk=0.1, exposure=0.1, blast=1),
        ))
    eng.recompute(at=_t0())
    sc = eng.scorecard()
    assert sc.total_outcomes == 3
    assert sc.mean_threat_reduction > 0.5


def test_engine_control_effective_finding() -> None:
    eng = SecurityOutcomeScienceEngine()
    for i in range(3):
        eng.record_outcome(_outcome(
            f"o{i}", control_id="c1",
            pre=_state(risk=0.8), post=_state(risk=0.05),
        ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.CONTROL_EFFECTIVE in kinds


def test_engine_control_ineffective_finding() -> None:
    eng = SecurityOutcomeScienceEngine()
    for i in range(3):
        eng.record_outcome(_outcome(
            f"o{i}", control_id="c1",
            pre=_state(risk=0.8), post=_state(risk=0.79),
        ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.CONTROL_INEFFECTIVE in kinds


def test_engine_control_negative_finding() -> None:
    eng = SecurityOutcomeScienceEngine()
    for i in range(3):
        eng.record_outcome(_outcome(
            f"o{i}", control_id="c1",
            pre=_state(risk=0.2, exposure=0.2, blast=1),
            post=_state(risk=0.9, exposure=0.9, blast=8),
        ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.CONTROL_NEGATIVE in kinds


def test_engine_detection_degraded_finding() -> None:
    eng = SecurityOutcomeScienceEngine()
    for i in range(5):
        eng.record_outcome(_outcome(
            f"o{i}", detector_id="d",
            gt_positive=False, alert=True,
        ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.DETECTION_DEGRADED in kinds


def test_engine_detection_excellent_finding() -> None:
    eng = SecurityOutcomeScienceEngine()
    for i in range(3):
        eng.record_outcome(_outcome(
            f"tp{i}", detector_id="d",
            gt_positive=True, alert=True,
        ))
        eng.record_outcome(_outcome(
            f"tn{i}", detector_id="d",
            gt_positive=False, alert=False,
        ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.DETECTION_EXCELLENT in kinds


def test_engine_decision_harmful_finding() -> None:
    eng = SecurityOutcomeScienceEngine()
    for i in range(3):
        eng.record_outcome(_outcome(
            f"o{i}", intervention_id="i1",
            pre=_state(risk=0.2, exposure=0.2, blast=1),
            post=_state(risk=0.9, exposure=0.9, blast=8),
        ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.DECISION_HARMFUL in kinds


def test_engine_recovery_failed_finding() -> None:
    eng = SecurityOutcomeScienceEngine()
    for i in range(2):
        eng.record_outcome(_outcome(
            f"r{i}", kind=OutcomeKind.RECOVERY,
            action_verified=False,
            recovered_at=_t(60),
            tags=("ctx-1",),
        ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.RECOVERY_FAILED in kinds


def test_engine_residual_risk_high_finding() -> None:
    eng = SecurityOutcomeScienceEngine()
    eng.record_outcome(_outcome(
        "o1", pre=_state(risk=0.9), post=_state(risk=0.8),
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.RESIDUAL_RISK_HIGH in kinds


def test_engine_blast_radius_increased_finding() -> None:
    eng = SecurityOutcomeScienceEngine()
    eng.record_outcome(_outcome(
        "o1", pre=_state(blast=1), post=_state(blast=5),
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.BLAST_RADIUS_INCREASED in kinds


def test_engine_state_improved_finding() -> None:
    eng = SecurityOutcomeScienceEngine()
    eng.record_outcome(_outcome(
        "o1",
        pre=_state(risk=0.9, exposure=0.9, blast=5),
        post=_state(risk=0.05, exposure=0.05, blast=0),
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.STATE_IMPROVED in kinds


def test_engine_state_worsened_finding() -> None:
    eng = SecurityOutcomeScienceEngine()
    eng.record_outcome(_outcome(
        "o1",
        pre=_state(risk=0.1, exposure=0.1, blast=0),
        post=_state(risk=0.9, exposure=0.9, blast=8),
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.STATE_WORSENED in kinds


def test_engine_findings_by_kind() -> None:
    eng = SecurityOutcomeScienceEngine()
    eng.record_outcome(_outcome("o1", pre=_state(risk=0.9),
                                post=_state(risk=0.8)))
    eng.recompute(at=_t0())
    counts = eng.findings_by_kind()
    assert counts[FindingKind.RESIDUAL_RISK_HIGH] >= 1


def test_engine_top_findings_sorted() -> None:
    eng = SecurityOutcomeScienceEngine()
    for i in range(3):
        eng.record_outcome(_outcome(
            f"o{i}", control_id="c1",
            pre=_state(risk=0.2), post=_state(risk=0.9),
        ))
    eng.recompute(at=_t0())
    top = eng.top_findings(k=20)
    severities = [f.severity for f in top]
    assert severities == sorted(severities, reverse=True)


def test_engine_top_findings_invalid_k() -> None:
    eng = SecurityOutcomeScienceEngine()
    try:
        eng.top_findings(k=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_record_lookup() -> None:
    eng = SecurityOutcomeScienceEngine()
    eng.record_outcome(_outcome("o1"))
    eng.recompute(at=_t0())
    rec = eng.record("o1")
    assert rec is not None
    assert rec.kind is OutcomeKind.INTERVENTION


def test_engine_budget_scales_fp_cost() -> None:
    eng = SecurityOutcomeScienceEngine(
        budget=CostBudget(false_positive_unit=10.0),
    )
    eng.record_outcome(_outcome("o1", fp_count=2))
    eng.recompute(at=_t0())
    sc = eng.scorecard()
    assert sc.total_false_positive_cost == 20.0


def test_engine_budget_scales_fn_cost() -> None:
    eng = SecurityOutcomeScienceEngine(
        budget=CostBudget(false_negative_unit=100.0),
    )
    eng.record_outcome(_outcome("o1", fn_count=3))
    eng.recompute(at=_t0())
    sc = eng.scorecard()
    assert sc.total_false_negative_cost == 300.0


def test_engine_intervention_cost_summed() -> None:
    eng = SecurityOutcomeScienceEngine()
    eng.record_outcome(_outcome("o1", intervention_cost=1.5))
    eng.record_outcome(_outcome("o2", intervention_cost=2.5))
    eng.recompute(at=_t0())
    assert eng.scorecard().total_intervention_cost == 4.0


def test_engine_recovery_cost_summed() -> None:
    eng = SecurityOutcomeScienceEngine()
    eng.record_outcome(_outcome("o1", recovery_cost=3.0))
    eng.recompute(at=_t0())
    assert eng.scorecard().total_recovery_cost == 3.0


def test_engine_config_validation() -> None:
    try:
        OutcomeConfig(high_residual_risk=1.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_set_config() -> None:
    eng = SecurityOutcomeScienceEngine()
    c = OutcomeConfig(high_residual_risk=0.5)
    eng.set_config(c)
    assert eng.config() is c


def test_engine_set_budget() -> None:
    eng = SecurityOutcomeScienceEngine()
    b = CostBudget(false_positive_unit=5.0)
    eng.set_budget(b)
    assert eng.budget() is b


# ---- invariants ----

def test_invariant_clean_snapshot() -> None:
    eng = SecurityOutcomeScienceEngine()
    eng.record_outcome(_outcome("o1"))
    eng.recompute(at=_t0())
    assert eng.violations() == ()


def test_invariant_threat_reduction_bounded() -> None:
    o = _outcome("o1")
    bad = object.__new__(OutcomeRecord)
    for attr in (
        "outcome_id", "entity_id", "kind",
        "detector_id", "control_id", "intervention_id",
        "pre_state", "post_state",
        "ground_truth_positive", "alert_fired",
        "decision_at", "controlled_at", "recovered_at",
        "false_positive_count", "false_negative_count",
        "intervention_cost_units", "recovery_cost_units",
        "action_verified", "objective_achieved", "tags",
    ):
        object.__setattr__(bad, attr, getattr(o, attr))
    # monkey-patch threat_reduction via pre/post that would compute
    # out-of-bounds — impossible; use state improvement instead via a
    # crafted state with matching composites
    # Instead: check scorecard bound invariant with a fake
    snap = OutcomeSnapshot(
        outcomes=(o,),
        controls={}, detectors={}, decisions={}, recoveries={},
        scorecard=GlobalScorecard(
            total_outcomes=1,
            mean_threat_reduction=1.5,   # invalid
            mean_residual_risk=0.2,
            mean_state_improvement=0.1,
            mean_blast_radius_reduction=1.0,
            mean_time_to_control_seconds=None,
            mean_time_to_recovery_seconds=None,
            detection_quality=0.7,
            decision_quality=0.7,
            recovery_quality=0.7,
            total_false_positive_cost=0.0,
            total_false_negative_cost=0.0,
            total_intervention_cost=0.0,
            total_recovery_cost=0.0,
        ),
        findings=(),
    )
    v = check_invariants(snap)
    assert any(
        x.invariant_id == "out.scorecard_bounded" for x in v
    )


def test_invariant_time_ordering() -> None:
    from datetime import timedelta
    o = _outcome("o1", decision_at=_t(0))
    bad = object.__new__(OutcomeRecord)
    object.__setattr__(bad, "outcome_id", "bad")
    object.__setattr__(bad, "entity_id", "e")
    object.__setattr__(bad, "kind", OutcomeKind.INTERVENTION)
    object.__setattr__(bad, "detector_id", None)
    object.__setattr__(bad, "control_id", None)
    object.__setattr__(bad, "intervention_id", None)
    object.__setattr__(bad, "pre_state", o.pre_state)
    object.__setattr__(bad, "post_state", o.post_state)
    object.__setattr__(bad, "ground_truth_positive", True)
    object.__setattr__(bad, "alert_fired", True)
    object.__setattr__(bad, "decision_at", _t(60))
    object.__setattr__(bad, "controlled_at", _t(30))
    object.__setattr__(bad, "recovered_at", None)
    object.__setattr__(bad, "false_positive_count", 0)
    object.__setattr__(bad, "false_negative_count", 0)
    object.__setattr__(bad, "intervention_cost_units", 0.0)
    object.__setattr__(bad, "recovery_cost_units", 0.0)
    object.__setattr__(bad, "action_verified", True)
    object.__setattr__(bad, "objective_achieved", True)
    object.__setattr__(bad, "tags", frozenset())
    snap = OutcomeSnapshot(
        outcomes=(bad,),
        controls={}, detectors={}, decisions={}, recoveries={},
        scorecard=GlobalScorecard(
            total_outcomes=1,
            mean_threat_reduction=0.5, mean_residual_risk=0.5,
            mean_state_improvement=0.0,
            mean_blast_radius_reduction=0.0,
            mean_time_to_control_seconds=None,
            mean_time_to_recovery_seconds=None,
            detection_quality=0.5, decision_quality=0.5,
            recovery_quality=0.5,
            total_false_positive_cost=0.0,
            total_false_negative_cost=0.0,
            total_intervention_cost=0.0,
            total_recovery_cost=0.0,
        ),
        findings=(),
    )
    v = check_invariants(snap)
    assert any(x.invariant_id == "out.time_ordering" for x in v)


# ---- store ----

def test_in_memory_store_rejects_stale() -> None:
    s = InMemoryOutcomeStore()
    t = _t0()
    s.put(OutcomeStateRecord(
        "o1", "e", OutcomeKind.INTERVENTION,
        0.5, 0.3, 0.2, t,
    ))
    earlier = t.replace(year=t.year - 1)
    try:
        s.put(OutcomeStateRecord(
            "o1", "e", OutcomeKind.INTERVENTION,
            0.5, 0.3, 0.2, earlier,
        ))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "outcome.db")
    store = SqliteOutcomeStore(db)
    store.put(OutcomeStateRecord(
        "o1", "e1", OutcomeKind.INTERVENTION,
        0.75, 0.1, 0.4, _t0(),
    ))
    got = store.get("o1")
    assert got is not None
    assert got.entity_id == "e1"
    assert abs(got.threat_reduction - 0.75) < 1e-9


def test_sqlite_store_finding_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "outcome.db")
    store = SqliteOutcomeStore(db)
    f = OutcomeFinding(
        kind=FindingKind.CONTROL_EFFECTIVE,
        subject_id="c1", detail="x", severity=2, at=_t0(),
    )
    store.put_finding("fid-1", f)
    row = store._conn.execute(
        "SELECT payload_json FROM outcome_findings "
        "WHERE finding_id = 'fid-1'"
    ).fetchone()
    assert row is not None
    payload = json.loads(row[0])
    assert payload["kind"] == "control_effective"


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
