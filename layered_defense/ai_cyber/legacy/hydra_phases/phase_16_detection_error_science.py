"""
HYDRA POST-CORE — PHASE 16: DETECTION ERROR SCIENCE
======================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * Domain — detection outcomes, records, cost matrix, priors
  * Confusion matrix with derived metrics:
      - precision, recall, F1, MCC, FPR, FNR, specificity, accuracy
  * ROC curve construction + AUC (trapezoidal)
  * Cost-aware threshold optimizer
  * Expected-cost-per-event evaluation
  * Evidence quality scoring (composite of 5 attributes)
  * Detection confidence combining detector score, evidence quality,
    and sample maturity
  * Detection degradation detection (baseline vs recent window)
  * Failure condition predicates
  * Machine-checkable detection-error invariants
  * In-memory + SQLite stores
  * Phase-16 engine facade
  * Full test suite + manual runner

Purpose: optimize security decisions rather than maximize alerts.

This is NEW detection-error-science technology. It is not an alert
scorer, not a SIEM tuning tool — it is a formal cost/quality layer over
detection outputs.

No third-party dependencies.

Run tests:
    python hydra_phase16_detection_error_science.py
    pytest hydra_phase16_detection_error_science.py -q
"""
from __future__ import annotations

import json
import math
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import (
    ClassVar,
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
# SECTION 2 — DOMAIN
# =============================================================================


class DetectionOutcome(str, Enum):
    TP = "true_positive"
    FP = "false_positive"
    TN = "true_negative"
    FN = "false_negative"


class MetricKind(str, Enum):
    PRECISION = "precision"
    RECALL = "recall"
    F1 = "f1"
    FPR = "false_positive_rate"
    FNR = "false_negative_rate"
    SPECIFICITY = "specificity"
    ACCURACY = "accuracy"
    MCC = "matthews_correlation"


class DetectionFindingKind(str, Enum):
    HIGH_EXPECTED_COST = "high_expected_cost"
    DEGRADED_DETECTION = "degraded_detection"
    LOW_DETECTION_CONFIDENCE = "low_detection_confidence"
    LOW_EVIDENCE_QUALITY = "low_evidence_quality"
    FAILURE_CONDITION_MET = "failure_condition_met"
    THRESHOLD_MISALIGNED = "threshold_misaligned"


@dataclass(frozen=True)
class DetectionFinding:
    kind: DetectionFindingKind
    detector_id: str
    detail: str
    severity: int
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        if not 1 <= self.severity <= 5:
            raise ValueError("severity must be in [1,5]")


@dataclass(frozen=True)
class DetectionRecord:
    """A single detection decision with ground-truth resolution."""
    record_id: str
    detector_id: str
    entity_id: str
    score: float                # detector output in [0,1]
    threshold: float            # threshold at time of decision
    truth: bool                 # ground truth (True = real positive event)
    at: datetime

    def __post_init__(self) -> None:
        if not self.record_id:
            raise ValueError("record_id is required")
        if not self.detector_id:
            raise ValueError("detector_id is required")
        if not self.entity_id:
            raise ValueError("entity_id is required")
        if not 0.0 <= self.score <= 1.0:
            raise ValueError("score must be within [0,1]")
        if not 0.0 <= self.threshold <= 1.0:
            raise ValueError("threshold must be within [0,1]")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

    def outcome(self) -> DetectionOutcome:
        alerted = self.score >= self.threshold
        if self.truth and alerted:
            return DetectionOutcome.TP
        if not self.truth and alerted:
            return DetectionOutcome.FP
        if not self.truth and not alerted:
            return DetectionOutcome.TN
        return DetectionOutcome.FN


# =============================================================================
# SECTION 3 — COST MATRIX
# =============================================================================


@dataclass(frozen=True)
class CostMatrix:
    """Costs (in normalized units) for each outcome."""
    c_tp: float = 0.10     # cost of correctly acting
    c_fp: float = 0.30     # cost of acting on a false alarm
    c_tn: float = 0.00     # cost of correctly ignoring
    c_fn: float = 1.00     # cost of missing a real event

    def __post_init__(self) -> None:
        for n, v in (
            ("c_tp", self.c_tp), ("c_fp", self.c_fp),
            ("c_tn", self.c_tn), ("c_fn", self.c_fn),
        ):
            if not 0.0 <= v <= 1.0:
                raise ValueError(f"{n} must be within [0,1]")
        if self.c_fn <= self.c_fp:
            # A miss must be no cheaper than a false alarm — otherwise
            # the matrix is economically incoherent for security use.
            raise ValueError("c_fn must be > c_fp")

    def cost_of(self, outcome: DetectionOutcome) -> float:
        return {
            DetectionOutcome.TP: self.c_tp,
            DetectionOutcome.FP: self.c_fp,
            DetectionOutcome.TN: self.c_tn,
            DetectionOutcome.FN: self.c_fn,
        }[outcome]


@dataclass(frozen=True)
class PriorEstimate:
    """Base rate of positive events in the population."""
    positive_rate: float

    def __post_init__(self) -> None:
        if not 0.0 <= self.positive_rate <= 1.0:
            raise ValueError("positive_rate must be within [0,1]")

    @property
    def negative_rate(self) -> float:
        return 1.0 - self.positive_rate


def expected_cost_per_event(
    *,
    recall: float,
    fpr: float,
    cost: CostMatrix,
    prior: PriorEstimate,
) -> float:
    """E[cost] = P(pos)·(recall·C_TP + (1−recall)·C_FN)
              + P(neg)·(FPR·C_FP + (1−FPR)·C_TN)."""
    for n, v in (("recall", recall), ("fpr", fpr)):
        if not 0.0 <= v <= 1.0:
            raise ValueError(f"{n} must be within [0,1]")
    pos = prior.positive_rate
    neg = 1.0 - pos
    return (
        pos * (recall * cost.c_tp + (1.0 - recall) * cost.c_fn)
        + neg * (fpr * cost.c_fp + (1.0 - fpr) * cost.c_tn)
    )


# =============================================================================
# SECTION 4 — CONFUSION MATRIX + METRICS
# =============================================================================


@dataclass(frozen=True)
class ConfusionMatrix:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    def __post_init__(self) -> None:
        for n, v in (("tp", self.tp), ("fp", self.fp),
                     ("tn", self.tn), ("fn", self.fn)):
            if v < 0:
                raise ValueError(f"{n} must be >= 0")

    @classmethod
    def from_records(
        cls, records: Iterable[DetectionRecord],
    ) -> "ConfusionMatrix":
        tp = fp = tn = fn = 0
        for r in records:
            o = r.outcome()
            if o is DetectionOutcome.TP:
                tp += 1
            elif o is DetectionOutcome.FP:
                fp += 1
            elif o is DetectionOutcome.TN:
                tn += 1
            else:
                fn += 1
        return cls(tp=tp, fp=fp, tn=tn, fn=fn)

    @classmethod
    def from_outcomes(
        cls, outcomes: Iterable[DetectionOutcome],
    ) -> "ConfusionMatrix":
        tp = fp = tn = fn = 0
        for o in outcomes:
            if o is DetectionOutcome.TP:
                tp += 1
            elif o is DetectionOutcome.FP:
                fp += 1
            elif o is DetectionOutcome.TN:
                tn += 1
            else:
                fn += 1
        return cls(tp=tp, fp=fp, tn=tn, fn=fn)

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def positives(self) -> int:
        return self.tp + self.fn

    @property
    def negatives(self) -> int:
        return self.tn + self.fp

    @property
    def positives_predicted(self) -> int:
        return self.tp + self.fp

    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    def f1(self) -> float:
        p, r = self.precision(), self.recall()
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    def false_positive_rate(self) -> float:
        d = self.fp + self.tn
        return self.fp / d if d else 0.0

    def false_negative_rate(self) -> float:
        return 1.0 - self.recall()

    def specificity(self) -> float:
        return 1.0 - self.false_positive_rate()

    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.total if self.total else 0.0

    def mcc(self) -> float:
        num = (self.tp * self.tn) - (self.fp * self.fn)
        den = math.sqrt(
            (self.tp + self.fp)
            * (self.tp + self.fn)
            * (self.tn + self.fp)
            * (self.tn + self.fn)
        )
        return num / den if den > 0 else 0.0

    def metric(self, kind: MetricKind) -> float:
        return {
            MetricKind.PRECISION: self.precision,
            MetricKind.RECALL: self.recall,
            MetricKind.F1: self.f1,
            MetricKind.FPR: self.false_positive_rate,
            MetricKind.FNR: self.false_negative_rate,
            MetricKind.SPECIFICITY: self.specificity,
            MetricKind.ACCURACY: self.accuracy,
            MetricKind.MCC: self.mcc,
        }[kind]()

    def expected_cost(
        self,
        cost: CostMatrix,
        *,
        prior: Optional[PriorEstimate] = None,
    ) -> float:
        """Empirical expected cost. When `prior` is provided, use the
        analytical expectation with the sample's recall/FPR; otherwise
        compute the empirical average from counts."""
        if self.total == 0:
            return 0.0
        if prior is not None:
            return expected_cost_per_event(
                recall=self.recall(),
                fpr=self.false_positive_rate(),
                cost=cost, prior=prior,
            )
        total = 0.0
        total += self.tp * cost.c_tp
        total += self.fp * cost.c_fp
        total += self.tn * cost.c_tn
        total += self.fn * cost.c_fn
        return total / self.total


# =============================================================================
# SECTION 5 — ROC CURVE
# =============================================================================


@dataclass(frozen=True)
class ROCPoint:
    threshold: float
    recall: float
    fpr: float

    def __post_init__(self) -> None:
        if not 0.0 <= self.threshold <= 1.0:
            raise ValueError("threshold must be within [0,1]")
        if not 0.0 <= self.recall <= 1.0:
            raise ValueError("recall must be within [0,1]")
        if not 0.0 <= self.fpr <= 1.0:
            raise ValueError("fpr must be within [0,1]")


@dataclass(frozen=True)
class ROCCurve:
    detector_id: str
    points: Tuple[ROCPoint, ...]

    def __post_init__(self) -> None:
        if not self.detector_id:
            raise ValueError("detector_id is required")

    @classmethod
    def from_records(
        cls, detector_id: str, records: Sequence[DetectionRecord],
        *, thresholds: Optional[Sequence[float]] = None,
    ) -> "ROCCurve":
        """Build the ROC curve by sweeping thresholds over a sorted set
        of candidate cutoffs (score values + endpoints)."""
        if not records:
            return cls(detector_id=detector_id, points=())

        pos = sum(1 for r in records if r.truth)
        neg = len(records) - pos

        if thresholds is None:
            candidates = sorted(
                {0.0, 1.0}
                | {r.score for r in records}
                | {min(1.0, r.score + 1e-9) for r in records}
            )
        else:
            candidates = sorted(set(thresholds))
            if not candidates or candidates[0] > 0.0:
                candidates = [0.0] + list(candidates)
            if candidates[-1] < 1.0:
                candidates.append(1.0)

        points: List[ROCPoint] = []
        for t in candidates:
            tp = fp = 0
            for r in records:
                alerted = r.score >= t
                if r.truth and alerted:
                    tp += 1
                elif not r.truth and alerted:
                    fp += 1
            recall = tp / pos if pos else 0.0
            fpr = fp / neg if neg else 0.0
            points.append(ROCPoint(threshold=t, recall=recall, fpr=fpr))

        points.sort(key=lambda p: (p.fpr, p.recall, p.threshold))
        return cls(detector_id=detector_id, points=tuple(points))

    def auc(self) -> float:
        """Trapezoidal AUC over sorted (FPR, recall)."""
        if len(self.points) < 2:
            return 0.0
        pts = sorted(self.points, key=lambda p: p.fpr)
        auc = 0.0
        for i in range(1, len(pts)):
            x0, x1 = pts[i - 1].fpr, pts[i].fpr
            y0, y1 = pts[i - 1].recall, pts[i].recall
            auc += (x1 - x0) * (y0 + y1) * 0.5
        return max(0.0, min(1.0, auc))

    def point_at_threshold(self, threshold: float) -> Optional[ROCPoint]:
        for p in self.points:
            if abs(p.threshold - threshold) < 1e-12:
                return p
        return None


# =============================================================================
# SECTION 6 — THRESHOLD OPTIMIZATION
# =============================================================================


@dataclass(frozen=True)
class OptimalThreshold:
    detector_id: str
    threshold: float
    recall: float
    fpr: float
    expected_cost: float
    rationale: str


def optimize_threshold(
    curve: ROCCurve,
    cost: CostMatrix,
    prior: PriorEstimate,
) -> Optional[OptimalThreshold]:
    if not curve.points:
        return None
    best: Optional[OptimalThreshold] = None
    for p in curve.points:
        ec = expected_cost_per_event(
            recall=p.recall, fpr=p.fpr, cost=cost, prior=prior,
        )
        if best is None or ec < best.expected_cost - 1e-12:
            best = OptimalThreshold(
                detector_id=curve.detector_id,
                threshold=p.threshold,
                recall=p.recall,
                fpr=p.fpr,
                expected_cost=ec,
                rationale=(
                    f"min expected cost {ec:.4f} at threshold "
                    f"{p.threshold:.4f} (recall={p.recall:.3f}, "
                    f"fpr={p.fpr:.3f})"
                ),
            )
    return best


# =============================================================================
# SECTION 7 — EVIDENCE QUALITY
# =============================================================================


@dataclass(frozen=True)
class EvidenceQuality:
    source_reliability: float
    freshness: float
    specificity: float
    corroboration: float
    independence: float

    def __post_init__(self) -> None:
        for n, v in (
            ("source_reliability", self.source_reliability),
            ("freshness", self.freshness),
            ("specificity", self.specificity),
            ("corroboration", self.corroboration),
            ("independence", self.independence),
        ):
            if not 0.0 <= v <= 1.0:
                raise ValueError(f"{n} must be within [0,1]")

    # Weighted composite; the weights are the security-relevant
    # priorities: reliability > corroboration > specificity >
    # freshness > independence.
    _WEIGHTS: ClassVar[Mapping[str, float]] = {
        "source_reliability": 0.30,
        "freshness": 0.15,
        "specificity": 0.20,
        "corroboration": 0.20,
        "independence": 0.15,
    }

    def composite(self) -> float:
        w = self._WEIGHTS
        return max(0.0, min(1.0,
            self.source_reliability * w["source_reliability"]
            + self.freshness * w["freshness"]
            + self.specificity * w["specificity"]
            + self.corroboration * w["corroboration"]
            + self.independence * w["independence"]
        ))


# =============================================================================
# SECTION 8 — DETECTION CONFIDENCE
# =============================================================================


@dataclass(frozen=True)
class DetectionConfidence:
    detector_id: str
    record_id: str
    detector_score: float
    evidence_quality: float
    sample_count: int
    min_samples: int
    combined_confidence: float

    def __post_init__(self) -> None:
        if not self.detector_id:
            raise ValueError("detector_id is required")
        if not self.record_id:
            raise ValueError("record_id is required")
        for n, v in (
            ("detector_score", self.detector_score),
            ("evidence_quality", self.evidence_quality),
            ("combined_confidence", self.combined_confidence),
        ):
            if not 0.0 <= v <= 1.0:
                raise ValueError(f"{n} must be within [0,1]")
        if self.sample_count < 0:
            raise ValueError("sample_count must be >= 0")
        if self.min_samples < 1:
            raise ValueError("min_samples must be >= 1")


def compute_detection_confidence(
    *,
    detector_id: str,
    record_id: str,
    detector_score: float,
    evidence_quality: float,
    sample_count: int,
    min_samples: int,
) -> DetectionConfidence:
    """combined = score · (0.3 + 0.7·eq) · sample_factor
    where sample_factor = min(1, sqrt(sample_count / min_samples))."""
    if not 0.0 <= detector_score <= 1.0:
        raise ValueError("detector_score must be within [0,1]")
    if not 0.0 <= evidence_quality <= 1.0:
        raise ValueError("evidence_quality must be within [0,1]")
    if sample_count < 0:
        raise ValueError("sample_count must be >= 0")
    if min_samples < 1:
        raise ValueError("min_samples must be >= 1")

    eq_factor = 0.3 + 0.7 * evidence_quality
    sample_factor = min(1.0, math.sqrt(sample_count / min_samples)) \
        if min_samples else 1.0
    combined = max(0.0, min(1.0, detector_score * eq_factor * sample_factor))
    return DetectionConfidence(
        detector_id=detector_id, record_id=record_id,
        detector_score=detector_score,
        evidence_quality=evidence_quality,
        sample_count=sample_count, min_samples=min_samples,
        combined_confidence=combined,
    )


# =============================================================================
# SECTION 9 — DEGRADATION
# =============================================================================


@dataclass(frozen=True)
class DegradationReport:
    detector_id: str
    baseline: ConfusionMatrix
    recent: ConfusionMatrix
    delta_precision: float
    delta_recall: float
    delta_f1: float
    delta_fpr: float
    degraded: bool
    rationale: str
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


def detect_degradation(
    *,
    detector_id: str,
    baseline: ConfusionMatrix,
    recent: ConfusionMatrix,
    min_f1_drop: float = 0.10,
    min_recall_drop: float = 0.10,
    max_fpr_increase: float = 0.10,
    at: datetime,
) -> DegradationReport:
    if at.tzinfo is None:
        raise ValueError("at must be timezone-aware")
    for n, v in (
        ("min_f1_drop", min_f1_drop),
        ("min_recall_drop", min_recall_drop),
        ("max_fpr_increase", max_fpr_increase),
    ):
        if not 0.0 <= v <= 1.0:
            raise ValueError(f"{n} must be within [0,1]")

    d_prec = recent.precision() - baseline.precision()
    d_rec = recent.recall() - baseline.recall()
    d_f1 = recent.f1() - baseline.f1()
    d_fpr = recent.false_positive_rate() - baseline.false_positive_rate()

    reasons: List[str] = []
    if d_f1 <= -min_f1_drop:
        reasons.append(f"F1 dropped {abs(d_f1):.3f}")
    if d_rec <= -min_recall_drop:
        reasons.append(f"recall dropped {abs(d_rec):.3f}")
    if d_fpr >= max_fpr_increase:
        reasons.append(f"FPR rose {d_fpr:.3f}")

    degraded = bool(reasons)
    rationale = "; ".join(reasons) if reasons else "stable"

    return DegradationReport(
        detector_id=detector_id,
        baseline=baseline, recent=recent,
        delta_precision=d_prec, delta_recall=d_rec,
        delta_f1=d_f1, delta_fpr=d_fpr,
        degraded=degraded, rationale=rationale, at=at,
    )


# =============================================================================
# SECTION 10 — FAILURE CONDITIONS
# =============================================================================


@dataclass(frozen=True)
class FailureCondition:
    condition_id: str
    detector_id: str
    description: str
    predicate: Callable[[ConfusionMatrix, int], bool]

    def __post_init__(self) -> None:
        if not self.condition_id:
            raise ValueError("condition_id is required")
        if not self.detector_id:
            raise ValueError("detector_id is required")
        if not self.description:
            raise ValueError("description is required")


@dataclass(frozen=True)
class FailureConditionResult:
    condition_id: str
    detector_id: str
    met: bool
    detail: str


def evaluate_failure_conditions(
    conditions: Iterable[FailureCondition],
    matrix: ConfusionMatrix,
    *,
    sample_count: int,
) -> Tuple[FailureConditionResult, ...]:
    out: List[FailureConditionResult] = []
    for c in conditions:
        try:
            met = bool(c.predicate(matrix, sample_count))
            detail = f"met={met}"
        except Exception as exc:  # noqa: BLE001
            met = False
            detail = f"predicate raised: {type(exc).__name__}"
        out.append(FailureConditionResult(
            condition_id=c.condition_id, detector_id=c.detector_id,
            met=met, detail=detail,
        ))
    return tuple(out)


def make_min_samples_condition(
    detector_id: str, min_samples: int,
) -> FailureCondition:
    if min_samples < 1:
        raise ValueError("min_samples must be >= 1")
    return FailureCondition(
        condition_id=f"{detector_id}.min_samples",
        detector_id=detector_id,
        description=f"requires at least {min_samples} samples",
        predicate=lambda m, n: n < min_samples,
    )


def make_min_precision_condition(
    detector_id: str, min_precision: float,
) -> FailureCondition:
    if not 0.0 <= min_precision <= 1.0:
        raise ValueError("min_precision must be within [0,1]")
    return FailureCondition(
        condition_id=f"{detector_id}.min_precision",
        detector_id=detector_id,
        description=f"precision must be >= {min_precision:.2f}",
        predicate=lambda m, n: m.total > 0 and m.precision() < min_precision,
    )


def make_min_recall_condition(
    detector_id: str, min_recall: float,
) -> FailureCondition:
    if not 0.0 <= min_recall <= 1.0:
        raise ValueError("min_recall must be within [0,1]")
    return FailureCondition(
        condition_id=f"{detector_id}.min_recall",
        detector_id=detector_id,
        description=f"recall must be >= {min_recall:.2f}",
        predicate=lambda m, n: m.total > 0 and m.recall() < min_recall,
    )


# =============================================================================
# SECTION 11 — INVARIANTS
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
class DetectionSnapshot:
    matrices: Mapping[str, ConfusionMatrix]
    costs: Mapping[str, CostMatrix]
    priors: Mapping[str, PriorEstimate]
    optima: Mapping[str, OptimalThreshold]
    degradations: Mapping[str, DegradationReport]


@dataclass(frozen=True)
class DetectionInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[DetectionSnapshot],
                        Tuple[InvariantViolation, ...]]
    description: str


def _inv_counts_nonneg(snap: DetectionSnapshot) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for did, m in snap.matrices.items():
        for n, v in (("tp", m.tp), ("fp", m.fp), ("tn", m.tn), ("fn", m.fn)):
            if v < 0:
                out.append(InvariantViolation(
                    invariant_id="det.counts_nonneg",
                    severity=InvariantSeverity.CRITICAL,
                    subject_id=f"{did}:{n}",
                    detail=f"{n} = {v}",
                ))
    return tuple(out)


def _inv_metrics_in_unit(snap: DetectionSnapshot) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for did, m in snap.matrices.items():
        for kind in (MetricKind.PRECISION, MetricKind.RECALL,
                     MetricKind.F1, MetricKind.FPR, MetricKind.FNR,
                     MetricKind.SPECIFICITY, MetricKind.ACCURACY):
            v = m.metric(kind)
            if not -1e-9 <= v <= 1.0 + 1e-9:
                out.append(InvariantViolation(
                    invariant_id="det.metrics_in_unit",
                    severity=InvariantSeverity.HIGH,
                    subject_id=f"{did}:{kind.value}",
                    detail=f"{kind.value} = {v}",
                ))
    return tuple(out)


def _inv_mcc_in_range(snap: DetectionSnapshot) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for did, m in snap.matrices.items():
        v = m.mcc()
        if not -1.0 - 1e-9 <= v <= 1.0 + 1e-9:
            out.append(InvariantViolation(
                invariant_id="det.mcc_in_range",
                severity=InvariantSeverity.HIGH,
                subject_id=did,
                detail=f"MCC = {v}",
            ))
    return tuple(out)


def _inv_cost_matrix_coherent(
    snap: DetectionSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for did, c in snap.costs.items():
        if c.c_fn <= c.c_fp:
            out.append(InvariantViolation(
                invariant_id="det.cost_coherent",
                severity=InvariantSeverity.CRITICAL,
                subject_id=did,
                detail=f"c_fn {c.c_fn} <= c_fp {c.c_fp}",
            ))
    return tuple(out)


def _inv_optimal_threshold_in_unit(
    snap: DetectionSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for did, ot in snap.optima.items():
        if not 0.0 <= ot.threshold <= 1.0:
            out.append(InvariantViolation(
                invariant_id="det.optimal_threshold_in_unit",
                severity=InvariantSeverity.HIGH,
                subject_id=did,
                detail=f"threshold {ot.threshold}",
            ))
    return tuple(out)


def _inv_degradation_requires_lower_f1(
    snap: DetectionSnapshot,
) -> Tuple[InvariantViolation, ...]:
    """If a detector is marked degraded, at least one metric must have
    actually moved the wrong way."""
    out: List[InvariantViolation] = []
    for did, d in snap.degradations.items():
        if not d.degraded:
            continue
        if d.delta_f1 >= 0.0 and d.delta_fpr <= 0.0 \
           and d.delta_recall >= 0.0:
            out.append(InvariantViolation(
                invariant_id="det.degradation_consistent",
                severity=InvariantSeverity.HIGH,
                subject_id=did,
                detail=(
                    f"degraded=True but deltas are non-negative: "
                    f"df1={d.delta_f1}, drecall={d.delta_recall}, "
                    f"dfpr={d.delta_fpr}"
                ),
            ))
    return tuple(out)


DEFAULT_INVARIANTS: Tuple[DetectionInvariant, ...] = (
    DetectionInvariant(
        invariant_id="det.counts_nonneg",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_counts_nonneg,
        description="Confusion matrix counts must be non-negative.",
    ),
    DetectionInvariant(
        invariant_id="det.metrics_in_unit",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_metrics_in_unit,
        description="Detection metrics must lie within [0,1].",
    ),
    DetectionInvariant(
        invariant_id="det.mcc_in_range",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_mcc_in_range,
        description="MCC must lie within [-1,1].",
    ),
    DetectionInvariant(
        invariant_id="det.cost_coherent",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_cost_matrix_coherent,
        description="Cost matrix must be economically coherent (c_fn > c_fp).",
    ),
    DetectionInvariant(
        invariant_id="det.optimal_threshold_in_unit",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_optimal_threshold_in_unit,
        description="Optimal threshold must lie within [0,1].",
    ),
    DetectionInvariant(
        invariant_id="det.degradation_consistent",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_degradation_requires_lower_f1,
        description="Degradation must be backed by a wrong-direction metric.",
    ),
)


def check_invariants(
    snap: DetectionSnapshot,
    invariants: Iterable[DetectionInvariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 12 — STORE
# =============================================================================


@dataclass(frozen=True)
class DetectorRecord:
    detector_id: str
    precision: float
    recall: float
    f1: float
    fpr: float
    expected_cost: float
    optimal_threshold: float
    degraded: bool
    updated_at: datetime


class DetectionStore(Protocol):
    def get(self, detector_id: str) -> Optional[DetectorRecord]: ...
    def put(self, record: DetectorRecord) -> None: ...
    def all(self) -> Tuple[DetectorRecord, ...]: ...


class InMemoryDetectionStore:
    def __init__(self) -> None:
        self._data: Dict[str, DetectorRecord] = {}

    def get(self, detector_id: str) -> Optional[DetectorRecord]:
        return self._data.get(detector_id)

    def put(self, record: DetectorRecord) -> None:
        existing = self._data.get(record.detector_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._data[record.detector_id] = record

    def all(self) -> Tuple[DetectorRecord, ...]:
        return tuple(self._data.values())


class SqliteDetectionStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS det_state (
                detector_id TEXT PRIMARY KEY,
                precision REAL NOT NULL,
                recall REAL NOT NULL,
                f1 REAL NOT NULL,
                fpr REAL NOT NULL,
                expected_cost REAL NOT NULL,
                optimal_threshold REAL NOT NULL,
                degraded INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS det_records (
                record_id TEXT PRIMARY KEY,
                detector_id TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def get(self, detector_id: str) -> Optional[DetectorRecord]:
        row = self._conn.execute(
            "SELECT precision, recall, f1, fpr, expected_cost, "
            "optimal_threshold, degraded, updated_at FROM det_state "
            "WHERE detector_id = ?",
            (detector_id,),
        ).fetchone()
        if row is None:
            return None
        return DetectorRecord(
            detector_id=detector_id,
            precision=float(row[0]), recall=float(row[1]),
            f1=float(row[2]), fpr=float(row[3]),
            expected_cost=float(row[4]),
            optimal_threshold=float(row[5]),
            degraded=bool(row[6]),
            updated_at=datetime.fromisoformat(row[7]),
        )

    def put(self, record: DetectorRecord) -> None:
        existing = self.get(record.detector_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._conn.execute(
            """
            INSERT INTO det_state
              (detector_id, precision, recall, f1, fpr, expected_cost,
               optimal_threshold, degraded, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(detector_id) DO UPDATE SET
              precision=excluded.precision,
              recall=excluded.recall,
              f1=excluded.f1,
              fpr=excluded.fpr,
              expected_cost=excluded.expected_cost,
              optimal_threshold=excluded.optimal_threshold,
              degraded=excluded.degraded,
              updated_at=excluded.updated_at
            """,
            (
                record.detector_id, record.precision, record.recall,
                record.f1, record.fpr, record.expected_cost,
                record.optimal_threshold, int(record.degraded),
                record.updated_at.isoformat(),
            ),
        )
        self._conn.commit()

    def all(self) -> Tuple[DetectorRecord, ...]:
        rows = self._conn.execute(
            "SELECT detector_id FROM det_state"
        ).fetchall()
        return tuple(
            r for r in (self.get(x[0]) for x in rows) if r is not None
        )

    def put_record(self, rec: DetectionRecord) -> None:
        payload = {
            "record_id": rec.record_id,
            "detector_id": rec.detector_id,
            "entity_id": rec.entity_id,
            "score": rec.score,
            "threshold": rec.threshold,
            "truth": rec.truth,
            "at": rec.at.isoformat(),
        }
        self._conn.execute(
            "INSERT OR REPLACE INTO det_records "
            "(record_id, detector_id, payload_json) VALUES (?, ?, ?)",
            (rec.record_id, rec.detector_id,
             json.dumps(payload, sort_keys=True)),
        )
        self._conn.commit()


# =============================================================================
# SECTION 13 — ENGINE
# =============================================================================


@dataclass
class _DetectorState:
    detector_id: str
    records: List[DetectionRecord] = field(default_factory=list)
    cost: CostMatrix = field(default_factory=CostMatrix)
    prior: PriorEstimate = field(default_factory=lambda: PriorEstimate(0.05))
    min_samples: int = 20
    conditions: List[FailureCondition] = field(default_factory=list)


class DetectionErrorEngine:
    """Detection-error-science engine. Turns detector outputs into
    quality metrics, cost-aware thresholds, degradation findings, and
    evidence-aware confidence."""

    def __init__(
        self,
        *,
        store: Optional[DetectionStore] = None,
        high_expected_cost: float = 0.2,
        low_detection_confidence: float = 0.3,
        low_evidence_quality: float = 0.3,
        max_records_per_detector: int = 5000,
    ) -> None:
        for n, v in (
            ("high_expected_cost", high_expected_cost),
            ("low_detection_confidence", low_detection_confidence),
            ("low_evidence_quality", low_evidence_quality),
        ):
            if not 0.0 <= v <= 1.0:
                raise ValueError(f"{n} must be within [0,1]")
        if max_records_per_detector < 1:
            raise ValueError("max_records_per_detector must be >= 1")

        self._store: DetectionStore = store or InMemoryDetectionStore()
        self._detectors: Dict[str, _DetectorState] = {}
        self._matrices: Dict[str, ConfusionMatrix] = {}
        self._curves: Dict[str, ROCCurve] = {}
        self._optima: Dict[str, OptimalThreshold] = {}
        self._degradations: Dict[str, DegradationReport] = {}
        self._confidences: List[DetectionConfidence] = []
        self._failure_results: List[FailureConditionResult] = []
        self._findings: List[DetectionFinding] = []
        self._violations: Tuple[InvariantViolation, ...] = ()

        self._high_ec = high_expected_cost
        self._low_conf = low_detection_confidence
        self._low_eq = low_evidence_quality
        self._max_records = max_records_per_detector

    # ---- registration ----------------------------------------------------

    def register_detector(
        self,
        detector_id: str,
        *,
        cost: Optional[CostMatrix] = None,
        prior: Optional[PriorEstimate] = None,
        min_samples: int = 20,
    ) -> None:
        if not detector_id:
            raise ValueError("detector_id is required")
        if detector_id in self._detectors:
            raise ValueError(f"detector {detector_id} already registered")
        if min_samples < 1:
            raise ValueError("min_samples must be >= 1")
        self._detectors[detector_id] = _DetectorState(
            detector_id=detector_id,
            cost=cost or CostMatrix(),
            prior=prior or PriorEstimate(0.05),
            min_samples=min_samples,
        )

    def register_failure_condition(self, condition: FailureCondition) -> None:
        if condition.detector_id not in self._detectors:
            raise KeyError(f"unknown detector {condition.detector_id}")
        self._detectors[condition.detector_id].conditions.append(condition)

    def set_cost(self, detector_id: str, cost: CostMatrix) -> None:
        self._require(detector_id).cost = cost

    def set_prior(self, detector_id: str, prior: PriorEstimate) -> None:
        self._require(detector_id).prior = prior

    # ---- ingestion -------------------------------------------------------

    def report(self, record: DetectionRecord) -> None:
        st = self._detectors.get(record.detector_id)
        if st is None:
            raise KeyError(f"unknown detector {record.detector_id}")
        st.records.append(record)
        if len(st.records) > self._max_records:
            st.records = st.records[-self._max_records:]
        if isinstance(self._store, SqliteDetectionStore):
            self._store.put_record(record)

    # ---- evidence + confidence -------------------------------------------

    def register_detection_confidence(
        self, confidence: DetectionConfidence,
    ) -> None:
        if confidence.detector_id not in self._detectors:
            raise KeyError(f"unknown detector {confidence.detector_id}")
        self._confidences.append(confidence)

    # ---- recompute -------------------------------------------------------

    def recompute(self, *, at: datetime) -> Tuple[DetectorRecord, ...]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

        self._findings = []
        self._failure_results = []
        records: List[DetectorRecord] = []

        for did, st in self._detectors.items():
            matrix = ConfusionMatrix.from_records(st.records)
            self._matrices[did] = matrix

            curve = ROCCurve.from_records(did, st.records)
            self._curves[did] = curve

            optimum = optimize_threshold(curve, st.cost, st.prior)
            if optimum is not None:
                self._optima[did] = optimum
            expected_cost = matrix.expected_cost(st.cost, prior=st.prior)

            # Degradation vs a frozen baseline of the first half
            degradation = self._compute_degradation(
                st, matrix, at=at,
            )
            self._degradations[did] = degradation

            # Failure conditions
            results = evaluate_failure_conditions(
                st.conditions, matrix,
                sample_count=len(st.records),
            )
            for r in results:
                self._failure_results.append(r)
                if r.met:
                    self._findings.append(DetectionFinding(
                        kind=DetectionFindingKind.FAILURE_CONDITION_MET,
                        detector_id=did,
                        detail=f"{r.condition_id}: {r.detail}",
                        severity=3, at=at,
                    ))

            # Findings
            if expected_cost >= self._high_ec:
                self._findings.append(DetectionFinding(
                    kind=DetectionFindingKind.HIGH_EXPECTED_COST,
                    detector_id=did,
                    detail=(
                        f"expected cost {expected_cost:.3f} >= "
                        f"{self._high_ec:.2f}"
                    ),
                    severity=4, at=at,
                ))
            if degradation.degraded:
                self._findings.append(DetectionFinding(
                    kind=DetectionFindingKind.DEGRADED_DETECTION,
                    detector_id=did,
                    detail=degradation.rationale,
                    severity=4, at=at,
                ))

            rec = DetectorRecord(
                detector_id=did,
                precision=matrix.precision(),
                recall=matrix.recall(),
                f1=matrix.f1(),
                fpr=matrix.false_positive_rate(),
                expected_cost=expected_cost,
                optimal_threshold=(
                    optimum.threshold if optimum is not None else 0.5
                ),
                degraded=degradation.degraded,
                updated_at=at,
            )
            self._store.put(rec)
            records.append(rec)

        # Confidence findings
        for c in self._confidences:
            if c.combined_confidence < self._low_conf:
                self._findings.append(DetectionFinding(
                    kind=DetectionFindingKind.LOW_DETECTION_CONFIDENCE,
                    detector_id=c.detector_id,
                    detail=(
                        f"record {c.record_id} confidence "
                        f"{c.combined_confidence:.3f}"
                    ),
                    severity=3, at=at,
                ))
            if c.evidence_quality < self._low_eq:
                self._findings.append(DetectionFinding(
                    kind=DetectionFindingKind.LOW_EVIDENCE_QUALITY,
                    detector_id=c.detector_id,
                    detail=(
                        f"record {c.record_id} evidence quality "
                        f"{c.evidence_quality:.3f}"
                    ),
                    severity=3, at=at,
                ))

        self._violations = check_invariants(self.snapshot())
        return tuple(records)

    def _compute_degradation(
        self, st: _DetectorState, matrix: ConfusionMatrix, *, at: datetime,
    ) -> DegradationReport:
        records = st.records
        if len(records) < 4:
            # Not enough data → no degradation signal.
            return DegradationReport(
                detector_id=st.detector_id,
                baseline=matrix, recent=matrix,
                delta_precision=0.0, delta_recall=0.0, delta_f1=0.0,
                delta_fpr=0.0, degraded=False,
                rationale="insufficient data", at=at,
            )
        mid = len(records) // 2
        baseline = ConfusionMatrix.from_records(records[:mid])
        recent = ConfusionMatrix.from_records(records[mid:])
        return detect_degradation(
            detector_id=st.detector_id,
            baseline=baseline, recent=recent, at=at,
        )

    # ---- queries ---------------------------------------------------------

    def matrix(self, detector_id: str) -> Optional[ConfusionMatrix]:
        return self._matrices.get(detector_id)

    def curve(self, detector_id: str) -> Optional[ROCCurve]:
        return self._curves.get(detector_id)

    def optimum(self, detector_id: str) -> Optional[OptimalThreshold]:
        return self._optima.get(detector_id)

    def degradation(self, detector_id: str) -> Optional[DegradationReport]:
        return self._degradations.get(detector_id)

    def failure_results(self) -> Tuple[FailureConditionResult, ...]:
        return tuple(self._failure_results)

    def findings(self) -> Tuple[DetectionFinding, ...]:
        return tuple(self._findings)

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return self._violations

    def record(self, detector_id: str) -> Optional[DetectorRecord]:
        return self._store.get(detector_id)

    def snapshot(self) -> DetectionSnapshot:
        return DetectionSnapshot(
            matrices=dict(self._matrices),
            costs={did: st.cost for did, st in self._detectors.items()},
            priors={did: st.prior for did, st in self._detectors.items()},
            optima=dict(self._optima),
            degradations=dict(self._degradations),
        )

    # ---- internals -------------------------------------------------------

    def _require(self, detector_id: str) -> _DetectorState:
        st = self._detectors.get(detector_id)
        if st is None:
            raise KeyError(f"unknown detector {detector_id}")
        return st


# =============================================================================
# SECTION 14 — TESTS
# =============================================================================


def _t0() -> datetime:
    from datetime import timezone
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _t(seconds: int) -> datetime:
    from datetime import timedelta
    return _t0() + timedelta(seconds=seconds)


def _rec(
    rid: str, did: str = "d1", *,
    score: float = 0.9, threshold: float = 0.5,
    truth: bool = True, at: Optional[datetime] = None,
    eid: str = "e1",
) -> DetectionRecord:
    return DetectionRecord(
        record_id=rid, detector_id=did, entity_id=eid,
        score=score, threshold=threshold, truth=truth,
        at=at or _t0(),
    )


# ---- domain ----

def test_record_rejects_bad_score() -> None:
    try:
        _rec("r", score=1.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_record_rejects_bad_time() -> None:
    from datetime import datetime as dt
    try:
        DetectionRecord(
            record_id="r", detector_id="d", entity_id="e",
            score=0.5, threshold=0.5, truth=True, at=dt(2026, 1, 1),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_outcome_tp() -> None:
    assert _rec("r", score=0.9, threshold=0.5, truth=True).outcome() \
        is DetectionOutcome.TP


def test_outcome_fp() -> None:
    assert _rec("r", score=0.9, threshold=0.5, truth=False).outcome() \
        is DetectionOutcome.FP


def test_outcome_tn() -> None:
    assert _rec("r", score=0.1, threshold=0.5, truth=False).outcome() \
        is DetectionOutcome.TN


def test_outcome_fn() -> None:
    assert _rec("r", score=0.1, threshold=0.5, truth=True).outcome() \
        is DetectionOutcome.FN


# ---- cost matrix ----

def test_cost_matrix_rejects_incoherent() -> None:
    try:
        CostMatrix(c_fn=0.1, c_fp=0.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_cost_matrix_rejects_out_of_unit() -> None:
    try:
        CostMatrix(c_tp=1.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_cost_of_outcome() -> None:
    c = CostMatrix(c_tp=0.1, c_fp=0.3, c_tn=0.0, c_fn=1.0)
    assert c.cost_of(DetectionOutcome.FP) == 0.3
    assert c.cost_of(DetectionOutcome.FN) == 1.0


def test_prior_rate_bounds() -> None:
    try:
        PriorEstimate(positive_rate=1.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_prior_negative_rate() -> None:
    assert PriorEstimate(positive_rate=0.2).negative_rate == 0.8


def test_expected_cost_perfect_detector() -> None:
    ec = expected_cost_per_event(
        recall=1.0, fpr=0.0,
        cost=CostMatrix(c_tp=0.1, c_fp=0.3, c_tn=0.0, c_fn=1.0),
        prior=PriorEstimate(0.05),
    )
    assert abs(ec - 0.05 * 0.1) < 1e-9


def test_expected_cost_miss_everything() -> None:
    ec = expected_cost_per_event(
        recall=0.0, fpr=0.0,
        cost=CostMatrix(c_tp=0.1, c_fp=0.3, c_tn=0.0, c_fn=1.0),
        prior=PriorEstimate(0.05),
    )
    assert abs(ec - 0.05 * 1.0) < 1e-9


def test_expected_cost_alert_everything() -> None:
    ec = expected_cost_per_event(
        recall=1.0, fpr=1.0,
        cost=CostMatrix(c_tp=0.1, c_fp=0.3, c_tn=0.0, c_fn=1.0),
        prior=PriorEstimate(0.05),
    )
    assert abs(ec - (0.05 * 0.1 + 0.95 * 0.3)) < 1e-9


def test_expected_cost_rejects_bad_inputs() -> None:
    try:
        expected_cost_per_event(
            recall=1.5, fpr=0.0, cost=CostMatrix(),
            prior=PriorEstimate(0.05),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- confusion matrix ----

def test_confusion_matrix_precision() -> None:
    m = ConfusionMatrix(tp=8, fp=2, tn=90, fn=0)
    assert abs(m.precision() - 0.8) < 1e-9


def test_confusion_matrix_recall() -> None:
    m = ConfusionMatrix(tp=8, fp=2, tn=90, fn=2)
    assert abs(m.recall() - 0.8) < 1e-9


def test_confusion_matrix_f1() -> None:
    m = ConfusionMatrix(tp=8, fp=2, tn=90, fn=2)
    assert abs(m.f1() - 0.8) < 1e-9


def test_confusion_matrix_zero_division() -> None:
    m = ConfusionMatrix(tp=0, fp=0, tn=0, fn=0)
    assert m.precision() == 0.0
    assert m.recall() == 0.0
    assert m.f1() == 0.0


def test_confusion_matrix_fpr_specificity() -> None:
    m = ConfusionMatrix(tp=10, fp=5, tn=95, fn=0)
    assert abs(m.false_positive_rate() - 0.05) < 1e-9
    assert abs(m.specificity() - 0.95) < 1e-9


def test_confusion_matrix_mcc_perfect() -> None:
    m = ConfusionMatrix(tp=10, fp=0, tn=10, fn=0)
    assert abs(m.mcc() - 1.0) < 1e-9


def test_confusion_matrix_mcc_worst() -> None:
    m = ConfusionMatrix(tp=0, fp=10, tn=0, fn=10)
    assert abs(m.mcc() + 1.0) < 1e-9


def test_confusion_matrix_metric_lookup() -> None:
    m = ConfusionMatrix(tp=4, fp=1, tn=4, fn=1)
    assert abs(m.metric(MetricKind.PRECISION) - 0.8) < 1e-9
    assert abs(m.metric(MetricKind.RECALL) - 0.8) < 1e-9
    assert abs(m.metric(MetricKind.ACCURACY) - 0.8) < 1e-9


def test_confusion_matrix_expected_cost_empirical() -> None:
    m = ConfusionMatrix(tp=10, fp=10, tn=80, fn=0)
    c = CostMatrix(c_tp=0.1, c_fp=0.3, c_tn=0.0, c_fn=1.0)
    ec = m.expected_cost(c)
    # (10·0.1 + 10·0.3 + 0) / 100 = (1 + 3) / 100 = 0.04
    assert abs(ec - 0.04) < 1e-9


def test_confusion_matrix_from_outcomes() -> None:
    m = ConfusionMatrix.from_outcomes([
        DetectionOutcome.TP, DetectionOutcome.FP,
        DetectionOutcome.TN, DetectionOutcome.FN,
    ])
    assert m.tp == 1 and m.fp == 1 and m.tn == 1 and m.fn == 1


# ---- ROC ----

def test_roc_curve_from_records_non_empty() -> None:
    records = [
        _rec("1", score=0.9, truth=True),
        _rec("2", score=0.7, truth=True),
        _rec("3", score=0.3, truth=False),
        _rec("4", score=0.1, truth=False),
    ]
    curve = ROCCurve.from_records("d1", records)
    assert len(curve.points) >= 2


def test_roc_auc_perfect_separation() -> None:
    records = [
        _rec("1", score=0.9, truth=True),
        _rec("2", score=0.8, truth=True),
        _rec("3", score=0.2, truth=False),
        _rec("4", score=0.1, truth=False),
    ]
    curve = ROCCurve.from_records("d1", records)
    assert abs(curve.auc() - 1.0) < 1e-6


def test_roc_auc_in_unit() -> None:
    records = [
        _rec("1", score=0.6, truth=True),
        _rec("2", score=0.5, truth=False),
        _rec("3", score=0.4, truth=True),
        _rec("4", score=0.3, truth=False),
    ]
    curve = ROCCurve.from_records("d1", records)
    assert 0.0 <= curve.auc() <= 1.0


def test_roc_empty_returns_zero_auc() -> None:
    curve = ROCCurve.from_records("d1", [])
    assert curve.auc() == 0.0


def test_roc_point_at_threshold() -> None:
    records = [
        _rec("1", score=0.9, truth=True),
        _rec("2", score=0.1, truth=False),
    ]
    curve = ROCCurve.from_records(
        "d1", records, thresholds=[0.1, 0.5, 0.9],
    )
    p = curve.point_at_threshold(0.5)
    assert p is not None
    assert 0.0 <= p.fpr <= 1.0


# ---- threshold optimizer ----

def test_optimal_threshold_picks_low_cost() -> None:
    # Perfectly separated; the optimum should have low cost
    records = [
        _rec("1", score=0.95, truth=True),
        _rec("2", score=0.85, truth=True),
        _rec("3", score=0.15, truth=False),
        _rec("4", score=0.05, truth=False),
    ]
    curve = ROCCurve.from_records("d1", records)
    ot = optimize_threshold(
        curve,
        CostMatrix(c_tp=0.1, c_fp=0.3, c_tn=0.0, c_fn=1.0),
        PriorEstimate(0.1),
    )
    assert ot is not None
    assert ot.expected_cost <= 0.1


def test_optimal_threshold_high_fn_cost_pushes_lower_threshold() -> None:
    records = [
        _rec("1", score=0.9, truth=True),
        _rec("2", score=0.7, truth=True),
        _rec("3", score=0.5, truth=False),
        _rec("4", score=0.3, truth=False),
        _rec("5", score=0.1, truth=False),
    ]
    curve = ROCCurve.from_records("d1", records)
    # Very high FN cost pushes threshold lower
    ot_hi_fn = optimize_threshold(
        curve,
        CostMatrix(c_tp=0.05, c_fp=0.10, c_tn=0.0, c_fn=1.0),
        PriorEstimate(0.3),
    )
    ot_lo_fn = optimize_threshold(
        curve,
        CostMatrix(c_tp=0.05, c_fp=0.50, c_tn=0.0, c_fn=0.60),
        PriorEstimate(0.3),
    )
    assert ot_hi_fn is not None and ot_lo_fn is not None
    # Higher FN cost should not pick a higher threshold
    assert ot_hi_fn.threshold <= ot_lo_fn.threshold + 1e-9


def test_optimal_threshold_empty_returns_none() -> None:
    curve = ROCCurve.from_records("d1", [])
    assert optimize_threshold(
        curve, CostMatrix(), PriorEstimate(0.05),
    ) is None


# ---- evidence quality ----

def test_evidence_quality_composite_bounds() -> None:
    eq = EvidenceQuality(
        source_reliability=0.9, freshness=0.8,
        specificity=0.7, corroboration=0.6, independence=0.5,
    )
    c = eq.composite()
    assert 0.0 <= c <= 1.0


def test_evidence_quality_rejects_bad_field() -> None:
    try:
        EvidenceQuality(
            source_reliability=1.5, freshness=0.5,
            specificity=0.5, corroboration=0.5, independence=0.5,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_evidence_quality_all_ones() -> None:
    eq = EvidenceQuality(1.0, 1.0, 1.0, 1.0, 1.0)
    assert abs(eq.composite() - 1.0) < 1e-9


def test_evidence_quality_all_zero() -> None:
    eq = EvidenceQuality(0.0, 0.0, 0.0, 0.0, 0.0)
    assert eq.composite() == 0.0


# ---- detection confidence ----

def test_detection_confidence_high() -> None:
    c = compute_detection_confidence(
        detector_id="d1", record_id="r1",
        detector_score=0.9, evidence_quality=0.9,
        sample_count=50, min_samples=20,
    )
    assert c.combined_confidence > 0.7


def test_detection_confidence_low_with_poor_evidence() -> None:
    c = compute_detection_confidence(
        detector_id="d1", record_id="r1",
        detector_score=0.9, evidence_quality=0.0,
        sample_count=50, min_samples=20,
    )
    # eq_factor = 0.3, sample_factor = 1 → 0.27
    assert abs(c.combined_confidence - 0.9 * 0.3) < 1e-9


def test_detection_confidence_low_with_few_samples() -> None:
    c = compute_detection_confidence(
        detector_id="d1", record_id="r1",
        detector_score=0.9, evidence_quality=1.0,
        sample_count=1, min_samples=100,
    )
    # eq_factor = 1.0, sample_factor = sqrt(0.01) = 0.1 → 0.09
    assert abs(c.combined_confidence - 0.09) < 1e-9


def test_detection_confidence_rejects_bad_score() -> None:
    try:
        compute_detection_confidence(
            detector_id="d1", record_id="r1",
            detector_score=1.5, evidence_quality=0.5,
            sample_count=10, min_samples=20,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- degradation ----

def test_degradation_stable_when_similar() -> None:
    base = ConfusionMatrix(tp=80, fp=20, tn=880, fn=20)
    recent = ConfusionMatrix(tp=78, fp=22, tn=878, fn=22)
    d = detect_degradation(
        detector_id="d1", baseline=base, recent=recent, at=_t0(),
    )
    assert not d.degraded


def test_degradation_detected_when_f1_drops() -> None:
    base = ConfusionMatrix(tp=90, fp=10, tn=890, fn=10)
    recent = ConfusionMatrix(tp=50, fp=10, tn=890, fn=50)
    d = detect_degradation(
        detector_id="d1", baseline=base, recent=recent, at=_t0(),
    )
    assert d.degraded
    assert d.delta_f1 < 0


def test_degradation_detected_when_fpr_rises() -> None:
    base = ConfusionMatrix(tp=90, fp=10, tn=890, fn=10)
    recent = ConfusionMatrix(tp=90, fp=100, tn=800, fn=10)
    d = detect_degradation(
        detector_id="d1", baseline=base, recent=recent, at=_t0(),
    )
    assert d.degraded
    assert d.delta_fpr > 0


def test_degradation_rejects_bad_time() -> None:
    from datetime import datetime as dt
    try:
        detect_degradation(
            detector_id="d1",
            baseline=ConfusionMatrix(), recent=ConfusionMatrix(),
            at=dt(2026, 1, 1),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- failure conditions ----

def test_failure_condition_min_samples() -> None:
    c = make_min_samples_condition("d1", 10)
    results = evaluate_failure_conditions(
        [c], ConfusionMatrix(tp=5, fp=1, tn=1, fn=1), sample_count=5,
    )
    assert results[0].met is True


def test_failure_condition_min_precision() -> None:
    c = make_min_precision_condition("d1", 0.5)
    m = ConfusionMatrix(tp=2, fp=8, tn=100, fn=0)
    results = evaluate_failure_conditions([c], m, sample_count=10)
    assert results[0].met is True


def test_failure_condition_predicate_exception_caught() -> None:
    c = FailureCondition(
        condition_id="bad", detector_id="d1", description="raises",
        predicate=lambda m, n: (_ for _ in ()).throw(RuntimeError()),
    )
    results = evaluate_failure_conditions(
        [c], ConfusionMatrix(), sample_count=0,
    )
    assert results[0].met is False


def test_failure_condition_min_recall() -> None:
    c = make_min_recall_condition("d1", 0.8)
    m = ConfusionMatrix(tp=5, fp=0, tn=100, fn=5)
    results = evaluate_failure_conditions([c], m, sample_count=10)
    assert results[0].met is True


# ---- engine basics ----

def test_engine_register_detector() -> None:
    eng = DetectionErrorEngine()
    eng.register_detector("d1")
    eng.report(_rec("r1", "d1"))
    eng.recompute(at=_t0())


def test_engine_rejects_duplicate_detector() -> None:
    eng = DetectionErrorEngine()
    eng.register_detector("d1")
    try:
        eng.register_detector("d1")
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_rejects_unknown_detector_on_report() -> None:
    eng = DetectionErrorEngine()
    try:
        eng.report(_rec("r1", "missing"))
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_engine_metrics_computed() -> None:
    eng = DetectionErrorEngine()
    eng.register_detector("d1", min_samples=4)
    for i in range(10):
        eng.report(_rec(
            f"r{i}", "d1", score=0.9 if i % 2 == 0 else 0.1,
            truth=i % 2 == 0, at=_t(i),
        ))
    eng.recompute(at=_t(100))
    m = eng.matrix("d1")
    assert m is not None
    assert abs(m.precision() - 1.0) < 1e-9
    assert abs(m.recall() - 1.0) < 1e-9


def test_engine_roc_auc_computed() -> None:
    eng = DetectionErrorEngine()
    eng.register_detector("d1")
    for i in range(20):
        eng.report(_rec(
            f"r{i}", "d1",
            score=0.9 if i % 2 == 0 else 0.1,
            truth=i % 2 == 0, at=_t(i),
        ))
    eng.recompute(at=_t(50))
    curve = eng.curve("d1")
    assert curve is not None
    assert curve.auc() > 0.9


def test_engine_optimal_threshold_computed() -> None:
    eng = DetectionErrorEngine()
    eng.register_detector("d1")
    for i in range(20):
        eng.report(_rec(
            f"r{i}", "d1",
            score=0.9 if i % 2 == 0 else 0.1,
            truth=i % 2 == 0, at=_t(i),
        ))
    eng.recompute(at=_t(50))
    ot = eng.optimum("d1")
    assert ot is not None
    assert 0.0 <= ot.threshold <= 1.0


def test_engine_record_lookup() -> None:
    eng = DetectionErrorEngine()
    eng.register_detector("d1")
    for i in range(20):
        eng.report(_rec(f"r{i}", "d1", score=0.9, truth=True, at=_t(i)))
    eng.recompute(at=_t(50))
    rec = eng.record("d1")
    assert rec is not None
    assert rec.precision == 1.0


def test_engine_high_expected_cost_finding() -> None:
    eng = DetectionErrorEngine()
    eng.register_detector("d1", prior=PriorEstimate(0.5))
    for i in range(20):
        # miss half of positives → high FN cost
        eng.report(_rec(
            f"r{i}", "d1", score=0.1 if i < 10 else 0.9,
            truth=True, at=_t(i),
        ))
    eng.recompute(at=_t(50))
    kinds = {f.kind for f in eng.findings()}
    assert DetectionFindingKind.HIGH_EXPECTED_COST in kinds


def test_engine_degraded_detection_finding() -> None:
    eng = DetectionErrorEngine()
    eng.register_detector("d1", min_samples=4)
    # First half: perfect; second half: collapsed
    for i in range(20):
        if i < 10:
            eng.report(_rec(
                f"a{i}", "d1", score=0.9, truth=True, at=_t(i),
            ))
        else:
            eng.report(_rec(
                f"b{i}", "d1", score=0.9, truth=False, at=_t(i),
            ))
    eng.recompute(at=_t(50))
    kinds = {f.kind for f in eng.findings()}
    assert DetectionFindingKind.DEGRADED_DETECTION in kinds


def test_engine_failure_condition_finding() -> None:
    eng = DetectionErrorEngine()
    eng.register_detector("d1", min_samples=20)
    eng.register_failure_condition(
        make_min_samples_condition("d1", 20)
    )
    for i in range(5):
        eng.report(_rec(f"r{i}", "d1", at=_t(i)))
    eng.recompute(at=_t(50))
    kinds = {f.kind for f in eng.findings()}
    assert DetectionFindingKind.FAILURE_CONDITION_MET in kinds


def test_engine_low_detection_confidence_finding() -> None:
    eng = DetectionErrorEngine()
    eng.register_detector("d1")
    conf = compute_detection_confidence(
        detector_id="d1", record_id="r1",
        detector_score=0.1, evidence_quality=0.1,
        sample_count=1, min_samples=100,
    )
    eng.register_detection_confidence(conf)
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert DetectionFindingKind.LOW_DETECTION_CONFIDENCE in kinds


def test_engine_low_evidence_quality_finding() -> None:
    eng = DetectionErrorEngine()
    eng.register_detector("d1")
    conf = compute_detection_confidence(
        detector_id="d1", record_id="r1",
        detector_score=0.9, evidence_quality=0.05,
        sample_count=50, min_samples=20,
    )
    eng.register_detection_confidence(conf)
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert DetectionFindingKind.LOW_EVIDENCE_QUALITY in kinds


def test_engine_confidence_unknown_detector_rejected() -> None:
    eng = DetectionErrorEngine()
    conf = compute_detection_confidence(
        detector_id="missing", record_id="r1",
        detector_score=0.5, evidence_quality=0.5,
        sample_count=5, min_samples=20,
    )
    try:
        eng.register_detection_confidence(conf)
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_engine_failure_condition_unknown_detector_rejected() -> None:
    eng = DetectionErrorEngine()
    c = make_min_samples_condition("missing", 5)
    try:
        eng.register_failure_condition(c)
    except KeyError:
        return
    raise AssertionError("expected KeyError")


# ---- invariants ----

def test_invariant_clean_snapshot() -> None:
    eng = DetectionErrorEngine()
    eng.register_detector("d1")
    for i in range(20):
        eng.report(_rec(f"r{i}", "d1", at=_t(i)))
    eng.recompute(at=_t(50))
    assert eng.violations() == ()


def test_invariant_cost_coherent() -> None:
    # Bypass CostMatrix.__post_init__ to test the invariant
    bad = object.__new__(CostMatrix)
    object.__setattr__(bad, "c_tp", 0.1)
    object.__setattr__(bad, "c_fp", 0.5)
    object.__setattr__(bad, "c_tn", 0.0)
    object.__setattr__(bad, "c_fn", 0.1)
    snap = DetectionSnapshot(
        matrices={}, costs={"d1": bad}, priors={},
        optima={}, degradations={},
    )
    v = check_invariants(snap)
    assert any(x.invariant_id == "det.cost_coherent" for x in v)


def test_invariant_degradation_consistent() -> None:
    # Fake degradation with non-negative deltas
    bad = DegradationReport(
        detector_id="d1",
        baseline=ConfusionMatrix(), recent=ConfusionMatrix(),
        delta_precision=0.0, delta_recall=0.0, delta_f1=0.0,
        delta_fpr=0.0, degraded=True, rationale="fake", at=_t0(),
    )
    snap = DetectionSnapshot(
        matrices={}, costs={}, priors={}, optima={},
        degradations={"d1": bad},
    )
    v = check_invariants(snap)
    assert any(x.invariant_id == "det.degradation_consistent" for x in v)


# ---- policy ----

def test_engine_constructor_validation() -> None:
    try:
        DetectionErrorEngine(high_expected_cost=1.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_max_records_validation() -> None:
    try:
        DetectionErrorEngine(max_records_per_detector=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_max_records_trimming() -> None:
    eng = DetectionErrorEngine(max_records_per_detector=10)
    eng.register_detector("d1")
    for i in range(30):
        eng.report(_rec(f"r{i}", "d1", at=_t(i)))
    # internal trimming
    assert len(eng._detectors["d1"].records) == 10


# ---- store ----

def test_in_memory_store_rejects_stale() -> None:
    s = InMemoryDetectionStore()
    t = _t0()
    s.put(DetectorRecord(
        "d1", 0.9, 0.9, 0.9, 0.05, 0.1, 0.5, False, t,
    ))
    from datetime import timedelta
    earlier = t - timedelta(days=1)
    try:
        s.put(DetectorRecord(
            "d1", 0.5, 0.5, 0.5, 0.1, 0.5, 0.5, False, earlier,
        ))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_record_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "det.db")
    store = SqliteDetectionStore(db)
    t = _t0()
    store.put(DetectorRecord(
        "d1", precision=0.9, recall=0.85, f1=0.87, fpr=0.05,
        expected_cost=0.12, optimal_threshold=0.55, degraded=False,
        updated_at=t,
    ))
    got = store.get("d1")
    assert got is not None
    assert abs(got.precision - 0.9) < 1e-9
    assert not got.degraded


def test_sqlite_store_detection_record_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "det.db")
    store = SqliteDetectionStore(db)
    rec = _rec("r1", score=0.7, truth=True)
    store.put_record(rec)
    row = store._conn.execute(
        "SELECT payload_json FROM det_records WHERE record_id = 'r1'"
    ).fetchone()
    assert row is not None
    payload = json.loads(row[0])
    assert payload["record_id"] == "r1"
    assert payload["score"] == 0.7


# =============================================================================
# SECTION 15 — MANUAL RUNNER
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
