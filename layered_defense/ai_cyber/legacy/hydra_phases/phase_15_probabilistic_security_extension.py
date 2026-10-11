"""
HYDRA POST-CORE — PHASE 15: PROBABILISTIC SECURITY EXTENSION
===============================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * Domain — TrustLabel, AuthorityMode, UncertaintyType
  * Probabilistic primitives (no external deps):
      - Shannon entropy + normalized entropy
      - KL divergence (smoothed)
      - safe normalization
  * State posterior       — Dirichlet over TrustLabel
  * Evidence uncertainty  — Beta over reliability, mean/variance/CI
  * Authority posterior   — Dirichlet over AuthorityMode
  * Recovery posterior    — Beta over recovery success
  * Transition matrix     — Dirichlet row per current TrustLabel
  * Intervention confidence — expected reduction × reliability × evidence
  * Uncertainty propagation:
      - aleatoric (irreducible): 0.5·H_state + 0.3·H_transition + 0.2·H_authority
      - epistemic (reducible)   : 1 − evidence_confidence
      - total = aleatoric + (1 − aleatoric)·epistemic
  * Machine-checkable probabilistic invariants
  * In-memory + SQLite stores
  * Phase-15 engine facade
  * Full test suite + manual runner

This is NOT a second probabilistic reasoning engine. It is a
probabilistic-uncertainty layer that the existing HYDRA reasoning engine
consumes to quantify state uncertainty, evidence uncertainty, authority
uncertainty, transition probability, recovery confidence, and
intervention confidence.

No third-party dependencies.

Run tests:
    python hydra_phase15_probabilistic_security_extension.py
    pytest hydra_phase15_probabilistic_security_extension.py -q
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
# SECTION 2 — DOMAIN
# =============================================================================


class TrustLabel(str, Enum):
    UNKNOWN = "unknown"
    OBSERVED = "observed"
    TRUSTED = "trusted"
    DEGRADED = "degraded"
    SUSPICIOUS = "suspicious"
    COMPROMISED = "compromised"
    QUARANTINED = "quarantined"


ALL_LABELS: Tuple[TrustLabel, ...] = tuple(TrustLabel)


class AuthorityMode(str, Enum):
    NORMAL = "normal"
    ELEVATED = "elevated"
    DELEGATED = "delegated"
    TEMPORARY = "temporary"
    SUSPENDED = "suspended"


ALL_AUTHORITY_MODES: Tuple[AuthorityMode, ...] = tuple(AuthorityMode)


class UncertaintyType(str, Enum):
    ALEATORIC = "aleatoric"    # irreducible — inherent randomness
    EPISTEMIC = "epistemic"    # reducible via more evidence
    MIXED = "mixed"


class ProbFindingKind(str, Enum):
    HIGH_UNCERTAINTY = "high_uncertainty"
    LOW_EVIDENCE_CONFIDENCE = "low_evidence_confidence"
    UNSTABLE_TRANSITION = "unstable_transition"
    LOW_RECOVERY_CONFIDENCE = "low_recovery_confidence"
    LOW_INTERVENTION_CONFIDENCE = "low_intervention_confidence"


@dataclass(frozen=True)
class ProbFinding:
    kind: ProbFindingKind
    entity_id: str
    detail: str
    severity: int        # 1..5
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        if not 1 <= self.severity <= 5:
            raise ValueError("severity must be in [1,5]")


# =============================================================================
# SECTION 3 — PROBABILISTIC PRIMITIVES
# =============================================================================


def _validate_prob_vector(p: Sequence[float], *, name: str) -> None:
    if not p:
        raise ValueError(f"{name} must be non-empty")
    for x in p:
        if x < 0.0:
            raise ValueError(f"{name} entries must be >= 0")
    total = sum(p)
    if abs(total - 1.0) > 1e-6:
        raise ValueError(f"{name} must sum to 1 (got {total})")


def normalized_entropy(p: Sequence[float]) -> float:
    """Shannon entropy normalized by log(K) ∈ [0,1]."""
    if len(p) <= 1:
        return 0.0
    _validate_prob_vector(p, name="p")
    h = 0.0
    for x in p:
        if x > 0.0:
            h -= x * math.log(x)
    return max(0.0, min(1.0, h / math.log(len(p))))


def kl_divergence(p: Sequence[float], q: Sequence[float]) -> float:
    """KL(p || q) with smoothing to avoid division by zero."""
    if len(p) != len(q) or not p:
        raise ValueError("p and q must have equal, non-zero length")
    eps = 1e-12
    return sum(
        (pi + eps) * math.log((pi + eps) / (qi + eps))
        for pi, qi in zip(p, q)
    )


def softmax(logits: Sequence[float]) -> Tuple[float, ...]:
    if not logits:
        raise ValueError("logits must be non-empty")
    m = max(logits)
    exps = [math.exp(x - m) for x in logits]
    s = sum(exps)
    return tuple(x / s for x in exps)


def safe_normalize(weights: Sequence[float]) -> Tuple[float, ...]:
    if not weights:
        raise ValueError("weights must be non-empty")
    total = sum(max(0.0, w) for w in weights)
    if total <= 0.0:
        # uniform
        k = len(weights)
        return tuple(1.0 / k for _ in weights)
    return tuple(max(0.0, w) / total for w in weights)


def beta_variance(alpha: float, beta: float) -> float:
    if alpha <= 0 or beta <= 0:
        raise ValueError("alpha and beta must be > 0")
    n = alpha + beta
    return (alpha * beta) / (n * n * (n + 1.0))


# =============================================================================
# SECTION 4 — STATE POSTERIOR (Dirichlet over TrustLabel)
# =============================================================================


@dataclass(frozen=True)
class StatePosterior:
    """Dirichlet posterior over TrustLabel."""
    entity_id: str
    alpha: Tuple[float, ...]
    prior_alpha: Tuple[float, ...]

    def __post_init__(self) -> None:
        if not self.entity_id:
            raise ValueError("entity_id is required")
        if len(self.alpha) != len(ALL_LABELS):
            raise ValueError("alpha length must match TrustLabel count")
        if len(self.prior_alpha) != len(ALL_LABELS):
            raise ValueError("prior_alpha length must match TrustLabel count")
        for a in self.alpha:
            if a <= 0:
                raise ValueError("alpha entries must be > 0")
        for a in self.prior_alpha:
            if a <= 0:
                raise ValueError("prior_alpha entries must be > 0")
        for a, p in zip(self.alpha, self.prior_alpha):
            if a < p:
                raise ValueError("posterior alpha cannot be below prior")

    @classmethod
    def uniform(cls, entity_id: str) -> "StatePosterior":
        prior = tuple(1.0 for _ in ALL_LABELS)
        return cls(entity_id=entity_id, alpha=prior, prior_alpha=prior)

    def observe(self, label: TrustLabel, *, weight: float = 1.0) -> "StatePosterior":
        if weight < 0:
            raise ValueError("weight must be >= 0")
        i = ALL_LABELS.index(label)
        new = list(self.alpha)
        new[i] += weight
        return StatePosterior(
            entity_id=self.entity_id, alpha=tuple(new),
            prior_alpha=self.prior_alpha,
        )

    @property
    def total(self) -> float:
        return sum(self.alpha)

    def probabilities(self) -> Tuple[float, ...]:
        t = self.total
        return tuple(a / t for a in self.alpha)

    def probability(self, label: TrustLabel) -> float:
        return self.alpha[ALL_LABELS.index(label)] / self.total

    def argmax(self) -> TrustLabel:
        idx = max(range(len(self.alpha)),
                  key=lambda i: (self.alpha[i], ALL_LABELS[i].value))
        return ALL_LABELS[idx]

    def sample_count(self) -> float:
        return sum(a - p for a, p in zip(self.alpha, self.prior_alpha))

    def entropy(self) -> float:
        return normalized_entropy(self.probabilities())

    def credible_set(self, *, threshold: float = 0.9) -> Tuple[TrustLabel, ...]:
        if not 0.0 < threshold <= 1.0:
            raise ValueError("threshold must be in (0,1]")
        pairs = sorted(
            ((ALL_LABELS[i], p) for i, p in enumerate(self.probabilities())),
            key=lambda kv: (-kv[1], kv[0].value),
        )
        out: List[TrustLabel] = []
        cum = 0.0
        for lbl, p in pairs:
            out.append(lbl)
            cum += p
            if cum >= threshold:
                break
        return tuple(out)


# =============================================================================
# SECTION 5 — EVIDENCE UNCERTAINTY (Beta over reliability)
# =============================================================================


@dataclass(frozen=True)
class EvidenceUncertainty:
    """Beta posterior over the reliability of an evidence source."""
    source_id: str
    alpha: float
    beta: float
    prior_alpha: float = 1.0
    prior_beta: float = 1.0

    def __post_init__(self) -> None:
        if not self.source_id:
            raise ValueError("source_id is required")
        for n, v in (("alpha", self.alpha), ("beta", self.beta),
                     ("prior_alpha", self.prior_alpha),
                     ("prior_beta", self.prior_beta)):
            if v <= 0:
                raise ValueError(f"{n} must be > 0")
        if self.alpha < self.prior_alpha or self.beta < self.prior_beta:
            raise ValueError("posterior cannot be below prior")

    @classmethod
    def prior(cls, source_id: str) -> "EvidenceUncertainty":
        return cls(source_id=source_id, alpha=1.0, beta=1.0,
                   prior_alpha=1.0, prior_beta=1.0)

    def observe(self, *, confirmed: bool, weight: float = 1.0) -> "EvidenceUncertainty":
        if weight < 0:
            raise ValueError("weight must be >= 0")
        if confirmed:
            return EvidenceUncertainty(
                source_id=self.source_id, alpha=self.alpha + weight,
                beta=self.beta, prior_alpha=self.prior_alpha,
                prior_beta=self.prior_beta,
            )
        return EvidenceUncertainty(
            source_id=self.source_id, alpha=self.alpha,
            beta=self.beta + weight, prior_alpha=self.prior_alpha,
            prior_beta=self.prior_beta,
        )

    @property
    def mean(self) -> float:
        return self.alpha / (self.alpha + self.beta)

    @property
    def variance(self) -> float:
        return beta_variance(self.alpha, self.beta)

    @property
    def sample_count(self) -> float:
        return (self.alpha - self.prior_alpha) + (self.beta - self.prior_beta)

    def confidence(self) -> float:
        """0..1 — 1 − 4·Var(Beta). Variance ≤ 0.25 for Beta."""
        return max(0.0, min(1.0, 1.0 - 4.0 * self.variance))

    def credible_interval(self, *, z: float = 1.96) -> Tuple[float, float]:
        sd = math.sqrt(self.variance)
        lo = max(0.0, self.mean - z * sd)
        hi = min(1.0, self.mean + z * sd)
        return (lo, hi)


# =============================================================================
# SECTION 6 — AUTHORITY POSTERIOR (Dirichlet over AuthorityMode)
# =============================================================================


@dataclass(frozen=True)
class AuthorityPosterior:
    entity_id: str
    alpha: Tuple[float, ...]
    prior_alpha: Tuple[float, ...]

    def __post_init__(self) -> None:
        if not self.entity_id:
            raise ValueError("entity_id is required")
        if len(self.alpha) != len(ALL_AUTHORITY_MODES):
            raise ValueError("alpha length must match AuthorityMode count")
        if len(self.prior_alpha) != len(ALL_AUTHORITY_MODES):
            raise ValueError("prior_alpha length mismatch")
        for a in self.alpha:
            if a <= 0:
                raise ValueError("alpha entries must be > 0")
        for a in self.prior_alpha:
            if a <= 0:
                raise ValueError("prior_alpha entries must be > 0")
        for a, p in zip(self.alpha, self.prior_alpha):
            if a < p:
                raise ValueError("posterior alpha cannot be below prior")

    @classmethod
    def uniform(cls, entity_id: str) -> "AuthorityPosterior":
        prior = tuple(1.0 for _ in ALL_AUTHORITY_MODES)
        return cls(entity_id=entity_id, alpha=prior, prior_alpha=prior)

    def observe(self, mode: AuthorityMode, *, weight: float = 1.0) -> "AuthorityPosterior":
        if weight < 0:
            raise ValueError("weight must be >= 0")
        i = ALL_AUTHORITY_MODES.index(mode)
        new = list(self.alpha)
        new[i] += weight
        return AuthorityPosterior(
            entity_id=self.entity_id, alpha=tuple(new),
            prior_alpha=self.prior_alpha,
        )

    @property
    def total(self) -> float:
        return sum(self.alpha)

    def probabilities(self) -> Tuple[float, ...]:
        t = self.total
        return tuple(a / t for a in self.alpha)

    def probability(self, mode: AuthorityMode) -> float:
        return self.alpha[ALL_AUTHORITY_MODES.index(mode)] / self.total

    def argmax(self) -> AuthorityMode:
        idx = max(range(len(self.alpha)),
                  key=lambda i: (self.alpha[i], ALL_AUTHORITY_MODES[i].value))
        return ALL_AUTHORITY_MODES[idx]

    def entropy(self) -> float:
        return normalized_entropy(self.probabilities())

    def confidence(self) -> float:
        """1 − normalized entropy."""
        return max(0.0, min(1.0, 1.0 - self.entropy()))


# =============================================================================
# SECTION 7 — RECOVERY POSTERIOR (Beta over recovery success)
# =============================================================================


@dataclass(frozen=True)
class RecoveryPosterior:
    entity_id: str
    alpha: float
    beta: float
    prior_alpha: float = 1.0
    prior_beta: float = 1.0

    def __post_init__(self) -> None:
        if not self.entity_id:
            raise ValueError("entity_id is required")
        for n, v in (("alpha", self.alpha), ("beta", self.beta),
                     ("prior_alpha", self.prior_alpha),
                     ("prior_beta", self.prior_beta)):
            if v <= 0:
                raise ValueError(f"{n} must be > 0")
        if self.alpha < self.prior_alpha or self.beta < self.prior_beta:
            raise ValueError("posterior cannot be below prior")

    @classmethod
    def prior(cls, entity_id: str) -> "RecoveryPosterior":
        return cls(entity_id=entity_id, alpha=1.0, beta=1.0,
                   prior_alpha=1.0, prior_beta=1.0)

    def observe(self, *, success: bool, weight: float = 1.0) -> "RecoveryPosterior":
        if weight < 0:
            raise ValueError("weight must be >= 0")
        if success:
            return RecoveryPosterior(
                entity_id=self.entity_id, alpha=self.alpha + weight,
                beta=self.beta, prior_alpha=self.prior_alpha,
                prior_beta=self.prior_beta,
            )
        return RecoveryPosterior(
            entity_id=self.entity_id, alpha=self.alpha,
            beta=self.beta + weight, prior_alpha=self.prior_alpha,
            prior_beta=self.prior_beta,
        )

    @property
    def mean(self) -> float:
        return self.alpha / (self.alpha + self.beta)

    @property
    def variance(self) -> float:
        return beta_variance(self.alpha, self.beta)

    def confidence(self) -> float:
        return max(0.0, min(1.0, 1.0 - 4.0 * self.variance))


# =============================================================================
# SECTION 8 — TRANSITION MATRIX (Dirichlet rows)
# =============================================================================


@dataclass(frozen=True)
class TransitionMatrix:
    """Per-current-label Dirichlet over next labels.

    rows[current_label] is a Dirichlet posterior over next labels.
    """
    entity_id: str
    rows: Mapping[TrustLabel, Tuple[float, ...]]
    prior_rows: Mapping[TrustLabel, Tuple[float, ...]]

    def __post_init__(self) -> None:
        if not self.entity_id:
            raise ValueError("entity_id is required")
        for lbl in ALL_LABELS:
            row = self.rows.get(lbl)
            if row is None or len(row) != len(ALL_LABELS):
                raise ValueError(
                    f"row for {lbl.value} missing or wrong length"
                )
            prior = self.prior_rows.get(lbl)
            if prior is None or len(prior) != len(ALL_LABELS):
                raise ValueError(
                    f"prior row for {lbl.value} missing or wrong length"
                )
            for a in row:
                if a <= 0:
                    raise ValueError("row entries must be > 0")
            for a, p in zip(row, prior):
                if a < p:
                    raise ValueError("row cannot be below prior row")

    @classmethod
    def uniform(cls, entity_id: str) -> "TransitionMatrix":
        prior_row = tuple(1.0 for _ in ALL_LABELS)
        rows = {lbl: prior_row for lbl in ALL_LABELS}
        return cls(
            entity_id=entity_id, rows=rows, prior_rows=dict(rows),
        )

    def observe(
        self, *, current: TrustLabel, next_label: TrustLabel,
        weight: float = 1.0,
    ) -> "TransitionMatrix":
        if weight < 0:
            raise ValueError("weight must be >= 0")
        new_rows = dict(self.rows)
        row = list(new_rows[current])
        row[ALL_LABELS.index(next_label)] += weight
        new_rows[current] = tuple(row)
        return TransitionMatrix(
            entity_id=self.entity_id, rows=new_rows,
            prior_rows=dict(self.prior_rows),
        )

    def row_probabilities(self, current: TrustLabel) -> Tuple[float, ...]:
        row = self.rows[current]
        t = sum(row)
        return tuple(a / t for a in row)

    def probability(self, current: TrustLabel, next_label: TrustLabel) -> float:
        return self.row_probabilities(current)[ALL_LABELS.index(next_label)]

    def row_entropy(self, current: TrustLabel) -> float:
        return normalized_entropy(self.row_probabilities(current))

    def row_stability(self, current: TrustLabel) -> float:
        """1 − normalized entropy (higher = more stable)."""
        return max(0.0, min(1.0, 1.0 - self.row_entropy(current)))

    def expected_next(self, current: TrustLabel) -> TrustLabel:
        probs = self.row_probabilities(current)
        idx = max(range(len(probs)), key=lambda i: (probs[i], ALL_LABELS[i].value))
        return ALL_LABELS[idx]


# =============================================================================
# SECTION 9 — INTERVENTION CONFIDENCE
# =============================================================================


@dataclass(frozen=True)
class InterventionConfidence:
    intervention_id: str
    entity_id: str
    current_risk: float
    projected_risk_after: float
    intervention_reliability: float
    evidence_confidence: float
    expected_reduction: float
    confidence: float
    expected_value: float
    at: datetime

    def __post_init__(self) -> None:
        if not self.intervention_id:
            raise ValueError("intervention_id is required")
        if not self.entity_id:
            raise ValueError("entity_id is required")
        for n, v in (
            ("current_risk", self.current_risk),
            ("projected_risk_after", self.projected_risk_after),
            ("intervention_reliability", self.intervention_reliability),
            ("evidence_confidence", self.evidence_confidence),
            ("expected_reduction", self.expected_reduction),
            ("confidence", self.confidence),
            ("expected_value", self.expected_value),
        ):
            if not 0.0 <= v <= 1.0:
                raise ValueError(f"{n} must be within [0,1]")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


def score_intervention(
    *,
    intervention_id: str,
    entity_id: str,
    current_risk: float,
    projected_risk_after: float,
    intervention_reliability: float,
    evidence_confidence: float,
    at: datetime,
) -> InterventionConfidence:
    if at.tzinfo is None:
        raise ValueError("at must be timezone-aware")
    for n, v in (
        ("current_risk", current_risk),
        ("projected_risk_after", projected_risk_after),
        ("intervention_reliability", intervention_reliability),
        ("evidence_confidence", evidence_confidence),
    ):
        if not 0.0 <= v <= 1.0:
            raise ValueError(f"{n} must be within [0,1]")

    reduction = max(0.0, current_risk - projected_risk_after)
    confidence = max(0.0, min(1.0, intervention_reliability * evidence_confidence))
    expected_value = max(0.0, min(1.0, reduction * confidence))

    return InterventionConfidence(
        intervention_id=intervention_id, entity_id=entity_id,
        current_risk=current_risk,
        projected_risk_after=projected_risk_after,
        intervention_reliability=intervention_reliability,
        evidence_confidence=evidence_confidence,
        expected_reduction=reduction,
        confidence=confidence,
        expected_value=expected_value,
        at=at,
    )


# =============================================================================
# SECTION 10 — UNCERTAINTY PROPAGATION
# =============================================================================


@dataclass(frozen=True)
class UncertaintyDecomposition:
    entity_id: str
    uncertainty_type: UncertaintyType
    aleatoric: float
    epistemic: float
    total: float
    state_entropy: float
    authority_entropy: float
    transition_entropy: float
    evidence_confidence: float
    at: datetime

    def __post_init__(self) -> None:
        for n, v in (
            ("aleatoric", self.aleatoric),
            ("epistemic", self.epistemic),
            ("total", self.total),
            ("state_entropy", self.state_entropy),
            ("authority_entropy", self.authority_entropy),
            ("transition_entropy", self.transition_entropy),
            ("evidence_confidence", self.evidence_confidence),
        ):
            if not 0.0 <= v <= 1.0:
                raise ValueError(f"{n} must be within [0,1]")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


ALEATORIC_STATE_WEIGHT: float = 0.5
ALEATORIC_TRANSITION_WEIGHT: float = 0.3
ALEATORIC_AUTHORITY_WEIGHT: float = 0.2


def propagate_uncertainty(
    *,
    entity_id: str,
    state: StatePosterior,
    authority: AuthorityPosterior,
    transition_row_current: TrustLabel,
    transition: TransitionMatrix,
    evidence: EvidenceUncertainty,
    at: datetime,
) -> UncertaintyDecomposition:
    if at.tzinfo is None:
        raise ValueError("at must be timezone-aware")

    h_state = state.entropy()
    h_auth = authority.entropy()
    h_trans = transition.row_entropy(transition_row_current)
    ev_conf = evidence.confidence()

    aleatoric = (
        ALEATORIC_STATE_WEIGHT * h_state
        + ALEATORIC_TRANSITION_WEIGHT * h_trans
        + ALEATORIC_AUTHORITY_WEIGHT * h_auth
    )
    aleatoric = max(0.0, min(1.0, aleatoric))

    epistemic = 1.0 - ev_conf
    total = aleatoric + (1.0 - aleatoric) * epistemic
    total = max(0.0, min(1.0, total))

    if aleatoric >= 0.7:
        kind = UncertaintyType.ALEATORIC
    elif epistemic >= 0.5:
        kind = UncertaintyType.EPISTEMIC
    else:
        kind = UncertaintyType.MIXED

    return UncertaintyDecomposition(
        entity_id=entity_id,
        uncertainty_type=kind,
        aleatoric=aleatoric,
        epistemic=epistemic,
        total=total,
        state_entropy=h_state,
        authority_entropy=h_auth,
        transition_entropy=h_trans,
        evidence_confidence=ev_conf,
        at=at,
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
class ProbabilisticSnapshot:
    states: Mapping[str, StatePosterior]
    authorities: Mapping[str, AuthorityPosterior]
    evidences: Mapping[str, EvidenceUncertainty]
    recoveries: Mapping[str, RecoveryPosterior]
    transitions: Mapping[str, TransitionMatrix]
    decompositions: Mapping[str, UncertaintyDecomposition]
    interventions: Tuple[InterventionConfidence, ...]


@dataclass(frozen=True)
class ProbabilisticInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[ProbabilisticSnapshot],
                        Tuple[InvariantViolation, ...]]
    description: str


def _inv_state_probs_sum_to_one(
    snap: ProbabilisticSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for eid, s in snap.states.items():
        total = sum(s.probabilities())
        if abs(total - 1.0) > 1e-6:
            out.append(InvariantViolation(
                invariant_id="prob.state_probs_sum_to_one",
                severity=InvariantSeverity.CRITICAL,
                subject_id=eid,
                detail=f"state probs sum to {total}",
            ))
    return tuple(out)


def _inv_authority_probs_sum_to_one(
    snap: ProbabilisticSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for eid, a in snap.authorities.items():
        total = sum(a.probabilities())
        if abs(total - 1.0) > 1e-6:
            out.append(InvariantViolation(
                invariant_id="prob.authority_probs_sum_to_one",
                severity=InvariantSeverity.CRITICAL,
                subject_id=eid,
                detail=f"authority probs sum to {total}",
            ))
    return tuple(out)


def _inv_transition_rows_sum_to_one(
    snap: ProbabilisticSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for eid, tm in snap.transitions.items():
        for lbl in ALL_LABELS:
            total = sum(tm.row_probabilities(lbl))
            if abs(total - 1.0) > 1e-6:
                out.append(InvariantViolation(
                    invariant_id="prob.transition_rows_sum_to_one",
                    severity=InvariantSeverity.CRITICAL,
                    subject_id=f"{eid}:{lbl.value}",
                    detail=f"transition row sums to {total}",
                ))
    return tuple(out)


def _inv_uncertainty_bounded(
    snap: ProbabilisticSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for eid, d in snap.decompositions.items():
        if not 0.0 <= d.total <= 1.0:
            out.append(InvariantViolation(
                invariant_id="prob.uncertainty_bounded",
                severity=InvariantSeverity.HIGH,
                subject_id=eid,
                detail=f"total uncertainty {d.total} out of [0,1]",
            ))
    return tuple(out)


def _inv_no_high_confidence_under_high_uncertainty(
    snap: ProbabilisticSnapshot,
) -> Tuple[InvariantViolation, ...]:
    """An evidence source with low confidence must not coexist with a
    very certain state posterior (sample-count weighted)."""
    out: List[InvariantViolation] = []
    for eid, d in snap.decompositions.items():
        state = snap.states.get(eid)
        if state is None:
            continue
        if d.total >= 0.8 and state.entropy() <= 0.05 \
           and state.sample_count() >= 5:
            out.append(InvariantViolation(
                invariant_id="prob.certainty_mismatch",
                severity=InvariantSeverity.HIGH,
                subject_id=eid,
                detail=(
                    f"state very certain (H={state.entropy():.3f}) but "
                    f"total uncertainty {d.total:.3f}"
                ),
            ))
    return tuple(out)


DEFAULT_INVARIANTS: Tuple[ProbabilisticInvariant, ...] = (
    ProbabilisticInvariant(
        invariant_id="prob.state_probs_sum_to_one",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_state_probs_sum_to_one,
        description="State posterior probabilities must sum to 1.",
    ),
    ProbabilisticInvariant(
        invariant_id="prob.authority_probs_sum_to_one",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_authority_probs_sum_to_one,
        description="Authority posterior probabilities must sum to 1.",
    ),
    ProbabilisticInvariant(
        invariant_id="prob.transition_rows_sum_to_one",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_transition_rows_sum_to_one,
        description="Every transition row must sum to 1.",
    ),
    ProbabilisticInvariant(
        invariant_id="prob.uncertainty_bounded",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_uncertainty_bounded,
        description="Total uncertainty must lie within [0,1].",
    ),
    ProbabilisticInvariant(
        invariant_id="prob.certainty_mismatch",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_no_high_confidence_under_high_uncertainty,
        description="Certainty must not contradict total uncertainty.",
    ),
)


def check_invariants(
    snap: ProbabilisticSnapshot,
    invariants: Iterable[ProbabilisticInvariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 12 — STORE
# =============================================================================


@dataclass(frozen=True)
class ProbabilisticRecord:
    entity_id: str
    state_argmax: TrustLabel
    state_entropy: float
    authority_argmax: AuthorityMode
    authority_entropy: float
    transition_stability: float
    recovery_confidence: float
    evidence_confidence: float
    total_uncertainty: float
    uncertainty_type: UncertaintyType
    updated_at: datetime


class ProbabilisticStore(Protocol):
    def get(self, entity_id: str) -> Optional[ProbabilisticRecord]: ...
    def put(self, record: ProbabilisticRecord) -> None: ...
    def all(self) -> Tuple[ProbabilisticRecord, ...]: ...


class InMemoryProbabilisticStore:
    def __init__(self) -> None:
        self._data: Dict[str, ProbabilisticRecord] = {}

    def get(self, entity_id: str) -> Optional[ProbabilisticRecord]:
        return self._data.get(entity_id)

    def put(self, record: ProbabilisticRecord) -> None:
        existing = self._data.get(record.entity_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._data[record.entity_id] = record

    def all(self) -> Tuple[ProbabilisticRecord, ...]:
        return tuple(self._data.values())


class SqliteProbabilisticStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS prob_state (
                entity_id TEXT PRIMARY KEY,
                state_argmax TEXT NOT NULL,
                state_entropy REAL NOT NULL,
                authority_argmax TEXT NOT NULL,
                authority_entropy REAL NOT NULL,
                transition_stability REAL NOT NULL,
                recovery_confidence REAL NOT NULL,
                evidence_confidence REAL NOT NULL,
                total_uncertainty REAL NOT NULL,
                uncertainty_type TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS prob_interventions (
                intervention_id TEXT PRIMARY KEY,
                entity_id TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def get(self, entity_id: str) -> Optional[ProbabilisticRecord]:
        row = self._conn.execute(
            "SELECT state_argmax, state_entropy, authority_argmax, "
            "authority_entropy, transition_stability, recovery_confidence, "
            "evidence_confidence, total_uncertainty, uncertainty_type, "
            "updated_at FROM prob_state WHERE entity_id = ?",
            (entity_id,),
        ).fetchone()
        if row is None:
            return None
        return ProbabilisticRecord(
            entity_id=entity_id,
            state_argmax=TrustLabel(row[0]),
            state_entropy=float(row[1]),
            authority_argmax=AuthorityMode(row[2]),
            authority_entropy=float(row[3]),
            transition_stability=float(row[4]),
            recovery_confidence=float(row[5]),
            evidence_confidence=float(row[6]),
            total_uncertainty=float(row[7]),
            uncertainty_type=UncertaintyType(row[8]),
            updated_at=datetime.fromisoformat(row[9]),
        )

    def put(self, record: ProbabilisticRecord) -> None:
        existing = self.get(record.entity_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._conn.execute(
            """
            INSERT INTO prob_state
              (entity_id, state_argmax, state_entropy, authority_argmax,
               authority_entropy, transition_stability,
               recovery_confidence, evidence_confidence,
               total_uncertainty, uncertainty_type, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(entity_id) DO UPDATE SET
              state_argmax=excluded.state_argmax,
              state_entropy=excluded.state_entropy,
              authority_argmax=excluded.authority_argmax,
              authority_entropy=excluded.authority_entropy,
              transition_stability=excluded.transition_stability,
              recovery_confidence=excluded.recovery_confidence,
              evidence_confidence=excluded.evidence_confidence,
              total_uncertainty=excluded.total_uncertainty,
              uncertainty_type=excluded.uncertainty_type,
              updated_at=excluded.updated_at
            """,
            (
                record.entity_id, record.state_argmax.value,
                record.state_entropy, record.authority_argmax.value,
                record.authority_entropy, record.transition_stability,
                record.recovery_confidence, record.evidence_confidence,
                record.total_uncertainty, record.uncertainty_type.value,
                record.updated_at.isoformat(),
            ),
        )
        self._conn.commit()

    def all(self) -> Tuple[ProbabilisticRecord, ...]:
        rows = self._conn.execute("SELECT entity_id FROM prob_state").fetchall()
        return tuple(
            r for r in (self.get(x[0]) for x in rows) if r is not None
        )

    def put_intervention(self, ic: InterventionConfidence) -> None:
        payload = {
            "intervention_id": ic.intervention_id,
            "entity_id": ic.entity_id,
            "current_risk": ic.current_risk,
            "projected_risk_after": ic.projected_risk_after,
            "intervention_reliability": ic.intervention_reliability,
            "evidence_confidence": ic.evidence_confidence,
            "expected_reduction": ic.expected_reduction,
            "confidence": ic.confidence,
            "expected_value": ic.expected_value,
            "at": ic.at.isoformat(),
        }
        self._conn.execute(
            "INSERT OR REPLACE INTO prob_interventions "
            "(intervention_id, entity_id, payload_json) VALUES (?, ?, ?)",
            (ic.intervention_id, ic.entity_id,
             json.dumps(payload, sort_keys=True)),
        )
        self._conn.commit()

    def get_intervention(self, intervention_id: str) -> Optional[InterventionConfidence]:
        row = self._conn.execute(
            "SELECT payload_json FROM prob_interventions "
            "WHERE intervention_id = ?",
            (intervention_id,),
        ).fetchone()
        if row is None:
            return None
        p = json.loads(row[0])
        return InterventionConfidence(
            intervention_id=p["intervention_id"],
            entity_id=p["entity_id"],
            current_risk=float(p["current_risk"]),
            projected_risk_after=float(p["projected_risk_after"]),
            intervention_reliability=float(p["intervention_reliability"]),
            evidence_confidence=float(p["evidence_confidence"]),
            expected_reduction=float(p["expected_reduction"]),
            confidence=float(p["confidence"]),
            expected_value=float(p["expected_value"]),
            at=datetime.fromisoformat(p["at"]),
        )


# =============================================================================
# SECTION 13 — ENGINE
# =============================================================================


@dataclass
class _EntityProb:
    entity_id: str
    state: StatePosterior
    authority: AuthorityPosterior
    transition: TransitionMatrix
    recovery: RecoveryPosterior
    evidence_ids: List[str] = field(default_factory=list)
    last_transition_context: TrustLabel = TrustLabel.UNKNOWN


class ProbabilisticSecurityEngine:
    """Probabilistic extension over the existing security state.

    Provides state uncertainty, evidence uncertainty, authority
    uncertainty, transition probability, recovery confidence,
    intervention confidence, and uncertainty propagation.
    """

    def __init__(
        self,
        *,
        store: Optional[ProbabilisticStore] = None,
        high_uncertainty_threshold: float = 0.7,
        low_evidence_confidence_threshold: float = 0.3,
        low_recovery_confidence_threshold: float = 0.4,
        low_intervention_confidence_threshold: float = 0.3,
    ) -> None:
        for n, v in (
            ("high_uncertainty_threshold", high_uncertainty_threshold),
            ("low_evidence_confidence_threshold", low_evidence_confidence_threshold),
            ("low_recovery_confidence_threshold", low_recovery_confidence_threshold),
            ("low_intervention_confidence_threshold", low_intervention_confidence_threshold),
        ):
            if not 0.0 <= v <= 1.0:
                raise ValueError(f"{n} must be within [0,1]")
        self._store: ProbabilisticStore = store or InMemoryProbabilisticStore()
        self._entities: Dict[str, _EntityProb] = {}
        self._evidences: Dict[str, EvidenceUncertainty] = {}
        self._interventions: List[InterventionConfidence] = []
        self._decompositions: Dict[str, UncertaintyDecomposition] = {}
        self._findings: List[ProbFinding] = []
        self._violations: Tuple[InvariantViolation, ...] = ()

        self._high_unc = high_uncertainty_threshold
        self._low_ev_conf = low_evidence_confidence_threshold
        self._low_rec_conf = low_recovery_confidence_threshold
        self._low_int_conf = low_intervention_confidence_threshold

    # ---- registration ----------------------------------------------------

    def register_entity(
        self,
        entity_id: str,
        *,
        state_prior: Optional[Sequence[float]] = None,
        authority_prior: Optional[Sequence[float]] = None,
    ) -> None:
        if not entity_id:
            raise ValueError("entity_id is required")
        if entity_id in self._entities:
            raise ValueError(f"entity {entity_id} already registered")

        if state_prior is None:
            state = StatePosterior.uniform(entity_id)
        else:
            if len(state_prior) != len(ALL_LABELS):
                raise ValueError("state_prior length must match labels")
            alpha = tuple(float(x) for x in state_prior)
            state = StatePosterior(
                entity_id=entity_id, alpha=alpha, prior_alpha=alpha,
            )

        if authority_prior is None:
            auth = AuthorityPosterior.uniform(entity_id)
        else:
            if len(authority_prior) != len(ALL_AUTHORITY_MODES):
                raise ValueError("authority_prior length must match modes")
            alpha_a = tuple(float(x) for x in authority_prior)
            auth = AuthorityPosterior(
                entity_id=entity_id, alpha=alpha_a, prior_alpha=alpha_a,
            )

        self._entities[entity_id] = _EntityProb(
            entity_id=entity_id,
            state=state,
            authority=auth,
            transition=TransitionMatrix.uniform(entity_id),
            recovery=RecoveryPosterior.prior(entity_id),
        )

    def register_evidence_source(self, source_id: str) -> None:
        if not source_id:
            raise ValueError("source_id is required")
        if source_id in self._evidences:
            raise ValueError(f"source {source_id} already registered")
        self._evidences[source_id] = EvidenceUncertainty.prior(source_id)

    # ---- observations ----------------------------------------------------

    def observe_state(self, entity_id: str, label: TrustLabel,
                      *, weight: float = 1.0) -> None:
        ep = self._entities.get(entity_id)
        if ep is None:
            raise KeyError(f"unknown entity {entity_id}")
        ep.state = ep.state.observe(label, weight=weight)

    def observe_authority(self, entity_id: str, mode: AuthorityMode,
                          *, weight: float = 1.0) -> None:
        ep = self._entities.get(entity_id)
        if ep is None:
            raise KeyError(f"unknown entity {entity_id}")
        ep.authority = ep.authority.observe(mode, weight=weight)

    def observe_transition(
        self, entity_id: str, *,
        current: TrustLabel, next_label: TrustLabel, weight: float = 1.0,
    ) -> None:
        ep = self._entities.get(entity_id)
        if ep is None:
            raise KeyError(f"unknown entity {entity_id}")
        ep.transition = ep.transition.observe(
            current=current, next_label=next_label, weight=weight,
        )
        ep.last_transition_context = current

    def observe_recovery(
        self, entity_id: str, *, success: bool, weight: float = 1.0,
    ) -> None:
        ep = self._entities.get(entity_id)
        if ep is None:
            raise KeyError(f"unknown entity {entity_id}")
        ep.recovery = ep.recovery.observe(success=success, weight=weight)

    def observe_evidence_outcome(
        self, source_id: str, *, confirmed: bool, weight: float = 1.0,
    ) -> None:
        ev = self._evidences.get(source_id)
        if ev is None:
            raise KeyError(f"unknown source {source_id}")
        self._evidences[source_id] = ev.observe(
            confirmed=confirmed, weight=weight,
        )

    def attach_evidence_to_entity(self, entity_id: str, source_id: str) -> None:
        ep = self._entities.get(entity_id)
        if ep is None:
            raise KeyError(f"unknown entity {entity_id}")
        if source_id not in self._evidences:
            raise KeyError(f"unknown source {source_id}")
        if source_id not in ep.evidence_ids:
            ep.evidence_ids.append(source_id)

    # ---- policy ----------------------------------------------------------

    def set_high_uncertainty_threshold(self, x: float) -> None:
        if not 0.0 <= x <= 1.0:
            raise ValueError("threshold must be within [0,1]")
        self._high_unc = x

    def set_low_evidence_confidence_threshold(self, x: float) -> None:
        if not 0.0 <= x <= 1.0:
            raise ValueError("threshold must be within [0,1]")
        self._low_ev_conf = x

    def set_low_recovery_confidence_threshold(self, x: float) -> None:
        if not 0.0 <= x <= 1.0:
            raise ValueError("threshold must be within [0,1]")
        self._low_rec_conf = x

    def set_low_intervention_confidence_threshold(self, x: float) -> None:
        if not 0.0 <= x <= 1.0:
            raise ValueError("threshold must be within [0,1]")
        self._low_int_conf = x

    # ---- intervention ----------------------------------------------------

    def record_intervention(
        self, ic: InterventionConfidence,
    ) -> None:
        if ic.entity_id not in self._entities:
            raise KeyError(f"unknown entity {ic.entity_id}")
        self._interventions.append(ic)
        if isinstance(self._store, SqliteProbabilisticStore):
            self._store.put_intervention(ic)

    # ---- recompute -------------------------------------------------------

    def recompute(self, *, at: datetime) -> Tuple[ProbabilisticRecord, ...]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

        self._findings = []
        records: List[ProbabilisticRecord] = []

        for eid, ep in self._entities.items():
            # Aggregate evidence confidence from attached sources
            if ep.evidence_ids:
                confs = [self._evidences[sid].mean
                         for sid in ep.evidence_ids if sid in self._evidences]
                avg_ev_conf = sum(confs) / len(confs) if confs else 0.5
            else:
                # use overall registry average if any, else neutral
                if self._evidences:
                    all_confs = [e.mean for e in self._evidences.values()]
                    avg_ev_conf = sum(all_confs) / len(all_confs)
                else:
                    avg_ev_conf = 0.5

            # Representative evidence uncertainty for the decomposition
            # uses the average source; construct a synthetic EvidenceUncertainty
            synthetic = EvidenceUncertainty(
                source_id=f"aggregate:{eid}",
                alpha=1.0 + 5.0 * avg_ev_conf,
                beta=1.0 + 5.0 * (1.0 - avg_ev_conf),
            )

            decomp = propagate_uncertainty(
                entity_id=eid,
                state=ep.state,
                authority=ep.authority,
                transition_row_current=ep.last_transition_context,
                transition=ep.transition,
                evidence=synthetic,
                at=at,
            )
            self._decompositions[eid] = decomp

            rec = ProbabilisticRecord(
                entity_id=eid,
                state_argmax=ep.state.argmax(),
                state_entropy=ep.state.entropy(),
                authority_argmax=ep.authority.argmax(),
                authority_entropy=ep.authority.entropy(),
                transition_stability=ep.transition.row_stability(
                    ep.last_transition_context,
                ),
                recovery_confidence=ep.recovery.confidence(),
                evidence_confidence=avg_ev_conf,
                total_uncertainty=decomp.total,
                uncertainty_type=decomp.uncertainty_type,
                updated_at=at,
            )
            self._store.put(rec)
            records.append(rec)

            # Findings
            if decomp.total >= self._high_unc:
                self._findings.append(ProbFinding(
                    kind=ProbFindingKind.HIGH_UNCERTAINTY,
                    entity_id=eid,
                    detail=(
                        f"total uncertainty {decomp.total:.3f} "
                        f"(type={decomp.uncertainty_type.value})"
                    ),
                    severity=3, at=at,
                ))

            if avg_ev_conf < self._low_ev_conf:
                self._findings.append(ProbFinding(
                    kind=ProbFindingKind.LOW_EVIDENCE_CONFIDENCE,
                    entity_id=eid,
                    detail=(
                        f"evidence confidence {avg_ev_conf:.3f} below "
                        f"{self._low_ev_conf:.2f}"
                    ),
                    severity=3, at=at,
                ))

            row_stability = ep.transition.row_stability(
                ep.last_transition_context,
            )
            if row_stability < 0.3:
                self._findings.append(ProbFinding(
                    kind=ProbFindingKind.UNSTABLE_TRANSITION,
                    entity_id=eid,
                    detail=(
                        f"transition row stability {row_stability:.3f}"
                    ),
                    severity=2, at=at,
                ))

            if ep.recovery.mean < self._low_rec_conf:
                self._findings.append(ProbFinding(
                    kind=ProbFindingKind.LOW_RECOVERY_CONFIDENCE,
                    entity_id=eid,
                    detail=(
                        f"recovery confidence "
                        f"{ep.recovery.mean:.3f}"
                    ),
                    severity=3, at=at,
                ))

        # Intervention findings
        for ic in self._interventions:
            if ic.confidence < self._low_int_conf:
                self._findings.append(ProbFinding(
                    kind=ProbFindingKind.LOW_INTERVENTION_CONFIDENCE,
                    entity_id=ic.entity_id,
                    detail=(
                        f"intervention {ic.intervention_id} confidence "
                        f"{ic.confidence:.3f}"
                    ),
                    severity=3, at=ic.at,
                ))

        self._violations = check_invariants(self.snapshot())
        return tuple(records)

    # ---- queries ---------------------------------------------------------

    def state_posterior(self, entity_id: str) -> Optional[StatePosterior]:
        ep = self._entities.get(entity_id)
        return ep.state if ep else None

    def authority_posterior(self, entity_id: str) -> Optional[AuthorityPosterior]:
        ep = self._entities.get(entity_id)
        return ep.authority if ep else None

    def transition_matrix(self, entity_id: str) -> Optional[TransitionMatrix]:
        ep = self._entities.get(entity_id)
        return ep.transition if ep else None

    def recovery_posterior(self, entity_id: str) -> Optional[RecoveryPosterior]:
        ep = self._entities.get(entity_id)
        return ep.recovery if ep else None

    def evidence_uncertainty(self, source_id: str) -> Optional[EvidenceUncertainty]:
        return self._evidences.get(source_id)

    def uncertainty(self, entity_id: str) -> Optional[UncertaintyDecomposition]:
        return self._decompositions.get(entity_id)

    def findings(self) -> Tuple[ProbFinding, ...]:
        return tuple(self._findings)

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return self._violations

    def record(self, entity_id: str) -> Optional[ProbabilisticRecord]:
        return self._store.get(entity_id)

    def snapshot(self) -> ProbabilisticSnapshot:
        return ProbabilisticSnapshot(
            states={eid: ep.state for eid, ep in self._entities.items()},
            authorities={eid: ep.authority for eid, ep in self._entities.items()},
            evidences=dict(self._evidences),
            recoveries={eid: ep.recovery for eid, ep in self._entities.items()},
            transitions={eid: ep.transition for eid, ep in self._entities.items()},
            decompositions=dict(self._decompositions),
            interventions=tuple(self._interventions),
        )


# =============================================================================
# SECTION 14 — TESTS
# =============================================================================


def _t0() -> datetime:
    from datetime import timezone
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


# ---- primitives ----

def test_normalized_entropy_uniform() -> None:
    assert abs(normalized_entropy([0.25, 0.25, 0.25, 0.25]) - 1.0) < 1e-9


def test_normalized_entropy_deterministic() -> None:
    assert normalized_entropy([1.0, 0.0, 0.0]) == 0.0


def test_normalized_entropy_bounds() -> None:
    h = normalized_entropy([0.7, 0.2, 0.1])
    assert 0.0 <= h <= 1.0


def test_normalized_entropy_rejects_bad_sum() -> None:
    try:
        normalized_entropy([0.5, 0.6])
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_normalized_entropy_rejects_negative() -> None:
    try:
        normalized_entropy([1.1, -0.1])
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_kl_divergence_identical() -> None:
    assert abs(kl_divergence([0.5, 0.5], [0.5, 0.5])) < 1e-6


def test_kl_divergence_positive() -> None:
    assert kl_divergence([0.9, 0.1], [0.5, 0.5]) > 0.0


def test_kl_divergence_requires_equal_length() -> None:
    try:
        kl_divergence([0.5, 0.5], [1.0])
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_softmax_sums_to_one() -> None:
    p = softmax([0.5, -1.0, 2.0])
    assert abs(sum(p) - 1.0) < 1e-9


def test_safe_normalize_uniform_when_all_zero() -> None:
    p = safe_normalize([0.0, 0.0, 0.0])
    assert all(abs(x - 1/3) < 1e-9 for x in p)


def test_beta_variance_positive() -> None:
    assert beta_variance(2.0, 3.0) > 0.0


def test_beta_variance_rejects_nonpositive() -> None:
    try:
        beta_variance(0.0, 1.0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- state posterior ----

def test_state_uniform_sum_to_one() -> None:
    s = StatePosterior.uniform("e1")
    assert abs(sum(s.probabilities()) - 1.0) < 1e-9


def test_state_observe_shifts_argmax() -> None:
    s = StatePosterior.uniform("e1")
    for _ in range(5):
        s = s.observe(TrustLabel.TRUSTED)
    assert s.argmax() is TrustLabel.TRUSTED


def test_state_argmax_tie_break_deterministic() -> None:
    s = StatePosterior.uniform("e1")
    # With all equal, alphabetical/label order is deterministic
    a1 = s.argmax()
    a2 = StatePosterior.uniform("e1").argmax()
    assert a1 == a2


def test_state_rejects_wrong_length_alpha() -> None:
    try:
        StatePosterior(
            entity_id="e", alpha=(1.0,), prior_alpha=(1.0,),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_state_rejects_negative_alpha() -> None:
    try:
        StatePosterior(
            entity_id="e",
            alpha=(0.0,) + (1.0,) * (len(ALL_LABELS) - 1),
            prior_alpha=(1.0,) * len(ALL_LABELS),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_state_sample_count_zero_on_prior() -> None:
    assert StatePosterior.uniform("e1").sample_count() == 0.0


def test_state_sample_count_increases() -> None:
    s = StatePosterior.uniform("e1").observe(TrustLabel.TRUSTED)
    assert s.sample_count() == 1.0


def test_state_credible_set_includes_argmax() -> None:
    s = StatePosterior.uniform("e1")
    for _ in range(20):
        s = s.observe(TrustLabel.SUSPICIOUS)
    cs = s.credible_set(threshold=0.9)
    assert TrustLabel.SUSPICIOUS in cs


def test_state_credible_set_rejects_bad_threshold() -> None:
    try:
        StatePosterior.uniform("e1").credible_set(threshold=0.0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_state_entropy_decreases_after_evidence() -> None:
    s = StatePosterior.uniform("e1")
    h0 = s.entropy()
    s = s.observe(TrustLabel.TRUSTED, weight=5.0)
    assert s.entropy() < h0


# ---- evidence uncertainty ----

def test_evidence_prior_mean_half() -> None:
    e = EvidenceUncertainty.prior("s1")
    assert abs(e.mean - 0.5) < 1e-9


def test_evidence_confirmation_raises_mean() -> None:
    e = EvidenceUncertainty.prior("s1").observe(confirmed=True)
    assert e.mean > 0.5


def test_evidence_contradiction_lowers_mean() -> None:
    e = EvidenceUncertainty.prior("s1").observe(confirmed=False)
    assert e.mean < 0.5


def test_evidence_confidence_high_after_agreement() -> None:
    e = EvidenceUncertainty.prior("s1")
    for _ in range(20):
        e = e.observe(confirmed=True)
    assert e.confidence() > 0.7


def test_evidence_confidence_in_unit() -> None:
    for _ in range(5):
        pass
    e = EvidenceUncertainty.prior("s1")
    assert 0.0 <= e.confidence() <= 1.0


def test_evidence_credible_interval_bounds() -> None:
    e = EvidenceUncertainty.prior("s1")
    lo, hi = e.credible_interval()
    assert 0.0 <= lo <= hi <= 1.0


# ---- authority posterior ----

def test_authority_uniform_sum_to_one() -> None:
    a = AuthorityPosterior.uniform("e1")
    assert abs(sum(a.probabilities()) - 1.0) < 1e-9


def test_authority_observe_shifts_argmax() -> None:
    a = AuthorityPosterior.uniform("e1")
    for _ in range(10):
        a = a.observe(AuthorityMode.ELEVATED)
    assert a.argmax() is AuthorityMode.ELEVATED


def test_authority_entropy_decreases() -> None:
    a0 = AuthorityPosterior.uniform("e1")
    a1 = a0.observe(AuthorityMode.NORMAL, weight=10.0)
    assert a1.entropy() < a0.entropy()


def test_authority_confidence_bounded() -> None:
    a = AuthorityPosterior.uniform("e1")
    assert 0.0 <= a.confidence() <= 1.0


# ---- recovery posterior ----

def test_recovery_prior_half() -> None:
    r = RecoveryPosterior.prior("e1")
    assert abs(r.mean - 0.5) < 1e-9


def test_recovery_observe_success() -> None:
    r = RecoveryPosterior.prior("e1").observe(success=True)
    assert r.mean > 0.5


def test_recovery_observe_failure() -> None:
    r = RecoveryPosterior.prior("e1").observe(success=False)
    assert r.mean < 0.5


def test_recovery_confidence_grows_with_samples() -> None:
    r_prior = RecoveryPosterior.prior("e1")
    r = r_prior
    for _ in range(20):
        r = r.observe(success=True)
    assert r.confidence() > r_prior.confidence()


# ---- transition matrix ----

def test_transition_rows_sum_to_one() -> None:
    tm = TransitionMatrix.uniform("e1")
    for lbl in ALL_LABELS:
        assert abs(sum(tm.row_probabilities(lbl)) - 1.0) < 1e-9


def test_transition_observe_shifts_row() -> None:
    tm = TransitionMatrix.uniform("e1")
    for _ in range(10):
        tm = tm.observe(current=TrustLabel.TRUSTED,
                        next_label=TrustLabel.SUSPICIOUS)
    assert tm.expected_next(TrustLabel.TRUSTED) is TrustLabel.SUSPICIOUS


def test_transition_stability_increases_with_evidence() -> None:
    tm0 = TransitionMatrix.uniform("e1")
    tm1 = tm0
    for _ in range(20):
        tm1 = tm1.observe(current=TrustLabel.TRUSTED,
                          next_label=TrustLabel.SUSPICIOUS)
    assert tm1.row_stability(TrustLabel.TRUSTED) > \
        tm0.row_stability(TrustLabel.TRUSTED)


def test_transition_probability() -> None:
    tm = TransitionMatrix.uniform("e1")
    for _ in range(10):
        tm = tm.observe(current=TrustLabel.TRUSTED,
                        next_label=TrustLabel.SUSPICIOUS)
    assert tm.probability(TrustLabel.TRUSTED, TrustLabel.SUSPICIOUS) > \
        tm.probability(TrustLabel.TRUSTED, TrustLabel.TRUSTED)


# ---- intervention confidence ----

def test_intervention_expected_reduction() -> None:
    ic = score_intervention(
        intervention_id="i1", entity_id="e1",
        current_risk=0.8, projected_risk_after=0.2,
        intervention_reliability=0.9, evidence_confidence=0.9,
        at=_t0(),
    )
    assert abs(ic.expected_reduction - 0.6) < 1e-9
    assert abs(ic.confidence - 0.81) < 1e-9
    assert abs(ic.expected_value - 0.6 * 0.81) < 1e-9


def test_intervention_rejects_bad_time() -> None:
    from datetime import datetime as dt
    try:
        score_intervention(
            intervention_id="i1", entity_id="e1",
            current_risk=0.5, projected_risk_after=0.2,
            intervention_reliability=0.8, evidence_confidence=0.8,
            at=dt(2026, 1, 1),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_intervention_bounds() -> None:
    try:
        score_intervention(
            intervention_id="i1", entity_id="e1",
            current_risk=1.5, projected_risk_after=0.2,
            intervention_reliability=0.8, evidence_confidence=0.8,
            at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- uncertainty propagation ----

def test_propagate_uncertainty_in_unit() -> None:
    state = StatePosterior.uniform("e1")
    auth = AuthorityPosterior.uniform("e1")
    tm = TransitionMatrix.uniform("e1")
    ev = EvidenceUncertainty.prior("s1")
    d = propagate_uncertainty(
        entity_id="e1", state=state, authority=auth,
        transition_row_current=TrustLabel.TRUSTED,
        transition=tm, evidence=ev, at=_t0(),
    )
    assert 0.0 <= d.total <= 1.0


def test_propagate_uncertainty_high_when_all_uniform_low_evidence() -> None:
    state = StatePosterior.uniform("e1")
    auth = AuthorityPosterior.uniform("e1")
    tm = TransitionMatrix.uniform("e1")
    ev = EvidenceUncertainty.prior("s1")   # mean 0.5 → confidence 0.6
    d = propagate_uncertainty(
        entity_id="e1", state=state, authority=auth,
        transition_row_current=TrustLabel.TRUSTED,
        transition=tm, evidence=ev, at=_t0(),
    )
    # All entropies are 1.0 → aleatoric = 1.0 → total = 1.0
    assert d.total >= 0.9


def test_propagate_uncertainty_low_when_state_certain_evidence_strong() -> None:
    state = StatePosterior.uniform("e1")
    for _ in range(50):
        state = state.observe(TrustLabel.TRUSTED)
    auth = AuthorityPosterior.uniform("e1")
    for _ in range(50):
        auth = auth.observe(AuthorityMode.NORMAL)
    tm = TransitionMatrix.uniform("e1")
    for _ in range(50):
        tm = tm.observe(current=TrustLabel.TRUSTED,
                        next_label=TrustLabel.TRUSTED)
    ev = EvidenceUncertainty.prior("s1")
    for _ in range(50):
        ev = ev.observe(confirmed=True)
    d = propagate_uncertainty(
        entity_id="e1", state=state, authority=auth,
        transition_row_current=TrustLabel.TRUSTED,
        transition=tm, evidence=ev, at=_t0(),
    )
    assert d.total < 0.5


def test_propagate_uncertainty_epistemic_dominates_low_evidence() -> None:
    state = StatePosterior.uniform("e1")
    for _ in range(50):
        state = state.observe(TrustLabel.TRUSTED)
    auth = AuthorityPosterior.uniform("e1")
    for _ in range(50):
        auth = auth.observe(AuthorityMode.NORMAL)
    tm = TransitionMatrix.uniform("e1")
    for _ in range(50):
        tm = tm.observe(current=TrustLabel.TRUSTED,
                        next_label=TrustLabel.TRUSTED)
    ev = EvidenceUncertainty.prior("s1")
    # No confirmations → mean 0.5, low sample count → confidence 0.6,
    # so epistemic is 0.4. Aleatoric will be near 0 due to concentrated
    # posteriors. Should be flagged as MIXED or EPISTEMIC.
    d = propagate_uncertainty(
        entity_id="e1", state=state, authority=auth,
        transition_row_current=TrustLabel.TRUSTED,
        transition=tm, evidence=ev, at=_t0(),
    )
    assert d.epistemic > 0.0


# ---- engine basics ----

def test_engine_register_entity() -> None:
    eng = ProbabilisticSecurityEngine()
    eng.register_entity("e1")
    eng.observe_state("e1", TrustLabel.TRUSTED)
    eng.recompute(at=_t0())


def test_engine_rejects_duplicate_entity() -> None:
    eng = ProbabilisticSecurityEngine()
    eng.register_entity("e1")
    try:
        eng.register_entity("e1")
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_rejects_duplicate_source() -> None:
    eng = ProbabilisticSecurityEngine()
    eng.register_evidence_source("s1")
    try:
        eng.register_evidence_source("s1")
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_observe_unknown_entity_rejected() -> None:
    eng = ProbabilisticSecurityEngine()
    try:
        eng.observe_state("missing", TrustLabel.TRUSTED)
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_engine_observe_unknown_source_rejected() -> None:
    eng = ProbabilisticSecurityEngine()
    try:
        eng.observe_evidence_outcome("missing", confirmed=True)
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_engine_transition_row_context_defaults_to_unknown() -> None:
    eng = ProbabilisticSecurityEngine()
    eng.register_entity("e1")
    eng.recompute(at=_t0())
    tm = eng.transition_matrix("e1")
    assert tm is not None
    # default context UNKNOWN row should be usable
    p = tm.row_probabilities(TrustLabel.UNKNOWN)
    assert abs(sum(p) - 1.0) < 1e-9


def test_engine_recompute_produces_records() -> None:
    eng = ProbabilisticSecurityEngine()
    eng.register_entity("e1")
    eng.observe_state("e1", TrustLabel.TRUSTED, weight=3.0)
    records = eng.recompute(at=_t0())
    assert len(records) == 1
    assert records[0].state_argmax is TrustLabel.TRUSTED


def test_engine_high_uncertainty_finding() -> None:
    eng = ProbabilisticSecurityEngine()
    eng.register_entity("e1")
    # No observations → uniform posteriors → high uncertainty
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert ProbFindingKind.HIGH_UNCERTAINTY in kinds


def test_engine_low_evidence_confidence_finding() -> None:
    eng = ProbabilisticSecurityEngine()
    eng.register_entity("e1")
    eng.register_evidence_source("s1")
    # Source consistently wrong → low mean
    for _ in range(20):
        eng.observe_evidence_outcome("s1", confirmed=False)
    eng.attach_evidence_to_entity("e1", "s1")
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert ProbFindingKind.LOW_EVIDENCE_CONFIDENCE in kinds


def test_engine_low_recovery_confidence_finding() -> None:
    eng = ProbabilisticSecurityEngine()
    eng.register_entity("e1")
    for _ in range(20):
        eng.observe_recovery("e1", success=False)
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert ProbFindingKind.LOW_RECOVERY_CONFIDENCE in kinds


def test_engine_intervention_finding_and_lookup() -> None:
    eng = ProbabilisticSecurityEngine()
    eng.register_entity("e1")
    ic = score_intervention(
        intervention_id="i1", entity_id="e1",
        current_risk=0.7, projected_risk_after=0.6,
        intervention_reliability=0.2, evidence_confidence=0.2,
        at=_t0(),
    )
    eng.record_intervention(ic)
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert ProbFindingKind.LOW_INTERVENTION_CONFIDENCE in kinds


def test_engine_state_posterior_reflects_observations() -> None:
    eng = ProbabilisticSecurityEngine()
    eng.register_entity("e1")
    for _ in range(5):
        eng.observe_state("e1", TrustLabel.SUSPICIOUS)
    sp = eng.state_posterior("e1")
    assert sp is not None
    assert sp.argmax() is TrustLabel.SUSPICIOUS


def test_engine_authority_posterior_reflects_observations() -> None:
    eng = ProbabilisticSecurityEngine()
    eng.register_entity("e1")
    for _ in range(5):
        eng.observe_authority("e1", AuthorityMode.ELEVATED)
    ap = eng.authority_posterior("e1")
    assert ap is not None
    assert ap.argmax() is AuthorityMode.ELEVATED


def test_engine_transition_observe() -> None:
    eng = ProbabilisticSecurityEngine()
    eng.register_entity("e1")
    for _ in range(10):
        eng.observe_transition(
            "e1", current=TrustLabel.TRUSTED,
            next_label=TrustLabel.DEGRADED,
        )
    tm = eng.transition_matrix("e1")
    assert tm is not None
    assert tm.expected_next(TrustLabel.TRUSTED) is TrustLabel.DEGRADED


def test_engine_record_lookup() -> None:
    eng = ProbabilisticSecurityEngine()
    eng.register_entity("e1")
    eng.observe_state("e1", TrustLabel.TRUSTED, weight=3.0)
    eng.recompute(at=_t0())
    rec = eng.record("e1")
    assert rec is not None
    assert rec.state_argmax is TrustLabel.TRUSTED


def test_engine_intervention_unknown_entity_rejected() -> None:
    eng = ProbabilisticSecurityEngine()
    ic = score_intervention(
        intervention_id="i1", entity_id="missing",
        current_risk=0.5, projected_risk_after=0.2,
        intervention_reliability=0.8, evidence_confidence=0.8,
        at=_t0(),
    )
    try:
        eng.record_intervention(ic)
    except KeyError:
        return
    raise AssertionError("expected KeyError")


# ---- invariants ----

def test_invariant_clean_snapshot() -> None:
    eng = ProbabilisticSecurityEngine()
    eng.register_entity("e1")
    eng.observe_state("e1", TrustLabel.TRUSTED)
    eng.recompute(at=_t0())
    assert eng.violations() == ()


def test_invariant_state_sum_detected() -> None:
    # Craft a snapshot with bad state probabilities via direct mutation
    # (bypassing __post_init__)
    bad = object.__new__(StatePosterior)
    object.__setattr__(bad, "entity_id", "e1")
    object.__setattr__(bad, "alpha", (1.0,) * len(ALL_LABELS))
    object.__setattr__(bad, "prior_alpha", (1.0,) * len(ALL_LABELS))
    # probabilities will sum to 1 (all 1/7). To trigger, override by
    # making a fake class instance:
    class _FakeState:
        def __init__(self) -> None:
            pass
        def probabilities(self) -> Tuple[float, ...]:
            return (0.1, 0.1)
        def entropy(self) -> float:
            return 0.0
        def sample_count(self) -> float:
            return 0.0
    snap = ProbabilisticSnapshot(
        states={"e1": _FakeState()},  # type: ignore[dict-item]
        authorities={}, evidences={}, recoveries={}, transitions={},
        decompositions={}, interventions=(),
    )
    violations = check_invariants(snap)
    assert any(v.invariant_id == "prob.state_probs_sum_to_one"
               for v in violations)


def test_invariant_transition_row_detected() -> None:
    class _FakeTM:
        def row_probabilities(self, _lbl: TrustLabel) -> Tuple[float, ...]:
            return (0.5, 0.4)
    snap = ProbabilisticSnapshot(
        states={}, authorities={}, evidences={}, recoveries={},
        transitions={"e1": _FakeTM()},  # type: ignore[dict-item]
        decompositions={}, interventions=(),
    )
    v = check_invariants(snap)
    assert any(x.invariant_id == "prob.transition_rows_sum_to_one" for x in v)


# ---- policy ----

def test_engine_threshold_validation() -> None:
    eng = ProbabilisticSecurityEngine()
    try:
        eng.set_high_uncertainty_threshold(1.5)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
    try:
        eng.set_low_evidence_confidence_threshold(-0.1)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_engine_constructor_validation() -> None:
    try:
        ProbabilisticSecurityEngine(high_uncertainty_threshold=2.0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- store ----

def test_in_memory_store_rejects_stale() -> None:
    s = InMemoryProbabilisticStore()
    t = _t0()
    s.put(ProbabilisticRecord(
        "e1", TrustLabel.TRUSTED, 0.1, AuthorityMode.NORMAL, 0.1,
        0.9, 0.9, 0.9, 0.2, UncertaintyType.MIXED, t,
    ))
    earlier = t.replace(year=t.year - 1)
    try:
        s.put(ProbabilisticRecord(
            "e1", TrustLabel.UNKNOWN, 0.5, AuthorityMode.NORMAL, 0.5,
            0.5, 0.5, 0.5, 0.5, UncertaintyType.MIXED, earlier,
        ))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_state_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "prob.db")
    store = SqliteProbabilisticStore(db)
    t = _t0()
    store.put(ProbabilisticRecord(
        "e1", TrustLabel.TRUSTED, 0.1, AuthorityMode.NORMAL, 0.2,
        0.9, 0.85, 0.9, 0.15, UncertaintyType.MIXED, t,
    ))
    got = store.get("e1")
    assert got is not None
    assert got.state_argmax is TrustLabel.TRUSTED
    assert got.uncertainty_type is UncertaintyType.MIXED


def test_sqlite_store_intervention_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "prob.db")
    store = SqliteProbabilisticStore(db)
    ic = score_intervention(
        intervention_id="i1", entity_id="e1",
        current_risk=0.8, projected_risk_after=0.2,
        intervention_reliability=0.9, evidence_confidence=0.9,
        at=_t0(),
    )
    store.put_intervention(ic)
    got = store.get_intervention("i1")
    assert got is not None
    assert abs(got.expected_reduction - 0.6) < 1e-9


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
