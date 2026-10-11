"""
HYDRA POST-CORE — PHASE 12: ADAPTIVE BEHAVIORAL SECURITY
============================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * Behavior domain — layers, authority states, environment states,
    outcomes, trust labels
  * Statistical primitives (Welford Gaussian, Beta)
  * Multi-layer behavioral state — per (entity, layer) statistical profile
  * Behavior-conditioned state — per (entity, authority, environment)
  * Adaptive trust boundaries — baseline + conditioner widening +
    confidence widening + time-based widening
  * Behavior change attribution — per-layer + per-conditioner
  * Behavior-driven transition prediction (short-horizon)
  * Behavior findings (boundary exceeded, layer deviation, novel
    behavior, rapid change, conditioner violation)
  * Machine-checkable behavioral invariants
  * In-memory + SQLite stores
  * Phase-12 engine facade
  * Full test suite + manual runner

This is NEW adaptive behavioral security technology. It is not a UEBA
product, not an anomaly detector — it is behavior-conditioned trust state
with adaptive boundaries and change attribution.

No third-party dependencies.

Run tests:
    python hydra_phase12_adaptive_behavioral_security.py
    pytest hydra_phase12_adaptive_behavioral_security.py -q
"""
from __future__ import annotations

import json
import math
import sqlite3
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
# SECTION 2 — DOMAIN
# =============================================================================


class BehaviorLayer(str, Enum):
    PROCESS = "process"
    NETWORK = "network"
    IDENTITY = "identity"
    DATA = "data"
    CLOUD = "cloud"
    AGENT = "agent"


ALL_LAYERS: Tuple[BehaviorLayer, ...] = tuple(BehaviorLayer)


class AuthorityState(str, Enum):
    NORMAL = "normal"
    ELEVATED = "elevated"
    DELEGATED = "delegated"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


class EnvironmentState(str, Enum):
    BUSINESS_HOURS = "business_hours"
    OFF_HOURS = "off_hours"
    INCIDENT = "incident"
    MAINTENANCE = "maintenance"
    DEPLOYMENT = "deployment"


class BehaviorOutcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


class TrustLabel(str, Enum):
    UNKNOWN = "unknown"
    OBSERVED = "observed"
    TRUSTED = "trusted"
    DEGRADED = "degraded"
    SUSPICIOUS = "suspicious"
    COMPROMISED = "compromised"
    QUARANTINED = "quarantined"


_LABEL_SEVERITY: Mapping[TrustLabel, int] = {
    TrustLabel.UNKNOWN: 0,
    TrustLabel.OBSERVED: 1,
    TrustLabel.TRUSTED: 1,
    TrustLabel.DEGRADED: 2,
    TrustLabel.SUSPICIOUS: 3,
    TrustLabel.COMPROMISED: 4,
    TrustLabel.QUARANTINED: 5,
}


def label_severity(label: TrustLabel) -> int:
    return _LABEL_SEVERITY[label]


def worse_of(a: TrustLabel, b: TrustLabel) -> TrustLabel:
    return a if label_severity(a) >= label_severity(b) else b


def is_untrusted(label: TrustLabel) -> bool:
    return label in (
        TrustLabel.SUSPICIOUS,
        TrustLabel.COMPROMISED,
        TrustLabel.QUARANTINED,
    )


class BehaviorFindingKind(str, Enum):
    BOUNDARY_EXCEEDED = "boundary_exceeded"
    LAYER_DEVIATION = "layer_deviation"
    CONDITIONER_VIOLATION = "conditioner_violation"
    NOVEL_BEHAVIOR = "novel_behavior"
    RAPID_CHANGE = "rapid_change"
    LOW_CONFIDENCE_BASELINE = "low_confidence_baseline"


class ChangeDirection(str, Enum):
    IMPROVING = "improving"
    STABLE = "stable"
    WORSENING = "worsening"


# =============================================================================
# SECTION 3 — OBSERVATION
# =============================================================================


@dataclass(frozen=True)
class BehaviorObservation:
    observation_id: str
    entity_id: str
    layer: BehaviorLayer
    action: str
    target: str
    authority: AuthorityState
    environment: EnvironmentState
    score: float                     # 0..1, security-relevant risk/behaviour score
    outcome: BehaviorOutcome
    at: datetime

    def __post_init__(self) -> None:
        if not self.observation_id:
            raise ValueError("observation_id is required")
        if not self.entity_id:
            raise ValueError("entity_id is required")
        if not self.action:
            raise ValueError("action is required")
        if not self.target:
            raise ValueError("target is required")
        if not 0.0 <= self.score <= 1.0:
            raise ValueError("score must be within [0,1]")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

    @property
    def key(self) -> Tuple[str, BehaviorLayer]:
        return (self.entity_id, self.layer)


# =============================================================================
# SECTION 4 — STATISTICAL PRIMITIVES
# =============================================================================


Z_95: float = 1.959963984540054


@dataclass(frozen=True)
class GaussianEstimate:
    """Online mean/variance via Welford's algorithm."""
    count: int
    mean: float
    m2: float

    def __post_init__(self) -> None:
        if self.count < 0:
            raise ValueError("count must be >= 0")
        if self.m2 < 0:
            raise ValueError("m2 must be >= 0")

    @classmethod
    def empty(cls) -> "GaussianEstimate":
        return cls(count=0, mean=0.0, m2=0.0)

    def observe(self, x: float) -> "GaussianEstimate":
        n = self.count + 1
        delta = x - self.mean
        mean = self.mean + delta / n
        delta2 = x - mean
        m2 = self.m2 + delta * delta2
        return GaussianEstimate(count=n, mean=mean, m2=m2)

    def observe_many(self, xs: Iterable[float]) -> "GaussianEstimate":
        cur = self
        for x in xs:
            cur = cur.observe(x)
        return cur

    @property
    def variance_sample(self) -> float:
        if self.count < 2:
            return 0.0
        return self.m2 / (self.count - 1)

    @property
    def stddev_sample(self) -> float:
        return math.sqrt(self.variance_sample)


@dataclass(frozen=True)
class BetaEstimate:
    alpha: float
    beta: float
    prior_alpha: float = 1.0
    prior_beta: float = 1.0

    def __post_init__(self) -> None:
        for n, v in (
            ("alpha", self.alpha), ("beta", self.beta),
            ("prior_alpha", self.prior_alpha),
            ("prior_beta", self.prior_beta),
        ):
            if v <= 0:
                raise ValueError(f"{n} must be > 0")
        if self.alpha < self.prior_alpha or self.beta < self.prior_beta:
            raise ValueError("posterior cannot be below prior")

    @classmethod
    def prior(cls, alpha: float = 1.0, beta: float = 1.0) -> "BetaEstimate":
        return cls(alpha=alpha, beta=beta,
                   prior_alpha=alpha, prior_beta=beta)

    @property
    def mean(self) -> float:
        return self.alpha / (self.alpha + self.beta)

    @property
    def sample_count(self) -> float:
        return (self.alpha - self.prior_alpha) + (self.beta - self.prior_beta)

    def observe(self, *, success: bool, weight: float = 1.0) -> "BetaEstimate":
        if weight < 0:
            raise ValueError("weight must be >= 0")
        if success:
            return BetaEstimate(
                alpha=self.alpha + weight, beta=self.beta,
                prior_alpha=self.prior_alpha, prior_beta=self.prior_beta,
            )
        return BetaEstimate(
            alpha=self.alpha, beta=self.beta + weight,
            prior_alpha=self.prior_alpha, prior_beta=self.prior_beta,
        )


# =============================================================================
# SECTION 5 — BEHAVIORAL PROFILES
# =============================================================================


@dataclass(frozen=True)
class BehaviorProfile:
    """Statistical profile of behavior for (entity, layer)."""
    entity_id: str
    layer: BehaviorLayer
    score_stats: GaussianEstimate
    success_rate: BetaEstimate
    sample_count: int
    last_observed_at: Optional[datetime]

    def __post_init__(self) -> None:
        if not self.entity_id:
            raise ValueError("entity_id is required")
        if self.sample_count < 0:
            raise ValueError("sample_count must be >= 0")
        if self.last_observed_at is not None \
           and self.last_observed_at.tzinfo is None:
            raise ValueError("last_observed_at must be timezone-aware")

    @classmethod
    def empty(cls, entity_id: str, layer: BehaviorLayer) -> "BehaviorProfile":
        return cls(
            entity_id=entity_id, layer=layer,
            score_stats=GaussianEstimate.empty(),
            success_rate=BetaEstimate.prior(),
            sample_count=0, last_observed_at=None,
        )

    def observe(
        self,
        obs: BehaviorObservation,
        *,
        weight: float = 1.0,
    ) -> "BehaviorProfile":
        if weight < 0:
            raise ValueError("weight must be >= 0")
        stats = self.score_stats.observe(obs.score)
        success = obs.outcome is BehaviorOutcome.SUCCESS
        rate = self.success_rate.observe(success=success, weight=weight)
        return BehaviorProfile(
            entity_id=self.entity_id, layer=self.layer,
            score_stats=stats, success_rate=rate,
            sample_count=self.sample_count + 1,
            last_observed_at=obs.at,
        )


@dataclass(frozen=True)
class ConditionedProfile:
    """Behavior profile for (entity, authority, environment)."""
    entity_id: str
    authority: AuthorityState
    environment: EnvironmentState
    score_stats: GaussianEstimate
    sample_count: int

    @classmethod
    def empty(
        cls, entity_id: str,
        authority: AuthorityState,
        environment: EnvironmentState,
    ) -> "ConditionedProfile":
        return cls(
            entity_id=entity_id, authority=authority,
            environment=environment,
            score_stats=GaussianEstimate.empty(), sample_count=0,
        )

    def observe(self, score: float) -> "ConditionedProfile":
        return ConditionedProfile(
            entity_id=self.entity_id,
            authority=self.authority, environment=self.environment,
            score_stats=self.score_stats.observe(score),
            sample_count=self.sample_count + 1,
        )

    @property
    def key(self) -> Tuple[str, AuthorityState, EnvironmentState]:
        return (self.entity_id, self.authority, self.environment)


# =============================================================================
# SECTION 6 — ADAPTIVE BOUNDARY
# =============================================================================


# Conditioner widening: how much extra width the boundary gets under
# specific authority/environment contexts.
_AUTHORITY_WIDENING: Mapping[AuthorityState, float] = {
    AuthorityState.NORMAL: 0.0,
    AuthorityState.ELEVATED: 0.10,
    AuthorityState.DELEGATED: 0.05,
    AuthorityState.SUSPENDED: 0.0,
    AuthorityState.REVOKED: 0.0,
}

_ENVIRONMENT_WIDENING: Mapping[EnvironmentState, float] = {
    EnvironmentState.BUSINESS_HOURS: 0.0,
    EnvironmentState.OFF_HOURS: 0.05,
    EnvironmentState.INCIDENT: 0.15,
    EnvironmentState.MAINTENANCE: 0.20,
    EnvironmentState.DEPLOYMENT: 0.15,
}


@dataclass(frozen=True)
class AdaptiveBoundary:
    """Trust boundary for an entity's behavior at a specific context.

    upper = base_mu + k·sd + authority_widen + environment_widen
            + sample_pad + time_pad
    """
    entity_id: str
    layer: BehaviorLayer
    lower: float
    upper: float
    confidence: float
    authority: AuthorityState
    environment: EnvironmentState

    def __post_init__(self) -> None:
        if self.lower > self.upper:
            raise ValueError("lower must be <= upper")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be within [0,1]")

    def contains(self, score: float) -> bool:
        return self.lower <= score <= self.upper


DEFAULT_SIGMA_MULTIPLIER: float = 2.0
DEFAULT_MIN_SAMPLES: int = 20
PAD_PER_SAMPLE: float = 0.01
TIME_PAD_SCALE: float = 0.2
DEFAULT_SIGMA_FALLBACK: float = 0.1


def compute_adaptive_boundary(
    profile: BehaviorProfile,
    *,
    authority: AuthorityState,
    environment: EnvironmentState,
    confidence: float,
    sigma_multiplier: float = DEFAULT_SIGMA_MULTIPLIER,
    min_samples: int = DEFAULT_MIN_SAMPLES,
    conditioned_profile: Optional[ConditionedProfile] = None,
) -> AdaptiveBoundary:
    if confidence < 0.0 or confidence > 1.0:
        raise ValueError("confidence must be within [0,1]")
    if sigma_multiplier < 0:
        raise ValueError("sigma_multiplier must be >= 0")

    # Baseline from conditioned profile if it has enough samples,
    # otherwise the layer's global baseline.
    if conditioned_profile is not None and conditioned_profile.sample_count >= 5:
        mu = conditioned_profile.score_stats.mean
        sd = conditioned_profile.score_stats.stddev_sample \
            or DEFAULT_SIGMA_FALLBACK
    else:
        mu = profile.score_stats.mean
        sd = profile.score_stats.stddev_sample or DEFAULT_SIGMA_FALLBACK

    half = sigma_multiplier * sd
    half += _AUTHORITY_WIDENING.get(authority, 0.0)
    half += _ENVIRONMENT_WIDENING.get(environment, 0.0)
    # Sample pad: fewer samples → wider
    sample_deficit = max(0, min_samples - profile.sample_count)
    half += sample_deficit * PAD_PER_SAMPLE
    # Confidence pad: lower confidence → wider
    half += (1.0 - confidence) * TIME_PAD_SCALE

    lower = max(0.0, mu - half)
    upper = min(1.0, mu + half)
    return AdaptiveBoundary(
        entity_id=profile.entity_id, layer=profile.layer,
        lower=lower, upper=upper, confidence=confidence,
        authority=authority, environment=environment,
    )


# =============================================================================
# SECTION 7 — CHANGE ATTRIBUTION
# =============================================================================


@dataclass(frozen=True)
class ChangeAttribution:
    entity_id: str
    direction: ChangeDirection
    total_change: float
    by_layer: Mapping[BehaviorLayer, float]
    by_authority: Mapping[AuthorityState, float]
    by_environment: Mapping[EnvironmentState, float]
    dominant_layer: Optional[BehaviorLayer]
    dominant_authority: Optional[AuthorityState]
    dominant_environment: Optional[EnvironmentState]
    rationale: str
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        if not 0.0 <= self.total_change <= 1.0:
            raise ValueError("total_change must be within [0,1]")


def _normalized_deviation(
    recent_mean: float, baseline_mean: float, baseline_sd: float,
) -> float:
    """Signed, normalized deviation in baseline-σ units, clipped."""
    if baseline_sd <= 0:
        baseline_sd = DEFAULT_SIGMA_FALLBACK
    z = (recent_mean - baseline_mean) / baseline_sd
    if z > 3.0:
        z = 3.0
    if z < -3.0:
        z = -3.0
    return z / 3.0


def attribute_change(
    entity_id: str,
    *,
    profiles: Mapping[BehaviorLayer, BehaviorProfile],
    recent_observations: Sequence[BehaviorObservation],
    baseline_conditioner_mix: Mapping[
        Tuple[AuthorityState, EnvironmentState], float
    ],
    at: datetime,
) -> ChangeAttribution:
    if at.tzinfo is None:
        raise ValueError("at must be timezone-aware")

    by_layer: Dict[BehaviorLayer, float] = {}
    signed_layer: Dict[BehaviorLayer, float] = {}

    for layer in ALL_LAYERS:
        prof = profiles.get(layer)
        layer_obs = [o for o in recent_observations if o.layer is layer]
        if prof is None or not layer_obs:
            by_layer[layer] = 0.0
            signed_layer[layer] = 0.0
            continue
        recent_mean = sum(o.score for o in layer_obs) / len(layer_obs)
        z = _normalized_deviation(
            recent_mean, prof.score_stats.mean,
            prof.score_stats.stddev_sample,
        )
        signed_layer[layer] = z
        by_layer[layer] = abs(z)

    # Total change = RMS over layers (bounded 0..1)
    if by_layer:
        total = math.sqrt(sum(v * v for v in by_layer.values())
                          / len(by_layer))
    else:
        total = 0.0
    total = max(0.0, min(1.0, total))

    # Direction from sign of weighted mean of signed deviations
    weights = [by_layer[l] for l in ALL_LAYERS if by_layer[l] > 0]
    if not weights:
        direction = ChangeDirection.STABLE
    else:
        signed_sum = sum(signed_layer[l] for l in ALL_LAYERS)
        if abs(signed_sum) < 0.05:
            direction = ChangeDirection.STABLE
        elif signed_sum > 0:
            direction = ChangeDirection.WORSENING
        else:
            direction = ChangeDirection.IMPROVING

    dominant_layer: Optional[BehaviorLayer] = None
    if by_layer:
        best = max(by_layer.items(), key=lambda kv: (kv[1], kv[0].value))
        if best[1] > 0.0:
            dominant_layer = best[0]

    # Authority attribution — recent distribution vs baseline mix
    auth_counts: Dict[AuthorityState, int] = {a: 0 for a in AuthorityState}
    env_counts: Dict[EnvironmentState, int] = {e: 0 for e in EnvironmentState}
    for o in recent_observations:
        auth_counts[o.authority] += 1
        env_counts[o.environment] += 1
    n = max(1, len(recent_observations))

    by_authority: Dict[AuthorityState, float] = {}
    baseline_auth: Dict[AuthorityState, float] = {a: 0.0 for a in AuthorityState}
    for (a, _e), w in baseline_conditioner_mix.items():
        baseline_auth[a] += w
    for a in AuthorityState:
        observed = auth_counts[a] / n
        baseline = baseline_auth.get(a, 0.0)
        delta = abs(observed - baseline)
        by_authority[a] = max(0.0, min(1.0, delta))

    by_environment: Dict[EnvironmentState, float] = {}
    baseline_env: Dict[EnvironmentState, float] = {e: 0.0 for e in EnvironmentState}
    for (_a, e), w in baseline_conditioner_mix.items():
        baseline_env[e] += w
    for e in EnvironmentState:
        observed = env_counts[e] / n
        baseline = baseline_env.get(e, 0.0)
        delta = abs(observed - baseline)
        by_environment[e] = max(0.0, min(1.0, delta))

    dominant_auth: Optional[AuthorityState] = None
    if by_authority:
        best_a = max(by_authority.items(), key=lambda kv: (kv[1], kv[0].value))
        if best_a[1] > 0.0:
            dominant_auth = best_a[0]

    dominant_env: Optional[EnvironmentState] = None
    if by_environment:
        best_e = max(by_environment.items(),
                     key=lambda kv: (kv[1], kv[0].value))
        if best_e[1] > 0.0:
            dominant_env = best_e[0]

    rationale_parts = [
        f"direction={direction.value}",
        f"total_change={total:.3f}",
    ]
    if dominant_layer is not None:
        rationale_parts.append(f"layer={dominant_layer.value}")
    if dominant_auth is not None:
        rationale_parts.append(f"authority={dominant_auth.value}")
    if dominant_env is not None:
        rationale_parts.append(f"environment={dominant_env.value}")

    return ChangeAttribution(
        entity_id=entity_id,
        direction=direction,
        total_change=total,
        by_layer=by_layer,
        by_authority=by_authority,
        by_environment=by_environment,
        dominant_layer=dominant_layer,
        dominant_authority=dominant_auth,
        dominant_environment=dominant_env,
        rationale=", ".join(rationale_parts),
        at=at,
    )


# =============================================================================
# SECTION 8 — TRANSITION PREDICTION
# =============================================================================


@dataclass(frozen=True)
class TransitionPrediction:
    entity_id: str
    current_label: TrustLabel
    predicted_label: TrustLabel
    probability: float
    horizon_seconds: float
    rationale: str
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        if not 0.0 <= self.probability <= 1.0:
            raise ValueError("probability must be within [0,1]")
        if self.horizon_seconds <= 0:
            raise ValueError("horizon_seconds must be > 0")


def _next_worse(label: TrustLabel) -> TrustLabel:
    order = [
        TrustLabel.TRUSTED, TrustLabel.OBSERVED, TrustLabel.DEGRADED,
        TrustLabel.SUSPICIOUS, TrustLabel.COMPROMISED, TrustLabel.QUARANTINED,
    ]
    if label not in order:
        return TrustLabel.OBSERVED
    i = order.index(label)
    return order[min(i + 1, len(order) - 1)]


def _next_better(label: TrustLabel) -> TrustLabel:
    order = [
        TrustLabel.QUARANTINED, TrustLabel.COMPROMISED,
        TrustLabel.SUSPICIOUS, TrustLabel.DEGRADED,
        TrustLabel.OBSERVED, TrustLabel.TRUSTED,
    ]
    if label not in order:
        return TrustLabel.OBSERVED
    i = order.index(label)
    return order[min(i + 1, len(order) - 1)]


def predict_transition(
    entity_id: str,
    *,
    current_label: TrustLabel,
    attribution: ChangeAttribution,
    recent_windows: Sequence[float],   # per-window mean score, oldest first
    at: datetime,
    horizon_seconds: float = 3600.0,
) -> TransitionPrediction:
    if at.tzinfo is None:
        raise ValueError("at must be timezone-aware")
    if horizon_seconds <= 0:
        raise ValueError("horizon_seconds must be > 0")

    # Trend = slope of last windows (positive = worsening)
    if len(recent_windows) >= 2:
        n = len(recent_windows)
        xs = list(range(n))
        mx = sum(xs) / n
        my = sum(recent_windows) / n
        num = sum((x - mx) * (y - my) for x, y in zip(xs, recent_windows))
        den = sum((x - mx) ** 2 for x in xs) or 1.0
        slope = num / den
    else:
        slope = 0.0

    # Combine slope and attribution direction
    worsening_signal = 0.0
    if attribution.direction is ChangeDirection.WORSENING:
        worsening_signal += attribution.total_change
    if slope > 0.0:
        worsening_signal += min(0.5, slope * 5.0)

    improving_signal = 0.0
    if attribution.direction is ChangeDirection.IMPROVING:
        improving_signal += attribution.total_change
    if slope < 0.0:
        improving_signal += min(0.5, abs(slope) * 5.0)

    if worsening_signal >= improving_signal and worsening_signal >= 0.2:
        predicted = _next_worse(current_label)
        prob = max(0.0, min(1.0, worsening_signal))
        rationale = (
            f"worsening signal {worsening_signal:.3f} "
            f"(slope {slope:.3f}, attribution {attribution.total_change:.3f})"
        )
    elif improving_signal > 0.0 and improving_signal >= 0.2:
        predicted = _next_better(current_label)
        prob = max(0.0, min(1.0, improving_signal))
        rationale = (
            f"improving signal {improving_signal:.3f} "
            f"(slope {slope:.3f})"
        )
    else:
        predicted = current_label
        prob = 0.5
        rationale = (
            f"stable: slope {slope:.3f}, "
            f"attribution {attribution.total_change:.3f}"
        )

    return TransitionPrediction(
        entity_id=entity_id,
        current_label=current_label,
        predicted_label=predicted,
        probability=prob,
        horizon_seconds=horizon_seconds,
        rationale=rationale,
        at=at,
    )


# =============================================================================
# SECTION 9 — FINDINGS + LABELS
# =============================================================================


@dataclass(frozen=True)
class BehaviorFinding:
    kind: BehaviorFindingKind
    entity_id: str
    layer: Optional[BehaviorLayer]
    detail: str
    severity: int
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        if not 1 <= self.severity <= 5:
            raise ValueError("severity must be in [1,5]")


def derive_label_from_behavior(
    *,
    base_confidence: float,
    breach_rate: float,          # fraction of recent obs outside boundary
    change_score: float,         # 0..1
    boundary_coverage: float,    # fraction inside boundary
) -> TrustLabel:
    """Derive a trust label from behavior-conditioned signals."""
    if base_confidence < 0.4:
        return TrustLabel.UNKNOWN
    if breach_rate >= 0.5 or change_score >= 0.7:
        return TrustLabel.SUSPICIOUS
    if breach_rate >= 0.25 or change_score >= 0.4:
        return TrustLabel.DEGRADED
    if breach_rate > 0.0 or change_score >= 0.2:
        return TrustLabel.OBSERVED
    if boundary_coverage >= 0.95 and change_score < 0.1:
        return TrustLabel.TRUSTED
    return TrustLabel.OBSERVED


# =============================================================================
# SECTION 10 — INVARIANTS
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
class BehaviorSnapshot:
    profiles: Mapping[Tuple[str, BehaviorLayer], BehaviorProfile]
    boundaries: Mapping[Tuple[str, BehaviorLayer], AdaptiveBoundary]
    attributions: Mapping[str, ChangeAttribution]
    predictions: Mapping[str, TransitionPrediction]
    labels: Mapping[str, TrustLabel]


@dataclass(frozen=True)
class BehaviorInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[BehaviorSnapshot], Tuple[InvariantViolation, ...]]
    description: str


def _inv_boundary_lower_leq_upper(
    snap: BehaviorSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for (eid, layer), b in snap.boundaries.items():
        if b.lower > b.upper:
            out.append(InvariantViolation(
                invariant_id="behav.boundary_lower_leq_upper",
                severity=InvariantSeverity.CRITICAL,
                subject_id=f"{eid}/{layer.value}",
                detail=f"boundary lower {b.lower} > upper {b.upper}",
            ))
    return tuple(out)


def _inv_boundary_in_unit(
    snap: BehaviorSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for (eid, layer), b in snap.boundaries.items():
        if not (0.0 <= b.lower <= 1.0 and 0.0 <= b.upper <= 1.0):
            out.append(InvariantViolation(
                invariant_id="behav.boundary_in_unit",
                severity=InvariantSeverity.HIGH,
                subject_id=f"{eid}/{layer.value}",
                detail=f"boundary not within [0,1]: [{b.lower}, {b.upper}]",
            ))
    return tuple(out)


def _inv_attribution_bounded(
    snap: BehaviorSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for eid, a in snap.attributions.items():
        if not 0.0 <= a.total_change <= 1.0:
            out.append(InvariantViolation(
                invariant_id="behav.attribution_bounded",
                severity=InvariantSeverity.HIGH,
                subject_id=eid,
                detail=f"total_change {a.total_change} out of [0,1]",
            ))
        for layer, v in a.by_layer.items():
            if not 0.0 <= v <= 1.0:
                out.append(InvariantViolation(
                    invariant_id="behav.attribution_bounded",
                    severity=InvariantSeverity.HIGH,
                    subject_id=f"{eid}/{layer.value}",
                    detail=f"per-layer change {v} out of [0,1]",
                ))
    return tuple(out)


def _inv_prediction_probability_bounded(
    snap: BehaviorSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for eid, p in snap.predictions.items():
        if not 0.0 <= p.probability <= 1.0:
            out.append(InvariantViolation(
                invariant_id="behav.prediction_probability_bounded",
                severity=InvariantSeverity.HIGH,
                subject_id=eid,
                detail=f"probability {p.probability} out of [0,1]",
            ))
    return tuple(out)


def _inv_no_trusted_under_worsening_change(
    snap: BehaviorSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for eid, label in snap.labels.items():
        if label is not TrustLabel.TRUSTED:
            continue
        attr = snap.attributions.get(eid)
        if attr is None:
            continue
        if attr.direction is ChangeDirection.WORSENING \
           and attr.total_change >= 0.4:
            out.append(InvariantViolation(
                invariant_id="behav.no_trusted_under_worsening",
                severity=InvariantSeverity.CRITICAL,
                subject_id=eid,
                detail=(
                    f"entity {eid} TRUSTED while behavior is worsening "
                    f"(change {attr.total_change:.3f})"
                ),
            ))
    return tuple(out)


DEFAULT_INVARIANTS: Tuple[BehaviorInvariant, ...] = (
    BehaviorInvariant(
        invariant_id="behav.boundary_lower_leq_upper",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_boundary_lower_leq_upper,
        description="Boundary lower must be <= upper.",
    ),
    BehaviorInvariant(
        invariant_id="behav.boundary_in_unit",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_boundary_in_unit,
        description="Boundary endpoints must lie within [0,1].",
    ),
    BehaviorInvariant(
        invariant_id="behav.attribution_bounded",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_attribution_bounded,
        description="Attribution values must lie within [0,1].",
    ),
    BehaviorInvariant(
        invariant_id="behav.prediction_probability_bounded",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_prediction_probability_bounded,
        description="Prediction probability must lie within [0,1].",
    ),
    BehaviorInvariant(
        invariant_id="behav.no_trusted_under_worsening",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_no_trusted_under_worsening_change,
        description="TRUSTED must not coexist with significant worsening change.",
    ),
)


def check_invariants(
    snap: BehaviorSnapshot,
    invariants: Iterable[BehaviorInvariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 11 — STORE
# =============================================================================


@dataclass(frozen=True)
class BehaviorStateRecord:
    entity_id: str
    label: TrustLabel
    direction: ChangeDirection
    total_change: float
    predicted_label: TrustLabel
    prediction_probability: float
    updated_at: datetime


class BehaviorStore(Protocol):
    def get(self, entity_id: str) -> Optional[BehaviorStateRecord]: ...
    def put(self, record: BehaviorStateRecord) -> None: ...
    def all(self) -> Tuple[BehaviorStateRecord, ...]: ...


class InMemoryBehaviorStore:
    def __init__(self) -> None:
        self._data: Dict[str, BehaviorStateRecord] = {}

    def get(self, entity_id: str) -> Optional[BehaviorStateRecord]:
        return self._data.get(entity_id)

    def put(self, record: BehaviorStateRecord) -> None:
        existing = self._data.get(record.entity_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._data[record.entity_id] = record

    def all(self) -> Tuple[BehaviorStateRecord, ...]:
        return tuple(self._data.values())


class SqliteBehaviorStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS behav_state (
                entity_id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                direction TEXT NOT NULL,
                total_change REAL NOT NULL,
                predicted_label TEXT NOT NULL,
                prediction_probability REAL NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS behav_observations (
                observation_id TEXT PRIMARY KEY,
                entity_id TEXT NOT NULL,
                layer TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def get(self, entity_id: str) -> Optional[BehaviorStateRecord]:
        row = self._conn.execute(
            "SELECT label, direction, total_change, predicted_label, "
            "prediction_probability, updated_at FROM behav_state "
            "WHERE entity_id = ?",
            (entity_id,),
        ).fetchone()
        if row is None:
            return None
        return BehaviorStateRecord(
            entity_id=entity_id,
            label=TrustLabel(row[0]),
            direction=ChangeDirection(row[1]),
            total_change=float(row[2]),
            predicted_label=TrustLabel(row[3]),
            prediction_probability=float(row[4]),
            updated_at=datetime.fromisoformat(row[5]),
        )

    def put(self, record: BehaviorStateRecord) -> None:
        existing = self.get(record.entity_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._conn.execute(
            """
            INSERT INTO behav_state
              (entity_id, label, direction, total_change, predicted_label,
               prediction_probability, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(entity_id) DO UPDATE SET
              label=excluded.label,
              direction=excluded.direction,
              total_change=excluded.total_change,
              predicted_label=excluded.predicted_label,
              prediction_probability=excluded.prediction_probability,
              updated_at=excluded.updated_at
            """,
            (record.entity_id, record.label.value, record.direction.value,
             record.total_change, record.predicted_label.value,
             record.prediction_probability, record.updated_at.isoformat()),
        )
        self._conn.commit()

    def all(self) -> Tuple[BehaviorStateRecord, ...]:
        rows = self._conn.execute(
            "SELECT entity_id FROM behav_state"
        ).fetchall()
        return tuple(
            r for r in (self.get(x[0]) for x in rows) if r is not None
        )

    def put_observation(self, obs: BehaviorObservation) -> None:
        payload = {
            "observation_id": obs.observation_id,
            "entity_id": obs.entity_id,
            "layer": obs.layer.value,
            "action": obs.action,
            "target": obs.target,
            "authority": obs.authority.value,
            "environment": obs.environment.value,
            "score": obs.score,
            "outcome": obs.outcome.value,
            "at": obs.at.isoformat(),
        }
        self._conn.execute(
            "INSERT OR REPLACE INTO behav_observations "
            "(observation_id, entity_id, layer, payload_json) "
            "VALUES (?, ?, ?, ?)",
            (obs.observation_id, obs.entity_id, obs.layer.value,
             json.dumps(payload, sort_keys=True)),
        )
        self._conn.commit()

    def get_observation(self, observation_id: str) -> Optional[BehaviorObservation]:
        row = self._conn.execute(
            "SELECT payload_json FROM behav_observations "
            "WHERE observation_id = ?",
            (observation_id,),
        ).fetchone()
        if row is None:
            return None
        p = json.loads(row[0])
        return BehaviorObservation(
            observation_id=p["observation_id"], entity_id=p["entity_id"],
            layer=BehaviorLayer(p["layer"]), action=p["action"],
            target=p["target"], authority=AuthorityState(p["authority"]),
            environment=EnvironmentState(p["environment"]),
            score=float(p["score"]), outcome=BehaviorOutcome(p["outcome"]),
            at=datetime.fromisoformat(p["at"]),
        )


# =============================================================================
# SECTION 12 — ENGINE
# =============================================================================


@dataclass
class _EntityState:
    entity_id: str
    profiles: Dict[BehaviorLayer, BehaviorProfile] = field(default_factory=dict)
    conditioned: Dict[Tuple[AuthorityState, EnvironmentState], ConditionedProfile] = field(default_factory=dict)
    recent_observations: List[BehaviorObservation] = field(default_factory=list)
    baseline_conditioner_mix: Dict[Tuple[AuthorityState, EnvironmentState], float] = field(default_factory=dict)
    windows: List[float] = field(default_factory=list)
    label: TrustLabel = TrustLabel.UNKNOWN


class AdaptiveBehaviorEngine:
    """Adaptive behavioral security engine.

    Maintains per-entity multi-layer statistical profiles, adaptive trust
    boundaries conditioned on authority and environment, change
    attribution, and short-horizon transition prediction.
    """

    def __init__(
        self,
        *,
        store: Optional[BehaviorStore] = None,
        recent_window_size: int = 20,
        window_bucket_size: int = 5,
        confidence_half_life: float = 3600.0,
    ) -> None:
        if recent_window_size <= 0:
            raise ValueError("recent_window_size must be > 0")
        if window_bucket_size <= 0:
            raise ValueError("window_bucket_size must be > 0")
        if confidence_half_life <= 0:
            raise ValueError("confidence_half_life must be > 0")
        self._store: BehaviorStore = store or InMemoryBehaviorStore()
        self._state: Dict[str, _EntityState] = {}
        self._recent_window_size = recent_window_size
        self._window_bucket_size = window_bucket_size
        self._confidence_half_life = confidence_half_life
        self._findings: List[BehaviorFinding] = []
        self._attributions: Dict[str, ChangeAttribution] = {}
        self._predictions: Dict[str, TransitionPrediction] = {}
        self._boundaries: Dict[Tuple[str, BehaviorLayer], AdaptiveBoundary] = {}
        self._labels: Dict[str, TrustLabel] = {}
        self._violations: Tuple[InvariantViolation, ...] = ()

        # Policy knobs
        self._sigma_multiplier = DEFAULT_SIGMA_MULTIPLIER
        self._min_samples = DEFAULT_MIN_SAMPLES
        self._breach_warning_threshold = 0.15

    # ---- registration ----------------------------------------------------

    def register_entity(self, entity_id: str) -> None:
        if not entity_id:
            raise ValueError("entity_id is required")
        if entity_id in self._state:
            raise ValueError(f"entity {entity_id} already registered")
        self._state[entity_id] = _EntityState(entity_id=entity_id)

    # ---- observation -----------------------------------------------------

    def observe(self, obs: BehaviorObservation) -> None:
        st = self._state.get(obs.entity_id)
        if st is None:
            raise KeyError(f"unknown entity {obs.entity_id}")

        # Update per-layer profile
        prof = st.profiles.get(obs.layer) or BehaviorProfile.empty(
            obs.entity_id, obs.layer,
        )
        st.profiles[obs.layer] = prof.observe(obs)

        # Update conditioned profile
        ckey = (obs.authority, obs.environment)
        cp = st.conditioned.get(ckey) or ConditionedProfile.empty(
            obs.entity_id, obs.authority, obs.environment,
        )
        st.conditioned[ckey] = cp.observe(obs.score)

        # Recent window
        st.recent_observations.append(obs)
        if len(st.recent_observations) > self._recent_window_size:
            st.recent_observations = st.recent_observations[
                -self._recent_window_size:
            ]

        # Baseline conditioner mix (all-time counter)
        st.baseline_conditioner_mix[ckey] = (
            st.baseline_conditioner_mix.get(ckey, 0.0) + 1.0
        )

        if isinstance(self._store, SqliteBehaviorStore):
            self._store.put_observation(obs)

    # ---- policy ----------------------------------------------------------

    def set_sigma_multiplier(self, multiplier: float) -> None:
        if multiplier < 0:
            raise ValueError("sigma_multiplier must be >= 0")
        self._sigma_multiplier = multiplier

    def set_min_samples(self, n: int) -> None:
        if n < 0:
            raise ValueError("min_samples must be >= 0")
        self._min_samples = n

    def set_breach_warning_threshold(self, p: float) -> None:
        if not 0.0 <= p <= 1.0:
            raise ValueError("threshold must be within [0,1]")
        self._breach_warning_threshold = p

    # ---- recompute -------------------------------------------------------

    def recompute(
        self,
        *,
        at: datetime,
        context: Optional[
            Mapping[str, Tuple[AuthorityState, EnvironmentState]]
        ] = None,
    ) -> Tuple[BehaviorStateRecord, ...]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

        self._findings = []
        self._boundaries = {}
        records: List[BehaviorStateRecord] = []

        for eid, st in self._state.items():
            # Determine current context: caller-provided or last observed
            if context is not None and eid in context:
                authority, environment = context[eid]
            elif st.recent_observations:
                last = st.recent_observations[-1]
                authority, environment = last.authority, last.environment
            else:
                authority, environment = (
                    AuthorityState.NORMAL, EnvironmentState.BUSINESS_HOURS,
                )

            # Confidence: based on sample count (saturating) and recency
            total_samples = sum(p.sample_count for p in st.profiles.values())
            base_conf = min(1.0, total_samples / self._min_samples) \
                if self._min_samples else 1.0
            last_seen = max(
                (p.last_observed_at for p in st.profiles.values()
                 if p.last_observed_at is not None),
                default=None,
            )
            if last_seen is not None:
                age = (at - last_seen).total_seconds()
                recency_factor = 0.5 ** (age / self._confidence_half_life) \
                    if age > 0 else 1.0
            else:
                recency_factor = 0.0
            confidence = base_conf * recency_factor

            # Adaptive boundaries per layer
            breach_count = 0
            total_layer_obs = 0
            for layer in ALL_LAYERS:
                prof = st.profiles.get(layer)
                if prof is None:
                    continue
                cond = st.conditioned.get((authority, environment))
                boundary = compute_adaptive_boundary(
                    prof,
                    authority=authority, environment=environment,
                    confidence=confidence,
                    sigma_multiplier=self._sigma_multiplier,
                    min_samples=self._min_samples,
                    conditioned_profile=cond,
                )
                self._boundaries[(eid, layer)] = boundary

                # Layer deviation finding
                if prof.sample_count >= 5:
                    mu = prof.score_stats.mean
                    sd = prof.score_stats.stddev_sample or DEFAULT_SIGMA_FALLBACK
                    if sd > 0:
                        z = abs(prof.score_stats.mean - mu) / sd
                        # not useful — mean compared to itself; instead check
                        # last observation's distance from mean
                    if st.recent_observations:
                        recent_layer = [
                            o for o in st.recent_observations
                            if o.layer is layer
                        ]
                        if recent_layer:
                            recent_mean = (
                                sum(o.score for o in recent_layer)
                                / len(recent_layer)
                            )
                            if not boundary.contains(recent_mean):
                                breach_count += 1
                            total_layer_obs += 1

            breach_rate = (
                breach_count / total_layer_obs if total_layer_obs else 0.0
            )

            # Attribution
            recent = tuple(st.recent_observations)
            attribution = attribute_change(
                eid,
                profiles=st.profiles,
                recent_observations=recent,
                baseline_conditioner_mix=st.baseline_conditioner_mix,
                at=at,
            )
            self._attributions[eid] = attribution

            # Update windows
            if recent:
                window_mean = sum(o.score for o in recent) / len(recent)
                st.windows.append(window_mean)
                if len(st.windows) > 8:
                    st.windows = st.windows[-8:]

            # Prediction
            prediction = predict_transition(
                eid,
                current_label=st.label,
                attribution=attribution,
                recent_windows=tuple(st.windows),
                at=at,
            )
            self._predictions[eid] = prediction

            # Derive label
            label = derive_label_from_behavior(
                base_confidence=confidence,
                breach_rate=breach_rate,
                change_score=attribution.total_change,
                boundary_coverage=1.0 - breach_rate,
            )
            st.label = label
            self._labels[eid] = label

            # Findings
            if breach_rate >= self._breach_warning_threshold:
                severity = 4 if breach_rate >= 0.5 else 3
                self._findings.append(BehaviorFinding(
                    kind=BehaviorFindingKind.BOUNDARY_EXCEEDED,
                    entity_id=eid, layer=None,
                    detail=(
                        f"recent behavior outside adaptive boundary on "
                        f"{breach_count}/{total_layer_obs} layer(s)"
                    ),
                    severity=severity, at=at,
                ))

            if attribution.total_change >= 0.12 \
               and attribution.dominant_layer is not None:
                self._findings.append(BehaviorFinding(
                    kind=BehaviorFindingKind.LAYER_DEVIATION,
                    entity_id=eid, layer=attribution.dominant_layer,
                    detail=(
                        f"layer {attribution.dominant_layer.value} "
                        f"deviated (change {attribution.total_change:.3f})"
                    ),
                    severity=3, at=at,
                ))

            if attribution.dominant_authority is not None \
               and attribution.by_authority.get(
                   attribution.dominant_authority, 0.0) >= 0.4:
                self._findings.append(BehaviorFinding(
                    kind=BehaviorFindingKind.CONDITIONER_VIOLATION,
                    entity_id=eid, layer=None,
                    detail=(
                        f"authority context shift "
                        f"{attribution.dominant_authority.value}"
                    ),
                    severity=3, at=at,
                ))

            if attribution.dominant_environment is not None \
               and attribution.by_environment.get(
                   attribution.dominant_environment, 0.0) >= 0.4:
                self._findings.append(BehaviorFinding(
                    kind=BehaviorFindingKind.CONDITIONER_VIOLATION,
                    entity_id=eid, layer=None,
                    detail=(
                        f"environment context shift "
                        f"{attribution.dominant_environment.value}"
                    ),
                    severity=3, at=at,
                ))

            if attribution.direction is ChangeDirection.WORSENING \
               and attribution.total_change >= 0.13:
                self._findings.append(BehaviorFinding(
                    kind=BehaviorFindingKind.RAPID_CHANGE,
                    entity_id=eid, layer=None,
                    detail=(
                        f"rapid worsening change "
                        f"{attribution.total_change:.3f}"
                    ),
                    severity=4, at=at,
                ))

            # Novel behavior: any layer with < min_samples but high score
            for layer in ALL_LAYERS:
                prof = st.profiles.get(layer)
                if prof is None or prof.sample_count == 0:
                    continue
                if prof.sample_count < 5 and prof.score_stats.mean >= 0.7:
                    self._findings.append(BehaviorFinding(
                        kind=BehaviorFindingKind.NOVEL_BEHAVIOR,
                        entity_id=eid, layer=layer,
                        detail=(
                            f"layer {layer.value} has high-score behavior "
                            f"with only {prof.sample_count} sample(s)"
                        ),
                        severity=3, at=at,
                    ))

            if confidence < 0.4:
                self._findings.append(BehaviorFinding(
                    kind=BehaviorFindingKind.LOW_CONFIDENCE_BASELINE,
                    entity_id=eid, layer=None,
                    detail=f"baseline confidence {confidence:.3f}",
                    severity=2, at=at,
                ))

            record = BehaviorStateRecord(
                entity_id=eid, label=label,
                direction=attribution.direction,
                total_change=attribution.total_change,
                predicted_label=prediction.predicted_label,
                prediction_probability=prediction.probability,
                updated_at=at,
            )
            self._store.put(record)
            records.append(record)

        self._violations = check_invariants(self.snapshot())
        return tuple(records)

    # ---- queries ---------------------------------------------------------

    def boundary(
        self, entity_id: str, layer: BehaviorLayer,
    ) -> Optional[AdaptiveBoundary]:
        return self._boundaries.get((entity_id, layer))

    def attribution(self, entity_id: str) -> Optional[ChangeAttribution]:
        return self._attributions.get(entity_id)

    def prediction(self, entity_id: str) -> Optional[TransitionPrediction]:
        return self._predictions.get(entity_id)

    def label(self, entity_id: str) -> Optional[TrustLabel]:
        return self._labels.get(entity_id)

    def profile(
        self, entity_id: str, layer: BehaviorLayer,
    ) -> Optional[BehaviorProfile]:
        st = self._state.get(entity_id)
        if st is None:
            return None
        return st.profiles.get(layer)

    def findings(self) -> Tuple[BehaviorFinding, ...]:
        return tuple(self._findings)

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return self._violations

    def state(self, entity_id: str) -> Optional[BehaviorStateRecord]:
        return self._store.get(entity_id)

    def snapshot(self) -> BehaviorSnapshot:
        profiles: Dict[Tuple[str, BehaviorLayer], BehaviorProfile] = {}
        for eid, st in self._state.items():
            for layer, prof in st.profiles.items():
                profiles[(eid, layer)] = prof
        return BehaviorSnapshot(
            profiles=profiles,
            boundaries=dict(self._boundaries),
            attributions=dict(self._attributions),
            predictions=dict(self._predictions),
            labels=dict(self._labels),
        )


# =============================================================================
# SECTION 13 — TESTS
# =============================================================================


def _t0() -> datetime:
    from datetime import timezone
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _t(seconds: int) -> datetime:
    return _t0() + timedelta(seconds=seconds)


def _obs(
    oid: str, eid: str = "e1", *,
    layer: BehaviorLayer = BehaviorLayer.PROCESS,
    action: str = "exec",
    target: str = "t",
    authority: AuthorityState = AuthorityState.NORMAL,
    environment: EnvironmentState = EnvironmentState.BUSINESS_HOURS,
    score: float = 0.2,
    outcome: BehaviorOutcome = BehaviorOutcome.SUCCESS,
    at: Optional[datetime] = None,
) -> BehaviorObservation:
    return BehaviorObservation(
        observation_id=oid, entity_id=eid, layer=layer,
        action=action, target=target, authority=authority,
        environment=environment, score=score, outcome=outcome,
        at=at or _t0(),
    )


# ---- domain ----

def test_observation_validates_score() -> None:
    try:
        _obs("o", score=1.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_observation_validates_timezone() -> None:
    from datetime import datetime as dt
    try:
        BehaviorObservation(
            observation_id="o", entity_id="e", layer=BehaviorLayer.PROCESS,
            action="a", target="t", authority=AuthorityState.NORMAL,
            environment=EnvironmentState.BUSINESS_HOURS, score=0.5,
            outcome=BehaviorOutcome.SUCCESS, at=dt(2026, 1, 1),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_observation_key() -> None:
    o = _obs("o")
    assert o.key == ("e1", BehaviorLayer.PROCESS)


# ---- statistics ----

def test_gaussian_welford_mean() -> None:
    g = GaussianEstimate.empty().observe_many([1.0, 2.0, 3.0, 4.0])
    assert abs(g.mean - 2.5) < 1e-9
    assert g.count == 4


def test_gaussian_sample_variance() -> None:
    g = GaussianEstimate.empty().observe_many([1.0, 2.0, 3.0, 4.0])
    assert abs(g.variance_sample - 5.0/3.0) < 1e-9


def test_beta_prior_half() -> None:
    assert abs(BetaEstimate.prior().mean - 0.5) < 1e-9


def test_beta_success_raises_mean() -> None:
    assert BetaEstimate.prior().observe(success=True).mean > 0.5


# ---- profiles ----

def test_profile_empty() -> None:
    p = BehaviorProfile.empty("e1", BehaviorLayer.PROCESS)
    assert p.sample_count == 0


def test_profile_observe_updates() -> None:
    p = BehaviorProfile.empty("e1", BehaviorLayer.PROCESS)
    p2 = p.observe(_obs("o"))
    assert p2.sample_count == 1
    assert p2.last_observed_at == _t0()


def test_profile_rejects_bad_weight() -> None:
    p = BehaviorProfile.empty("e1", BehaviorLayer.PROCESS)
    try:
        p.observe(_obs("o"), weight=-1)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_conditioned_profile_observe() -> None:
    cp = ConditionedProfile.empty(
        "e1", AuthorityState.NORMAL, EnvironmentState.BUSINESS_HOURS,
    )
    cp2 = cp.observe(0.5)
    assert cp2.sample_count == 1
    assert abs(cp2.score_stats.mean - 0.5) < 1e-9


# ---- adaptive boundary ----

def test_boundary_lower_leq_upper() -> None:
    prof = BehaviorProfile.empty("e1", BehaviorLayer.PROCESS)
    for i in range(30):
        prof = prof.observe(_obs(f"o{i}", score=0.5))
    b = compute_adaptive_boundary(
        prof, authority=AuthorityState.NORMAL,
        environment=EnvironmentState.BUSINESS_HOURS, confidence=0.9,
    )
    assert b.lower <= b.upper


def test_boundary_wider_for_elevated_authority() -> None:
    prof = BehaviorProfile.empty("e1", BehaviorLayer.PROCESS)
    for i in range(30):
        prof = prof.observe(_obs(f"o{i}", score=0.5))
    b_normal = compute_adaptive_boundary(
        prof, authority=AuthorityState.NORMAL,
        environment=EnvironmentState.BUSINESS_HOURS, confidence=0.9,
    )
    b_elev = compute_adaptive_boundary(
        prof, authority=AuthorityState.ELEVATED,
        environment=EnvironmentState.BUSINESS_HOURS, confidence=0.9,
    )
    assert (b_elev.upper - b_elev.lower) > (b_normal.upper - b_normal.lower)


def test_boundary_wider_for_incident() -> None:
    prof = BehaviorProfile.empty("e1", BehaviorLayer.PROCESS)
    for i in range(30):
        prof = prof.observe(_obs(f"o{i}", score=0.5))
    b_bh = compute_adaptive_boundary(
        prof, authority=AuthorityState.NORMAL,
        environment=EnvironmentState.BUSINESS_HOURS, confidence=0.9,
    )
    b_inc = compute_adaptive_boundary(
        prof, authority=AuthorityState.NORMAL,
        environment=EnvironmentState.INCIDENT, confidence=0.9,
    )
    assert (b_inc.upper - b_inc.lower) > (b_bh.upper - b_bh.lower)


def test_boundary_wider_with_low_samples() -> None:
    prof_small = BehaviorProfile.empty("e1", BehaviorLayer.PROCESS)
    prof_small = prof_small.observe(_obs("o1"))
    prof_big = BehaviorProfile.empty("e1", BehaviorLayer.PROCESS)
    for i in range(30):
        prof_big = prof_big.observe(_obs(f"o{i}"))
    b_small = compute_adaptive_boundary(
        prof_small, authority=AuthorityState.NORMAL,
        environment=EnvironmentState.BUSINESS_HOURS, confidence=0.9,
    )
    b_big = compute_adaptive_boundary(
        prof_big, authority=AuthorityState.NORMAL,
        environment=EnvironmentState.BUSINESS_HOURS, confidence=0.9,
    )
    assert (b_small.upper - b_small.lower) > (b_big.upper - b_big.lower)


def test_boundary_wider_with_low_confidence() -> None:
    prof = BehaviorProfile.empty("e1", BehaviorLayer.PROCESS)
    for i in range(30):
        prof = prof.observe(_obs(f"o{i}"))
    b_hi = compute_adaptive_boundary(
        prof, authority=AuthorityState.NORMAL,
        environment=EnvironmentState.BUSINESS_HOURS, confidence=1.0,
    )
    b_lo = compute_adaptive_boundary(
        prof, authority=AuthorityState.NORMAL,
        environment=EnvironmentState.BUSINESS_HOURS, confidence=0.1,
    )
    assert (b_lo.upper - b_lo.lower) > (b_hi.upper - b_hi.lower)


def test_boundary_contains() -> None:
    b = AdaptiveBoundary(
        entity_id="e", layer=BehaviorLayer.PROCESS,
        lower=0.2, upper=0.6, confidence=0.9,
        authority=AuthorityState.NORMAL,
        environment=EnvironmentState.BUSINESS_HOURS,
    )
    assert b.contains(0.4)
    assert not b.contains(0.1)


def test_boundary_requires_lower_leq_upper() -> None:
    try:
        AdaptiveBoundary(
            entity_id="e", layer=BehaviorLayer.PROCESS,
            lower=0.6, upper=0.2, confidence=0.5,
            authority=AuthorityState.NORMAL,
            environment=EnvironmentState.BUSINESS_HOURS,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_boundary_rejects_bad_confidence() -> None:
    try:
        AdaptiveBoundary(
            entity_id="e", layer=BehaviorLayer.PROCESS,
            lower=0.2, upper=0.6, confidence=1.5,
            authority=AuthorityState.NORMAL,
            environment=EnvironmentState.BUSINESS_HOURS,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- attribution ----

def test_attribution_zero_change_no_recent() -> None:
    profiles = {BehaviorLayer.PROCESS: BehaviorProfile.empty(
        "e1", BehaviorLayer.PROCESS)}
    attr = attribute_change(
        "e1", profiles=profiles, recent_observations=(),
        baseline_conditioner_mix={}, at=_t0(),
    )
    assert attr.total_change == 0.0
    assert attr.direction is ChangeDirection.STABLE


def test_attribution_stable_when_recent_matches_baseline() -> None:
    prof = BehaviorProfile.empty("e1", BehaviorLayer.PROCESS)
    for i in range(20):
        prof = prof.observe(_obs(f"o{i}", score=0.5))
    profiles = {BehaviorLayer.PROCESS: prof}
    recent = tuple(_obs(f"r{i}", score=0.5) for i in range(5))
    attr = attribute_change(
        "e1", profiles=profiles, recent_observations=recent,
        baseline_conditioner_mix={(
            AuthorityState.NORMAL, EnvironmentState.BUSINESS_HOURS
        ): 1.0}, at=_t0(),
    )
    assert attr.direction is ChangeDirection.STABLE


def test_attribution_worsening_when_recent_high() -> None:
    prof = BehaviorProfile.empty("e1", BehaviorLayer.PROCESS)
    for i in range(20):
        prof = prof.observe(_obs(f"o{i}", score=0.3))
    profiles = {BehaviorLayer.PROCESS: prof}
    recent = tuple(_obs(f"r{i}", score=0.9) for i in range(5))
    attr = attribute_change(
        "e1", profiles=profiles, recent_observations=recent,
        baseline_conditioner_mix={(
            AuthorityState.NORMAL, EnvironmentState.BUSINESS_HOURS
        ): 1.0}, at=_t0(),
    )
    assert attr.direction is ChangeDirection.WORSENING
    assert attr.total_change > 0.3


def test_attribution_improving_when_recent_low() -> None:
    prof = BehaviorProfile.empty("e1", BehaviorLayer.PROCESS)
    for i in range(20):
        prof = prof.observe(_obs(f"o{i}", score=0.8))
    profiles = {BehaviorLayer.PROCESS: prof}
    recent = tuple(_obs(f"r{i}", score=0.2) for i in range(5))
    attr = attribute_change(
        "e1", profiles=profiles, recent_observations=recent,
        baseline_conditioner_mix={(
            AuthorityState.NORMAL, EnvironmentState.BUSINESS_HOURS
        ): 1.0}, at=_t0(),
    )
    assert attr.direction is ChangeDirection.IMPROVING


def test_attribution_dominant_layer() -> None:
    p1 = BehaviorProfile.empty("e1", BehaviorLayer.PROCESS)
    for i in range(20):
        p1 = p1.observe(_obs(f"p{i}", score=0.3, layer=BehaviorLayer.PROCESS))
    p2 = BehaviorProfile.empty("e1", BehaviorLayer.NETWORK)
    for i in range(20):
        p2 = p2.observe(_obs(f"n{i}", score=0.3, layer=BehaviorLayer.NETWORK))
    profiles = {BehaviorLayer.PROCESS: p1, BehaviorLayer.NETWORK: p2}
    # Only PROCESS shows change
    recent = (
        tuple(_obs(f"rp{i}", score=0.3, layer=BehaviorLayer.PROCESS)
              for i in range(3)) +
        tuple(_obs(f"rn{i}", score=0.9, layer=BehaviorLayer.NETWORK)
              for i in range(3))
    )
    attr = attribute_change(
        "e1", profiles=profiles, recent_observations=recent,
        baseline_conditioner_mix={(
            AuthorityState.NORMAL, EnvironmentState.BUSINESS_HOURS
        ): 1.0}, at=_t0(),
    )
    assert attr.dominant_layer is BehaviorLayer.NETWORK


# ---- prediction ----

def test_prediction_stable_when_no_change() -> None:
    attr = ChangeAttribution(
        entity_id="e1", direction=ChangeDirection.STABLE,
        total_change=0.0, by_layer={}, by_authority={},
        by_environment={}, dominant_layer=None,
        dominant_authority=None, dominant_environment=None,
        rationale="x", at=_t0(),
    )
    p = predict_transition(
        "e1", current_label=TrustLabel.TRUSTED,
        attribution=attr, recent_windows=(0.5, 0.5), at=_t0(),
    )
    assert p.predicted_label is TrustLabel.TRUSTED


def test_prediction_worsening_moves_label_down() -> None:
    attr = ChangeAttribution(
        entity_id="e1", direction=ChangeDirection.WORSENING,
        total_change=0.6, by_layer={}, by_authority={},
        by_environment={}, dominant_layer=None,
        dominant_authority=None, dominant_environment=None,
        rationale="x", at=_t0(),
    )
    p = predict_transition(
        "e1", current_label=TrustLabel.TRUSTED,
        attribution=attr, recent_windows=(0.3, 0.6, 0.9), at=_t0(),
    )
    assert p.predicted_label is not TrustLabel.TRUSTED


def test_prediction_improving_moves_label_up() -> None:
    attr = ChangeAttribution(
        entity_id="e1", direction=ChangeDirection.IMPROVING,
        total_change=0.5, by_layer={}, by_authority={},
        by_environment={}, dominant_layer=None,
        dominant_authority=None, dominant_environment=None,
        rationale="x", at=_t0(),
    )
    p = predict_transition(
        "e1", current_label=TrustLabel.SUSPICIOUS,
        attribution=attr, recent_windows=(0.9, 0.5, 0.2), at=_t0(),
    )
    assert label_severity(p.predicted_label) < label_severity(TrustLabel.SUSPICIOUS)


# ---- engine ----

def test_engine_register_duplicate_rejected() -> None:
    eng = AdaptiveBehaviorEngine()
    eng.register_entity("e1")
    try:
        eng.register_entity("e1")
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_unknown_entity_rejected() -> None:
    eng = AdaptiveBehaviorEngine()
    try:
        eng.observe(_obs("o", eid="missing"))
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_engine_observe_updates_profile() -> None:
    eng = AdaptiveBehaviorEngine()
    eng.register_entity("e1")
    for i in range(5):
        eng.observe(_obs(f"o{i}", score=0.4, at=_t(i)))
    prof = eng.profile("e1", BehaviorLayer.PROCESS)
    assert prof is not None
    assert prof.sample_count == 5


def test_engine_boundary_computed() -> None:
    eng = AdaptiveBehaviorEngine()
    eng.register_entity("e1")
    for i in range(20):
        eng.observe(_obs(f"o{i}", score=0.3, at=_t(i)))
    eng.recompute(at=_t(20))
    b = eng.boundary("e1", BehaviorLayer.PROCESS)
    assert b is not None
    assert b.lower <= b.upper


def test_engine_low_confidence_unknown_label() -> None:
    eng = AdaptiveBehaviorEngine()
    eng.register_entity("e1")
    eng.recompute(at=_t0())
    assert eng.label("e1") in (TrustLabel.UNKNOWN, TrustLabel.OBSERVED)


def test_engine_worsening_change_triggers_finding() -> None:
    eng = AdaptiveBehaviorEngine()
    eng.register_entity("e1")
    for i in range(30):
        eng.observe(_obs(f"b{i}", score=0.2, at=_t(i)))
    for i in range(25):
        eng.observe(_obs(f"w{i}", score=0.95, at=_t(40 + i)))
    eng.recompute(at=_t(70))
    kinds = {f.kind for f in eng.findings()}
    assert BehaviorFindingKind.RAPID_CHANGE in kinds \
        or BehaviorFindingKind.LAYER_DEVIATION in kinds


def test_engine_attribution_worsening() -> None:
    eng = AdaptiveBehaviorEngine()
    eng.register_entity("e1")
    for i in range(30):
        eng.observe(_obs(f"b{i}", score=0.2, at=_t(i)))
    for i in range(5):
        eng.observe(_obs(f"w{i}", score=0.95, at=_t(40 + i)))
    eng.recompute(at=_t(50))
    attr = eng.attribution("e1")
    assert attr is not None
    assert attr.direction is ChangeDirection.WORSENING


def test_engine_prediction_present() -> None:
    eng = AdaptiveBehaviorEngine()
    eng.register_entity("e1")
    for i in range(30):
        eng.observe(_obs(f"b{i}", score=0.3, at=_t(i)))
    eng.recompute(at=_t(30))
    pred = eng.prediction("e1")
    assert pred is not None


def test_engine_conditioner_specific_boundary() -> None:
    eng = AdaptiveBehaviorEngine()
    eng.register_entity("e1")
    # Observe only normal/business-hours
    for i in range(30):
        eng.observe(_obs(
            f"o{i}", score=0.3, at=_t(i),
            authority=AuthorityState.NORMAL,
            environment=EnvironmentState.BUSINESS_HOURS,
        ))
    # Now recompute under elevated/incident context
    eng.recompute(at=_t(30), context={
        "e1": (AuthorityState.ELEVATED, EnvironmentState.INCIDENT),
    })
    b_elev = eng.boundary("e1", BehaviorLayer.PROCESS)
    # Compare with normal context boundary
    eng.recompute(at=_t(30), context={
        "e1": (AuthorityState.NORMAL, EnvironmentState.BUSINESS_HOURS),
    })
    b_normal = eng.boundary("e1", BehaviorLayer.PROCESS)
    assert b_elev is not None and b_normal is not None
    assert (b_elev.upper - b_elev.lower) > (b_normal.upper - b_normal.lower)


def test_engine_multi_layer_state() -> None:
    eng = AdaptiveBehaviorEngine()
    eng.register_entity("e1")
    for i in range(10):
        eng.observe(_obs(
            f"p{i}", score=0.3, at=_t(i),
            layer=BehaviorLayer.PROCESS,
        ))
        eng.observe(_obs(
            f"n{i}", score=0.4, at=_t(i),
            layer=BehaviorLayer.NETWORK,
        ))
    prof_p = eng.profile("e1", BehaviorLayer.PROCESS)
    prof_n = eng.profile("e1", BehaviorLayer.NETWORK)
    assert prof_p.sample_count == 10
    assert prof_n.sample_count == 10


def test_engine_no_trusted_under_worsening_invariant() -> None:
    eng = AdaptiveBehaviorEngine()
    eng.register_entity("e1")
    for i in range(30):
        eng.observe(_obs(f"b{i}", score=0.2, at=_t(i)))
    for i in range(5):
        eng.observe(_obs(f"w{i}", score=0.95, at=_t(40 + i)))
    eng.recompute(at=_t(50))
    # Should not be TRUSTED, so no invariant violation from this rule
    v = eng.violations()
    for x in v:
        assert x.invariant_id != "behav.no_trusted_under_worsening" or \
            eng.label("e1") is TrustLabel.TRUSTED


def test_engine_snapshot_shape() -> None:
    eng = AdaptiveBehaviorEngine()
    eng.register_entity("e1")
    for i in range(10):
        eng.observe(_obs(f"o{i}", score=0.3, at=_t(i)))
    eng.recompute(at=_t(10))
    snap = eng.snapshot()
    assert ("e1", BehaviorLayer.PROCESS) in snap.profiles
    assert "e1" in snap.labels


def test_engine_set_policy_validation() -> None:
    eng = AdaptiveBehaviorEngine()
    try:
        eng.set_sigma_multiplier(-1)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
    try:
        eng.set_min_samples(-1)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


# ---- store ----

def test_in_memory_store_rejects_stale() -> None:
    s = InMemoryBehaviorStore()
    t = _t0()
    s.put(BehaviorStateRecord(
        "e1", TrustLabel.TRUSTED, ChangeDirection.STABLE, 0.0,
        TrustLabel.TRUSTED, 0.5, t,
    ))
    earlier = t.replace(year=t.year - 1)
    try:
        s.put(BehaviorStateRecord(
            "e1", TrustLabel.UNKNOWN, ChangeDirection.STABLE, 0.0,
            TrustLabel.UNKNOWN, 0.5, earlier,
        ))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_state_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "b.db")
    store = SqliteBehaviorStore(db)
    t = _t0()
    store.put(BehaviorStateRecord(
        "e1", TrustLabel.SUSPICIOUS, ChangeDirection.WORSENING, 0.6,
        TrustLabel.COMPROMISED, 0.7, t,
    ))
    got = store.get("e1")
    assert got is not None
    assert got.label is TrustLabel.SUSPICIOUS
    assert got.direction is ChangeDirection.WORSENING


def test_sqlite_store_observation_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "b.db")
    store = SqliteBehaviorStore(db)
    obs = _obs("o1", score=0.5)
    store.put_observation(obs)
    got = store.get_observation("o1")
    assert got is not None
    assert got.entity_id == "e1"
    assert abs(got.score - 0.5) < 1e-9


# =============================================================================
# SECTION 14 — MANUAL RUNNER
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
