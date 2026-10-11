"""
HYDRA POST-CORE — PHASE 11: STATISTICAL SECURITY FOUNDATION
================================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * Statistical primitives:
      - BetaEstimate        (Bernoulli / proportion posterior)
      - DirichletEstimate   (categorical state-label posterior)
      - GaussianEstimate    (Welford — continuous score posterior)
      - Wilson score interval (proportion confidence interval)
      - Bootstrap CI (deterministic seed)
  * Evidence reliability tracker (per-source Beta posterior)
  * Rare-event reasoning (base-rate + Bayes factor)
  * Change-point detection (CUSUM control chart)
  * Confidence degradation over time (half-life decay)
  * Statistical state characterization:
      - state-label distribution
      - continuous score distribution
      - success rate with Wilson CI
      - entropy-based uncertainty
      - confidence degradation
  * Machine-checkable statistical invariants
  * In-memory + SQLite stores
  * Phase-11 engine facade
  * Full test suite + manual runner

This is NEW statistical foundation for security state. It is NOT a
statistics library — it provides security-state-relevant estimators,
confidence degradation, rare-event reasoning, and change-point
detection with provenance-carrying outputs.

No third-party dependencies (no numpy/scipy).

Run tests:
    python hydra_phase11_statistical_security_foundation.py
    pytest hydra_phase11_statistical_security_foundation.py -q
"""
from __future__ import annotations

import json
import math
import random
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


# Two-sided z-values (no scipy).
Z_80: float = 1.2815515655446004
Z_90: float = 1.6448536269514722
Z_95: float = 1.959963984540054
Z_99: float = 2.5758293035489004


def _require_positive(name: str, value: float) -> None:
    if value <= 0:
        raise ValueError(f"{name} must be > 0")


def _require_unit(name: str, value: float) -> None:
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be within [0,1]")


class StatisticalFindingKind(str, Enum):
    RARE_EVENT = "rare_event"
    CHANGE_POINT = "change_point"
    LOW_CONFIDENCE = "low_confidence"
    DEGRADED_EVIDENCE = "degraded_evidence"
    HIGH_UNCERTAINTY = "high_uncertainty"


@dataclass(frozen=True)
class StatisticalFinding:
    kind: StatisticalFindingKind
    entity_id: str
    detail: str
    severity: int                # 1..5
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        if not 1 <= self.severity <= 5:
            raise ValueError("severity must be in [1,5]")


# =============================================================================
# SECTION 3 — BETA ESTIMATE
# =============================================================================


@dataclass(frozen=True)
class BetaEstimate:
    """Posterior over a Bernoulli parameter.

    Prior Beta(alpha0, beta0) → posterior after observations.
    """
    alpha: float
    beta: float
    prior_alpha: float = 1.0
    prior_beta: float = 1.0

    def __post_init__(self) -> None:
        _require_positive("alpha", self.alpha)
        _require_positive("beta", self.beta)
        _require_positive("prior_alpha", self.prior_alpha)
        _require_positive("prior_beta", self.prior_beta)
        if self.alpha < self.prior_alpha or self.beta < self.prior_beta:
            raise ValueError(
                "posterior parameters cannot be below prior parameters"
            )

    @classmethod
    def prior(cls, alpha: float = 1.0, beta: float = 1.0) -> "BetaEstimate":
        return cls(alpha=alpha, beta=beta,
                   prior_alpha=alpha, prior_beta=beta)

    @property
    def mean(self) -> float:
        return self.alpha / (self.alpha + self.beta)

    @property
    def variance(self) -> float:
        a, b = self.alpha, self.beta
        n = a + b
        return (a * b) / (n * n * (n + 1.0))

    @property
    def stddev(self) -> float:
        return math.sqrt(self.variance)

    @property
    def sample_count(self) -> float:
        """Effective weighted observations seen."""
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

    def credible_interval(self, *, z: float = Z_95) -> Tuple[float, float]:
        """Normal approximation credible interval (clipped to [0,1])."""
        m = self.mean
        sd = self.stddev
        return (max(0.0, m - z * sd), min(1.0, m + z * sd))


def bernoulli_weighted_update(
    beta: BetaEstimate,
    successes: float,
    failures: float,
) -> BetaEstimate:
    if successes < 0 or failures < 0:
        raise ValueError("successes/failures must be >= 0")
    return BetaEstimate(
        alpha=beta.alpha + successes, beta=beta.beta + failures,
        prior_alpha=beta.prior_alpha, prior_beta=beta.prior_beta,
    )


# =============================================================================
# SECTION 4 — DIRICHLET ESTIMATE
# =============================================================================


@dataclass(frozen=True)
class DirichletEstimate:
    """Posterior over a categorical distribution over labelled states."""
    labels: Tuple[str, ...]
    alpha: Tuple[float, ...]
    prior_alpha: Tuple[float, ...]

    def __post_init__(self) -> None:
        if not self.labels:
            raise ValueError("labels must be non-empty")
        if len(self.labels) != len(self.alpha):
            raise ValueError("labels and alpha must have equal length")
        if len(self.labels) != len(self.prior_alpha):
            raise ValueError("labels and prior_alpha must have equal length")
        if len(set(self.labels)) != len(self.labels):
            raise ValueError("labels must be unique")
        for a in self.alpha:
            _require_positive("alpha", a)
        for a in self.prior_alpha:
            _require_positive("prior_alpha", a)
        for a, p in zip(self.alpha, self.prior_alpha):
            if a < p:
                raise ValueError(
                    "posterior alpha cannot be below prior alpha"
                )

    @classmethod
    def uniform_prior(cls, labels: Iterable[str]) -> "DirichletEstimate":
        labs = tuple(labels)
        if not labs:
            raise ValueError("labels must be non-empty")
        prior = tuple(1.0 for _ in labs)
        return cls(labels=labs, alpha=prior, prior_alpha=prior)

    @classmethod
    def from_prior(
        cls, labels: Iterable[str], prior_alpha: Iterable[float],
    ) -> "DirichletEstimate":
        labs = tuple(labels)
        prior = tuple(prior_alpha)
        if not labs or len(labs) != len(prior):
            raise ValueError("labels and prior_alpha must match in length")
        for a in prior:
            _require_positive("prior_alpha", a)
        return cls(labels=labs, alpha=prior, prior_alpha=prior)

    @property
    def total(self) -> float:
        return sum(self.alpha)

    @property
    def sample_count(self) -> float:
        return sum(a - p for a, p in zip(self.alpha, self.prior_alpha))

    def probabilities(self) -> Tuple[float, ...]:
        t = self.total
        return tuple(a / t for a in self.alpha)

    def probability(self, label: str) -> float:
        try:
            i = self.labels.index(label)
        except ValueError:
            raise KeyError(f"unknown label {label}")
        return self.alpha[i] / self.total

    def argmax(self) -> str:
        i = max(range(len(self.alpha)), key=lambda k: (self.alpha[k],
                                                       self.labels[k]))
        return self.labels[i]

    def observe(
        self, label: str, *, weight: float = 1.0,
    ) -> "DirichletEstimate":
        if weight < 0:
            raise ValueError("weight must be >= 0")
        if label not in self.labels:
            raise KeyError(f"unknown label {label}")
        new_alpha = list(self.alpha)
        i = self.labels.index(label)
        new_alpha[i] += weight
        return DirichletEstimate(
            labels=self.labels, alpha=tuple(new_alpha),
            prior_alpha=self.prior_alpha,
        )

    def variance(self, label: str) -> float:
        i = self.labels.index(label)
        A = self.total
        a = self.alpha[i]
        return (a * (A - a)) / (A * A * (A + 1.0))

    def entropy(self) -> float:
        """Shannon entropy (nats). Max = log(K) for uniform."""
        ps = self.probabilities()
        return -sum(p * math.log(p) for p in ps if p > 0.0)

    def max_entropy(self) -> float:
        return math.log(len(self.labels))

    def normalized_uncertainty(self) -> float:
        m = self.max_entropy()
        if m <= 0:
            return 0.0
        return self.entropy() / m


# =============================================================================
# SECTION 5 — GAUSSIAN ESTIMATE (Welford)
# =============================================================================


@dataclass(frozen=True)
class GaussianEstimate:
    """Online mean / variance estimator (Welford's algorithm)."""
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
    def variance_population(self) -> float:
        if self.count == 0:
            return 0.0
        return self.m2 / self.count

    @property
    def variance_sample(self) -> float:
        if self.count < 2:
            return 0.0
        return self.m2 / (self.count - 1)

    @property
    def stddev_sample(self) -> float:
        return math.sqrt(self.variance_sample)

    def confidence_interval(self, *, z: float = Z_95) -> Tuple[float, float]:
        if self.count == 0:
            return (-math.inf, math.inf)
        sem = math.sqrt(self.variance_sample / self.count) \
            if self.count > 1 else 0.0
        return (self.mean - z * sem, self.mean + z * sem)


# =============================================================================
# SECTION 6 — WILSON INTERVAL + BOOTSTRAP CI
# =============================================================================


def wilson_interval(
    successes: int, trials: int, *, z: float = Z_95,
) -> Tuple[float, float]:
    """Wilson score interval for a proportion."""
    if trials < 0 or successes < 0 or successes > trials:
        raise ValueError("invalid success/trial counts")
    if trials == 0:
        return (0.0, 1.0)
    p = successes / trials
    denom = 1.0 + z * z / trials
    center = (p + z * z / (2.0 * trials)) / denom
    half = (z * math.sqrt(p * (1.0 - p) / trials
                          + z * z / (4.0 * trials * trials))) / denom
    return (max(0.0, center - half), min(1.0, center + half))


def bootstrap_ci(
    samples: Sequence[float],
    statistic: Callable[[Sequence[float]], float],
    *,
    iterations: int = 200,
    confidence: float = 0.95,
    seed: int = 0,
) -> Tuple[float, float]:
    """Deterministic bootstrap CI. `iterations` must be >= 20."""
    if iterations < 20:
        raise ValueError("iterations must be >= 20")
    _require_unit("confidence", confidence)
    if not samples:
        return (math.nan, math.nan)
    rng = random.Random(seed)
    n = len(samples)
    values: List[float] = []
    for _ in range(iterations):
        resampled = [samples[rng.randrange(n)] for _ in range(n)]
        values.append(statistic(resampled))
    values.sort()
    alpha = (1.0 - confidence) / 2.0
    lo_i = max(0, int(math.floor(alpha * (iterations - 1))))
    hi_i = min(iterations - 1, int(math.ceil((1.0 - alpha) * (iterations - 1))))
    return (values[lo_i], values[hi_i])


def _mean(samples: Sequence[float]) -> float:
    if not samples:
        return 0.0
    return sum(samples) / len(samples)


# =============================================================================
# SECTION 7 — CONFIDENCE DEGRADATION
# =============================================================================


def decay_confidence(
    base_confidence: float,
    last_observed_at: datetime,
    at: datetime,
    *,
    half_life_seconds: float,
) -> float:
    if half_life_seconds <= 0:
        raise ValueError("half_life_seconds must be > 0")
    _require_unit("base_confidence", base_confidence)
    age = (at - last_observed_at).total_seconds()
    if age <= 0:
        return base_confidence
    factor = 0.5 ** (age / half_life_seconds)
    return max(0.0, min(1.0, base_confidence * factor))


# =============================================================================
# SECTION 8 — EVIDENCE RELIABILITY
# =============================================================================


@dataclass(frozen=True)
class EvidenceSourceState:
    source_id: str
    reliability: BetaEstimate
    last_outcome_at: Optional[datetime]

    def __post_init__(self) -> None:
        if not self.source_id:
            raise ValueError("source_id is required")

    def report(
        self, *, confirmed: bool, at: datetime, weight: float = 1.0,
    ) -> "EvidenceSourceState":
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        new_rel = self.reliability.observe(success=confirmed, weight=weight)
        return EvidenceSourceState(
            source_id=self.source_id, reliability=new_rel,
            last_outcome_at=at,
        )


def bayes_factor(prior_p: float, alt_likelihood: float) -> float:
    """Simple likelihood ratio p(evidence|alt) / p(evidence|null)."""
    _require_unit("prior_p", prior_p)
    _require_unit("alt_likelihood", alt_likelihood)
    if prior_p <= 0.0:
        return math.inf
    return alt_likelihood / prior_p


# =============================================================================
# SECTION 9 — RARE EVENT OBSERVATION
# =============================================================================


@dataclass(frozen=True)
class RareEventObservation:
    observation_id: str
    entity_id: str
    event_label: str
    prior_probability: float
    alt_likelihood: float
    observed_at: datetime

    def __post_init__(self) -> None:
        if not self.observation_id:
            raise ValueError("observation_id is required")
        if not self.entity_id:
            raise ValueError("entity_id is required")
        if not self.event_label:
            raise ValueError("event_label is required")
        _require_unit("prior_probability", self.prior_probability)
        _require_unit("alt_likelihood", self.alt_likelihood)
        if self.observed_at.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")


# =============================================================================
# SECTION 10 — CUSUM CHANGE-POINT DETECTOR
# =============================================================================


@dataclass(frozen=True)
class CusumState:
    target: float
    threshold: float
    drift: float
    s_pos: float
    s_neg: float
    sample_count: int

    def __post_init__(self) -> None:
        if self.threshold <= 0:
            raise ValueError("threshold must be > 0")
        if self.drift < 0:
            raise ValueError("drift must be >= 0")
        if self.s_pos < 0 or self.s_neg < 0:
            raise ValueError("CUSUM scores must be >= 0")

    @classmethod
    def fresh(
        cls, *, target: float, threshold: float, drift: float,
    ) -> "CusumState":
        return cls(target=target, threshold=threshold, drift=drift,
                   s_pos=0.0, s_neg=0.0, sample_count=0)

    def update(self, x: float) -> Tuple["CusumState", bool]:
        s_pos = max(0.0, self.s_pos + (x - self.target - self.drift))
        s_neg = max(0.0, self.s_neg + (self.target - x - self.drift))
        alarm = s_pos > self.threshold or s_neg > self.threshold
        nxt = CusumState(
            target=self.target, threshold=self.threshold, drift=self.drift,
            s_pos=s_pos, s_neg=s_neg,
            sample_count=self.sample_count + 1,
        )
        return (nxt, alarm)

    def reset_after_alarm(self) -> "CusumState":
        return CusumState.fresh(
            target=self.target, threshold=self.threshold, drift=self.drift,
        )


# =============================================================================
# SECTION 11 — STATISTICAL PROFILE
# =============================================================================


@dataclass(frozen=True)
class StatisticalProfile:
    """Per-entity statistical characterization of security state."""
    entity_id: str
    label_distribution: DirichletEstimate
    score_distribution: GaussianEstimate
    success_rate: BetaEstimate
    success_wilson: Tuple[float, float]
    last_observed_at: Optional[datetime]
    base_confidence: float

    def confidence_at(
        self, at: datetime, *, half_life_seconds: float,
    ) -> float:
        if self.last_observed_at is None:
            return 0.0
        return decay_confidence(
            self.base_confidence, self.last_observed_at, at,
            half_life_seconds=half_life_seconds,
        )

    def uncertainty(self) -> float:
        return self.label_distribution.normalized_uncertainty()

    def sample_count(self) -> float:
        return (
            self.label_distribution.sample_count
            + self.score_distribution.count
            + self.success_rate.sample_count
        )

    def dominant_label(self) -> str:
        return self.label_distribution.argmax()


# =============================================================================
# SECTION 12 — INVARIANTS
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
class StatisticalSnapshot:
    profiles: Mapping[str, StatisticalProfile]
    evidence_sources: Mapping[str, EvidenceSourceState]
    cusum_states: Mapping[str, CusumState]


@dataclass(frozen=True)
class StatisticalInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[StatisticalSnapshot], Tuple[InvariantViolation, ...]]
    description: str


def _inv_beta_positive(snap: StatisticalSnapshot) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for sid, s in snap.evidence_sources.items():
        r = s.reliability
        if r.alpha <= 0 or r.beta <= 0:
            out.append(InvariantViolation(
                invariant_id="stat.beta_positive",
                severity=InvariantSeverity.CRITICAL,
                subject_id=sid,
                detail=(
                    f"source {sid} Beta params must be > 0 "
                    f"(α={r.alpha}, β={r.beta})"
                ),
            ))
    return tuple(out)


def _inv_dirichlet_positive(
    snap: StatisticalSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for eid, p in snap.profiles.items():
        for i, a in enumerate(p.label_distribution.alpha):
            if a <= 0:
                out.append(InvariantViolation(
                    invariant_id="stat.dirichlet_positive",
                    severity=InvariantSeverity.CRITICAL,
                    subject_id=eid,
                    detail=(
                        f"profile {eid} Dirichlet alpha[{i}] <= 0"
                    ),
                ))
    return tuple(out)


def _inv_cusum_non_negative(
    snap: StatisticalSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for eid, c in snap.cusum_states.items():
        if c.s_pos < 0 or c.s_neg < 0:
            out.append(InvariantViolation(
                invariant_id="stat.cusum_non_negative",
                severity=InvariantSeverity.CRITICAL,
                subject_id=eid,
                detail=(
                    f"CUSUM scores for {eid} must be non-negative"
                ),
            ))
    return tuple(out)


def _inv_uncertainty_bounded(
    snap: StatisticalSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for eid, p in snap.profiles.items():
        u = p.uncertainty()
        if not 0.0 <= u <= 1.0 + 1e-9:
            out.append(InvariantViolation(
                invariant_id="stat.uncertainty_bounded",
                severity=InvariantSeverity.HIGH,
                subject_id=eid,
                detail=(
                    f"profile {eid} normalized uncertainty {u} out of "
                    f"[0,1]"
                ),
            ))
    return tuple(out)


def _inv_confidence_bounded(
    snap: StatisticalSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for eid, p in snap.profiles.items():
        if not 0.0 <= p.base_confidence <= 1.0:
            out.append(InvariantViolation(
                invariant_id="stat.confidence_bounded",
                severity=InvariantSeverity.HIGH,
                subject_id=eid,
                detail=(
                    f"profile {eid} confidence "
                    f"{p.base_confidence} out of [0,1]"
                ),
            ))
    return tuple(out)


DEFAULT_INVARIANTS: Tuple[StatisticalInvariant, ...] = (
    StatisticalInvariant(
        invariant_id="stat.beta_positive",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_beta_positive,
        description="Beta parameters must be strictly positive.",
    ),
    StatisticalInvariant(
        invariant_id="stat.dirichlet_positive",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_dirichlet_positive,
        description="Dirichlet alpha parameters must be strictly positive.",
    ),
    StatisticalInvariant(
        invariant_id="stat.cusum_non_negative",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_cusum_non_negative,
        description="CUSUM scores must be non-negative.",
    ),
    StatisticalInvariant(
        invariant_id="stat.uncertainty_bounded",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_uncertainty_bounded,
        description="Normalized uncertainty must be within [0,1].",
    ),
    StatisticalInvariant(
        invariant_id="stat.confidence_bounded",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_confidence_bounded,
        description="Base confidence must be within [0,1].",
    ),
)


def check_invariants(
    snap: StatisticalSnapshot,
    invariants: Iterable[StatisticalInvariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 13 — STORE
# =============================================================================


@dataclass(frozen=True)
class ProfileRecord:
    entity_id: str
    dominant_label: str
    confidence: float
    uncertainty: float
    sample_count: float
    updated_at: datetime


class StatisticalStore(Protocol):
    def get(self, entity_id: str) -> Optional[ProfileRecord]: ...
    def put(self, record: ProfileRecord) -> None: ...
    def all(self) -> Tuple[ProfileRecord, ...]: ...


class InMemoryStatisticalStore:
    def __init__(self) -> None:
        self._data: Dict[str, ProfileRecord] = {}

    def get(self, entity_id: str) -> Optional[ProfileRecord]:
        return self._data.get(entity_id)

    def put(self, record: ProfileRecord) -> None:
        existing = self._data.get(record.entity_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._data[record.entity_id] = record

    def all(self) -> Tuple[ProfileRecord, ...]:
        return tuple(self._data.values())


class SqliteStatisticalStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS stat_profile (
                entity_id TEXT PRIMARY KEY,
                dominant_label TEXT NOT NULL,
                confidence REAL NOT NULL,
                uncertainty REAL NOT NULL,
                sample_count REAL NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS stat_evidence_sources (
                source_id TEXT PRIMARY KEY,
                alpha REAL NOT NULL,
                beta REAL NOT NULL,
                prior_alpha REAL NOT NULL,
                prior_beta REAL NOT NULL,
                last_outcome_at TEXT
            )
            """
        )
        self._conn.commit()

    def get(self, entity_id: str) -> Optional[ProfileRecord]:
        row = self._conn.execute(
            "SELECT dominant_label, confidence, uncertainty, sample_count, "
            "updated_at FROM stat_profile WHERE entity_id = ?",
            (entity_id,),
        ).fetchone()
        if row is None:
            return None
        return ProfileRecord(
            entity_id=entity_id, dominant_label=row[0],
            confidence=float(row[1]), uncertainty=float(row[2]),
            sample_count=float(row[3]),
            updated_at=datetime.fromisoformat(row[4]),
        )

    def put(self, record: ProfileRecord) -> None:
        existing = self.get(record.entity_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._conn.execute(
            """
            INSERT INTO stat_profile
              (entity_id, dominant_label, confidence, uncertainty,
               sample_count, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(entity_id) DO UPDATE SET
              dominant_label=excluded.dominant_label,
              confidence=excluded.confidence,
              uncertainty=excluded.uncertainty,
              sample_count=excluded.sample_count,
              updated_at=excluded.updated_at
            """,
            (record.entity_id, record.dominant_label, record.confidence,
             record.uncertainty, record.sample_count,
             record.updated_at.isoformat()),
        )
        self._conn.commit()

    def all(self) -> Tuple[ProfileRecord, ...]:
        rows = self._conn.execute(
            "SELECT entity_id FROM stat_profile"
        ).fetchall()
        return tuple(
            r for r in (self.get(x[0]) for x in rows) if r is not None
        )

    def put_evidence_source(self, s: EvidenceSourceState) -> None:
        self._conn.execute(
            """
            INSERT OR REPLACE INTO stat_evidence_sources
              (source_id, alpha, beta, prior_alpha, prior_beta,
               last_outcome_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                s.source_id, s.reliability.alpha, s.reliability.beta,
                s.reliability.prior_alpha, s.reliability.prior_beta,
                s.last_outcome_at.isoformat() if s.last_outcome_at else None,
            ),
        )
        self._conn.commit()

    def get_evidence_source(self, source_id: str) -> Optional[EvidenceSourceState]:
        row = self._conn.execute(
            "SELECT alpha, beta, prior_alpha, prior_beta, last_outcome_at "
            "FROM stat_evidence_sources WHERE source_id = ?",
            (source_id,),
        ).fetchone()
        if row is None:
            return None
        beta = BetaEstimate(
            alpha=float(row[0]), beta=float(row[1]),
            prior_alpha=float(row[2]), prior_beta=float(row[3]),
        )
        last = datetime.fromisoformat(row[4]) if row[4] else None
        return EvidenceSourceState(
            source_id=source_id, reliability=beta, last_outcome_at=last,
        )


# =============================================================================
# SECTION 14 — ENGINE
# =============================================================================


class StatisticalSecurityEngine:
    """Statistical foundation for security-state characterization.

    Not a statistics library — this engine turns raw observations into
    statistically-characterized security state with:
      * categorical label distribution (Dirichlet)
      * continuous score distribution (Gaussian/Welford)
      * success-rate estimate (Beta + Wilson CI)
      * uncertainty (normalized entropy)
      * confidence degradation
      * rare-event reasoning
      * change-point detection (CUSUM)
    """

    def __init__(self, *, store: Optional[StatisticalStore] = None) -> None:
        self._store: StatisticalStore = store or InMemoryStatisticalStore()
        self._labels: Dict[str, Tuple[str, ...]] = {}
        self._dirichlet: Dict[str, DirichletEstimate] = {}
        self._gauss: Dict[str, GaussianEstimate] = {}
        self._success: Dict[str, BetaEstimate] = {}
        self._success_counts: Dict[str, Tuple[int, int]] = {}
        self._base_confidence: Dict[str, float] = {}
        self._last_observed: Dict[str, datetime] = {}
        self._evidence: Dict[str, EvidenceSourceState] = {}
        self._cusum: Dict[str, CusumState] = {}
        self._cusum_cfg: Dict[str, Tuple[float, float, float]] = {}
        self._rare_events: List[RareEventObservation] = []
        self._findings: List[StatisticalFinding] = []
        self._violations: Tuple[InvariantViolation, ...] = ()

        # Policy
        self._rare_threshold: float = 0.01
        self._confidence_half_life: float = 3600.0
        self._min_confidence: float = 0.3
        self._min_source_reliability: float = 0.4
        self._high_uncertainty_threshold: float = 0.85

    # ---- registration ----------------------------------------------------

    def register_entity(
        self,
        entity_id: str,
        *,
        labels: Iterable[str],
        prior_alpha: Optional[Iterable[float]] = None,
        prior_confidence: float = 0.5,
    ) -> None:
        if not entity_id:
            raise ValueError("entity_id is required")
        if entity_id in self._dirichlet:
            raise ValueError(f"entity {entity_id} already registered")
        labs = tuple(labels)
        if not labs:
            raise ValueError("labels must be non-empty")
        if prior_alpha is not None:
            dist = DirichletEstimate.from_prior(labs, prior_alpha)
        else:
            dist = DirichletEstimate.uniform_prior(labs)
        _require_unit("prior_confidence", prior_confidence)
        self._labels[entity_id] = labs
        self._dirichlet[entity_id] = dist
        self._gauss[entity_id] = GaussianEstimate.empty()
        self._success[entity_id] = BetaEstimate.prior()
        self._success_counts[entity_id] = (0, 0)
        self._base_confidence[entity_id] = prior_confidence

    def register_evidence_source(
        self,
        source_id: str,
        *,
        prior_alpha: float = 1.0,
        prior_beta: float = 1.0,
    ) -> None:
        if not source_id:
            raise ValueError("source_id is required")
        if source_id in self._evidence:
            raise ValueError(f"source {source_id} already registered")
        state = EvidenceSourceState(
            source_id=source_id,
            reliability=BetaEstimate.prior(prior_alpha, prior_beta),
            last_outcome_at=None,
        )
        self._evidence[source_id] = state
        if isinstance(self._store, SqliteStatisticalStore):
            self._store.put_evidence_source(state)

    # ---- observation -----------------------------------------------------

    def observe_label(
        self,
        entity_id: str,
        label: str,
        *,
        at: datetime,
        weight: float = 1.0,
        bump_confidence: bool = True,
    ) -> None:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        if weight < 0:
            raise ValueError("weight must be >= 0")
        dist = self._dirichlet.get(entity_id)
        if dist is None:
            raise KeyError(f"unknown entity {entity_id}")
        self._dirichlet[entity_id] = dist.observe(label, weight=weight)
        self._last_observed[entity_id] = at
        if bump_confidence:
            self._base_confidence[entity_id] = min(
                1.0, self._base_confidence[entity_id] + 0.05
            )

    def observe_score(
        self,
        entity_id: str,
        score: float,
        *,
        at: datetime,
    ) -> None:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        if entity_id not in self._gauss:
            raise KeyError(f"unknown entity {entity_id}")
        self._gauss[entity_id] = self._gauss[entity_id].observe(score)
        self._last_observed[entity_id] = at

    def observe_success(
        self,
        entity_id: str,
        *,
        success: bool,
        at: datetime,
        weight: float = 1.0,
    ) -> None:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        if entity_id not in self._success:
            raise KeyError(f"unknown entity {entity_id}")
        self._success[entity_id] = self._success[entity_id].observe(
            success=success, weight=weight,
        )
        s, t = self._success_counts[entity_id]
        if success:
            s += int(round(weight))
        t += int(round(weight))
        self._success_counts[entity_id] = (s, t)
        self._last_observed[entity_id] = at

    # ---- evidence reliability -------------------------------------------

    def report_evidence_outcome(
        self,
        source_id: str,
        *,
        confirmed: bool,
        at: datetime,
        weight: float = 1.0,
    ) -> None:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        cur = self._evidence.get(source_id)
        if cur is None:
            raise KeyError(f"unknown source {source_id}")
        updated = cur.report(confirmed=confirmed, at=at, weight=weight)
        self._evidence[source_id] = updated
        if isinstance(self._store, SqliteStatisticalStore):
            self._store.put_evidence_source(updated)

    # ---- rare events -----------------------------------------------------

    def observe_rare_event(self, obs: RareEventObservation) -> None:
        if obs.entity_id not in self._dirichlet:
            raise KeyError(f"unknown entity {obs.entity_id}")
        self._rare_events.append(obs)

    def set_rare_threshold(self, threshold: float) -> None:
        _require_unit("threshold", threshold)
        self._rare_threshold = threshold

    def set_confidence_half_life(self, seconds: float) -> None:
        if seconds <= 0:
            raise ValueError("half life must be > 0")
        self._confidence_half_life = seconds

    def set_min_confidence(self, threshold: float) -> None:
        _require_unit("threshold", threshold)
        self._min_confidence = threshold

    def set_min_source_reliability(self, threshold: float) -> None:
        _require_unit("threshold", threshold)
        self._min_source_reliability = threshold

    def set_high_uncertainty_threshold(self, threshold: float) -> None:
        _require_unit("threshold", threshold)
        self._high_uncertainty_threshold = threshold

    # ---- CUSUM -----------------------------------------------------------

    def configure_cusum(
        self,
        entity_id: str,
        *,
        target: float,
        threshold: float,
        drift: float,
    ) -> None:
        if entity_id not in self._dirichlet:
            raise KeyError(f"unknown entity {entity_id}")
        if threshold <= 0:
            raise ValueError("threshold must be > 0")
        if drift < 0:
            raise ValueError("drift must be >= 0")
        self._cusum_cfg[entity_id] = (target, threshold, drift)
        self._cusum[entity_id] = CusumState.fresh(
            target=target, threshold=threshold, drift=drift,
        )

    def observe_cusum_sample(
        self, entity_id: str, value: float,
    ) -> bool:
        cur = self._cusum.get(entity_id)
        if cur is None:
            raise KeyError(f"CUSUM not configured for {entity_id}")
        nxt, alarm = cur.update(value)
        self._cusum[entity_id] = nxt
        return alarm

    def reset_cusum(self, entity_id: str) -> None:
        cur = self._cusum.get(entity_id)
        if cur is None:
            raise KeyError(f"CUSUM not configured for {entity_id}")
        self._cusum[entity_id] = cur.reset_after_alarm()

    # ---- recompute -------------------------------------------------------

    def recompute(self, *, at: datetime) -> Tuple[ProfileRecord, ...]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

        self._findings = []
        records: List[ProfileRecord] = []

        for eid in self._dirichlet:
            dist = self._dirichlet[eid]
            gauss = self._gauss[eid]
            success = self._success[eid]
            s_cnt, t_cnt = self._success_counts[eid]
            wilson = wilson_interval(s_cnt, t_cnt)
            base_conf = self._base_confidence[eid]
            last = self._last_observed.get(eid)

            profile = StatisticalProfile(
                entity_id=eid,
                label_distribution=dist,
                score_distribution=gauss,
                success_rate=success,
                success_wilson=wilson,
                last_observed_at=last,
                base_confidence=base_conf,
            )

            # Confidence degradation finding
            if last is not None:
                conf = profile.confidence_at(
                    at, half_life_seconds=self._confidence_half_life,
                )
                if conf < self._min_confidence:
                    self._findings.append(StatisticalFinding(
                        kind=StatisticalFindingKind.LOW_CONFIDENCE,
                        entity_id=eid,
                        detail=(
                            f"confidence decayed to {conf:.3f} "
                            f"(min {self._min_confidence:.2f})"
                        ),
                        severity=3,
                        at=at,
                    ))
            else:
                self._findings.append(StatisticalFinding(
                    kind=StatisticalFindingKind.LOW_CONFIDENCE,
                    entity_id=eid,
                    detail="no observations recorded",
                    severity=2,
                    at=at,
                ))

            # High uncertainty finding
            u = profile.uncertainty()
            if u >= self._high_uncertainty_threshold:
                self._findings.append(StatisticalFinding(
                    kind=StatisticalFindingKind.HIGH_UNCERTAINTY,
                    entity_id=eid,
                    detail=(
                        f"normalized uncertainty {u:.3f} "
                        f"(>= {self._high_uncertainty_threshold:.2f})"
                    ),
                    severity=2,
                    at=at,
                ))

            # Rare events
            for ev in self._rare_events:
                if ev.entity_id != eid:
                    continue
                if ev.prior_probability < self._rare_threshold:
                    bf = bayes_factor(
                        ev.prior_probability, ev.alt_likelihood,
                    )
                    self._findings.append(StatisticalFinding(
                        kind=StatisticalFindingKind.RARE_EVENT,
                        entity_id=eid,
                        detail=(
                            f"rare event '{ev.event_label}' observed "
                            f"(prior={ev.prior_probability:.4f}, "
                            f"BF={bf:.2f})"
                        ),
                        severity=3,
                        at=at,
                    ))

            # CUSUM alarm already recorded in observe_cusum_sample but
            # we surface it here as a statistical finding.
            cs = self._cusum.get(eid)
            if cs is not None and (
                cs.s_pos > cs.threshold or cs.s_neg > cs.threshold
            ):
                self._findings.append(StatisticalFinding(
                    kind=StatisticalFindingKind.CHANGE_POINT,
                    entity_id=eid,
                    detail=(
                        f"CUSUM alarm (s+={cs.s_pos:.2f}, "
                        f"s-={cs.s_neg:.2f}, h={cs.threshold:.2f})"
                    ),
                    severity=4,
                    at=at,
                ))

            record = ProfileRecord(
                entity_id=eid, dominant_label=dist.argmax(),
                confidence=base_conf, uncertainty=u,
                sample_count=profile.sample_count(), updated_at=at,
            )
            self._store.put(record)
            records.append(record)

        # Degraded evidence source findings
        for sid, s in self._evidence.items():
            if s.reliability.sample_count > 0 \
               and s.reliability.mean < self._min_source_reliability:
                self._findings.append(StatisticalFinding(
                    kind=StatisticalFindingKind.DEGRADED_EVIDENCE,
                    entity_id=sid,
                    detail=(
                        f"source reliability {s.reliability.mean:.3f} "
                        f"below min {self._min_source_reliability:.2f}"
                    ),
                    severity=3,
                    at=at,
                ))

        self._violations = check_invariants(self.snapshot())
        return tuple(records)

    # ---- queries ---------------------------------------------------------

    def profile(self, entity_id: str) -> StatisticalProfile:
        if entity_id not in self._dirichlet:
            raise KeyError(f"unknown entity {entity_id}")
        dist = self._dirichlet[entity_id]
        s_cnt, t_cnt = self._success_counts[entity_id]
        return StatisticalProfile(
            entity_id=entity_id,
            label_distribution=dist,
            score_distribution=self._gauss[entity_id],
            success_rate=self._success[entity_id],
            success_wilson=wilson_interval(s_cnt, t_cnt),
            last_observed_at=self._last_observed.get(entity_id),
            base_confidence=self._base_confidence[entity_id],
        )

    def evidence_source(self, source_id: str) -> EvidenceSourceState:
        s = self._evidence.get(source_id)
        if s is None:
            raise KeyError(f"unknown source {source_id}")
        return s

    def cusum_state(self, entity_id: str) -> Optional[CusumState]:
        return self._cusum.get(entity_id)

    def findings(self) -> Tuple[StatisticalFinding, ...]:
        return tuple(self._findings)

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return self._violations

    def snapshot(self) -> StatisticalSnapshot:
        profiles: Dict[str, StatisticalProfile] = {}
        for eid in self._dirichlet:
            profiles[eid] = self.profile(eid)
        return StatisticalSnapshot(
            profiles=profiles,
            evidence_sources=dict(self._evidence),
            cusum_states=dict(self._cusum),
        )


# =============================================================================
# SECTION 15 — TESTS
# =============================================================================


def _t0() -> datetime:
    from datetime import timezone
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _t(seconds: int) -> datetime:
    return _t0() + timedelta(seconds=seconds)


# ---- Beta ----

def test_beta_prior_mean_half() -> None:
    b = BetaEstimate.prior()
    assert abs(b.mean - 0.5) < 1e-9


def test_beta_rejects_non_positive() -> None:
    try:
        BetaEstimate(alpha=0.0, beta=1.0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_beta_success_raises_mean() -> None:
    b = BetaEstimate.prior().observe(success=True)
    assert b.mean > 0.5


def test_beta_failure_lowers_mean() -> None:
    b = BetaEstimate.prior().observe(success=False)
    assert b.mean < 0.5


def test_beta_more_samples_lower_variance() -> None:
    b1 = BetaEstimate.prior().observe(success=True)
    b2 = BetaEstimate.prior()
    for _ in range(10):
        b2 = b2.observe(success=True)
    assert b2.variance < b1.variance


def test_beta_sample_count() -> None:
    b = BetaEstimate.prior()
    for _ in range(3):
        b = b.observe(success=True)
    for _ in range(2):
        b = b.observe(success=False)
    assert abs(b.sample_count - 5.0) < 1e-9


def test_beta_credible_interval_bounds() -> None:
    b = BetaEstimate.prior()
    lo, hi = b.credible_interval()
    assert 0.0 <= lo <= hi <= 1.0


def test_bernoulli_weighted_update() -> None:
    b = BetaEstimate.prior()
    b2 = bernoulli_weighted_update(b, 5.0, 5.0)
    assert abs(b2.mean - 0.5) < 1e-9
    assert abs(b2.sample_count - 10.0) < 1e-9


# ---- Dirichlet ----

def test_dirichlet_uniform_prior() -> None:
    d = DirichletEstimate.uniform_prior(("a", "b", "c"))
    ps = d.probabilities()
    assert all(abs(p - 1/3) < 1e-9 for p in ps)


def test_dirichlet_rejects_empty() -> None:
    try:
        DirichletEstimate.uniform_prior(())
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_dirichlet_observe_updates_argmax() -> None:
    d = DirichletEstimate.uniform_prior(("a", "b"))
    for _ in range(5):
        d = d.observe("a")
    assert d.argmax() == "a"


def test_dirichlet_probability() -> None:
    d = DirichletEstimate.uniform_prior(("a", "b"))
    assert abs(d.probability("a") - 0.5) < 1e-9


def test_dirichlet_unknown_label_rejected() -> None:
    d = DirichletEstimate.uniform_prior(("a", "b"))
    try:
        d.observe("z")
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_dirichlet_entropy_max_at_uniform() -> None:
    d = DirichletEstimate.uniform_prior(("a", "b", "c"))
    assert abs(d.entropy() - math.log(3.0)) < 1e-9


def test_dirichlet_entropy_decreases_with_evidence() -> None:
    d = DirichletEstimate.uniform_prior(("a", "b", "c"))
    e0 = d.entropy()
    d = d.observe("a")
    assert d.entropy() < e0


def test_dirichlet_normalized_uncertainty_in_unit() -> None:
    d = DirichletEstimate.uniform_prior(("a", "b"))
    assert 0.0 <= d.normalized_uncertainty() <= 1.0


def test_dirichlet_variance_positive() -> None:
    d = DirichletEstimate.uniform_prior(("a", "b"))
    assert d.variance("a") > 0


# ---- Gaussian / Welford ----

def test_gaussian_empty() -> None:
    g = GaussianEstimate.empty()
    assert g.count == 0
    assert g.mean == 0.0


def test_gaussian_welford_mean() -> None:
    g = GaussianEstimate.empty().observe_many([1.0, 2.0, 3.0, 4.0])
    assert abs(g.mean - 2.5) < 1e-9
    assert g.count == 4


def test_gaussian_sample_variance() -> None:
    g = GaussianEstimate.empty().observe_many([1.0, 2.0, 3.0, 4.0])
    # Sample variance for 1,2,3,4 is (4-1)^2/... = 5/3 ≈ 1.6667
    assert abs(g.variance_sample - 5.0/3.0) < 1e-9


def test_gaussian_matches_manual_variance() -> None:
    xs = [10.0, 12.0, 23.0, 23.0, 16.0, 23.0, 21.0, 16.0]
    g = GaussianEstimate.empty().observe_many(xs)
    m = sum(xs) / len(xs)
    manual = sum((x - m) ** 2 for x in xs) / (len(xs) - 1)
    assert abs(g.variance_sample - manual) < 1e-9


def test_gaussian_ci_widens_with_small_n() -> None:
    g1 = GaussianEstimate.empty().observe_many([1.0, 2.0])
    g2 = GaussianEstimate.empty().observe_many([1.0, 2.0] * 20)
    w1 = g1.confidence_interval()[1] - g1.confidence_interval()[0]
    w2 = g2.confidence_interval()[1] - g2.confidence_interval()[0]
    assert w2 < w1


# ---- Wilson ----

def test_wilson_interval_zero_trials() -> None:
    assert wilson_interval(0, 0) == (0.0, 1.0)


def test_wilson_interval_bounds() -> None:
    lo, hi = wilson_interval(5, 10)
    assert 0.0 <= lo <= hi <= 1.0


def test_wilson_interval_narrows_with_more_trials() -> None:
    lo1, hi1 = wilson_interval(50, 100)
    lo2, hi2 = wilson_interval(500, 1000)
    assert (hi2 - lo2) < (hi1 - lo1)


def test_wilson_interval_all_success_upper_clipped() -> None:
    _, hi = wilson_interval(10, 10)
    assert hi <= 1.0


def test_wilson_interval_invalid_counts() -> None:
    try:
        wilson_interval(5, 3)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- Bootstrap ----

def test_bootstrap_deterministic_seed() -> None:
    xs = [1.0, 2.0, 3.0, 4.0, 5.0]
    a = bootstrap_ci(xs, _mean, iterations=100, seed=42)
    b = bootstrap_ci(xs, _mean, iterations=100, seed=42)
    assert a == b


def test_bootstrap_ci_brackets_mean() -> None:
    xs = [1.0, 2.0, 3.0, 4.0, 5.0]
    lo, hi = bootstrap_ci(xs, _mean, iterations=200, seed=7)
    assert lo <= sum(xs) / len(xs) <= hi


def test_bootstrap_empty_returns_nan() -> None:
    lo, hi = bootstrap_ci([], _mean, seed=0)
    assert math.isnan(lo) and math.isnan(hi)


# ---- confidence degradation ----

def test_decay_at_zero_age_is_one() -> None:
    assert decay_confidence(0.9, _t0(), _t0(), half_life_seconds=60.0) == 0.9


def test_decay_at_half_life_halves() -> None:
    v = decay_confidence(1.0, _t0(), _t(60), half_life_seconds=60.0)
    assert abs(v - 0.5) < 1e-9


def test_decay_monotonic_decreasing() -> None:
    a = decay_confidence(1.0, _t0(), _t(30), half_life_seconds=60.0)
    b = decay_confidence(1.0, _t0(), _t(120), half_life_seconds=60.0)
    assert b < a


def test_decay_requires_positive_half_life() -> None:
    try:
        decay_confidence(1.0, _t0(), _t0(), half_life_seconds=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- evidence source ----

def test_evidence_source_initial_mean_half() -> None:
    s = EvidenceSourceState(
        source_id="s1", reliability=BetaEstimate.prior(),
        last_outcome_at=None,
    )
    assert abs(s.reliability.mean - 0.5) < 1e-9


def test_evidence_source_confirmation_raises_reliability() -> None:
    s = EvidenceSourceState(
        source_id="s1", reliability=BetaEstimate.prior(),
        last_outcome_at=None,
    )
    s2 = s.report(confirmed=True, at=_t0())
    assert s2.reliability.mean > s.reliability.mean


def test_evidence_source_contradiction_lowers_reliability() -> None:
    s = EvidenceSourceState(
        source_id="s1", reliability=BetaEstimate.prior(),
        last_outcome_at=None,
    )
    s2 = s.report(confirmed=False, at=_t0())
    assert s2.reliability.mean < s.reliability.mean


# ---- bayes factor ----

def test_bayes_factor_rare_event() -> None:
    bf = bayes_factor(0.001, 1.0)
    assert bf == 1000.0


def test_bayes_factor_equal_prior_alt() -> None:
    assert bayes_factor(0.5, 0.5) == 1.0


# ---- rare event observation ----

def test_rare_event_requires_unit_prior() -> None:
    try:
        RareEventObservation(
            observation_id="o", entity_id="e", event_label="x",
            prior_probability=1.5, alt_likelihood=0.5,
            observed_at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- CUSUM ----

def test_cusum_no_alarm_on_stable_stream() -> None:
    c = CusumState.fresh(target=0.0, threshold=10.0, drift=0.5)
    for _ in range(20):
        c, alarm = c.update(0.0)
        assert not alarm


def test_cusum_alarm_on_shift() -> None:
    c = CusumState.fresh(target=0.0, threshold=3.0, drift=0.0)
    alarms = 0
    for _ in range(10):
        c, alarm = c.update(1.0)
        if alarm:
            alarms += 1
    assert alarms >= 1


def test_cusum_scores_non_negative() -> None:
    c = CusumState.fresh(target=0.0, threshold=5.0, drift=0.0)
    for x in (-10.0, -5.0, 0.0, 5.0, 10.0):
        c, _ = c.update(x)
        assert c.s_pos >= 0 and c.s_neg >= 0


def test_cusum_reset_after_alarm() -> None:
    c = CusumState.fresh(target=0.0, threshold=1.0, drift=0.0)
    c, alarm = c.update(100.0)
    assert alarm
    c2 = c.reset_after_alarm()
    assert c2.s_pos == 0 and c2.s_neg == 0


def test_cusum_rejects_negative_threshold() -> None:
    try:
        CusumState.fresh(target=0.0, threshold=-1.0, drift=0.0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- invariants ----

def test_invariant_no_violations_clean_engine() -> None:
    eng = StatisticalSecurityEngine()
    eng.register_entity("e1", labels=("trusted", "suspicious"))
    eng.register_entity("e2", labels=("ok", "bad"))
    eng.recompute(at=_t0())
    assert eng.violations() == ()


def test_invariant_beta_positive_holds() -> None:
    eng = StatisticalSecurityEngine()
    eng.register_entity("e1", labels=("a",))
    eng.register_evidence_source("s1")
    eng.recompute(at=_t0())
    for v in eng.violations():
        assert v.invariant_id != "stat.beta_positive"


# ---- engine integration ----

def test_engine_labels_posterior_favours_observed() -> None:
    eng = StatisticalSecurityEngine()
    eng.register_entity("e1", labels=("trusted", "suspicious"))
    for i in range(5):
        eng.observe_label("e1", "trusted", at=_t(i))
    eng.recompute(at=_t(5))
    assert eng.profile("e1").dominant_label() == "trusted"


def test_engine_unknown_entity_raises() -> None:
    eng = StatisticalSecurityEngine()
    try:
        eng.observe_label("missing", "a", at=_t0())
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_engine_low_confidence_finding() -> None:
    eng = StatisticalSecurityEngine()
    eng.register_entity("e1", labels=("a",), prior_confidence=0.05)
    eng.observe_label("e1", "a", at=_t0(), bump_confidence=False)
    eng.set_min_confidence(0.3)
    eng.recompute(at=_t0())
    assert any(f.kind is StatisticalFindingKind.LOW_CONFIDENCE
               for f in eng.findings())


def test_engine_high_uncertainty_finding() -> None:
    eng = StatisticalSecurityEngine()
    eng.register_entity("e1", labels=("a", "b", "c", "d"))
    eng.recompute(at=_t0())
    assert any(f.kind is StatisticalFindingKind.HIGH_UNCERTAINTY
               for f in eng.findings())


def test_engine_rare_event_finding() -> None:
    eng = StatisticalSecurityEngine()
    eng.register_entity("e1", labels=("a",))
    eng.observe_rare_event(RareEventObservation(
        observation_id="o1", entity_id="e1",
        event_label="kernel_mod_load",
        prior_probability=0.0001, alt_likelihood=1.0,
        observed_at=_t0(),
    ))
    eng.recompute(at=_t0())
    assert any(f.kind is StatisticalFindingKind.RARE_EVENT
               for f in eng.findings())


def test_engine_change_point_finding() -> None:
    eng = StatisticalSecurityEngine()
    eng.register_entity("e1", labels=("a",))
    eng.configure_cusum("e1", target=0.0, threshold=2.0, drift=0.0)
    for _ in range(10):
        eng.observe_cusum_sample("e1", 1.0)
    eng.recompute(at=_t0())
    assert any(f.kind is StatisticalFindingKind.CHANGE_POINT
               for f in eng.findings())


def test_engine_degraded_evidence_finding() -> None:
    eng = StatisticalSecurityEngine()
    eng.register_evidence_source("s1")
    for i in range(10):
        eng.report_evidence_outcome("s1", confirmed=False, at=_t(i))
    eng.recompute(at=_t(20))
    assert any(f.kind is StatisticalFindingKind.DEGRADED_EVIDENCE
               for f in eng.findings())


def test_engine_success_rate_wilson_interval() -> None:
    eng = StatisticalSecurityEngine()
    eng.register_entity("e1", labels=("a",))
    for i in range(10):
        eng.observe_success("e1", success=True, at=_t(i))
    eng.recompute(at=_t(10))
    lo, hi = eng.profile("e1").success_wilson
    assert hi <= 1.0 and lo >= 0.0


def test_engine_score_distribution_tracks() -> None:
    eng = StatisticalSecurityEngine()
    eng.register_entity("e1", labels=("a",))
    for i, v in enumerate([1.0, 2.0, 3.0, 4.0]):
        eng.observe_score("e1", v, at=_t(i))
    g = eng.profile("e1").score_distribution
    assert g.count == 4
    assert abs(g.mean - 2.5) < 1e-9


def test_engine_rejects_duplicate_entity() -> None:
    eng = StatisticalSecurityEngine()
    eng.register_entity("e1", labels=("a",))
    try:
        eng.register_entity("e1", labels=("b",))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_rejects_duplicate_source() -> None:
    eng = StatisticalSecurityEngine()
    eng.register_evidence_source("s1")
    try:
        eng.register_evidence_source("s1")
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_unknown_source_raises() -> None:
    eng = StatisticalSecurityEngine()
    try:
        eng.report_evidence_outcome("missing", confirmed=True, at=_t0())
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_engine_cusum_not_configured_raises() -> None:
    eng = StatisticalSecurityEngine()
    eng.register_entity("e1", labels=("a",))
    try:
        eng.observe_cusum_sample("e1", 0.0)
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_engine_reset_cusum() -> None:
    eng = StatisticalSecurityEngine()
    eng.register_entity("e1", labels=("a",))
    eng.configure_cusum("e1", target=0.0, threshold=1.0, drift=0.0)
    eng.observe_cusum_sample("e1", 100.0)
    eng.reset_cusum("e1")
    assert eng.cusum_state("e1").s_pos == 0


def test_engine_confidence_degrades_over_time() -> None:
    eng = StatisticalSecurityEngine()
    eng.register_entity("e1", labels=("a",), prior_confidence=1.0)
    eng.observe_label("e1", "a", at=_t0(), bump_confidence=False)
    eng.set_confidence_half_life(60.0)
    eng.set_min_confidence(0.1)
    eng.recompute(at=_t(600))
    profile = eng.profile("e1")
    assert profile.confidence_at(_t(600),
                                 half_life_seconds=60.0) < 0.01


def test_engine_recompute_produces_records() -> None:
    eng = StatisticalSecurityEngine()
    eng.register_entity("e1", labels=("a", "b"))
    eng.observe_label("e1", "a", at=_t0())
    records = eng.recompute(at=_t(1))
    assert len(records) == 1
    assert records[0].dominant_label == "a"


# ---- store ----

def test_in_memory_store_rejects_stale() -> None:
    s = InMemoryStatisticalStore()
    t = _t0()
    s.put(ProfileRecord("e", "a", 0.9, 0.1, 5.0, t))
    earlier = t.replace(year=t.year - 1)
    try:
        s.put(ProfileRecord("e", "b", 0.5, 0.5, 3.0, earlier))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_profile_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "stat.db")
    store = SqliteStatisticalStore(db)
    t = _t0()
    store.put(ProfileRecord("e1", "trusted", 0.9, 0.2, 12.5, t))
    got = store.get("e1")
    assert got is not None
    assert got.dominant_label == "trusted"
    assert abs(got.sample_count - 12.5) < 1e-9


def test_sqlite_store_evidence_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "stat.db")
    store = SqliteStatisticalStore(db)
    s = EvidenceSourceState(
        source_id="s1",
        reliability=BetaEstimate.prior().observe(success=True),
        last_outcome_at=_t0(),
    )
    store.put_evidence_source(s)
    got = store.get_evidence_source("s1")
    assert got is not None
    assert got.reliability.mean > 0.5


# =============================================================================
# SECTION 16 — MANUAL RUNNER
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
