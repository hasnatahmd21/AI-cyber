"""
HYDRA POST-CORE — PHASE 13: MULTIVARIATE SECURITY STATE ANALYTICS
===================================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * Domain — 9 security dimensions (identity, network, application,
    cloud, agent, data, device, authority, threat), dimension values,
    multivariate observations
  * Marginal baseline — per-dimension value frequencies
  * Pairwise interaction detection — co-occurrence lift over expected
  * Dangerous-pattern rules (arbitrary multi-dimension combinations)
  * Combination risk scoring (weighted marginals + pattern boosts +
    interaction boosts, clipped [0,1])
  * Multivariate outlier detection (Hamming distance from per-dim mode)
  * Findings:
      - DANGEROUS_COMBINATION
      - UNEXPECTED_INTERACTION
      - MARGINAL_DEVIATION
      - MULTIVARIATE_OUTLIER
  * Explicit trust-label derivation
  * Machine-checkable multivariate invariants
  * In-memory + SQLite stores
  * Phase-13 engine facade
  * Full test suite + manual runner

This is NEW multivariate security-state analytics. It is not a SIEM
correlation engine — it treats the environment as a joint distribution
over 9 security dimensions and identifies dangerous combinations and
interactions that individual telemetry streams cannot express.

No third-party dependencies.

Run tests:
    python hydra_phase13_multivariate_security_state.py
    pytest hydra_phase13_multivariate_security_state.py -q
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


class DimensionKind(str, Enum):
    IDENTITY = "identity"
    NETWORK = "network"
    APPLICATION = "application"
    CLOUD = "cloud"
    AGENT = "agent"
    DATA = "data"
    DEVICE = "device"
    AUTHORITY = "authority"
    THREAT = "threat"


ALL_DIMENSIONS: Tuple[DimensionKind, ...] = tuple(DimensionKind)

_DIMENSION_ORDER: Mapping[DimensionKind, int] = {
    d: i for i, d in enumerate(ALL_DIMENSIONS)
}


def dimension_order(d: DimensionKind) -> int:
    return _DIMENSION_ORDER[d]


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


class MultivariateFindingKind(str, Enum):
    DANGEROUS_COMBINATION = "dangerous_combination"
    UNEXPECTED_INTERACTION = "unexpected_interaction"
    MARGINAL_DEVIATION = "marginal_deviation"
    MULTIVARIATE_OUTLIER = "multivariate_outlier"


@dataclass(frozen=True)
class DimensionValue:
    kind: DimensionKind
    value: str
    risk: float = 0.0

    def __post_init__(self) -> None:
        if not self.value:
            raise ValueError("value is required")
        if not 0.0 <= self.risk <= 1.0:
            raise ValueError("risk must be within [0,1]")

    @property
    def key(self) -> Tuple[DimensionKind, str]:
        return (self.kind, self.value)


@dataclass(frozen=True)
class MultivariateObservation:
    observation_id: str
    entity_id: str
    assignments: Tuple[DimensionValue, ...]
    at: datetime

    def __post_init__(self) -> None:
        if not self.observation_id:
            raise ValueError("observation_id is required")
        if not self.entity_id:
            raise ValueError("entity_id is required")
        if not self.assignments:
            raise ValueError("at least one assignment is required")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        seen: set = set()
        for a in self.assignments:
            if a.kind in seen:
                raise ValueError(
                    f"dimension {a.kind.value} appears more than once"
                )
            seen.add(a.kind)

    def value_of(self, kind: DimensionKind) -> Optional[str]:
        for a in self.assignments:
            if a.kind is kind:
                return a.value
        return None

    def dimension_map(self) -> Mapping[DimensionKind, DimensionValue]:
        return {a.kind: a for a in self.assignments}

    def dimension_set(self) -> FrozenSet[DimensionKind]:
        return frozenset(a.kind for a in self.assignments)


# =============================================================================
# SECTION 3 — DANGEROUS PATTERNS
# =============================================================================


@dataclass(frozen=True)
class DangerousPattern:
    """A multi-dimension combination that is dangerous when fully matched."""
    pattern_id: str
    antecedents: FrozenSet[Tuple[DimensionKind, str]]
    risk_label: str
    severity: int
    description: str = ""

    def __post_init__(self) -> None:
        if not self.pattern_id:
            raise ValueError("pattern_id is required")
        if not self.antecedents:
            raise ValueError("antecedents must be non-empty")
        if not self.risk_label:
            raise ValueError("risk_label is required")
        if not 1 <= self.severity <= 5:
            raise ValueError("severity must be in [1,5]")

    def matches(self, obs: MultivariateObservation) -> bool:
        m = obs.dimension_map()
        for (dim, val) in self.antecedents:
            d = m.get(dim)
            if d is None or d.value != val:
                return False
        return True

    def partial_score(self, obs: MultivariateObservation) -> float:
        """Fraction of antecedents satisfied (0..1)."""
        if not self.antecedents:
            return 0.0
        m = obs.dimension_map()
        hit = 0
        for (dim, val) in self.antecedents:
            d = m.get(dim)
            if d is not None and d.value == val:
                hit += 1
        return hit / len(self.antecedents)


# =============================================================================
# SECTION 4 — MARGINAL BASELINE
# =============================================================================


@dataclass(frozen=True)
class MarginalBaseline:
    """Frequencies of values in a single dimension."""
    dimension: DimensionKind
    value_counts: Mapping[str, int]
    total: int

    def __post_init__(self) -> None:
        if self.total < 0:
            raise ValueError("total must be >= 0")
        for v, c in self.value_counts.items():
            if c < 0:
                raise ValueError(f"count for {v} must be >= 0")

    def frequency(self, value: str) -> int:
        return self.value_counts.get(value, 0)

    def probability(self, value: str) -> float:
        if self.total == 0:
            return 0.0
        return self.value_counts.get(value, 0) / self.total

    def mode(self) -> Optional[str]:
        if not self.value_counts:
            return None
        return max(self.value_counts.items(),
                   key=lambda kv: (kv[1], kv[0]))[0]


# =============================================================================
# SECTION 5 — PAIRWISE INTERACTION
# =============================================================================


@dataclass(frozen=True)
class PairwiseInteraction:
    dim_a: DimensionKind
    val_a: str
    dim_b: DimensionKind
    val_b: str
    observed_count: int
    expected_count: float
    lift: float
    support: float

    def __post_init__(self) -> None:
        if self.observed_count < 0:
            raise ValueError("observed_count must be >= 0")
        if self.expected_count < 0:
            raise ValueError("expected_count must be >= 0")
        if self.lift < 0:
            raise ValueError("lift must be >= 0")
        if not 0.0 <= self.support <= 1.0:
            raise ValueError("support must be within [0,1]")
        if dimension_order(self.dim_a) >= dimension_order(self.dim_b):
            raise ValueError("dim_a must come before dim_b in order")

    @property
    def key(self) -> Tuple[DimensionKind, str, DimensionKind, str]:
        return (self.dim_a, self.val_a, self.dim_b, self.val_b)


# =============================================================================
# SECTION 6 — FINDINGS + ANALYSIS RESULT
# =============================================================================


@dataclass(frozen=True)
class MultivariateFinding:
    kind: MultivariateFindingKind
    entity_id: str
    detail: str
    severity: int
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        if not 1 <= self.severity <= 5:
            raise ValueError("severity must be in [1,5]")


@dataclass(frozen=True)
class CombinationAnalysis:
    entity_id: str
    observation_id: str
    combination_risk: float
    label: TrustLabel
    matched_patterns: Tuple[str, ...]
    high_lift_interactions: Tuple[Tuple[DimensionKind, str, DimensionKind, str], ...]
    marginal_deviation: float
    outlier_distance: float
    findings: Tuple[MultivariateFinding, ...]
    rationale: str
    at: datetime

    def __post_init__(self) -> None:
        if not 0.0 <= self.combination_risk <= 1.0:
            raise ValueError("combination_risk must be within [0,1]")
        if not 0.0 <= self.marginal_deviation <= 1.0:
            raise ValueError("marginal_deviation must be within [0,1]")
        if not 0.0 <= self.outlier_distance <= 1.0:
            raise ValueError("outlier_distance must be within [0,1]")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


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
class MultivariateSnapshot:
    marginals: Mapping[DimensionKind, MarginalBaseline]
    interactions: Mapping[Tuple[DimensionKind, str, DimensionKind, str],
                          PairwiseInteraction]
    analyses: Mapping[str, CombinationAnalysis]
    patterns: Mapping[str, DangerousPattern]


@dataclass(frozen=True)
class MultivariateInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[MultivariateSnapshot],
                        Tuple[InvariantViolation, ...]]
    description: str


def _inv_marginal_counts_nonneg(
    snap: MultivariateSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for dim, mb in snap.marginals.items():
        for v, c in mb.value_counts.items():
            if c < 0:
                out.append(InvariantViolation(
                    invariant_id="mv.marginal_counts_nonneg",
                    severity=InvariantSeverity.CRITICAL,
                    subject_id=f"{dim.value}:{v}",
                    detail=f"count {c} is negative",
                ))
    return tuple(out)


def _inv_lift_nonneg(snap: MultivariateSnapshot) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for key, inter in snap.interactions.items():
        if inter.lift < 0:
            out.append(InvariantViolation(
                invariant_id="mv.lift_nonneg",
                severity=InvariantSeverity.CRITICAL,
                subject_id="|".join([key[0].value, key[1],
                                     key[2].value, key[3]]),
                detail=f"lift {inter.lift} is negative",
            ))
    return tuple(out)


def _inv_risk_in_unit(snap: MultivariateSnapshot) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for eid, a in snap.analyses.items():
        if not 0.0 <= a.combination_risk <= 1.0:
            out.append(InvariantViolation(
                invariant_id="mv.risk_in_unit",
                severity=InvariantSeverity.HIGH,
                subject_id=eid,
                detail=f"combination_risk {a.combination_risk} out of [0,1]",
            ))
    return tuple(out)


def _inv_pattern_antecedents_nonempty(
    snap: MultivariateSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for pid, p in snap.patterns.items():
        if not p.antecedents:
            out.append(InvariantViolation(
                invariant_id="mv.pattern_antecedents_nonempty",
                severity=InvariantSeverity.CRITICAL,
                subject_id=pid,
                detail="pattern antecedents must be non-empty",
            ))
    return tuple(out)


def _inv_compromised_requires_pattern_match(
    snap: MultivariateSnapshot,
) -> Tuple[InvariantViolation, ...]:
    """A COMPROMISED label must be backed by at least one pattern match
    or a very high risk."""
    out: List[InvariantViolation] = []
    for eid, a in snap.analyses.items():
        if a.label is TrustLabel.COMPROMISED:
            if not a.matched_patterns and a.combination_risk < 0.85:
                out.append(InvariantViolation(
                    invariant_id="mv.compromised_requires_pattern",
                    severity=InvariantSeverity.HIGH,
                    subject_id=eid,
                    detail=(
                        f"{eid} COMPROMISED without pattern match and "
                        f"risk {a.combination_risk:.2f}"
                    ),
                ))
    return tuple(out)


DEFAULT_INVARIANTS: Tuple[MultivariateInvariant, ...] = (
    MultivariateInvariant(
        invariant_id="mv.marginal_counts_nonneg",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_marginal_counts_nonneg,
        description="Marginal value counts must be non-negative.",
    ),
    MultivariateInvariant(
        invariant_id="mv.lift_nonneg",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_lift_nonneg,
        description="Pairwise lift must be non-negative.",
    ),
    MultivariateInvariant(
        invariant_id="mv.risk_in_unit",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_risk_in_unit,
        description="Combination risk must lie within [0,1].",
    ),
    MultivariateInvariant(
        invariant_id="mv.pattern_antecedents_nonempty",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_pattern_antecedents_nonempty,
        description="Every pattern must have at least one antecedent.",
    ),
    MultivariateInvariant(
        invariant_id="mv.compromised_requires_pattern",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_compromised_requires_pattern_match,
        description="COMPROMISED must be supported by pattern match or high risk.",
    ),
)


def check_invariants(
    snap: MultivariateSnapshot,
    invariants: Iterable[MultivariateInvariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 8 — STORE
# =============================================================================


@dataclass(frozen=True)
class EntityCombinationRecord:
    entity_id: str
    observation_id: str
    label: TrustLabel
    combination_risk: float
    findings_count: int
    updated_at: datetime


class MultivariateStore(Protocol):
    def get(self, entity_id: str) -> Optional[EntityCombinationRecord]: ...
    def put(self, record: EntityCombinationRecord) -> None: ...
    def all(self) -> Tuple[EntityCombinationRecord, ...]: ...


class InMemoryMultivariateStore:
    def __init__(self) -> None:
        self._data: Dict[str, EntityCombinationRecord] = {}

    def get(self, entity_id: str) -> Optional[EntityCombinationRecord]:
        return self._data.get(entity_id)

    def put(self, record: EntityCombinationRecord) -> None:
        existing = self._data.get(record.entity_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._data[record.entity_id] = record

    def all(self) -> Tuple[EntityCombinationRecord, ...]:
        return tuple(self._data.values())


class SqliteMultivariateStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mv_entity_state (
                entity_id TEXT PRIMARY KEY,
                observation_id TEXT NOT NULL,
                label TEXT NOT NULL,
                combination_risk REAL NOT NULL,
                findings_count INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mv_observations (
                observation_id TEXT PRIMARY KEY,
                entity_id TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mv_patterns (
                pattern_id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def get(self, entity_id: str) -> Optional[EntityCombinationRecord]:
        row = self._conn.execute(
            "SELECT observation_id, label, combination_risk, "
            "findings_count, updated_at FROM mv_entity_state "
            "WHERE entity_id = ?",
            (entity_id,),
        ).fetchone()
        if row is None:
            return None
        return EntityCombinationRecord(
            entity_id=entity_id, observation_id=row[0],
            label=TrustLabel(row[1]), combination_risk=float(row[2]),
            findings_count=int(row[3]),
            updated_at=datetime.fromisoformat(row[4]),
        )

    def put(self, record: EntityCombinationRecord) -> None:
        existing = self.get(record.entity_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._conn.execute(
            """
            INSERT INTO mv_entity_state
              (entity_id, observation_id, label, combination_risk,
               findings_count, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(entity_id) DO UPDATE SET
              observation_id=excluded.observation_id,
              label=excluded.label,
              combination_risk=excluded.combination_risk,
              findings_count=excluded.findings_count,
              updated_at=excluded.updated_at
            """,
            (record.entity_id, record.observation_id, record.label.value,
             record.combination_risk, record.findings_count,
             record.updated_at.isoformat()),
        )
        self._conn.commit()

    def all(self) -> Tuple[EntityCombinationRecord, ...]:
        rows = self._conn.execute(
            "SELECT entity_id FROM mv_entity_state"
        ).fetchall()
        return tuple(
            r for r in (self.get(x[0]) for x in rows) if r is not None
        )

    def put_observation(self, obs: MultivariateObservation) -> None:
        payload = {
            "observation_id": obs.observation_id,
            "entity_id": obs.entity_id,
            "at": obs.at.isoformat(),
            "assignments": [
                {"kind": a.kind.value, "value": a.value, "risk": a.risk}
                for a in obs.assignments
            ],
        }
        self._conn.execute(
            "INSERT OR REPLACE INTO mv_observations "
            "(observation_id, entity_id, payload_json) VALUES (?, ?, ?)",
            (obs.observation_id, obs.entity_id,
             json.dumps(payload, sort_keys=True)),
        )
        self._conn.commit()

    def get_observation(
        self, observation_id: str,
    ) -> Optional[MultivariateObservation]:
        row = self._conn.execute(
            "SELECT payload_json FROM mv_observations "
            "WHERE observation_id = ?",
            (observation_id,),
        ).fetchone()
        if row is None:
            return None
        p = json.loads(row[0])
        return MultivariateObservation(
            observation_id=p["observation_id"],
            entity_id=p["entity_id"],
            assignments=tuple(
                DimensionValue(
                    kind=DimensionKind(a["kind"]),
                    value=a["value"], risk=float(a["risk"]),
                )
                for a in p["assignments"]
            ),
            at=datetime.fromisoformat(p["at"]),
        )

    def put_pattern(self, pattern: DangerousPattern) -> None:
        payload = {
            "pattern_id": pattern.pattern_id,
            "antecedents": [
                [d.value, v] for (d, v) in sorted(
                    pattern.antecedents, key=lambda x: (x[0].value, x[1]),
                )
            ],
            "risk_label": pattern.risk_label,
            "severity": pattern.severity,
            "description": pattern.description,
        }
        self._conn.execute(
            "INSERT OR REPLACE INTO mv_patterns (pattern_id, payload_json) "
            "VALUES (?, ?)",
            (pattern.pattern_id, json.dumps(payload, sort_keys=True)),
        )
        self._conn.commit()


# =============================================================================
# SECTION 9 — ENGINE
# =============================================================================


@dataclass
class _EntityState:
    entity_id: str
    latest_obs: Optional[MultivariateObservation] = None
    label: TrustLabel = TrustLabel.UNKNOWN


class MultivariateSecurityEngine:
    """Multivariate security-state analytics over 9 dimensions.

    Treats the environment as a joint distribution across dimensions and
    surfaces dangerous combinations and interactions.
    """

    def __init__(
        self,
        *,
        store: Optional[MultivariateStore] = None,
        min_pair_support: int = 3,
        lift_interaction_threshold: float = 2.0,
        outlier_distance_threshold: float = 0.5,
        marginal_deviation_ratio: float = 0.05,
    ) -> None:
        if min_pair_support < 1:
            raise ValueError("min_pair_support must be >= 1")
        if lift_interaction_threshold < 0:
            raise ValueError("lift_interaction_threshold must be >= 0")
        if not 0.0 <= outlier_distance_threshold <= 1.0:
            raise ValueError("outlier_distance_threshold must be within [0,1]")
        if not 0.0 <= marginal_deviation_ratio <= 1.0:
            raise ValueError("marginal_deviation_ratio must be within [0,1]")

        self._store: MultivariateStore = store or InMemoryMultivariateStore()
        self._entities: Dict[str, _EntityState] = {}
        self._observations: List[MultivariateObservation] = []
        self._patterns: Dict[str, DangerousPattern] = {}
        self._marginals: Dict[DimensionKind, MarginalBaseline] = {}
        self._interactions: Dict[
            Tuple[DimensionKind, str, DimensionKind, str], PairwiseInteraction
        ] = {}
        self._analyses: Dict[str, CombinationAnalysis] = {}
        self._violations: Tuple[InvariantViolation, ...] = ()

        self._min_pair_support = min_pair_support
        self._lift_interaction_threshold = lift_interaction_threshold
        self._outlier_distance_threshold = outlier_distance_threshold
        self._marginal_deviation_ratio = marginal_deviation_ratio

    # ---- registration ----------------------------------------------------

    def register_entity(self, entity_id: str) -> None:
        if not entity_id:
            raise ValueError("entity_id is required")
        if entity_id in self._entities:
            raise ValueError(f"entity {entity_id} already registered")
        self._entities[entity_id] = _EntityState(entity_id=entity_id)

    def register_pattern(self, pattern: DangerousPattern) -> None:
        if pattern.pattern_id in self._patterns:
            raise ValueError(f"pattern {pattern.pattern_id} already registered")
        self._patterns[pattern.pattern_id] = pattern
        if isinstance(self._store, SqliteMultivariateStore):
            self._store.put_pattern(pattern)

    def observe(self, obs: MultivariateObservation) -> None:
        if obs.entity_id not in self._entities:
            raise KeyError(f"unknown entity {obs.entity_id}")
        self._observations.append(obs)
        self._entities[obs.entity_id].latest_obs = obs
        if isinstance(self._store, SqliteMultivariateStore):
            self._store.put_observation(obs)

    # ---- policy ----------------------------------------------------------

    def set_min_pair_support(self, n: int) -> None:
        if n < 1:
            raise ValueError("min_pair_support must be >= 1")
        self._min_pair_support = n

    def set_lift_interaction_threshold(self, x: float) -> None:
        if x < 0:
            raise ValueError("threshold must be >= 0")
        self._lift_interaction_threshold = x

    def set_outlier_distance_threshold(self, x: float) -> None:
        if not 0.0 <= x <= 1.0:
            raise ValueError("threshold must be within [0,1]")
        self._outlier_distance_threshold = x

    def set_marginal_deviation_ratio(self, x: float) -> None:
        if not 0.0 <= x <= 1.0:
            raise ValueError("ratio must be within [0,1]")
        self._marginal_deviation_ratio = x

    # ---- baseline computation --------------------------------------------

    def _build_marginals(self) -> Dict[DimensionKind, MarginalBaseline]:
        counts: Dict[DimensionKind, Dict[str, int]] = {
            d: {} for d in ALL_DIMENSIONS
        }
        totals: Dict[DimensionKind, int] = {d: 0 for d in ALL_DIMENSIONS}
        for obs in self._observations:
            for a in obs.assignments:
                counts[a.kind][a.value] = counts[a.kind].get(a.value, 0) + 1
                totals[a.kind] += 1
        return {
            d: MarginalBaseline(
                dimension=d, value_counts=counts[d], total=totals[d],
            )
            for d in ALL_DIMENSIONS
        }

    def _build_interactions(
        self, marginals: Mapping[DimensionKind, MarginalBaseline],
    ) -> Dict[Tuple[DimensionKind, str, DimensionKind, str],
              PairwiseInteraction]:
        n = len(self._observations)
        if n == 0:
            return {}

        pair_counts: Dict[Tuple[DimensionKind, str, DimensionKind, str],
                          int] = {}
        for obs in self._observations:
            dims = sorted(obs.assignments, key=lambda a: dimension_order(a.kind))
            for i in range(len(dims)):
                for j in range(i + 1, len(dims)):
                    a, b = dims[i], dims[j]
                    if a.kind is b.kind:
                        continue
                    key = (a.kind, a.value, b.kind, b.value)
                    pair_counts[key] = pair_counts.get(key, 0) + 1

        out: Dict[Tuple[DimensionKind, str, DimensionKind, str],
                  PairwiseInteraction] = {}
        for key, count in pair_counts.items():
            dim_a, val_a, dim_b, val_b = key
            pa = marginals[dim_a].probability(val_a)
            pb = marginals[dim_b].probability(val_b)
            expected = pa * pb * n
            if expected <= 0.0:
                lift = 0.0
            else:
                lift = count / expected
            out[key] = PairwiseInteraction(
                dim_a=dim_a, val_a=val_a, dim_b=dim_b, val_b=val_b,
                observed_count=count, expected_count=expected,
                lift=lift, support=count / n,
            )
        return out

    # ---- per-observation analysis ---------------------------------------

    def _analyze(
        self,
        obs: MultivariateObservation,
        marginals: Mapping[DimensionKind, MarginalBaseline],
        interactions: Mapping[Tuple[DimensionKind, str, DimensionKind, str],
                              PairwiseInteraction],
    ) -> CombinationAnalysis:
        findings: List[MultivariateFinding] = []

        # 1. Dangerous pattern matches
        matched_pattern_ids: List[str] = []
        pattern_boost = 0.0
        for pid, p in self._patterns.items():
            if p.matches(obs):
                matched_pattern_ids.append(pid)
                pattern_boost += 0.15 * p.severity
                findings.append(MultivariateFinding(
                    kind=MultivariateFindingKind.DANGEROUS_COMBINATION,
                    entity_id=obs.entity_id,
                    detail=(
                        f"pattern {pid} matched: {p.description or p.risk_label}"
                    ),
                    severity=min(5, p.severity),
                    at=obs.at,
                ))
            else:
                score = p.partial_score(obs)
                if 0.5 <= score < 1.0 and p.severity >= 4:
                    findings.append(MultivariateFinding(
                        kind=MultivariateFindingKind.DANGEROUS_COMBINATION,
                        entity_id=obs.entity_id,
                        detail=(
                            f"pattern {pid} partially matched "
                            f"({score:.2f} antecedents)"
                        ),
                        severity=2,
                        at=obs.at,
                    ))

        # 2. High-lift interactions present in this observation
        present_keys: List[Tuple[DimensionKind, str, DimensionKind, str]] = []
        dims = sorted(obs.assignments, key=lambda a: dimension_order(a.kind))
        for i in range(len(dims)):
            for j in range(i + 1, len(dims)):
                a, b = dims[i], dims[j]
                if a.kind is b.kind:
                    continue
                # canonical order
                if dimension_order(a.kind) < dimension_order(b.kind):
                    key = (a.kind, a.value, b.kind, b.value)
                else:
                    key = (b.kind, b.value, a.kind, a.value)
                inter = interactions.get(key)
                if inter is None:
                    continue
                if inter.observed_count < self._min_pair_support:
                    continue
                if inter.lift >= self._lift_interaction_threshold:
                    present_keys.append(key)
                    findings.append(MultivariateFinding(
                        kind=MultivariateFindingKind.UNEXPECTED_INTERACTION,
                        entity_id=obs.entity_id,
                        detail=(
                            f"interaction {key[0].value}={key[1]} × "
                            f"{key[2].value}={key[3]} lift {inter.lift:.2f}"
                        ),
                        severity=3,
                        at=obs.at,
                    ))

        # 3. Marginal deviation: sum of (1 - P(value)) across dimensions,
        # normalized by number of assignments. High = rare combination.
        dev_sum = 0.0
        for a in obs.assignments:
            p = marginals[a.kind].probability(a.value)
            dev_sum += (1.0 - p)
        marginal_deviation = (
            dev_sum / len(obs.assignments) if obs.assignments else 0.0
        )
        if marginal_deviation >= 1.0 - self._marginal_deviation_ratio:
            findings.append(MultivariateFinding(
                kind=MultivariateFindingKind.MARGINAL_DEVIATION,
                entity_id=obs.entity_id,
                detail=(
                    f"marginal deviation {marginal_deviation:.2f} — values "
                    f"rarely seen in baseline"
                ),
                severity=2,
                at=obs.at,
            ))

        # 4. Outlier distance: mean Hamming distance from per-dim mode
        dist_sum = 0
        dims_known = 0
        for a in obs.assignments:
            mode = marginals[a.kind].mode()
            if mode is None:
                continue
            dims_known += 1
            if a.value != mode:
                dist_sum += 1
        outlier_distance = (
            dist_sum / dims_known if dims_known else 0.0
        )
        if outlier_distance >= self._outlier_distance_threshold:
            findings.append(MultivariateFinding(
                kind=MultivariateFindingKind.MULTIVARIATE_OUTLIER,
                entity_id=obs.entity_id,
                detail=(
                    f"outlier distance {outlier_distance:.2f} from "
                    f"per-dimension mode"
                ),
                severity=3,
                at=obs.at,
            ))

        # 5. Combination risk
        base_risk = (
            sum(a.risk for a in obs.assignments) / len(obs.assignments)
            if obs.assignments else 0.0
        )
        interaction_boost = 0.05 * len(present_keys)
        risk = base_risk + pattern_boost + interaction_boost
        risk = max(0.0, min(1.0, risk))

        label = _derive_label(
            risk, matched_pattern_ids, marginal_deviation, outlier_distance,
        )

        rationale_parts = [
            f"risk={risk:.2f}",
            f"patterns={matched_pattern_ids or 'none'}",
            f"marg_dev={marginal_deviation:.2f}",
            f"outlier={outlier_distance:.2f}",
        ]

        return CombinationAnalysis(
            entity_id=obs.entity_id,
            observation_id=obs.observation_id,
            combination_risk=risk,
            label=label,
            matched_patterns=tuple(matched_pattern_ids),
            high_lift_interactions=tuple(present_keys),
            marginal_deviation=marginal_deviation,
            outlier_distance=outlier_distance,
            findings=tuple(findings),
            rationale=", ".join(rationale_parts),
            at=obs.at,
        )

    # ---- recompute -------------------------------------------------------

    def recompute(
        self, *, at: datetime,
    ) -> Tuple[EntityCombinationRecord, ...]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

        marginals = self._build_marginals()
        interactions = self._build_interactions(marginals)
        self._marginals = marginals
        self._interactions = interactions

        records: List[EntityCombinationRecord] = []
        for eid, st in self._entities.items():
            if st.latest_obs is None:
                continue
            analysis = self._analyze(st.latest_obs, marginals, interactions)
            self._analyses[eid] = analysis
            st.label = analysis.label
            rec = EntityCombinationRecord(
                entity_id=eid,
                observation_id=analysis.observation_id,
                label=analysis.label,
                combination_risk=analysis.combination_risk,
                findings_count=len(analysis.findings),
                updated_at=at,
            )
            self._store.put(rec)
            records.append(rec)

        self._violations = check_invariants(self.snapshot())
        return tuple(records)

    # ---- queries ---------------------------------------------------------

    def marginal(self, dim: DimensionKind) -> Optional[MarginalBaseline]:
        return self._marginals.get(dim)

    def interaction(
        self,
        dim_a: DimensionKind, val_a: str,
        dim_b: DimensionKind, val_b: str,
    ) -> Optional[PairwiseInteraction]:
        if dimension_order(dim_a) < dimension_order(dim_b):
            key = (dim_a, val_a, dim_b, val_b)
        else:
            key = (dim_b, val_b, dim_a, val_a)
        return self._interactions.get(key)

    def analysis(self, entity_id: str) -> Optional[CombinationAnalysis]:
        return self._analyses.get(entity_id)

    def label(self, entity_id: str) -> Optional[TrustLabel]:
        st = self._entities.get(entity_id)
        if st is None:
            return None
        return st.label

    def top_interactions(
        self, *, k: int = 5, min_support: Optional[int] = None,
    ) -> Tuple[PairwiseInteraction, ...]:
        if k <= 0:
            raise ValueError("k must be > 0")
        ms = min_support if min_support is not None else self._min_pair_support
        items = [i for i in self._interactions.values()
                 if i.observed_count >= ms]
        items.sort(key=lambda i: (-i.lift, -i.observed_count, i.key))
        return tuple(items[:k])

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return self._violations

    def state(self, entity_id: str) -> Optional[EntityCombinationRecord]:
        return self._store.get(entity_id)

    def snapshot(self) -> MultivariateSnapshot:
        return MultivariateSnapshot(
            marginals=dict(self._marginals),
            interactions=dict(self._interactions),
            analyses=dict(self._analyses),
            patterns=dict(self._patterns),
        )


def _derive_label(
    risk: float,
    matched_patterns: Sequence[str],
    marginal_deviation: float,
    outlier_distance: float,
) -> TrustLabel:
    if matched_patterns and risk >= 0.7:
        return TrustLabel.COMPROMISED
    if matched_patterns or risk >= 0.8:
        return TrustLabel.SUSPICIOUS
    if risk >= 0.6 or outlier_distance >= 0.7:
        return TrustLabel.DEGRADED
    if risk >= 0.4 or marginal_deviation >= 0.9:
        return TrustLabel.OBSERVED
    return TrustLabel.TRUSTED


# Need Sequence import
from typing import Sequence  # noqa: E402


# =============================================================================
# SECTION 10 — TESTS
# =============================================================================


def _t0() -> datetime:
    from datetime import timezone
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _t(seconds: int) -> datetime:
    from datetime import timedelta
    return _t0() + timedelta(seconds=seconds)


def _dv(
    kind: DimensionKind, value: str, risk: float = 0.0,
) -> DimensionValue:
    return DimensionValue(kind=kind, value=value, risk=risk)


def _obs(
    oid: str, eid: str = "e1", *,
    assignments: Optional[Tuple[DimensionValue, ...]] = None,
    at: Optional[datetime] = None,
) -> MultivariateObservation:
    if assignments is None:
        assignments = (
            _dv(DimensionKind.IDENTITY, "user-alice"),
            _dv(DimensionKind.NETWORK, "internal"),
            _dv(DimensionKind.AUTHORITY, "normal"),
        )
    return MultivariateObservation(
        observation_id=oid, entity_id=eid,
        assignments=assignments, at=at or _t0(),
    )


# ---- domain ----

def test_dimension_value_validates_value() -> None:
    try:
        DimensionValue(kind=DimensionKind.IDENTITY, value="")
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_dimension_value_validates_risk() -> None:
    try:
        DimensionValue(kind=DimensionKind.IDENTITY, value="x", risk=1.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_observation_requires_aware_time() -> None:
    from datetime import datetime as dt
    try:
        MultivariateObservation(
            observation_id="o", entity_id="e",
            assignments=(_dv(DimensionKind.IDENTITY, "x"),),
            at=dt(2026, 1, 1),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_observation_requires_assignments() -> None:
    try:
        MultivariateObservation(
            observation_id="o", entity_id="e",
            assignments=(), at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_observation_rejects_duplicate_dimension() -> None:
    try:
        MultivariateObservation(
            observation_id="o", entity_id="e",
            assignments=(
                _dv(DimensionKind.IDENTITY, "a"),
                _dv(DimensionKind.IDENTITY, "b"),
            ),
            at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_observation_value_of() -> None:
    o = _obs("o")
    assert o.value_of(DimensionKind.IDENTITY) == "user-alice"
    assert o.value_of(DimensionKind.THREAT) is None


def test_observation_dimension_map() -> None:
    o = _obs("o")
    m = o.dimension_map()
    assert m[DimensionKind.NETWORK].value == "internal"


# ---- dangerous pattern ----

def test_pattern_requires_id() -> None:
    try:
        DangerousPattern(
            pattern_id="", antecedents=frozenset(
                {(DimensionKind.IDENTITY, "x")}),
            risk_label="r", severity=3,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_pattern_requires_antecedents() -> None:
    try:
        DangerousPattern(
            pattern_id="p", antecedents=frozenset(),
            risk_label="r", severity=3,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_pattern_severity_bounds() -> None:
    try:
        DangerousPattern(
            pattern_id="p",
            antecedents=frozenset({(DimensionKind.IDENTITY, "x")}),
            risk_label="r", severity=7,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_pattern_matches_all_antecedents() -> None:
    p = DangerousPattern(
        pattern_id="p",
        antecedents=frozenset({
            (DimensionKind.IDENTITY, "admin"),
            (DimensionKind.NETWORK, "public"),
        }),
        risk_label="admin-public", severity=5,
    )
    matching = _obs("o", assignments=(
        _dv(DimensionKind.IDENTITY, "admin"),
        _dv(DimensionKind.NETWORK, "public"),
    ))
    assert p.matches(matching)


def test_pattern_not_matching_when_value_differs() -> None:
    p = DangerousPattern(
        pattern_id="p",
        antecedents=frozenset({
            (DimensionKind.IDENTITY, "admin"),
            (DimensionKind.NETWORK, "public"),
        }),
        risk_label="admin-public", severity=5,
    )
    obs = _obs("o", assignments=(
        _dv(DimensionKind.IDENTITY, "user"),
        _dv(DimensionKind.NETWORK, "public"),
    ))
    assert not p.matches(obs)


def test_pattern_partial_score() -> None:
    p = DangerousPattern(
        pattern_id="p",
        antecedents=frozenset({
            (DimensionKind.IDENTITY, "admin"),
            (DimensionKind.NETWORK, "public"),
            (DimensionKind.AUTHORITY, "elevated"),
        }),
        risk_label="r", severity=4,
    )
    obs = _obs("o", assignments=(
        _dv(DimensionKind.IDENTITY, "admin"),
        _dv(DimensionKind.NETWORK, "public"),
        _dv(DimensionKind.AUTHORITY, "normal"),
    ))
    assert abs(p.partial_score(obs) - 2.0 / 3.0) < 1e-9


# ---- marginal baseline ----

def test_marginal_rejects_negative_total() -> None:
    try:
        MarginalBaseline(
            dimension=DimensionKind.IDENTITY,
            value_counts={}, total=-1,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_marginal_probability() -> None:
    mb = MarginalBaseline(
        dimension=DimensionKind.IDENTITY,
        value_counts={"a": 3, "b": 7}, total=10,
    )
    assert abs(mb.probability("a") - 0.3) < 1e-9
    assert abs(mb.probability("b") - 0.7) < 1e-9
    assert mb.probability("z") == 0.0


def test_marginal_mode() -> None:
    mb = MarginalBaseline(
        dimension=DimensionKind.IDENTITY,
        value_counts={"a": 3, "b": 7}, total=10,
    )
    assert mb.mode() == "b"


def test_marginal_mode_empty() -> None:
    mb = MarginalBaseline(
        dimension=DimensionKind.IDENTITY, value_counts={}, total=0,
    )
    assert mb.mode() is None


# ---- engine basics ----

def test_engine_register_entity() -> None:
    eng = MultivariateSecurityEngine()
    eng.register_entity("e1")
    eng.observe(_obs("o1", "e1"))
    eng.recompute(at=_t(1))


def test_engine_rejects_duplicate_entity() -> None:
    eng = MultivariateSecurityEngine()
    eng.register_entity("e1")
    try:
        eng.register_entity("e1")
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_observe_unknown_entity_rejected() -> None:
    eng = MultivariateSecurityEngine()
    try:
        eng.observe(_obs("o1", "missing"))
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_engine_rejects_duplicate_pattern() -> None:
    eng = MultivariateSecurityEngine()
    p = DangerousPattern(
        pattern_id="p1",
        antecedents=frozenset({(DimensionKind.IDENTITY, "x")}),
        risk_label="r", severity=3,
    )
    eng.register_pattern(p)
    try:
        eng.register_pattern(p)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- dangerous pattern in engine ----

def test_engine_detects_dangerous_combination() -> None:
    eng = MultivariateSecurityEngine()
    eng.register_entity("e1")
    eng.register_pattern(DangerousPattern(
        pattern_id="admin-public",
        antecedents=frozenset({
            (DimensionKind.IDENTITY, "admin"),
            (DimensionKind.NETWORK, "public"),
        }),
        risk_label="admin-public", severity=5,
    ))
    # baseline dominated by internal/user
    for i in range(20):
        eng.observe(_obs(
            f"b{i}", "e1",
            assignments=(
                _dv(DimensionKind.IDENTITY, "user"),
                _dv(DimensionKind.NETWORK, "internal"),
            ),
            at=_t(i),
        ))
    # current observation is dangerous
    eng.observe(_obs(
        "current", "e1",
        assignments=(
            _dv(DimensionKind.IDENTITY, "admin", 0.6),
            _dv(DimensionKind.NETWORK, "public", 0.7),
        ),
        at=_t(100),
    ))
    records = eng.recompute(at=_t(100))
    rec = next(r for r in records if r.entity_id == "e1")
    assert "admin-public" in eng.analysis("e1").matched_patterns
    assert rec.label in (
        TrustLabel.SUSPICIOUS, TrustLabel.COMPROMISED,
    )
    kinds = [f.kind for f in eng.analysis("e1").findings]
    assert MultivariateFindingKind.DANGEROUS_COMBINATION in kinds


def test_engine_partial_pattern_gives_weak_finding() -> None:
    eng = MultivariateSecurityEngine()
    eng.register_entity("e1")
    eng.register_pattern(DangerousPattern(
        pattern_id="trip",
        antecedents=frozenset({
            (DimensionKind.IDENTITY, "admin"),
            (DimensionKind.NETWORK, "public"),
            (DimensionKind.AUTHORITY, "elevated"),
        }),
        risk_label="trip", severity=5,
    ))
    for i in range(10):
        eng.observe(_obs(
            f"b{i}", "e1",
            assignments=(
                _dv(DimensionKind.IDENTITY, "user"),
                _dv(DimensionKind.NETWORK, "internal"),
                _dv(DimensionKind.AUTHORITY, "normal"),
            ),
            at=_t(i),
        ))
    eng.observe(_obs(
        "cur", "e1",
        assignments=(
            _dv(DimensionKind.IDENTITY, "admin"),
            _dv(DimensionKind.NETWORK, "public"),
            _dv(DimensionKind.AUTHORITY, "normal"),
        ),
        at=_t(20),
    ))
    eng.recompute(at=_t(20))
    kinds = [f.kind for f in eng.analysis("e1").findings]
    assert MultivariateFindingKind.DANGEROUS_COMBINATION in kinds
    # Partial (2/3) → severity 2 finding
    matching = [f for f in eng.analysis("e1").findings
                if f.kind is MultivariateFindingKind.DANGEROUS_COMBINATION]
    assert all(f.severity <= 3 for f in matching)


# ---- marginal deviation + outlier ----

def test_engine_marginal_deviation_detected() -> None:
    eng = MultivariateSecurityEngine()
    eng.register_entity("e1")
    # heavily skewed baseline
    for i in range(50):
        eng.observe(_obs(
            f"b{i}", "e1",
            assignments=(
                _dv(DimensionKind.IDENTITY, "user"),
                _dv(DimensionKind.NETWORK, "internal"),
            ),
            at=_t(i),
        ))
    # rare combo
    eng.observe(_obs(
        "cur", "e1",
        assignments=(
            _dv(DimensionKind.IDENTITY, "rare-user"),
            _dv(DimensionKind.NETWORK, "rare-net"),
        ),
        at=_t(60),
    ))
    eng.recompute(at=_t(60))
    kinds = [f.kind for f in eng.analysis("e1").findings]
    assert MultivariateFindingKind.MARGINAL_DEVIATION in kinds
    assert MultivariateFindingKind.MULTIVARIATE_OUTLIER in kinds


def test_engine_no_marginal_deviation_when_common() -> None:
    eng = MultivariateSecurityEngine()
    eng.register_entity("e1")
    for i in range(20):
        eng.observe(_obs(
            f"b{i}", "e1",
            assignments=(
                _dv(DimensionKind.IDENTITY, "user"),
                _dv(DimensionKind.NETWORK, "internal"),
            ),
            at=_t(i),
        ))
    eng.recompute(at=_t(20))
    kinds = [f.kind for f in eng.analysis("e1").findings]
    assert MultivariateFindingKind.MARGINAL_DEVIATION not in kinds


# ---- interaction detection ----

def test_engine_detects_high_lift_interaction() -> None:
    eng = MultivariateSecurityEngine()
    eng.register_entity("e1")
    # Co-occurrence of (identity=admin, network=public) far above chance
    for i in range(10):
        eng.observe(_obs(
            f"combo{i}", "e1",
            assignments=(
                _dv(DimensionKind.IDENTITY, "admin"),
                _dv(DimensionKind.NETWORK, "public"),
            ),
            at=_t(i),
        ))
    # Many other observations with decoupled values
    for i in range(50):
        eng.observe(_obs(
            f"bg{i}", "e1",
            assignments=(
                _dv(DimensionKind.IDENTITY, "user"),
                _dv(DimensionKind.NETWORK, "internal"),
            ),
            at=_t(100 + i),
        ))
    # Trigger baseline build
    eng.recompute(at=_t(200))
    inter = eng.interaction(
        DimensionKind.IDENTITY, "admin",
        DimensionKind.NETWORK, "public",
    )
    assert inter is not None
    assert inter.lift > 2.0


def test_engine_high_lift_interaction_finding() -> None:
    eng = MultivariateSecurityEngine()
    eng.register_entity("e1")
    # Baseline: user+internal in all obs
    for i in range(50):
        eng.observe(_obs(
            f"b{i}", "e1",
            assignments=(
                _dv(DimensionKind.IDENTITY, "user"),
                _dv(DimensionKind.NETWORK, "internal"),
            ),
            at=_t(i),
        ))
    # Plant the interaction by having 10 obs with the same pairing
    for i in range(10):
        eng.observe(_obs(
            f"pair{i}", "e1",
            assignments=(
                _dv(DimensionKind.IDENTITY, "admin"),
                _dv(DimensionKind.NETWORK, "public"),
            ),
            at=_t(100 + i),
        ))
    # Current observation
    eng.observe(_obs(
        "cur", "e1",
        assignments=(
            _dv(DimensionKind.IDENTITY, "admin"),
            _dv(DimensionKind.NETWORK, "public"),
        ),
        at=_t(200),
    ))
    eng.recompute(at=_t(200))
    kinds = [f.kind for f in eng.analysis("e1").findings]
    assert MultivariateFindingKind.UNEXPECTED_INTERACTION in kinds


def test_engine_top_interactions() -> None:
    eng = MultivariateSecurityEngine()
    eng.register_entity("e1")
    for i in range(15):
        eng.observe(_obs(
            f"a{i}", "e1",
            assignments=(
                _dv(DimensionKind.IDENTITY, "admin"),
                _dv(DimensionKind.NETWORK, "public"),
            ),
            at=_t(i),
        ))
    for i in range(30):
        eng.observe(_obs(
            f"b{i}", "e1",
            assignments=(
                _dv(DimensionKind.IDENTITY, "user"),
                _dv(DimensionKind.NETWORK, "internal"),
            ),
            at=_t(100 + i),
        ))
    eng.recompute(at=_t(200))
    top = eng.top_interactions(k=3)
    assert len(top) >= 1
    assert all(t.observed_count >= 3 for t in top)


# ---- invariants ----

def test_invariant_clean_snapshot() -> None:
    eng = MultivariateSecurityEngine()
    eng.register_entity("e1")
    for i in range(5):
        eng.observe(_obs(f"o{i}", "e1", at=_t(i)))
    eng.recompute(at=_t(10))
    assert eng.violations() == ()


def test_invariant_compromised_requires_pattern() -> None:
    # Build a snapshot with a COMPROMISED analysis but no pattern match
    snap = MultivariateSnapshot(
        marginals={},
        interactions={},
        analyses={
            "e1": CombinationAnalysis(
                entity_id="e1", observation_id="o",
                combination_risk=0.5,   # below 0.85
                label=TrustLabel.COMPROMISED,
                matched_patterns=(),
                high_lift_interactions=(),
                marginal_deviation=0.0, outlier_distance=0.0,
                findings=(), rationale="", at=_t0(),
            ),
        },
        patterns={},
    )
    v = check_invariants(snap)
    assert any(x.invariant_id == "mv.compromised_requires_pattern"
               for x in v)


# ---- labels ----

def test_engine_trusted_when_benign() -> None:
    eng = MultivariateSecurityEngine()
    eng.register_entity("e1")
    for i in range(20):
        eng.observe(_obs(
            f"o{i}", "e1",
            assignments=(
                _dv(DimensionKind.IDENTITY, "user", 0.1),
                _dv(DimensionKind.NETWORK, "internal", 0.1),
                _dv(DimensionKind.AUTHORITY, "normal", 0.0),
            ),
            at=_t(i),
        ))
    eng.recompute(at=_t(20))
    assert eng.label("e1") is TrustLabel.TRUSTED


def test_engine_suspicious_with_matched_pattern() -> None:
    eng = MultivariateSecurityEngine()
    eng.register_entity("e1")
    eng.register_pattern(DangerousPattern(
        pattern_id="p",
        antecedents=frozenset({
            (DimensionKind.IDENTITY, "admin"),
            (DimensionKind.NETWORK, "public"),
        }),
        risk_label="r", severity=5,
    ))
    for i in range(5):
        eng.observe(_obs(
            f"o{i}", "e1",
            assignments=(
                _dv(DimensionKind.IDENTITY, "admin", 0.5),
                _dv(DimensionKind.NETWORK, "public", 0.6),
            ),
            at=_t(i),
        ))
    eng.recompute(at=_t(10))
    assert eng.label("e1") in (
        TrustLabel.SUSPICIOUS, TrustLabel.COMPROMISED,
    )


# ---- recompute ----

def test_engine_recompute_returns_records() -> None:
    eng = MultivariateSecurityEngine()
    eng.register_entity("e1")
    eng.register_entity("e2")
    for i in range(5):
        eng.observe(_obs(f"a{i}", "e1", at=_t(i)))
        eng.observe(_obs(f"b{i}", "e2", at=_t(i)))
    records = eng.recompute(at=_t(10))
    assert len(records) == 2


def test_engine_marginals_built() -> None:
    eng = MultivariateSecurityEngine()
    eng.register_entity("e1")
    for i in range(5):
        eng.observe(_obs(f"o{i}", "e1", at=_t(i)))
    eng.recompute(at=_t(10))
    mb = eng.marginal(DimensionKind.IDENTITY)
    assert mb is not None
    assert mb.frequency("user-alice") == 5


# ---- store ----

def test_in_memory_store_rejects_stale() -> None:
    s = InMemoryMultivariateStore()
    t = _t0()
    s.put(EntityCombinationRecord(
        "e", "o", TrustLabel.TRUSTED, 0.1, 0, t,
    ))
    from datetime import timedelta
    earlier = t - timedelta(days=1)
    try:
        s.put(EntityCombinationRecord(
            "e", "o2", TrustLabel.UNKNOWN, 0.5, 0, earlier,
        ))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_state_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "mv.db")
    store = SqliteMultivariateStore(db)
    t = _t0()
    store.put(EntityCombinationRecord(
        "e1", "o1", TrustLabel.SUSPICIOUS, 0.7, 2, t,
    ))
    got = store.get("e1")
    assert got is not None
    assert got.label is TrustLabel.SUSPICIOUS
    assert got.findings_count == 2


def test_sqlite_store_observation_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "mv.db")
    store = SqliteMultivariateStore(db)
    obs = _obs("o1")
    store.put_observation(obs)
    got = store.get_observation("o1")
    assert got is not None
    assert got.entity_id == "e1"
    assert len(got.assignments) == len(obs.assignments)


def test_sqlite_store_pattern_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "mv.db")
    store = SqliteMultivariateStore(db)
    p = DangerousPattern(
        pattern_id="p1",
        antecedents=frozenset({
            (DimensionKind.IDENTITY, "admin"),
            (DimensionKind.NETWORK, "public"),
        }),
        risk_label="admin-public", severity=5,
        description="desc",
    )
    store.put_pattern(p)
    row = store._conn.execute(
        "SELECT payload_json FROM mv_patterns WHERE pattern_id = 'p1'"
    ).fetchone()
    assert row is not None
    payload = json.loads(row[0])
    assert payload["pattern_id"] == "p1"
    assert payload["severity"] == 5


# ---- pairwise interaction data class ----

def test_pairwise_interaction_validates_order() -> None:
    try:
        PairwiseInteraction(
            dim_a=DimensionKind.NETWORK, val_a="x",
            dim_b=DimensionKind.IDENTITY, val_b="y",
            observed_count=1, expected_count=1.0, lift=1.0, support=0.1,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_pairwise_interaction_lift_nonneg() -> None:
    try:
        PairwiseInteraction(
            dim_a=DimensionKind.IDENTITY, val_a="x",
            dim_b=DimensionKind.NETWORK, val_b="y",
            observed_count=1, expected_count=1.0, lift=-1.0, support=0.1,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- policy ----

def test_engine_policy_validation() -> None:
    eng = MultivariateSecurityEngine()
    try:
        eng.set_min_pair_support(0)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
    try:
        eng.set_lift_interaction_threshold(-1)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
    try:
        eng.set_outlier_distance_threshold(1.5)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_engine_constructor_validation() -> None:
    try:
        MultivariateSecurityEngine(min_pair_support=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


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
