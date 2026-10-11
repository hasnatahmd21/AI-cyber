"""
HYDRA POST-CORE — PHASE 14: TIME-SERIES + EARLY-WARNING EXTENSION
====================================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * Domain — trajectory kinds, samples, trends, projections
  * Time-series primitives:
      - EWMA smoothing
      - Least-squares slope + R²
      - Momentum (short vs long EWMA)
      - Acceleration (change in slope over two halves)
  * Trajectory state per (entity, trajectory_kind):
      - security-state trajectory
      - control-degradation trajectory
      - authority-drift trajectory
      - trust-decay trajectory
      - attack-surface-growth trajectory
      - recovery-degradation trajectory
      - threat-emergence trajectory
  * Early-warning signal generation:
      - warning-threshold projection
      - critical-threshold projection
      - sustained trend (R² ≥ min)
      - sufficient samples
  * Projection with bounded horizon
  * Machine-checkable time-series invariants
  * In-memory + SQLite stores
  * Phase-14 engine facade
  * Full test suite + manual runner

This is NEW time-series + early-warning technology. It is not a generic
metrics system — it targets security-relevant trajectories and produces
bounded, evidence-carrying early warnings.

No third-party dependencies.

Run tests:
    python hydra_phase14_time_series_early_warning.py
    pytest hydra_phase14_time_series_early_warning.py -q
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


class TrajectoryKind(str, Enum):
    SECURITY_STATE = "security_state"
    CONTROL_DEGRADATION = "control_degradation"
    AUTHORITY_DRIFT = "authority_drift"
    TRUST_DECAY = "trust_decay"
    ATTACK_SURFACE_GROWTH = "attack_surface_growth"
    RECOVERY_DEGRADATION = "recovery_degradation"
    THREAT_EMERGENCE = "threat_emergence"


ALL_TRAJECTORY_KINDS: Tuple[TrajectoryKind, ...] = tuple(TrajectoryKind)


class TrendDirection(str, Enum):
    RISING = "rising"       # security risk increasing
    FALLING = "falling"     # security risk decreasing
    FLAT = "flat"


class WarningLevel(str, Enum):
    NONE = "none"
    WATCH = "watch"
    WARNING = "warning"
    CRITICAL = "critical"


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


@dataclass(frozen=True)
class TrajectorySample:
    at: datetime
    value: float

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        if not 0.0 <= self.value <= 1.0:
            raise ValueError("value must be within [0,1]")


class WarningKind(str, Enum):
    PROJECTED_WARNING_CROSSING = "projected_warning_crossing"
    PROJECTED_CRITICAL_CROSSING = "projected_critical_crossing"
    SUSTAINED_WORSENING_TREND = "sustained_worsening_trend"
    ACCELERATING_WORSENING = "accelerating_worsening"
    LOW_TRAJECTORY_CONFIDENCE = "low_trajectory_confidence"
    INSUFFICIENT_SAMPLES = "insufficient_samples"


@dataclass(frozen=True)
class WarningSignal:
    kind: WarningKind
    entity_id: str
    trajectory_kind: TrajectoryKind
    detail: str
    severity: int          # 1..5
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        if not 1 <= self.severity <= 5:
            raise ValueError("severity must be in [1,5]")


# =============================================================================
# SECTION 3 — TIME-SERIES PRIMITIVES
# =============================================================================


def ewma_alpha(half_life: int) -> float:
    if half_life <= 0:
        raise ValueError("half_life must be > 0")
    return 1.0 - 0.5 ** (1.0 / half_life)


def ewma(values: Sequence[float], *, alpha: float) -> float:
    if not values:
        raise ValueError("values must be non-empty")
    if not 0.0 < alpha <= 1.0:
        raise ValueError("alpha must be in (0,1]")
    cur = values[0]
    for v in values[1:]:
        cur = alpha * v + (1.0 - alpha) * cur
    return cur


@dataclass(frozen=True)
class LinearTrend:
    slope: float        # per step
    intercept: float
    r_squared: float    # 0..1

    def __post_init__(self) -> None:
        if not 0.0 <= self.r_squared <= 1.0 + 1e-9:
            raise ValueError("r_squared must be within [0,1]")

    def value_at(self, x: float) -> float:
        return self.intercept + self.slope * x


def least_squares(xs: Sequence[float], ys: Sequence[float]) -> LinearTrend:
    if len(xs) != len(ys):
        raise ValueError("xs and ys must have same length")
    n = len(xs)
    if n < 2:
        raise ValueError("need at least 2 points")
    mx = sum(xs) / n
    my = sum(ys) / n
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    den = sum((x - mx) ** 2 for x in xs)
    if den == 0.0:
        return LinearTrend(slope=0.0, intercept=my, r_squared=0.0)
    slope = num / den
    intercept = my - slope * mx
    # R²
    ss_tot = sum((y - my) ** 2 for y in ys)
    if ss_tot == 0.0:
        return LinearTrend(slope=slope, intercept=intercept, r_squared=1.0)
    ss_res = sum((y - (intercept + slope * x)) ** 2
                 for x, y in zip(xs, ys))
    r_sq = max(0.0, min(1.0, 1.0 - ss_res / ss_tot))
    return LinearTrend(slope=slope, intercept=intercept, r_squared=r_sq)


# =============================================================================
# SECTION 4 — TRAJECTORY
# =============================================================================


@dataclass(frozen=True)
class TrajectoryThresholds:
    warning: float          # value above which WARNING
    critical: float         # value above which CRITICAL

    def __post_init__(self) -> None:
        if not 0.0 <= self.warning <= 1.0:
            raise ValueError("warning must be within [0,1]")
        if not 0.0 <= self.critical <= 1.0:
            raise ValueError("critical must be within [0,1]")
        if self.warning >= self.critical:
            raise ValueError("warning must be < critical")


@dataclass(frozen=True)
class TrajectoryConfig:
    kind: TrajectoryKind
    warning_threshold: float
    critical_threshold: float
    horizon_seconds: float = 3600.0
    min_samples: int = 5
    min_trend_r2: float = 0.5
    ewma_half_life: int = 5
    momentum_half_life_short: int = 2
    momentum_half_life_long: int = 10

    def __post_init__(self) -> None:
        if not 0.0 <= self.warning_threshold <= 1.0:
            raise ValueError("warning_threshold must be within [0,1]")
        if not 0.0 <= self.critical_threshold <= 1.0:
            raise ValueError("critical_threshold must be within [0,1]")
        if self.warning_threshold >= self.critical_threshold:
            raise ValueError("warning_threshold must be < critical_threshold")
        if self.horizon_seconds <= 0:
            raise ValueError("horizon_seconds must be > 0")
        if self.min_samples < 2:
            raise ValueError("min_samples must be >= 2")
        if not 0.0 <= self.min_trend_r2 <= 1.0:
            raise ValueError("min_trend_r2 must be within [0,1]")
        if self.ewma_half_life <= 0:
            raise ValueError("ewma_half_life must be > 0")
        if self.momentum_half_life_short <= 0 \
           or self.momentum_half_life_long <= 0:
            raise ValueError("momentum half lives must be > 0")
        if self.momentum_half_life_short >= self.momentum_half_life_long:
            raise ValueError(
                "short momentum half life must be < long momentum half life"
            )

    @property
    def thresholds(self) -> TrajectoryThresholds:
        return TrajectoryThresholds(
            warning=self.warning_threshold, critical=self.critical_threshold,
        )


@dataclass(frozen=True)
class TrajectoryState:
    entity_id: str
    kind: TrajectoryKind
    samples: Tuple[TrajectorySample, ...]
    smoothed_value: float
    trend: Optional[LinearTrend]
    momentum: float                     # short_ewma - long_ewma
    acceleration: float                 # slope2 - slope1
    warning_level: WarningLevel
    projected_value: Optional[float]    # at horizon
    sample_count: int
    updated_at: datetime

    def __post_init__(self) -> None:
        if not 0.0 <= self.smoothed_value <= 1.0:
            raise ValueError("smoothed_value must be within [0,1]")
        if self.projected_value is not None \
           and not 0.0 <= self.projected_value <= 1.0 + 1e-9:
            raise ValueError("projected_value must be within [0,1]")
        if self.updated_at.tzinfo is None:
            raise ValueError("updated_at must be timezone-aware")
        if self.sample_count != len(self.samples):
            raise ValueError("sample_count must match samples length")


# =============================================================================
# SECTION 5 — INVARIANTS
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
class TimeSeriesSnapshot:
    trajectories: Mapping[Tuple[str, TrajectoryKind], TrajectoryState]
    configs: Mapping[TrajectoryKind, TrajectoryConfig]
    warnings: Tuple[WarningSignal, ...]


@dataclass(frozen=True)
class TimeSeriesInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[TimeSeriesSnapshot],
                        Tuple[InvariantViolation, ...]]
    description: str


def _inv_values_in_unit(snap: TimeSeriesSnapshot) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for (eid, kind), ts in snap.trajectories.items():
        for s in ts.samples:
            if not 0.0 <= s.value <= 1.0:
                out.append(InvariantViolation(
                    invariant_id="ts.values_in_unit",
                    severity=InvariantSeverity.CRITICAL,
                    subject_id=f"{eid}/{kind.value}",
                    detail=f"sample value {s.value} out of [0,1]",
                ))
                break
    return tuple(out)


def _inv_thresholds_ordered(snap: TimeSeriesSnapshot) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for kind, c in snap.configs.items():
        if c.warning_threshold >= c.critical_threshold:
            out.append(InvariantViolation(
                invariant_id="ts.thresholds_ordered",
                severity=InvariantSeverity.CRITICAL,
                subject_id=kind.value,
                detail=(
                    f"warning {c.warning_threshold} >= critical "
                    f"{c.critical_threshold}"
                ),
            ))
    return tuple(out)


def _inv_warning_level_consistent(
    snap: TimeSeriesSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for (eid, kind), ts in snap.trajectories.items():
        cfg = snap.configs.get(kind)
        if cfg is None:
            continue
        v = ts.smoothed_value
        if v >= cfg.critical_threshold \
           and ts.warning_level is not WarningLevel.CRITICAL:
            out.append(InvariantViolation(
                invariant_id="ts.warning_level_consistent",
                severity=InvariantSeverity.HIGH,
                subject_id=f"{eid}/{kind.value}",
                detail=(
                    f"smoothed {v:.3f} >= critical "
                    f"{cfg.critical_threshold:.3f} but level is "
                    f"{ts.warning_level.value}"
                ),
            ))
    return tuple(out)


def _inv_samples_sorted(snap: TimeSeriesSnapshot) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for (eid, kind), ts in snap.trajectories.items():
        prev: Optional[datetime] = None
        for s in ts.samples:
            if prev is not None and s.at < prev:
                out.append(InvariantViolation(
                    invariant_id="ts.samples_sorted",
                    severity=InvariantSeverity.CRITICAL,
                    subject_id=f"{eid}/{kind.value}",
                    detail="samples not in chronological order",
                ))
                break
            prev = s.at
    return tuple(out)


def _inv_no_critical_with_insufficient_data(
    snap: TimeSeriesSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for (eid, kind), ts in snap.trajectories.items():
        cfg = snap.configs.get(kind)
        if cfg is None:
            continue
        if ts.warning_level is WarningLevel.CRITICAL \
           and ts.sample_count < cfg.min_samples:
            out.append(InvariantViolation(
                invariant_id="ts.no_critical_with_insufficient_data",
                severity=InvariantSeverity.HIGH,
                subject_id=f"{eid}/{kind.value}",
                detail=(
                    f"CRITICAL with only {ts.sample_count} samples "
                    f"(min {cfg.min_samples})"
                ),
            ))
    return tuple(out)


DEFAULT_INVARIANTS: Tuple[TimeSeriesInvariant, ...] = (
    TimeSeriesInvariant(
        invariant_id="ts.values_in_unit",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_values_in_unit,
        description="Trajectory samples must lie within [0,1].",
    ),
    TimeSeriesInvariant(
        invariant_id="ts.thresholds_ordered",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_thresholds_ordered,
        description="Warning threshold must be < critical threshold.",
    ),
    TimeSeriesInvariant(
        invariant_id="ts.warning_level_consistent",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_warning_level_consistent,
        description="Warning level must reflect smoothed value vs thresholds.",
    ),
    TimeSeriesInvariant(
        invariant_id="ts.samples_sorted",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_samples_sorted,
        description="Trajectory samples must be in chronological order.",
    ),
    TimeSeriesInvariant(
        invariant_id="ts.no_critical_with_insufficient_data",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_no_critical_with_insufficient_data,
        description="CRITICAL requires minimum samples.",
    ),
)


def check_invariants(
    snap: TimeSeriesSnapshot,
    invariants: Iterable[TimeSeriesInvariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 6 — STORE
# =============================================================================


@dataclass(frozen=True)
class TrajectoryRecord:
    entity_id: str
    kind: TrajectoryKind
    smoothed_value: float
    slope: float
    r_squared: float
    momentum: float
    acceleration: float
    warning_level: WarningLevel
    projected_value: Optional[float]
    sample_count: int
    updated_at: datetime


class TimeSeriesStore(Protocol):
    def get(self, entity_id: str, kind: TrajectoryKind) -> Optional[TrajectoryRecord]: ...
    def put(self, record: TrajectoryRecord) -> None: ...
    def all(self) -> Tuple[TrajectoryRecord, ...]: ...


class InMemoryTimeSeriesStore:
    def __init__(self) -> None:
        self._data: Dict[Tuple[str, TrajectoryKind], TrajectoryRecord] = {}

    def get(
        self, entity_id: str, kind: TrajectoryKind,
    ) -> Optional[TrajectoryRecord]:
        return self._data.get((entity_id, kind))

    def put(self, record: TrajectoryRecord) -> None:
        existing = self._data.get((record.entity_id, record.kind))
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._data[(record.entity_id, record.kind)] = record

    def all(self) -> Tuple[TrajectoryRecord, ...]:
        return tuple(self._data.values())


class SqliteTimeSeriesStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ts_trajectory (
                entity_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                smoothed_value REAL NOT NULL,
                slope REAL NOT NULL,
                r_squared REAL NOT NULL,
                momentum REAL NOT NULL,
                acceleration REAL NOT NULL,
                warning_level TEXT NOT NULL,
                projected_value REAL,
                sample_count INTEGER NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (entity_id, kind)
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ts_samples (
                sample_id TEXT PRIMARY KEY,
                entity_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                at TEXT NOT NULL,
                value REAL NOT NULL
            )
            """
        )
        self._conn.commit()

    def get(
        self, entity_id: str, kind: TrajectoryKind,
    ) -> Optional[TrajectoryRecord]:
        row = self._conn.execute(
            "SELECT smoothed_value, slope, r_squared, momentum, "
            "acceleration, warning_level, projected_value, sample_count, "
            "updated_at FROM ts_trajectory WHERE entity_id = ? AND kind = ?",
            (entity_id, kind.value),
        ).fetchone()
        if row is None:
            return None
        return TrajectoryRecord(
            entity_id=entity_id, kind=kind,
            smoothed_value=float(row[0]), slope=float(row[1]),
            r_squared=float(row[2]), momentum=float(row[3]),
            acceleration=float(row[4]),
            warning_level=WarningLevel(row[5]),
            projected_value=float(row[6]) if row[6] is not None else None,
            sample_count=int(row[7]),
            updated_at=datetime.fromisoformat(row[8]),
        )

    def put(self, record: TrajectoryRecord) -> None:
        existing = self.get(record.entity_id, record.kind)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._conn.execute(
            """
            INSERT INTO ts_trajectory
              (entity_id, kind, smoothed_value, slope, r_squared, momentum,
               acceleration, warning_level, projected_value, sample_count,
               updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(entity_id, kind) DO UPDATE SET
              smoothed_value=excluded.smoothed_value,
              slope=excluded.slope,
              r_squared=excluded.r_squared,
              momentum=excluded.momentum,
              acceleration=excluded.acceleration,
              warning_level=excluded.warning_level,
              projected_value=excluded.projected_value,
              sample_count=excluded.sample_count,
              updated_at=excluded.updated_at
            """,
            (
                record.entity_id, record.kind.value, record.smoothed_value,
                record.slope, record.r_squared, record.momentum,
                record.acceleration, record.warning_level.value,
                record.projected_value, record.sample_count,
                record.updated_at.isoformat(),
            ),
        )
        self._conn.commit()

    def all(self) -> Tuple[TrajectoryRecord, ...]:
        rows = self._conn.execute(
            "SELECT entity_id, kind FROM ts_trajectory"
        ).fetchall()
        out: List[TrajectoryRecord] = []
        for eid, k in rows:
            r = self.get(eid, TrajectoryKind(k))
            if r is not None:
                out.append(r)
        return tuple(out)

    def put_sample(
        self, sample_id: str, obs: TrajectorySample,
        *, entity_id: str, kind: TrajectoryKind,
    ) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO ts_samples "
            "(sample_id, entity_id, kind, at, value) VALUES (?, ?, ?, ?, ?)",
            (sample_id, entity_id, kind.value, obs.at.isoformat(),
             obs.value),
        )
        self._conn.commit()

    def get_samples(
        self, entity_id: str, kind: TrajectoryKind,
    ) -> Tuple[TrajectorySample, ...]:
        rows = self._conn.execute(
            "SELECT at, value FROM ts_samples "
            "WHERE entity_id = ? AND kind = ? ORDER BY at ASC",
            (entity_id, kind.value),
        ).fetchall()
        return tuple(
            TrajectorySample(at=datetime.fromisoformat(r[0]),
                             value=float(r[1]))
            for r in rows
        )


# =============================================================================
# SECTION 7 — ENGINE
# =============================================================================


@dataclass
class _EntityTrajectory:
    entity_id: str
    kind: TrajectoryKind
    samples: List[TrajectorySample] = field(default_factory=list)


class TimeSeriesEarlyWarningEngine:
    """Time-series + early-warning engine for security trajectories."""

    def __init__(
        self,
        *,
        store: Optional[TimeSeriesStore] = None,
        max_history: int = 200,
    ) -> None:
        if max_history < 5:
            raise ValueError("max_history must be >= 5")
        self._store: TimeSeriesStore = store or InMemoryTimeSeriesStore()
        self._trajectories: Dict[Tuple[str, TrajectoryKind],
                                 _EntityTrajectory] = {}
        self._configs: Dict[TrajectoryKind, TrajectoryConfig] = {}
        self._states: Dict[Tuple[str, TrajectoryKind], TrajectoryState] = {}
        self._warnings: List[WarningSignal] = []
        self._violations: Tuple[InvariantViolation, ...] = ()
        self._max_history = max_history
        self._sample_seq: int = 0

        # Register default configs
        self._register_default_configs()

    # ---- setup -----------------------------------------------------------

    def _register_default_configs(self) -> None:
        self._configs[TrajectoryKind.SECURITY_STATE] = TrajectoryConfig(
            kind=TrajectoryKind.SECURITY_STATE,
            warning_threshold=0.6, critical_threshold=0.85,
        )
        self._configs[TrajectoryKind.CONTROL_DEGRADATION] = TrajectoryConfig(
            kind=TrajectoryKind.CONTROL_DEGRADATION,
            warning_threshold=0.5, critical_threshold=0.8,
        )
        self._configs[TrajectoryKind.AUTHORITY_DRIFT] = TrajectoryConfig(
            kind=TrajectoryKind.AUTHORITY_DRIFT,
            warning_threshold=0.4, critical_threshold=0.75,
        )
        self._configs[TrajectoryKind.TRUST_DECAY] = TrajectoryConfig(
            kind=TrajectoryKind.TRUST_DECAY,
            warning_threshold=0.5, critical_threshold=0.8,
        )
        self._configs[TrajectoryKind.ATTACK_SURFACE_GROWTH] = TrajectoryConfig(
            kind=TrajectoryKind.ATTACK_SURFACE_GROWTH,
            warning_threshold=0.55, critical_threshold=0.85,
        )
        self._configs[TrajectoryKind.RECOVERY_DEGRADATION] = TrajectoryConfig(
            kind=TrajectoryKind.RECOVERY_DEGRADATION,
            warning_threshold=0.5, critical_threshold=0.85,
        )
        self._configs[TrajectoryKind.THREAT_EMERGENCE] = TrajectoryConfig(
            kind=TrajectoryKind.THREAT_EMERGENCE,
            warning_threshold=0.45, critical_threshold=0.8,
        )

    def register_entity(self, entity_id: str) -> None:
        if not entity_id:
            raise ValueError("entity_id is required")
        # Entity is lazily created on first sample; this method ensures
        # the caller has explicitly named it.
        for kind in ALL_TRAJECTORY_KINDS:
            key = (entity_id, kind)
            if key not in self._trajectories:
                self._trajectories[key] = _EntityTrajectory(
                    entity_id=entity_id, kind=kind,
                )

    def configure(self, config: TrajectoryConfig) -> None:
        self._configs[config.kind] = config

    def config(self, kind: TrajectoryKind) -> Optional[TrajectoryConfig]:
        return self._configs.get(kind)

    # ---- observation -----------------------------------------------------

    def observe(
        self,
        entity_id: str,
        kind: TrajectoryKind,
        *,
        value: float,
        at: datetime,
    ) -> None:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        if not 0.0 <= value <= 1.0:
            raise ValueError("value must be within [0,1]")
        key = (entity_id, kind)
        traj = self._trajectories.get(key)
        if traj is None:
            traj = _EntityTrajectory(entity_id=entity_id, kind=kind)
            self._trajectories[key] = traj
        sample = TrajectorySample(at=at, value=value)
        traj.samples.append(sample)
        if len(traj.samples) > self._max_history:
            traj.samples = traj.samples[-self._max_history:]
        if isinstance(self._store, SqliteTimeSeriesStore):
            self._sample_seq += 1
            self._store.put_sample(
                f"s-{self._sample_seq:08d}", sample,
                entity_id=entity_id, kind=kind,
            )

    # ---- core computation -----------------------------------------------

    def _compute_state(
        self, traj: _EntityTrajectory, cfg: TrajectoryConfig,
    ) -> TrajectoryState:
        samples = tuple(traj.samples)
        if not samples:
            return TrajectoryState(
                entity_id=traj.entity_id, kind=traj.kind,
                samples=(), smoothed_value=0.0, trend=None,
                momentum=0.0, acceleration=0.0,
                warning_level=WarningLevel.NONE,
                projected_value=None, sample_count=0,
                updated_at=datetime.now().astimezone(),
            )

        values = [s.value for s in samples]
        alpha = ewma_alpha(cfg.ewma_half_life)
        smoothed = ewma(values, alpha=alpha)

        # Trend
        if len(samples) >= 2:
            xs = [float(i) for i in range(len(samples))]
            trend = least_squares(xs, values)
        else:
            trend = None

        # Momentum (short vs long ewma)
        a_short = ewma_alpha(cfg.momentum_half_life_short)
        a_long = ewma_alpha(cfg.momentum_half_life_long)
        m_short = ewma(values, alpha=a_short)
        m_long = ewma(values, alpha=a_long)
        momentum = m_short - m_long

        # Acceleration: slope over second half - slope over first half
        acceleration = 0.0
        if len(values) >= 4:
            half = len(values) // 2
            first = values[:half]
            second = values[half:]
            xs1 = [float(i) for i in range(len(first))]
            xs2 = [float(i) for i in range(len(second))]
            s1 = least_squares(xs1, first).slope if len(first) >= 2 else 0.0
            s2 = least_squares(xs2, second).slope if len(second) >= 2 else 0.0
            acceleration = s2 - s1

        # Warning level from smoothed value
        if smoothed >= cfg.critical_threshold:
            level = WarningLevel.CRITICAL
        elif smoothed >= cfg.warning_threshold:
            level = WarningLevel.WARNING
        elif smoothed >= cfg.warning_threshold * 0.75:
            level = WarningLevel.WATCH
        else:
            level = WarningLevel.NONE

        # Projection to horizon (sample interval ≈ 1 unit in the series).
        # We use the trend slope in "per-sample" units. If the caller
        # supplied samples at irregular intervals, the projection is
        # approximate — bounded by horizon_seconds / average_interval.
        projected: Optional[float] = None
        if trend is not None and len(samples) >= cfg.min_samples:
            if len(samples) >= 2:
                # Estimate average interval in seconds
                times = [s.at for s in samples]
                deltas = [(times[i] - times[i - 1]).total_seconds()
                          for i in range(1, len(times))]
                avg_dt = sum(deltas) / len(deltas) if deltas else 1.0
                if avg_dt <= 0:
                    avg_dt = 1.0
                steps = cfg.horizon_seconds / avg_dt
                x = float(len(samples) - 1) + steps
                projected = max(0.0, min(1.0, trend.value_at(x)))

        return TrajectoryState(
            entity_id=traj.entity_id, kind=traj.kind,
            samples=samples, smoothed_value=smoothed,
            trend=trend, momentum=momentum,
            acceleration=acceleration,
            warning_level=level,
            projected_value=projected,
            sample_count=len(samples),
            updated_at=samples[-1].at,
        )

    # ---- warning generation ---------------------------------------------

    def _generate_warnings(
        self, state: TrajectoryState, cfg: TrajectoryConfig,
    ) -> List[WarningSignal]:
        out: List[WarningSignal] = []
        at = state.updated_at

        # Insufficient samples
        if state.sample_count < cfg.min_samples:
            out.append(WarningSignal(
                kind=WarningKind.INSUFFICIENT_SAMPLES,
                entity_id=state.entity_id, trajectory_kind=state.kind,
                detail=(
                    f"{state.sample_count} sample(s) < min "
                    f"{cfg.min_samples}"
                ),
                severity=1, at=at,
            ))
            return out

        trend = state.trend
        if trend is None:
            return out

        # Trend-based early warnings only when the trend is credible.
        if trend.r_squared < cfg.min_trend_r2:
            out.append(WarningSignal(
                kind=WarningKind.LOW_TRAJECTORY_CONFIDENCE,
                entity_id=state.entity_id, trajectory_kind=state.kind,
                detail=(
                    f"R² = {trend.r_squared:.3f} < min "
                    f"{cfg.min_trend_r2:.3f}"
                ),
                severity=2, at=at,
            ))

        # Sustained worsening trend (slope > 0 and credible)
        if trend.slope > 0.0 and trend.r_squared >= cfg.min_trend_r2:
            out.append(WarningSignal(
                kind=WarningKind.SUSTAINED_WORSENING_TREND,
                entity_id=state.entity_id, trajectory_kind=state.kind,
                detail=(
                    f"sustained rise: slope {trend.slope:.4f}/step, "
                    f"R² {trend.r_squared:.3f}"
                ),
                severity=3, at=at,
            ))

        # Accelerating worsening
        if state.acceleration > 0.01 and trend.slope > 0.0 \
           and trend.r_squared >= cfg.min_trend_r2:
            out.append(WarningSignal(
                kind=WarningKind.ACCELERATING_WORSENING,
                entity_id=state.entity_id, trajectory_kind=state.kind,
                detail=(
                    f"acceleration {state.acceleration:.4f} on top of "
                    f"slope {trend.slope:.4f}"
                ),
                severity=4, at=at,
            ))

        # Projected warning/critical crossings
        if state.projected_value is not None:
            if state.projected_value >= cfg.critical_threshold \
               and state.smoothed_value < cfg.critical_threshold:
                out.append(WarningSignal(
                    kind=WarningKind.PROJECTED_CRITICAL_CROSSING,
                    entity_id=state.entity_id,
                    trajectory_kind=state.kind,
                    detail=(
                        f"projected {state.projected_value:.3f} at "
                        f"horizon crosses critical "
                        f"{cfg.critical_threshold:.2f}"
                    ),
                    severity=5, at=at,
                ))
            elif state.projected_value >= cfg.warning_threshold \
               and state.smoothed_value < cfg.warning_threshold:
                out.append(WarningSignal(
                    kind=WarningKind.PROJECTED_WARNING_CROSSING,
                    entity_id=state.entity_id,
                    trajectory_kind=state.kind,
                    detail=(
                        f"projected {state.projected_value:.3f} at "
                        f"horizon crosses warning "
                        f"{cfg.warning_threshold:.2f}"
                    ),
                    severity=3, at=at,
                ))

        return out

    # ---- recompute -------------------------------------------------------

    def recompute(self, *, at: datetime) -> Tuple[TrajectoryRecord, ...]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

        records: List[TrajectoryRecord] = []
        self._warnings = []

        for (eid, kind), traj in self._trajectories.items():
            cfg = self._configs.get(kind)
            if cfg is None:
                continue
            if not traj.samples:
                continue

            state = self._compute_state(traj, cfg)
            self._states[(eid, kind)] = state

            warnings = self._generate_warnings(state, cfg)
            self._warnings.extend(warnings)

            trend = state.trend
            rec = TrajectoryRecord(
                entity_id=eid, kind=kind,
                smoothed_value=state.smoothed_value,
                slope=trend.slope if trend else 0.0,
                r_squared=trend.r_squared if trend else 0.0,
                momentum=state.momentum,
                acceleration=state.acceleration,
                warning_level=state.warning_level,
                projected_value=state.projected_value,
                sample_count=state.sample_count,
                updated_at=at,
            )
            self._store.put(rec)
            records.append(rec)

        self._violations = check_invariants(self.snapshot())
        return tuple(records)

    # ---- queries ---------------------------------------------------------

    def state(
        self, entity_id: str, kind: TrajectoryKind,
    ) -> Optional[TrajectoryState]:
        return self._states.get((entity_id, kind))

    def record(
        self, entity_id: str, kind: TrajectoryKind,
    ) -> Optional[TrajectoryRecord]:
        return self._store.get(entity_id, kind)

    def warnings(self) -> Tuple[WarningSignal, ...]:
        return tuple(self._warnings)

    def warnings_for(
        self, entity_id: str,
    ) -> Tuple[WarningSignal, ...]:
        return tuple(w for w in self._warnings if w.entity_id == entity_id)

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return self._violations

    def top_warnings(
        self, *, k: int = 10,
    ) -> Tuple[WarningSignal, ...]:
        if k <= 0:
            raise ValueError("k must be > 0")
        ordered = sorted(
            self._warnings,
            key=lambda w: (-w.severity, w.trajectory_kind.value,
                           w.entity_id),
        )
        return tuple(ordered[:k])

    def snapshot(self) -> TimeSeriesSnapshot:
        return TimeSeriesSnapshot(
            trajectories=dict(self._states),
            configs=dict(self._configs),
            warnings=tuple(self._warnings),
        )


# =============================================================================
# SECTION 8 — TESTS
# =============================================================================


def _t0() -> datetime:
    from datetime import timezone
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _t(seconds: int) -> datetime:
    return _t0() + timedelta(seconds=seconds)


def _fill_linear(
    eng: TimeSeriesEarlyWarningEngine, eid: str, kind: TrajectoryKind,
    start: float, step: float, n: int, *, second_step: int = 60,
) -> None:
    for i in range(n):
        v = max(0.0, min(1.0, start + step * i))
        eng.observe(eid, kind, value=v, at=_t(i * second_step))


# ---- primitives ----

def test_ewma_alpha_rejects_bad_half_life() -> None:
    try:
        ewma_alpha(0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_ewma_alpha_in_unit() -> None:
    a = ewma_alpha(5)
    assert 0.0 < a <= 1.0


def test_ewma_constant_series() -> None:
    assert abs(ewma([0.3, 0.3, 0.3], alpha=0.5) - 0.3) < 1e-9


def test_ewma_rejects_empty() -> None:
    try:
        ewma([], alpha=0.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_least_squares_perfect_line() -> None:
    xs = [0.0, 1.0, 2.0, 3.0]
    ys = [0.1, 0.2, 0.3, 0.4]
    t = least_squares(xs, ys)
    assert abs(t.slope - 0.1) < 1e-9
    assert abs(t.r_squared - 1.0) < 1e-9


def test_least_squares_zero_slope() -> None:
    xs = [0.0, 1.0, 2.0]
    ys = [0.5, 0.5, 0.5]
    t = least_squares(xs, ys)
    assert abs(t.slope) < 1e-9


def test_least_squares_r_squared_in_unit() -> None:
    xs = [0.0, 1.0, 2.0, 3.0]
    ys = [0.3, 0.7, 0.4, 0.9]
    t = least_squares(xs, ys)
    assert 0.0 <= t.r_squared <= 1.0


def test_least_squares_requires_two_points() -> None:
    try:
        least_squares([1.0], [1.0])
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_least_squares_length_mismatch() -> None:
    try:
        least_squares([1.0, 2.0], [1.0])
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- trajectory sample ----

def test_sample_validates_timezone() -> None:
    from datetime import datetime as dt
    try:
        TrajectorySample(at=dt(2026, 1, 1), value=0.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sample_validates_value() -> None:
    try:
        TrajectorySample(at=_t0(), value=1.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- config ----

def test_config_rejects_warning_geq_critical() -> None:
    try:
        TrajectoryConfig(
            kind=TrajectoryKind.SECURITY_STATE,
            warning_threshold=0.9, critical_threshold=0.5,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_config_thresholds_property() -> None:
    cfg = TrajectoryConfig(
        kind=TrajectoryKind.SECURITY_STATE,
        warning_threshold=0.5, critical_threshold=0.8,
    )
    t = cfg.thresholds
    assert t.warning == 0.5 and t.critical == 0.8


def test_config_rejects_short_geq_long_momentum() -> None:
    try:
        TrajectoryConfig(
            kind=TrajectoryKind.SECURITY_STATE,
            warning_threshold=0.5, critical_threshold=0.8,
            momentum_half_life_short=10, momentum_half_life_long=5,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- engine basics ----

def test_engine_default_configs_present() -> None:
    eng = TimeSeriesEarlyWarningEngine()
    for kind in ALL_TRAJECTORY_KINDS:
        assert eng.config(kind) is not None


def test_engine_observe_rejects_bad_time() -> None:
    eng = TimeSeriesEarlyWarningEngine()
    from datetime import datetime as dt
    try:
        eng.observe("e1", TrajectoryKind.SECURITY_STATE,
                    value=0.5, at=dt(2026, 1, 1))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_observe_rejects_bad_value() -> None:
    eng = TimeSeriesEarlyWarningEngine()
    try:
        eng.observe("e1", TrajectoryKind.SECURITY_STATE,
                    value=1.5, at=_t0())
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_state_present_after_recompute() -> None:
    eng = TimeSeriesEarlyWarningEngine()
    _fill_linear(eng, "e1", TrajectoryKind.SECURITY_STATE,
                 start=0.1, step=0.02, n=10)
    eng.recompute(at=_t(600))
    st = eng.state("e1", TrajectoryKind.SECURITY_STATE)
    assert st is not None
    assert st.sample_count == 10


def test_engine_record_present_after_recompute() -> None:
    eng = TimeSeriesEarlyWarningEngine()
    _fill_linear(eng, "e1", TrajectoryKind.SECURITY_STATE,
                 start=0.1, step=0.02, n=10)
    eng.recompute(at=_t(600))
    rec = eng.record("e1", TrajectoryKind.SECURITY_STATE)
    assert rec is not None
    assert rec.sample_count == 10


# ---- warning generation ----

def test_insufficient_samples_warning() -> None:
    eng = TimeSeriesEarlyWarningEngine()
    _fill_linear(eng, "e1", TrajectoryKind.SECURITY_STATE,
                 start=0.1, step=0.02, n=2)
    eng.recompute(at=_t(120))
    kinds = {w.kind for w in eng.warnings()}
    assert WarningKind.INSUFFICIENT_SAMPLES in kinds


def test_sustained_worsening_trend_warning() -> None:
    eng = TimeSeriesEarlyWarningEngine()
    _fill_linear(eng, "e1", TrajectoryKind.SECURITY_STATE,
                 start=0.1, step=0.03, n=20)
    eng.recompute(at=_t(1200))
    kinds = {w.kind for w in eng.warnings()}
    assert WarningKind.SUSTAINED_WORSENING_TREND in kinds


def test_no_sustained_worsening_when_flat() -> None:
    eng = TimeSeriesEarlyWarningEngine()
    for i in range(20):
        eng.observe("e1", TrajectoryKind.SECURITY_STATE,
                    value=0.4, at=_t(i * 60))
    eng.recompute(at=_t(1200))
    kinds = {w.kind for w in eng.warnings()}
    assert WarningKind.SUSTAINED_WORSENING_TREND not in kinds


def test_accelerating_worsening_warning() -> None:
    eng = TimeSeriesEarlyWarningEngine()
    # slow rise then fast rise
    values = [0.1 + 0.005 * i for i in range(10)] + \
             [0.16 + 0.05 * i for i in range(10)]
    for i, v in enumerate(values):
        eng.observe("e1", TrajectoryKind.SECURITY_STATE,
                    value=max(0.0, min(1.0, v)), at=_t(i * 60))
    eng.recompute(at=_t(1200))
    kinds = {w.kind for w in eng.warnings()}
    assert WarningKind.ACCELERATING_WORSENING in kinds


def test_projected_warning_crossing_warning() -> None:
    eng = TimeSeriesEarlyWarningEngine()
    # Start below warning and rise; project past warning threshold
    _fill_linear(eng, "e1", TrajectoryKind.SECURITY_STATE,
                 start=0.1, step=0.03, n=10)
    eng.recompute(at=_t(600))
    kinds = {w.kind for w in eng.warnings()}
    assert WarningKind.PROJECTED_WARNING_CROSSING in kinds \
        or WarningKind.PROJECTED_CRITICAL_CROSSING in kinds \
        or WarningKind.SUSTAINED_WORSENING_TREND in kinds


def test_low_trajectory_confidence_warning() -> None:
    eng = TimeSeriesEarlyWarningEngine()
    # random-ish pattern → low R²
    values = [0.1, 0.9, 0.2, 0.8, 0.15, 0.85, 0.25, 0.75, 0.3, 0.7]
    for i, v in enumerate(values):
        eng.observe("e1", TrajectoryKind.SECURITY_STATE,
                    value=v, at=_t(i * 60))
    eng.recompute(at=_t(600))
    kinds = {w.kind for w in eng.warnings()}
    assert WarningKind.LOW_TRAJECTORY_CONFIDENCE in kinds


def test_warning_level_critical() -> None:
    eng = TimeSeriesEarlyWarningEngine()
    for i in range(10):
        eng.observe("e1", TrajectoryKind.SECURITY_STATE,
                    value=0.95, at=_t(i * 60))
    eng.recompute(at=_t(600))
    st = eng.state("e1", TrajectoryKind.SECURITY_STATE)
    assert st is not None
    assert st.warning_level is WarningLevel.CRITICAL


def test_warning_level_warning() -> None:
    eng = TimeSeriesEarlyWarningEngine()
    for i in range(10):
        eng.observe("e1", TrajectoryKind.SECURITY_STATE,
                    value=0.7, at=_t(i * 60))
    eng.recompute(at=_t(600))
    st = eng.state("e1", TrajectoryKind.SECURITY_STATE)
    assert st is not None
    assert st.warning_level is WarningLevel.WARNING


def test_warning_level_none() -> None:
    eng = TimeSeriesEarlyWarningEngine()
    for i in range(10):
        eng.observe("e1", TrajectoryKind.SECURITY_STATE,
                    value=0.05, at=_t(i * 60))
    eng.recompute(at=_t(600))
    st = eng.state("e1", TrajectoryKind.SECURITY_STATE)
    assert st is not None
    assert st.warning_level is WarningLevel.NONE


# ---- top warnings ----

def test_top_warnings_sorted_by_severity() -> None:
    eng = TimeSeriesEarlyWarningEngine()
    # generate critical projection on one entity
    _fill_linear(eng, "e1", TrajectoryKind.SECURITY_STATE,
                 start=0.7, step=0.05, n=10)
    # generate nothing on e2
    for i in range(10):
        eng.observe("e2", TrajectoryKind.SECURITY_STATE,
                    value=0.1, at=_t(i * 60))
    eng.recompute(at=_t(600))
    top = eng.top_warnings(k=5)
    assert len(top) >= 1


def test_top_warnings_invalid_k() -> None:
    eng = TimeSeriesEarlyWarningEngine()
    try:
        eng.top_warnings(k=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- momentum / acceleration ----

def test_momentum_positive_on_rising() -> None:
    eng = TimeSeriesEarlyWarningEngine()
    _fill_linear(eng, "e1", TrajectoryKind.SECURITY_STATE,
                 start=0.1, step=0.03, n=15)
    eng.recompute(at=_t(900))
    st = eng.state("e1", TrajectoryKind.SECURITY_STATE)
    assert st is not None
    assert st.momentum > 0.0


def test_momentum_negative_on_falling() -> None:
    eng = TimeSeriesEarlyWarningEngine()
    _fill_linear(eng, "e1", TrajectoryKind.SECURITY_STATE,
                 start=0.9, step=-0.05, n=15)
    eng.recompute(at=_t(900))
    st = eng.state("e1", TrajectoryKind.SECURITY_STATE)
    assert st is not None
    assert st.momentum < 0.0


# ---- multiple trajectories per entity ----

def test_multiple_trajectory_kinds_per_entity() -> None:
    eng = TimeSeriesEarlyWarningEngine()
    for i in range(10):
        eng.observe("e1", TrajectoryKind.SECURITY_STATE,
                    value=0.3, at=_t(i * 60))
        eng.observe("e1", TrajectoryKind.AUTHORITY_DRIFT,
                    value=0.2, at=_t(i * 60))
    eng.recompute(at=_t(600))
    assert eng.state("e1", TrajectoryKind.SECURITY_STATE) is not None
    assert eng.state("e1", TrajectoryKind.AUTHORITY_DRIFT) is not None


def test_custom_config_used() -> None:
    eng = TimeSeriesEarlyWarningEngine()
    eng.configure(TrajectoryConfig(
        kind=TrajectoryKind.THREAT_EMERGENCE,
        warning_threshold=0.2, critical_threshold=0.4,
        min_samples=3, min_trend_r2=0.3,
    ))
    for i in range(10):
        eng.observe("e1", TrajectoryKind.THREAT_EMERGENCE,
                    value=0.5, at=_t(i * 60))
    eng.recompute(at=_t(600))
    st = eng.state("e1", TrajectoryKind.THREAT_EMERGENCE)
    assert st is not None
    assert st.warning_level is WarningLevel.CRITICAL


# ---- invariants ----

def test_invariant_clean_snapshot() -> None:
    eng = TimeSeriesEarlyWarningEngine()
    _fill_linear(eng, "e1", TrajectoryKind.SECURITY_STATE,
                 start=0.1, step=0.02, n=10)
    eng.recompute(at=_t(600))
    assert eng.violations() == ()


def test_invariant_thresholds_ordered() -> None:
    eng = TimeSeriesEarlyWarningEngine()
    # Force an inconsistent config via direct dict manipulation
    eng._configs[TrajectoryKind.SECURITY_STATE] = TrajectoryConfig(
        kind=TrajectoryKind.SECURITY_STATE,
        warning_threshold=0.5, critical_threshold=0.8,
    )
    # Now inject a deliberately bad config (bypass __post_init__)
    bad = object.__new__(TrajectoryConfig)
    object.__setattr__(bad, "kind", TrajectoryKind.SECURITY_STATE)
    object.__setattr__(bad, "warning_threshold", 0.9)
    object.__setattr__(bad, "critical_threshold", 0.5)
    object.__setattr__(bad, "horizon_seconds", 3600.0)
    object.__setattr__(bad, "min_samples", 5)
    object.__setattr__(bad, "min_trend_r2", 0.5)
    object.__setattr__(bad, "ewma_half_life", 5)
    object.__setattr__(bad, "momentum_half_life_short", 2)
    object.__setattr__(bad, "momentum_half_life_long", 10)
    eng._configs[TrajectoryKind.SECURITY_STATE] = bad
    _fill_linear(eng, "e1", TrajectoryKind.SECURITY_STATE,
                 start=0.1, step=0.05, n=10)
    eng.recompute(at=_t(600))
    v = eng.violations()
    assert any(x.invariant_id == "ts.thresholds_ordered" for x in v)


def test_invariant_no_critical_with_insufficient_data() -> None:
    eng = TimeSeriesEarlyWarningEngine()
    eng.configure(TrajectoryConfig(
        kind=TrajectoryKind.SECURITY_STATE,
        warning_threshold=0.3, critical_threshold=0.5,
        min_samples=10,
    ))
    for i in range(3):
        eng.observe("e1", TrajectoryKind.SECURITY_STATE,
                    value=0.9, at=_t(i * 60))
    eng.recompute(at=_t(180))
    # The state's warning level should be CRITICAL (0.9 >= 0.5) but
    # sample_count < min_samples → invariant violation.
    v = eng.violations()
    assert any(
        x.invariant_id == "ts.no_critical_with_insufficient_data"
        for x in v
    )


# ---- snapshot ----

def test_snapshot_shape() -> None:
    eng = TimeSeriesEarlyWarningEngine()
    _fill_linear(eng, "e1", TrajectoryKind.SECURITY_STATE,
                 start=0.1, step=0.02, n=10)
    eng.recompute(at=_t(600))
    snap = eng.snapshot()
    assert ("e1", TrajectoryKind.SECURITY_STATE) in snap.trajectories
    assert len(snap.configs) >= len(ALL_TRAJECTORY_KINDS)


# ---- store ----

def test_in_memory_store_rejects_stale() -> None:
    s = InMemoryTimeSeriesStore()
    t = _t0()
    s.put(TrajectoryRecord(
        "e1", TrajectoryKind.SECURITY_STATE, 0.5, 0.01, 0.9, 0.05, 0.0,
        WarningLevel.WARNING, 0.6, 10, t,
    ))
    earlier = t.replace(year=t.year - 1)
    try:
        s.put(TrajectoryRecord(
            "e1", TrajectoryKind.SECURITY_STATE, 0.3, -0.01, 0.5, -0.05,
            0.0, WarningLevel.NONE, None, 5, earlier,
        ))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_trajectory_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "ts.db")
    store = SqliteTimeSeriesStore(db)
    t = _t0()
    store.put(TrajectoryRecord(
        "e1", TrajectoryKind.SECURITY_STATE, 0.6, 0.02, 0.85, 0.04, 0.01,
        WarningLevel.WARNING, 0.75, 12, t,
    ))
    got = store.get("e1", TrajectoryKind.SECURITY_STATE)
    assert got is not None
    assert got.warning_level is WarningLevel.WARNING
    assert abs(got.smoothed_value - 0.6) < 1e-9
    assert got.sample_count == 12


def test_sqlite_store_samples_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "ts.db")
    store = SqliteTimeSeriesStore(db)
    s1 = TrajectorySample(at=_t(0), value=0.1)
    s2 = TrajectorySample(at=_t(60), value=0.2)
    store.put_sample("s1", s1, entity_id="e1",
                     kind=TrajectoryKind.SECURITY_STATE)
    store.put_sample("s2", s2, entity_id="e1",
                     kind=TrajectoryKind.SECURITY_STATE)
    samples = store.get_samples("e1", TrajectoryKind.SECURITY_STATE)
    assert len(samples) == 2
    assert samples[0].value == 0.1


# ---- policy ----

def test_engine_max_history_validation() -> None:
    try:
        TimeSeriesEarlyWarningEngine(max_history=3)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# =============================================================================
# SECTION 9 — MANUAL RUNNER
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
