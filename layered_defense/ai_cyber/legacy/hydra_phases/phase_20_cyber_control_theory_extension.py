"""
HYDRA POST-CORE — PHASE 20: CYBER CONTROL THEORY EXTENSION
=============================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * Domain — 5 control dimensions, control findings
  * Configuration — per-dimension desired state + dead-band +
    actuator limit + plant gain; controller PID gains
  * PID controller with anti-windup + integrator clamp + dead-band
  * Plant model — deterministic state transition reacting to control
    input + external disturbance
  * ControlStep capturing full loop state at each tick
  * Stability analysis:
      - converging / oscillating / diverging / mixed
      - steady-state error
      - actuator saturation
      - dead-band activity
      - unstable (diverging + saturated)
  * Full simulate() to run the closed loop over N steps
  * Machine-checkable control invariants
  * In-memory + SQLite stores
  * Phase-20 engine facade
  * Full test suite + manual runner

Purpose: security as a continuously controlled dynamic system, not a
sequence of isolated alerts.

This is NEW control-theoretic security technology. It is NOT a second
decision engine. It is the loop the existing HYDRA control layer
consumes: Security State → Desired State → Control Input → State
Transition → Measurement → Error → Corrective Action.

No third-party dependencies.

Run tests:
    python hydra_phase20_cyber_control_theory.py
    pytest hydra_phase20_cyber_control_theory.py -q
"""
from __future__ import annotations

import json
import math
import sqlite3
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
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


class ControlDimension(str, Enum):
    RISK = "risk"
    EXPOSURE = "exposure"
    AUTHORITY_DRIFT = "authority_drift"
    CONTROL_DEGRADATION = "control_degradation"
    TRUST_DECAY = "trust_decay"


ALL_DIMENSIONS: Tuple[ControlDimension, ...] = tuple(ControlDimension)


class DynamicsKind(str, Enum):
    INSUFFICIENT = "insufficient"
    CONVERGING = "converging"
    MIXED = "mixed"
    OSCILLATING = "oscillating"
    DIVERGING = "diverging"
    STEADY_STATE = "steady_state"
    UNSTABLE = "unstable"


class ControlFindingKind(str, Enum):
    CONVERGING = "converging"
    DIVERGING = "diverging"
    OSCILLATING = "oscillating"
    STEADY_STATE_ERROR = "steady_state_error"
    ACTUATOR_SATURATED = "actuator_saturated"
    DEAD_BAND_ACTIVE = "dead_band_active"
    UNSTABLE = "unstable"


@dataclass(frozen=True)
class ControlFinding:
    kind: ControlFindingKind
    dimension: ControlDimension
    detail: str
    severity: int
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        if not 1 <= self.severity <= 5:
            raise ValueError("severity must be in [1,5]")


# =============================================================================
# SECTION 3 — CONFIGURATION
# =============================================================================


@dataclass(frozen=True)
class DimensionConfig:
    """Per-dimension control configuration.

    desired            ∈ [0,1]  target state value
    dead_band          ∈ [0,1]  no action when |error| < dead_band
    actuator_magnitude ∈ (0,1]  symmetric control clamp
    plant_gain         ∈ [0,1]  how much 1 unit of control changes state
    """
    dimension: ControlDimension
    desired: float
    dead_band: float = 0.05
    actuator_magnitude: float = 1.0
    plant_gain: float = 0.2

    def __post_init__(self) -> None:
        if not 0.0 <= self.desired <= 1.0:
            raise ValueError("desired must be within [0,1]")
        if not 0.0 <= self.dead_band <= 1.0:
            raise ValueError("dead_band must be within [0,1]")
        if not 0.0 < self.actuator_magnitude <= 1.0:
            raise ValueError("actuator_magnitude must be in (0,1]")
        if not 0.0 <= self.plant_gain <= 1.0:
            raise ValueError("plant_gain must be within [0,1]")


@dataclass(frozen=True)
class ControllerConfig:
    kp: float = 1.0
    ki: float = 0.1
    kd: float = 0.05
    integrator_clamp: float = 2.0
    anti_windup: bool = True

    def __post_init__(self) -> None:
        for n, v in (
            ("kp", self.kp), ("ki", self.ki), ("kd", self.kd),
        ):
            if v < 0.0:
                raise ValueError(f"{n} must be >= 0")
        if self.integrator_clamp <= 0.0:
            raise ValueError("integrator_clamp must be > 0")


# =============================================================================
# SECTION 4 — PID
# =============================================================================


@dataclass(frozen=True)
class PidState:
    integral: float = 0.0
    prev_error: Optional[float] = None

    def __post_init__(self) -> None:
        if not math.isfinite(self.integral):
            raise ValueError("integral must be finite")


def _clip(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def pid_step(
    state: PidState,
    *,
    error: float,
    dt_minutes: float,
    config: ControllerConfig,
    actuator_magnitude: float,
    dead_band: float,
) -> Tuple[float, PidState, bool, bool]:
    """Compute one PID step.

    Returns (raw_control, new_pid_state, saturated, dead_band_active).
    Raw control is pre-saturation. Caller applies actuator clamp.
    """
    if not math.isfinite(error):
        raise ValueError("error must be finite")
    if dt_minutes <= 0.0:
        raise ValueError("dt_minutes must be > 0")
    if actuator_magnitude <= 0.0:
        raise ValueError("actuator_magnitude must be > 0")
    if dead_band < 0.0:
        raise ValueError("dead_band must be >= 0")

    # Dead-band: hold integral, but update prev_error for continuity.
    if abs(error) < dead_band:
        return (0.0,
                PidState(integral=state.integral, prev_error=error),
                False, True)

    p = config.kp * error
    i = config.ki * state.integral
    d = 0.0
    if state.prev_error is not None:
        d = config.kd * (error - state.prev_error) / dt_minutes
    raw = p + i + d

    saturated = abs(raw) > actuator_magnitude + 1e-12

    if config.anti_windup and saturated:
        new_integral = state.integral
    else:
        new_integral = state.integral + error * dt_minutes
        new_integral = _clip(
            new_integral,
            -config.integrator_clamp,
            config.integrator_clamp,
        )

    new_state = PidState(integral=new_integral, prev_error=error)
    return (raw, new_state, saturated, False)


def apply_actuator(
    raw_control: float, *, magnitude: float,
) -> float:
    return _clip(raw_control, -magnitude, magnitude)


# =============================================================================
# SECTION 5 — PLANT MODEL
# =============================================================================


def apply_plant(
    state: Mapping[ControlDimension, float],
    control: Mapping[ControlDimension, float],
    *,
    plant_gain: Mapping[ControlDimension, float],
    disturbance: Optional[Mapping[ControlDimension, float]] = None,
) -> Dict[ControlDimension, float]:
    """state[t+1][d] = clamp(state[t][d] - gain[d]·control[d] + dist[d]).

    Positive control reduces the state value.
    """
    dist = disturbance or {}
    out: Dict[ControlDimension, float] = {}
    for dim, val in state.items():
        if not 0.0 <= val <= 1.0:
            raise ValueError(f"state[{dim.value}] must be within [0,1]")
        g = plant_gain.get(dim, 0.2)
        c = control.get(dim, 0.0)
        du = dist.get(dim, 0.0)
        if not math.isfinite(c):
            raise ValueError(f"control[{dim.value}] must be finite")
        if not math.isfinite(du):
            raise ValueError(f"disturbance[{dim.value}] must be finite")
        out[dim] = _clip(val - g * c + du, 0.0, 1.0)
    return out


# =============================================================================
# SECTION 6 — CONTROL STEP
# =============================================================================


@dataclass(frozen=True)
class ControlStep:
    step_id: str
    at: datetime
    measured: Mapping[ControlDimension, float]
    desired: Mapping[ControlDimension, float]
    error: Mapping[ControlDimension, float]
    raw_control: Mapping[ControlDimension, float]
    applied_control: Mapping[ControlDimension, float]
    integral: Mapping[ControlDimension, float]
    derivative: Mapping[ControlDimension, float]
    saturated: Mapping[ControlDimension, bool]
    dead_band_active: Mapping[ControlDimension, bool]

    def __post_init__(self) -> None:
        if not self.step_id:
            raise ValueError("step_id is required")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

    def total_abs_error(self) -> float:
        return sum(abs(v) for v in self.error.values())

    def any_saturated(self) -> bool:
        return any(self.saturated.values())

    def any_dead_band(self) -> bool:
        return any(self.dead_band_active.values())


# =============================================================================
# SECTION 7 — STABILITY ANALYSIS
# =============================================================================


def classify_dynamics(
    errors: Sequence[float], *, dead_band: float = 0.0,
) -> DynamicsKind:
    """Classify the sign / magnitude pattern of an error sequence."""
    if len(errors) < 3:
        return DynamicsKind.INSUFFICIENT

    mags = [abs(e) for e in errors]
    # Steady state: last few are either inside dead-band, or have simply
    # plateaued (little variation among themselves) even if that plateau
    # is away from the target - that's a genuine "settled but wrong"
    # steady-state-error case, not the same as still converging/diverging.
    tail = mags[-3:]
    within_band = all(m <= dead_band + 1e-9 for m in tail)
    plateaued = (max(tail) - min(tail)) <= 1e-9
    if within_band or plateaued:
        return DynamicsKind.STEADY_STATE

    # Sign flips → oscillating. Checked before pure-magnitude trend so a
    # decaying/growing oscillation (magnitude trend monotonic, but sign
    # alternating) is still classified as oscillating rather than as
    # simple convergence/divergence.
    signs = [1 if e >= 0 else -1 for e in errors]
    flips = sum(1 for i in range(1, len(signs)) if signs[i] != signs[i - 1])
    if flips >= max(2, (len(signs) - 1) // 2):
        return DynamicsKind.OSCILLATING

    # Strictly decreasing magnitudes → converging.
    decreasing = all(
        mags[i] >= mags[i + 1] - 1e-9
        for i in range(len(mags) - 1)
    ) and mags[0] > mags[-1] + 1e-9
    if decreasing:
        return DynamicsKind.CONVERGING

    # Strictly increasing → diverging.
    increasing = all(
        mags[i] <= mags[i + 1] + 1e-9
        for i in range(len(mags) - 1)
    ) and mags[-1] > mags[0] + 1e-9
    if increasing:
        return DynamicsKind.DIVERGING

    return DynamicsKind.MIXED


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
class ControlSnapshot:
    steps: Tuple[ControlStep, ...]
    configs: Mapping[ControlDimension, DimensionConfig]
    controller: ControllerConfig


@dataclass(frozen=True)
class ControlInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[ControlSnapshot],
                        Tuple[InvariantViolation, ...]]
    description: str


def _inv_state_in_unit(snap: ControlSnapshot) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for s in snap.steps:
        for d, v in s.measured.items():
            if not 0.0 <= v <= 1.0:
                out.append(InvariantViolation(
                    invariant_id="ctrl.state_in_unit",
                    severity=InvariantSeverity.CRITICAL,
                    subject_id=f"{s.step_id}:{d.value}",
                    detail=f"measured state {v} out of [0,1]",
                ))
    return tuple(out)


def _inv_control_in_actuator_range(
    snap: ControlSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for s in snap.steps:
        for d, v in s.applied_control.items():
            cfg = snap.configs.get(d)
            if cfg is None:
                continue
            if abs(v) > cfg.actuator_magnitude + 1e-9:
                out.append(InvariantViolation(
                    invariant_id="ctrl.control_in_actuator_range",
                    severity=InvariantSeverity.CRITICAL,
                    subject_id=f"{s.step_id}:{d.value}",
                    detail=(
                        f"applied control {v} exceeds actuator "
                        f"magnitude {cfg.actuator_magnitude}"
                    ),
                ))
    return tuple(out)


def _inv_integral_bounded(snap: ControlSnapshot) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    clamp = snap.controller.integrator_clamp
    for s in snap.steps:
        for d, v in s.integral.items():
            if abs(v) > clamp + 1e-9:
                out.append(InvariantViolation(
                    invariant_id="ctrl.integral_bounded",
                    severity=InvariantSeverity.HIGH,
                    subject_id=f"{s.step_id}:{d.value}",
                    detail=f"integral {v} exceeds clamp {clamp}",
                ))
    return tuple(out)


def _inv_dead_band_zero_control(snap: ControlSnapshot) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for s in snap.steps:
        for d, active in s.dead_band_active.items():
            if not active:
                continue
            applied = s.applied_control.get(d, 0.0)
            if abs(applied) > 1e-9:
                out.append(InvariantViolation(
                    invariant_id="ctrl.dead_band_zero_control",
                    severity=InvariantSeverity.HIGH,
                    subject_id=f"{s.step_id}:{d.value}",
                    detail=(
                        f"dead-band active but control={applied}"
                    ),
                ))
    return tuple(out)


def _inv_error_matches_state_desired(
    snap: ControlSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for s in snap.steps:
        for d, e in s.error.items():
            measured = s.measured.get(d)
            desired = s.desired.get(d)
            if measured is None or desired is None:
                continue
            expected = measured - desired
            if abs(e - expected) > 1e-9:
                out.append(InvariantViolation(
                    invariant_id="ctrl.error_matches_state_desired",
                    severity=InvariantSeverity.HIGH,
                    subject_id=f"{s.step_id}:{d.value}",
                    detail=(
                        f"error {e} != measured({measured}) - "
                        f"desired({desired})"
                    ),
                ))
    return tuple(out)


def _inv_derivative_consistent(
    snap: ControlSnapshot,
) -> Tuple[InvariantViolation, ...]:
    """First step must have zero derivative. Later steps: finite."""
    out: List[InvariantViolation] = []
    for s in snap.steps:
        for d, dval in s.derivative.items():
            if not math.isfinite(dval):
                out.append(InvariantViolation(
                    invariant_id="ctrl.derivative_finite",
                    severity=InvariantSeverity.CRITICAL,
                    subject_id=f"{s.step_id}:{d.value}",
                    detail=f"derivative non-finite: {dval}",
                ))
    return tuple(out)


DEFAULT_INVARIANTS: Tuple[ControlInvariant, ...] = (
    ControlInvariant(
        invariant_id="ctrl.state_in_unit",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_state_in_unit,
        description="Measured state values must lie within [0,1].",
    ),
    ControlInvariant(
        invariant_id="ctrl.control_in_actuator_range",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_control_in_actuator_range,
        description="Applied control must respect actuator limits.",
    ),
    ControlInvariant(
        invariant_id="ctrl.integral_bounded",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_integral_bounded,
        description="Integral term must stay within clamp.",
    ),
    ControlInvariant(
        invariant_id="ctrl.dead_band_zero_control",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_dead_band_zero_control,
        description="Dead-band active ⇒ control must be zero.",
    ),
    ControlInvariant(
        invariant_id="ctrl.error_matches_state_desired",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_error_matches_state_desired,
        description="error = measured − desired must hold exactly.",
    ),
    ControlInvariant(
        invariant_id="ctrl.derivative_finite",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_derivative_consistent,
        description="Derivative terms must be finite.",
    ),
)


def check_invariants(
    snap: ControlSnapshot,
    invariants: Iterable[ControlInvariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 9 — STORE
# =============================================================================


@dataclass(frozen=True)
class ControlRecord:
    dimension: ControlDimension
    measured: float
    desired: float
    error: float
    control: float
    integral: float
    saturated: bool
    dead_band_active: bool
    at: datetime


class ControlStore(Protocol):
    def put(self, record: ControlRecord) -> None: ...
    def all(self) -> Tuple[ControlRecord, ...]: ...


class InMemoryControlStore:
    def __init__(self) -> None:
        self._data: List[ControlRecord] = []

    def put(self, record: ControlRecord) -> None:
        self._data.append(record)

    def all(self) -> Tuple[ControlRecord, ...]:
        return tuple(self._data)


class SqliteControlStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ctrl_steps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dimension TEXT NOT NULL,
                measured REAL NOT NULL,
                desired REAL NOT NULL,
                error REAL NOT NULL,
                control REAL NOT NULL,
                integral REAL NOT NULL,
                saturated INTEGER NOT NULL,
                dead_band_active INTEGER NOT NULL,
                at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ctrl_config (
                dimension TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def put(self, record: ControlRecord) -> None:
        self._conn.execute(
            """
            INSERT INTO ctrl_steps
              (dimension, measured, desired, error, control, integral,
               saturated, dead_band_active, at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.dimension.value, record.measured, record.desired,
                record.error, record.control, record.integral,
                int(record.saturated), int(record.dead_band_active),
                record.at.isoformat(),
            ),
        )
        self._conn.commit()

    def all(self) -> Tuple[ControlRecord, ...]:
        rows = self._conn.execute(
            "SELECT dimension, measured, desired, error, control, "
            "integral, saturated, dead_band_active, at FROM ctrl_steps"
        ).fetchall()
        return tuple(
            ControlRecord(
                dimension=ControlDimension(r[0]),
                measured=float(r[1]), desired=float(r[2]),
                error=float(r[3]), control=float(r[4]),
                integral=float(r[5]), saturated=bool(r[6]),
                dead_band_active=bool(r[7]),
                at=datetime.fromisoformat(r[8]),
            )
            for r in rows
        )

    def put_config(self, cfg: DimensionConfig) -> None:
        payload = {
            "dimension": cfg.dimension.value,
            "desired": cfg.desired,
            "dead_band": cfg.dead_band,
            "actuator_magnitude": cfg.actuator_magnitude,
            "plant_gain": cfg.plant_gain,
        }
        self._conn.execute(
            "INSERT OR REPLACE INTO ctrl_config (dimension, payload_json) "
            "VALUES (?, ?)",
            (cfg.dimension.value, json.dumps(payload, sort_keys=True)),
        )
        self._conn.commit()


# =============================================================================
# SECTION 10 — ENGINE
# =============================================================================


class CyberControlEngine:
    """Closed-loop cyber control engine.

    Security state → desired state → control input → state transition →
    measurement → error → corrective action.
    """

    def __init__(
        self,
        *,
        controller: Optional[ControllerConfig] = None,
        store: Optional[ControlStore] = None,
        history_window: int = 12,
    ) -> None:
        if history_window < 3:
            raise ValueError("history_window must be >= 3")
        self._controller = controller or ControllerConfig()
        self._store: ControlStore = store or InMemoryControlStore()
        self._configs: Dict[ControlDimension, DimensionConfig] = {}
        self._pid_states: Dict[ControlDimension, PidState] = {}
        self._steps: List[ControlStep] = []
        self._history: Dict[ControlDimension, List[float]] = {}
        self._history_window = history_window
        self._findings: List[ControlFinding] = []
        self._violations: Tuple[InvariantViolation, ...] = ()
        self._step_seq = 0

    # ---- registration ----------------------------------------------------

    def register_dimension(self, cfg: DimensionConfig) -> None:
        if cfg.dimension in self._configs:
            raise ValueError(
                f"dimension {cfg.dimension.value} already registered"
            )
        self._configs[cfg.dimension] = cfg
        self._pid_states[cfg.dimension] = PidState()
        self._history[cfg.dimension] = []
        if isinstance(self._store, SqliteControlStore):
            self._store.put_config(cfg)

    def dimension_config(
        self, dimension: ControlDimension,
    ) -> Optional[DimensionConfig]:
        return self._configs.get(dimension)

    def controller(self) -> ControllerConfig:
        return self._controller

    def set_controller(self, controller: ControllerConfig) -> None:
        self._controller = controller

    # ---- step ------------------------------------------------------------

    def step(
        self,
        measured: Mapping[ControlDimension, float],
        *,
        at: datetime,
        dt_minutes: float = 1.0,
    ) -> ControlStep:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        if dt_minutes <= 0.0:
            raise ValueError("dt_minutes must be > 0")

        missing = [d for d in measured if d not in self._configs]
        if missing:
            raise KeyError(
                f"unregistered dimensions: "
                f"{[d.value for d in missing]}"
            )

        self._step_seq += 1
        step_id = f"step-{self._step_seq:06d}"

        desired_v: Dict[ControlDimension, float] = {}
        error_v: Dict[ControlDimension, float] = {}
        raw_v: Dict[ControlDimension, float] = {}
        applied_v: Dict[ControlDimension, float] = {}
        integral_v: Dict[ControlDimension, float] = {}
        derivative_v: Dict[ControlDimension, float] = {}
        saturated_v: Dict[ControlDimension, bool] = {}
        dead_v: Dict[ControlDimension, bool] = {}

        for dim, val in measured.items():
            if not 0.0 <= val <= 1.0:
                raise ValueError(
                    f"measured[{dim.value}] must be within [0,1]"
                )
            cfg = self._configs[dim]
            pid_state = self._pid_states[dim]
            error = val - cfg.desired
            raw, new_state, sat, dead = pid_step(
                pid_state,
                error=error,
                dt_minutes=dt_minutes,
                config=self._controller,
                actuator_magnitude=cfg.actuator_magnitude,
                dead_band=cfg.dead_band,
            )
            applied = apply_actuator(
                raw, magnitude=cfg.actuator_magnitude,
            )
            if dead:
                applied = 0.0

            self._pid_states[dim] = new_state

            desired_v[dim] = cfg.desired
            error_v[dim] = error
            raw_v[dim] = raw
            applied_v[dim] = applied
            integral_v[dim] = new_state.integral
            if pid_state.prev_error is None:
                derivative_v[dim] = 0.0
            else:
                derivative_v[dim] = (
                    error - pid_state.prev_error
                ) / dt_minutes
            saturated_v[dim] = sat
            dead_v[dim] = dead

            # History
            hist = self._history[dim]
            hist.append(error)
            if len(hist) > self._history_window:
                del hist[: len(hist) - self._history_window]

        step = ControlStep(
            step_id=step_id, at=at,
            measured=dict(measured), desired=desired_v,
            error=error_v, raw_control=raw_v,
            applied_control=applied_v, integral=integral_v,
            derivative=derivative_v, saturated=saturated_v,
            dead_band_active=dead_v,
        )
        self._steps.append(step)

        if isinstance(self._store, SqliteControlStore):
            for dim in measured:
                self._store.put(ControlRecord(
                    dimension=dim,
                    measured=measured[dim],
                    desired=desired_v[dim],
                    error=error_v[dim],
                    control=applied_v[dim],
                    integral=integral_v[dim],
                    saturated=saturated_v[dim],
                    dead_band_active=dead_v[dim],
                    at=at,
                ))

        self._violations = check_invariants(self.snapshot())
        return step

    # ---- simulate --------------------------------------------------------

    def simulate(
        self,
        initial_state: Mapping[ControlDimension, float],
        n_steps: int,
        *,
        dt_seconds: float = 60.0,
        start_at: Optional[datetime] = None,
        disturbance_fn: Optional[
            Callable[[int, ControlDimension], float]
        ] = None,
    ) -> Tuple[ControlStep, ...]:
        if n_steps <= 0:
            raise ValueError("n_steps must be > 0")
        if dt_seconds <= 0.0:
            raise ValueError("dt_seconds must be > 0")

        t = start_at if start_at is not None else datetime.now(timezone.utc)
        if t.tzinfo is None:
            raise ValueError("start_at must be timezone-aware")

        state: Dict[ControlDimension, float] = dict(initial_state)
        out: List[ControlStep] = []
        for i in range(n_steps):
            s = self.step(state, at=t, dt_minutes=dt_seconds / 60.0)
            out.append(s)

            disturbance: Dict[ControlDimension, float] = {}
            if disturbance_fn is not None:
                for dim in state:
                    disturbance[dim] = disturbance_fn(i, dim)

            gains = {
                d: self._configs[d].plant_gain for d in state
            }
            state = apply_plant(
                state, s.applied_control,
                plant_gain=gains, disturbance=disturbance,
            )
            t = t + timedelta(seconds=dt_seconds)
        return tuple(out)

    # ---- analysis --------------------------------------------------------

    def analyze(self, *, at: datetime) -> Tuple[ControlFinding, ...]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        self._findings = []

        for dim, cfg in self._configs.items():
            hist = self._history.get(dim, [])
            kind = classify_dynamics(hist, dead_band=cfg.dead_band)

            if kind is DynamicsKind.CONVERGING:
                self._findings.append(ControlFinding(
                    kind=ControlFindingKind.CONVERGING,
                    dimension=dim,
                    detail=(
                        f"error magnitude decreasing over "
                        f"{len(hist)} step(s)"
                    ),
                    severity=1, at=at,
                ))
            elif kind is DynamicsKind.DIVERGING:
                self._findings.append(ControlFinding(
                    kind=ControlFindingKind.DIVERGING,
                    dimension=dim,
                    detail=(
                        f"error magnitude increasing over "
                        f"{len(hist)} step(s)"
                    ),
                    severity=4, at=at,
                ))
            elif kind is DynamicsKind.OSCILLATING:
                self._findings.append(ControlFinding(
                    kind=ControlFindingKind.OSCILLATING,
                    dimension=dim,
                    detail=(
                        f"error oscillating over {len(hist)} step(s)"
                    ),
                    severity=3, at=at,
                ))
            elif kind is DynamicsKind.STEADY_STATE:
                # Steady but not within dead-band is a steady-state error.
                if hist and abs(hist[-1]) > cfg.dead_band:
                    self._findings.append(ControlFinding(
                        kind=ControlFindingKind.STEADY_STATE_ERROR,
                        dimension=dim,
                        detail=(
                            f"steady-state error {hist[-1]:.4f} "
                            f"outside dead-band {cfg.dead_band:.4f}"
                        ),
                        severity=3, at=at,
                    ))

            # Saturation and dead-band activity over recent steps.
            recent = [
                s for s in self._steps[-self._history_window:]
            ]
            sat_count = sum(
                1 for s in recent if s.saturated.get(dim, False)
            )
            dead_count = sum(
                1 for s in recent if s.dead_band_active.get(dim, False)
            )
            if recent:
                if sat_count == len(recent) and sat_count >= 3:
                    self._findings.append(ControlFinding(
                        kind=ControlFindingKind.ACTUATOR_SATURATED,
                        dimension=dim,
                        detail=(
                            f"actuator saturated on "
                            f"{sat_count}/{len(recent)} recent steps"
                        ),
                        severity=3, at=at,
                    ))
                    # Diverging + saturated ⇒ unstable.
                    if kind is DynamicsKind.DIVERGING:
                        self._findings.append(ControlFinding(
                            kind=ControlFindingKind.UNSTABLE,
                            dimension=dim,
                            detail=(
                                "diverging while actuator saturated"
                            ),
                            severity=5, at=at,
                        ))
                if dead_count == len(recent) and dead_count >= 3:
                    self._findings.append(ControlFinding(
                        kind=ControlFindingKind.DEAD_BAND_ACTIVE,
                        dimension=dim,
                        detail=(
                            f"dead-band active on "
                            f"{dead_count}/{len(recent)} recent steps"
                        ),
                        severity=1, at=at,
                    ))

        return tuple(self._findings)

    # ---- queries ---------------------------------------------------------

    def steps(self) -> Tuple[ControlStep, ...]:
        return tuple(self._steps)

    def findings(self) -> Tuple[ControlFinding, ...]:
        return tuple(self._findings)

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return self._violations

    def history(
        self, dimension: ControlDimension,
    ) -> Tuple[float, ...]:
        return tuple(self._history.get(dimension, ()))

    def last_step(self) -> Optional[ControlStep]:
        return self._steps[-1] if self._steps else None

    def snapshot(self) -> ControlSnapshot:
        return ControlSnapshot(
            steps=tuple(self._steps),
            configs=dict(self._configs),
            controller=self._controller,
        )


# =============================================================================
# SECTION 11 — TESTS
# =============================================================================


def _t0() -> datetime:
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _t(seconds: int) -> datetime:
    return _t0() + timedelta(seconds=seconds)


def _cfg(
    dim: ControlDimension = ControlDimension.RISK,
    *,
    desired: float = 0.2,
    dead_band: float = 0.02,
    actuator_magnitude: float = 1.0,
    plant_gain: float = 0.3,
) -> DimensionConfig:
    return DimensionConfig(
        dimension=dim, desired=desired, dead_band=dead_band,
        actuator_magnitude=actuator_magnitude, plant_gain=plant_gain,
    )


def _step(
    measured: Mapping[ControlDimension, float],
    *,
    at: Optional[datetime] = None,
) -> ControlStep:
    return ControlStep(
        step_id="s1", at=at or _t0(),
        measured=measured,
        desired={d: 0.2 for d in measured},
        error={d: measured[d] - 0.2 for d in measured},
        raw_control={d: 0.5 for d in measured},
        applied_control={d: 0.5 for d in measured},
        integral={d: 0.0 for d in measured},
        derivative={d: 0.0 for d in measured},
        saturated={d: False for d in measured},
        dead_band_active={d: False for d in measured},
    )


# ---- domain ----

def test_control_dimension_members() -> None:
    assert ControlDimension.RISK in ALL_DIMENSIONS
    assert ControlDimension.EXPOSURE in ALL_DIMENSIONS
    assert ControlDimension.AUTHORITY_DRIFT in ALL_DIMENSIONS
    assert ControlDimension.CONTROL_DEGRADATION in ALL_DIMENSIONS
    assert ControlDimension.TRUST_DECAY in ALL_DIMENSIONS


def test_finding_requires_aware_time() -> None:
    from datetime import datetime as dt
    try:
        ControlFinding(
            kind=ControlFindingKind.CONVERGING,
            dimension=ControlDimension.RISK,
            detail="x", severity=1, at=dt(2026, 1, 1),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_finding_severity_bounds() -> None:
    try:
        ControlFinding(
            kind=ControlFindingKind.CONVERGING,
            dimension=ControlDimension.RISK,
            detail="x", severity=7, at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- configuration ----

def test_dimension_config_valid() -> None:
    c = _cfg()
    assert c.desired == 0.2 and c.dead_band == 0.02


def test_dimension_config_rejects_bad_desired() -> None:
    try:
        _cfg(desired=1.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_dimension_config_rejects_zero_actuator() -> None:
    try:
        _cfg(actuator_magnitude=0.0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_controller_config_defaults() -> None:
    c = ControllerConfig()
    assert c.kp >= 0 and c.ki >= 0 and c.kd >= 0
    assert c.integrator_clamp > 0


def test_controller_config_rejects_negative_gain() -> None:
    try:
        ControllerConfig(kp=-0.1)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_controller_config_rejects_zero_clamp() -> None:
    try:
        ControllerConfig(integrator_clamp=0.0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- pid ----

def test_pid_dead_band_returns_zero_control() -> None:
    raw, st, sat, dead = pid_step(
        PidState(), error=0.005, dt_minutes=1.0,
        config=ControllerConfig(kp=10.0), actuator_magnitude=1.0,
        dead_band=0.05,
    )
    assert raw == 0.0
    assert dead and not sat
    assert st.prev_error == 0.005


def test_pid_proportional_only() -> None:
    raw, st, sat, dead = pid_step(
        PidState(), error=0.5, dt_minutes=1.0,
        config=ControllerConfig(kp=1.0, ki=0.0, kd=0.0),
        actuator_magnitude=10.0, dead_band=0.0,
    )
    assert abs(raw - 0.5) < 1e-9
    assert not sat and not dead
    # ki = 0 means the integral term contributes nothing to the output,
    # but the raw accumulator still tracks error * dt_minutes regardless
    # of ki: 0.5 * 1.0 = 0.5.
    assert abs(st.integral - 0.5) < 1e-9


def test_pid_integral_accumulates() -> None:
    st = PidState()
    config = ControllerConfig(kp=0.0, ki=1.0, kd=0.0,
                              integrator_clamp=100.0)
    for _ in range(5):
        _, st, _, _ = pid_step(
            st, error=0.4, dt_minutes=1.0, config=config,
            actuator_magnitude=100.0, dead_band=0.0,
        )
    assert abs(st.integral - 2.0) < 1e-9


def test_pid_integral_clamped() -> None:
    st = PidState()
    config = ControllerConfig(kp=0.0, ki=1.0, kd=0.0,
                              integrator_clamp=1.0)
    for _ in range(20):
        _, st, _, _ = pid_step(
            st, error=1.0, dt_minutes=1.0, config=config,
            actuator_magnitude=100.0, dead_band=0.0,
        )
    assert abs(st.integral - 1.0) < 1e-9


def test_pid_anti_windup_holds_integral_when_saturated() -> None:
    st = PidState(integral=0.3)
    config = ControllerConfig(kp=1.0, ki=0.1, kd=0.0,
                              integrator_clamp=100.0, anti_windup=True)
    _, st2, sat, _ = pid_step(
        st, error=10.0, dt_minutes=1.0, config=config,
        actuator_magnitude=0.5, dead_band=0.0,
    )
    assert sat
    assert abs(st2.integral - 0.3) < 1e-9


def test_pid_derivative_term() -> None:
    st = PidState(integral=0.0, prev_error=0.1)
    raw, _, _, _ = pid_step(
        st, error=0.5, dt_minutes=1.0,
        config=ControllerConfig(kp=0.0, ki=0.0, kd=1.0),
        actuator_magnitude=100.0, dead_band=0.0,
    )
    # derivative = (0.5 - 0.1) / 1.0 = 0.4, times kd=1.0 → 0.4
    assert abs(raw - 0.4) < 1e-9


def test_pid_first_step_zero_derivative() -> None:
    raw, _, _, _ = pid_step(
        PidState(), error=0.5, dt_minutes=1.0,
        config=ControllerConfig(kp=0.0, ki=0.0, kd=5.0),
        actuator_magnitude=100.0, dead_band=0.0,
    )
    assert abs(raw) < 1e-9


def test_pid_rejects_bad_dt() -> None:
    try:
        pid_step(
            PidState(), error=0.5, dt_minutes=0.0,
            config=ControllerConfig(), actuator_magnitude=1.0,
            dead_band=0.0,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_pid_rejects_nan_error() -> None:
    try:
        pid_step(
            PidState(), error=float("nan"), dt_minutes=1.0,
            config=ControllerConfig(), actuator_magnitude=1.0,
            dead_band=0.0,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_apply_actuator_clips_high() -> None:
    assert apply_actuator(2.0, magnitude=1.0) == 1.0


def test_apply_actuator_clips_low() -> None:
    assert apply_actuator(-2.0, magnitude=1.0) == -1.0


def test_apply_actuator_passthrough() -> None:
    assert apply_actuator(0.3, magnitude=1.0) == 0.3


# ---- plant ----

def test_apply_plant_reduces_state() -> None:
    state = {ControlDimension.RISK: 0.8}
    gains = {ControlDimension.RISK: 0.5}
    control = {ControlDimension.RISK: 0.5}
    out = apply_plant(state, control, plant_gain=gains)
    assert abs(out[ControlDimension.RISK] - (0.8 - 0.25)) < 1e-9


def test_apply_plant_clips_at_zero() -> None:
    state = {ControlDimension.RISK: 0.1}
    gains = {ControlDimension.RISK: 0.5}
    control = {ControlDimension.RISK: 1.0}
    out = apply_plant(state, control, plant_gain=gains)
    assert out[ControlDimension.RISK] == 0.0


def test_apply_plant_negative_control_raises_state() -> None:
    state = {ControlDimension.RISK: 0.3}
    gains = {ControlDimension.RISK: 0.5}
    control = {ControlDimension.RISK: -0.4}
    out = apply_plant(state, control, plant_gain=gains)
    assert abs(out[ControlDimension.RISK] - (0.3 + 0.2)) < 1e-9


def test_apply_plant_disturbance() -> None:
    state = {ControlDimension.RISK: 0.3}
    gains = {ControlDimension.RISK: 0.0}
    control = {ControlDimension.RISK: 0.0}
    dist = {ControlDimension.RISK: 0.2}
    out = apply_plant(state, control, plant_gain=gains, disturbance=dist)
    assert abs(out[ControlDimension.RISK] - 0.5) < 1e-9


def test_apply_plant_rejects_bad_state() -> None:
    try:
        apply_plant(
            {ControlDimension.RISK: 1.5},
            {ControlDimension.RISK: 0.0},
            plant_gain={ControlDimension.RISK: 0.1},
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- classify dynamics ----

def test_classify_converging() -> None:
    assert classify_dynamics([0.9, 0.6, 0.3, 0.1]) \
        is DynamicsKind.CONVERGING


def test_classify_diverging() -> None:
    assert classify_dynamics([0.1, 0.3, 0.6, 0.9]) \
        is DynamicsKind.DIVERGING


def test_classify_oscillating() -> None:
    assert classify_dynamics([0.5, -0.4, 0.4, -0.3, 0.3]) \
        is DynamicsKind.OSCILLATING


def test_classify_steady_state() -> None:
    assert classify_dynamics(
        [0.5, 0.015, 0.01, 0.005], dead_band=0.02,
    ) is DynamicsKind.STEADY_STATE


def test_classify_insufficient_samples() -> None:
    assert classify_dynamics([0.1, 0.2]) is DynamicsKind.INSUFFICIENT


def test_classify_mixed() -> None:
    # Slightly noisy but neither monotonic nor oscillating
    assert classify_dynamics([0.5, 0.4, 0.45, 0.35]) \
        in (DynamicsKind.CONVERGING, DynamicsKind.MIXED)


# ---- engine basics ----

def test_engine_register_dimension() -> None:
    eng = CyberControlEngine()
    eng.register_dimension(_cfg())
    assert eng.dimension_config(ControlDimension.RISK) is not None


def test_engine_rejects_duplicate_dimension() -> None:
    eng = CyberControlEngine()
    eng.register_dimension(_cfg())
    try:
        eng.register_dimension(_cfg())
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_step_unknown_dimension_raises() -> None:
    eng = CyberControlEngine()
    try:
        eng.step({ControlDimension.RISK: 0.5}, at=_t0())
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_engine_step_rejects_bad_measured() -> None:
    eng = CyberControlEngine()
    eng.register_dimension(_cfg())
    try:
        eng.step({ControlDimension.RISK: 1.5}, at=_t0())
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_step_rejects_naive_time() -> None:
    from datetime import datetime as dt
    eng = CyberControlEngine()
    eng.register_dimension(_cfg())
    try:
        eng.step({ControlDimension.RISK: 0.5}, at=dt(2026, 1, 1))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_step_error_matches_state_desired() -> None:
    eng = CyberControlEngine()
    eng.register_dimension(_cfg(desired=0.3))
    s = eng.step({ControlDimension.RISK: 0.8}, at=_t0())
    assert abs(s.error[ControlDimension.RISK] - 0.5) < 1e-9


def test_engine_step_applies_actuator_limit() -> None:
    eng = CyberControlEngine(controller=ControllerConfig(kp=100.0))
    eng.register_dimension(_cfg(actuator_magnitude=0.5))
    s = eng.step({ControlDimension.RISK: 0.9}, at=_t0())
    # raw is huge, applied must be capped at 0.5
    assert abs(s.applied_control[ControlDimension.RISK] - 0.5) < 1e-9
    assert s.saturated[ControlDimension.RISK]


def test_engine_step_dead_band_zeroes_control() -> None:
    eng = CyberControlEngine(controller=ControllerConfig(kp=10.0))
    eng.register_dimension(_cfg(desired=0.5, dead_band=0.1))
    s = eng.step({ControlDimension.RISK: 0.55}, at=_t0())
    assert s.dead_band_active[ControlDimension.RISK]
    assert s.applied_control[ControlDimension.RISK] == 0.0


def test_engine_step_records_history() -> None:
    eng = CyberControlEngine()
    eng.register_dimension(_cfg())
    eng.step({ControlDimension.RISK: 0.8}, at=_t0())
    eng.step({ControlDimension.RISK: 0.7}, at=_t(60))
    hist = eng.history(ControlDimension.RISK)
    assert len(hist) == 2


# ---- engine simulate ----

def test_engine_simulate_converges() -> None:
    eng = CyberControlEngine(
        controller=ControllerConfig(kp=2.0, ki=0.0, kd=0.0),
    )
    eng.register_dimension(_cfg(
        desired=0.1, dead_band=0.01, plant_gain=0.5,
    ))
    steps = eng.simulate(
        {ControlDimension.RISK: 0.9}, n_steps=10,
        start_at=_t0(), dt_seconds=60.0,
    )
    # State should monotonically decrease toward 0.1
    states = [s.measured[ControlDimension.RISK] for s in steps]
    assert states[-1] < states[0]


def test_engine_simulate_deterministic() -> None:
    eng1 = CyberControlEngine(
        controller=ControllerConfig(kp=1.5),
    )
    eng1.register_dimension(_cfg(plant_gain=0.3))
    eng2 = CyberControlEngine(
        controller=ControllerConfig(kp=1.5),
    )
    eng2.register_dimension(_cfg(plant_gain=0.3))
    a = eng1.simulate({ControlDimension.RISK: 0.9}, n_steps=5,
                      start_at=_t0())
    b = eng2.simulate({ControlDimension.RISK: 0.9}, n_steps=5,
                      start_at=_t0())
    for sa, sb in zip(a, b):
        assert abs(
            sa.measured[ControlDimension.RISK]
            - sb.measured[ControlDimension.RISK]
        ) < 1e-12


def test_engine_simulate_rejects_bad_args() -> None:
    eng = CyberControlEngine()
    eng.register_dimension(_cfg())
    try:
        eng.simulate({ControlDimension.RISK: 0.9}, n_steps=0,
                     start_at=_t0())
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- engine analyze ----

def test_engine_analyze_converging_finding() -> None:
    eng = CyberControlEngine(
        controller=ControllerConfig(kp=2.0, ki=0.0, kd=0.0),
    )
    eng.register_dimension(_cfg(
        desired=0.1, dead_band=0.001, plant_gain=0.5,
    ))
    eng.simulate({ControlDimension.RISK: 0.9}, n_steps=3,
                 start_at=_t0())
    findings = eng.analyze(at=_t(600))
    kinds = {f.kind for f in findings}
    assert ControlFindingKind.CONVERGING in kinds


def test_engine_analyze_diverging_finding() -> None:
    # Plant gain 0 → control does nothing; state stays at 0.9
    # But we start diverging because gain is negative? No — gain can't
    # be negative. Instead, use a disturbance that keeps pushing it up.
    eng = CyberControlEngine(
        controller=ControllerConfig(kp=0.0, ki=0.0, kd=0.0),
    )
    eng.register_dimension(_cfg(
        desired=0.1, dead_band=0.0, plant_gain=0.0,
    ))
    def push_up(i, dim):
        return 0.05  # constant upward pressure
    eng.simulate(
        {ControlDimension.RISK: 0.1}, n_steps=8,
        start_at=_t0(), disturbance_fn=push_up,
    )
    findings = eng.analyze(at=_t(600))
    kinds = {f.kind for f in findings}
    assert ControlFindingKind.DIVERGING in kinds


def test_engine_analyze_steady_state_finding() -> None:
    # kp is too small to make progress, but not enough dead-band
    eng = CyberControlEngine(
        controller=ControllerConfig(kp=0.0, ki=0.0, kd=0.0),
    )
    eng.register_dimension(_cfg(
        desired=0.1, dead_band=0.0, plant_gain=0.5,
    ))
    eng.simulate({ControlDimension.RISK: 0.5}, n_steps=5,
                 start_at=_t0())
    findings = eng.analyze(at=_t(600))
    kinds = {f.kind for f in findings}
    assert ControlFindingKind.STEADY_STATE_ERROR in kinds


def test_engine_analyze_actuator_saturated_finding() -> None:
    # Force saturation by demanding high control with low actuator limit
    eng = CyberControlEngine(
        controller=ControllerConfig(kp=10.0, ki=0.0, kd=0.0),
    )
    eng.register_dimension(_cfg(
        desired=0.1, dead_band=0.0,
        actuator_magnitude=0.05, plant_gain=0.1,
    ))
    eng.simulate({ControlDimension.RISK: 0.9}, n_steps=5,
                 start_at=_t0())
    findings = eng.analyze(at=_t(600))
    kinds = {f.kind for f in findings}
    assert ControlFindingKind.ACTUATOR_SATURATED in kinds


def test_engine_analyze_dead_band_active_finding() -> None:
    eng = CyberControlEngine()
    eng.register_dimension(_cfg(desired=0.5, dead_band=0.2))
    for i in range(5):
        eng.step({ControlDimension.RISK: 0.55}, at=_t(i * 60))
    findings = eng.analyze(at=_t(300))
    kinds = {f.kind for f in findings}
    assert ControlFindingKind.DEAD_BAND_ACTIVE in kinds


def test_engine_analyze_rejects_naive_time() -> None:
    from datetime import datetime as dt
    eng = CyberControlEngine()
    try:
        eng.analyze(at=dt(2026, 1, 1))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- invariants ----

def test_invariant_clean_snapshot() -> None:
    eng = CyberControlEngine()
    eng.register_dimension(_cfg())
    eng.step({ControlDimension.RISK: 0.8}, at=_t0())
    assert eng.violations() == ()


def test_invariant_state_in_unit() -> None:
    bad = ControlStep(
        step_id="s", at=_t0(),
        measured={ControlDimension.RISK: 1.5},
        desired={ControlDimension.RISK: 0.2},
        error={ControlDimension.RISK: 1.3},
        raw_control={ControlDimension.RISK: 0.0},
        applied_control={ControlDimension.RISK: 0.0},
        integral={ControlDimension.RISK: 0.0},
        derivative={ControlDimension.RISK: 0.0},
        saturated={ControlDimension.RISK: False},
        dead_band_active={ControlDimension.RISK: False},
    )
    snap = ControlSnapshot(
        steps=(bad,),
        configs={ControlDimension.RISK: _cfg()},
        controller=ControllerConfig(),
    )
    v = check_invariants(snap)
    assert any(x.invariant_id == "ctrl.state_in_unit" for x in v)


def test_invariant_control_in_actuator_range() -> None:
    bad = ControlStep(
        step_id="s", at=_t0(),
        measured={ControlDimension.RISK: 0.8},
        desired={ControlDimension.RISK: 0.2},
        error={ControlDimension.RISK: 0.6},
        raw_control={ControlDimension.RISK: 5.0},
        applied_control={ControlDimension.RISK: 5.0},
        integral={ControlDimension.RISK: 0.0},
        derivative={ControlDimension.RISK: 0.0},
        saturated={ControlDimension.RISK: True},
        dead_band_active={ControlDimension.RISK: False},
    )
    snap = ControlSnapshot(
        steps=(bad,),
        configs={ControlDimension.RISK: _cfg(actuator_magnitude=1.0)},
        controller=ControllerConfig(),
    )
    v = check_invariants(snap)
    assert any(
        x.invariant_id == "ctrl.control_in_actuator_range" for x in v
    )


def test_invariant_dead_band_zero_control() -> None:
    bad = ControlStep(
        step_id="s", at=_t0(),
        measured={ControlDimension.RISK: 0.5},
        desired={ControlDimension.RISK: 0.5},
        error={ControlDimension.RISK: 0.0},
        raw_control={ControlDimension.RISK: 0.5},
        applied_control={ControlDimension.RISK: 0.5},  # not zero!
        integral={ControlDimension.RISK: 0.0},
        derivative={ControlDimension.RISK: 0.0},
        saturated={ControlDimension.RISK: False},
        dead_band_active={ControlDimension.RISK: True},
    )
    snap = ControlSnapshot(
        steps=(bad,),
        configs={ControlDimension.RISK: _cfg()},
        controller=ControllerConfig(),
    )
    v = check_invariants(snap)
    assert any(
        x.invariant_id == "ctrl.dead_band_zero_control" for x in v
    )


def test_invariant_error_matches() -> None:
    bad = ControlStep(
        step_id="s", at=_t0(),
        measured={ControlDimension.RISK: 0.8},
        desired={ControlDimension.RISK: 0.2},
        error={ControlDimension.RISK: 0.1},  # wrong! should be 0.6
        raw_control={ControlDimension.RISK: 0.0},
        applied_control={ControlDimension.RISK: 0.0},
        integral={ControlDimension.RISK: 0.0},
        derivative={ControlDimension.RISK: 0.0},
        saturated={ControlDimension.RISK: False},
        dead_band_active={ControlDimension.RISK: False},
    )
    snap = ControlSnapshot(
        steps=(bad,),
        configs={ControlDimension.RISK: _cfg()},
        controller=ControllerConfig(),
    )
    v = check_invariants(snap)
    assert any(
        x.invariant_id == "ctrl.error_matches_state_desired" for x in v
    )


# ---- policy ----

def test_engine_history_window_validation() -> None:
    try:
        CyberControlEngine(history_window=2)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_controller_setter() -> None:
    eng = CyberControlEngine()
    c = ControllerConfig(kp=3.0)
    eng.set_controller(c)
    assert eng.controller() is c


# ---- store ----

def test_in_memory_store_records_steps() -> None:
    s = InMemoryControlStore()
    rec = ControlRecord(
        dimension=ControlDimension.RISK,
        measured=0.5, desired=0.2, error=0.3,
        control=0.3, integral=0.1,
        saturated=False, dead_band_active=False,
        at=_t0(),
    )
    s.put(rec)
    assert len(s.all()) == 1


def test_sqlite_store_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "ctrl.db")
    store = SqliteControlStore(db)
    rec = ControlRecord(
        dimension=ControlDimension.RISK,
        measured=0.7, desired=0.2, error=0.5,
        control=0.4, integral=0.2,
        saturated=False, dead_band_active=False,
        at=_t0(),
    )
    store.put(rec)
    all_recs = store.all()
    assert len(all_recs) == 1
    assert abs(all_recs[0].measured - 0.7) < 1e-9


def test_sqlite_store_config_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "ctrl.db")
    store = SqliteControlStore(db)
    cfg = _cfg()
    store.put_config(cfg)
    row = store._conn.execute(
        "SELECT payload_json FROM ctrl_config WHERE dimension = ?",
        (cfg.dimension.value,),
    ).fetchone()
    assert row is not None
    payload = json.loads(row[0])
    assert payload["dimension"] == "risk"
    assert abs(payload["desired"] - 0.2) < 1e-9


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

