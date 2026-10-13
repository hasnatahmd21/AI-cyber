"""
HYDRA™ — Phase 16
Cyber Experiment Engine

STRICT SCOPE
------------
- Isolated cyber experiment definitions
- Scenario definitions
- Attack scenario modelling
- Defensive-response modelling
- Policy/identity manipulation scenarios
- AI manipulation scenarios
- Recovery scenario modelling as an EXPERIMENT ONLY
- Controlled experiment execution
- Experiment observations
- Experiment outcomes
- Baseline comparison
- Experiment isolation
- Deterministic/reproducible experiment metadata
- Safety limits
- Validation
- Tests

NOT IMPLEMENTED
---------------
Phase 17 -> Cyber Regeneration Engine
Phase 18 -> Adaptive Defense Engine
Phase 19 -> AI/Agent Self-Protection
Phase 20 -> Multi-Layer Defense Fabric

IMPORTANT
---------
This engine is a CONTROLLED SIMULATION FRAMEWORK.

It does not execute attacks against real systems.
It does not execute real recovery.
It does not deploy controls.
It does not modify production infrastructure.
"""


from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from threading import RLock
from typing import Dict, FrozenSet, Iterable, List, Optional, Tuple
import hashlib
import random
import unittest


# ============================================================================
# HELPERS
# ============================================================================

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def ensure_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware")
    return value


def stable_hash(*parts: object) -> str:
    material = "|".join(str(part) for part in parts)
    return hashlib.sha256(
        material.encode("utf-8")
    ).hexdigest()


# ============================================================================
# ENUMS
# ============================================================================

class ExperimentType(str, Enum):
    ATTACK = "ATTACK"
    DEFENSE = "DEFENSE"
    POLICY = "POLICY"
    IDENTITY = "IDENTITY"
    AI_MANIPULATION = "AI_MANIPULATION"
    RECOVERY = "RECOVERY"
    COMBINED = "COMBINED"


class ExperimentStatus(str, Enum):
    CREATED = "CREATED"
    PREPARED = "PREPARED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ABORTED = "ABORTED"


class ExperimentOutcomeStatus(str, Enum):
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class ScenarioType(str, Enum):
    ATTACK_PATH = "ATTACK_PATH"
    DEFENSIVE_RESPONSE = "DEFENSIVE_RESPONSE"
    POLICY_CHANGE = "POLICY_CHANGE"
    IDENTITY_CHANGE = "IDENTITY_CHANGE"
    AI_MANIPULATION = "AI_MANIPULATION"
    RECOVERY = "RECOVERY"


class SimulationResult(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"


class IsolationLevel(str, Enum):
    LOGICAL = "LOGICAL"
    PROCESS = "PROCESS"
    CONTAINER = "CONTAINER"
    OFFLINE = "OFFLINE"


class ObservationType(str, Enum):
    STATE = "STATE"
    EVENT = "EVENT"
    METRIC = "METRIC"
    POLICY = "POLICY"
    IDENTITY = "IDENTITY"
    AI_BEHAVIOR = "AI_BEHAVIOR"
    RECOVERY = "RECOVERY"


class ExperimentSafetyStatus(str, Enum):
    SAFE = "SAFE"
    BLOCKED = "BLOCKED"
    VIOLATION = "VIOLATION"


# ============================================================================
# EXPERIMENT TARGET
# ============================================================================

@dataclass(frozen=True)
class ExperimentTarget:
    target_id: str
    scope_id: str

    target_type: str

    simulated_only: bool = True

    attributes: Tuple[Tuple[str, str], ...] = ()

    def __post_init__(self) -> None:

        if not self.target_id.strip():
            raise ValueError(
                "target_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id must not be empty"
            )

        if not self.target_type.strip():
            raise ValueError(
                "target_type must not be empty"
            )

        if not self.simulated_only:
            raise ValueError(
                "Phase 16 targets must be simulated only"
            )


# ============================================================================
# SCENARIO
# ============================================================================

@dataclass(frozen=True)
class ExperimentScenario:
    scenario_id: str
    scope_id: str

    scenario_type: ScenarioType

    name: str
    description: str

    target_ids: Tuple[str, ...]

    parameters: Tuple[Tuple[str, str], ...] = ()

    expected_conditions: Tuple[Tuple[str, str], ...] = ()

    maximum_steps: int = 32

    def __post_init__(self) -> None:

        if not self.scenario_id.strip():
            raise ValueError(
                "scenario_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id must not be empty"
            )

        if not self.name.strip():
            raise ValueError(
                "scenario name must not be empty"
            )

        if not self.target_ids:
            raise ValueError(
                "scenario requires at least one target"
            )

        if self.maximum_steps < 1:
            raise ValueError(
                "maximum_steps must be >= 1"
            )


# ============================================================================
# EXPERIMENT STEP
# ============================================================================

@dataclass(frozen=True)
class ExperimentStep:
    step_id: str
    scenario_id: str

    sequence: int

    operation: str

    parameters: Tuple[Tuple[str, str], ...] = ()

    expected_result: Optional[str] = None

    def __post_init__(self) -> None:

        if not self.step_id.strip():
            raise ValueError(
                "step_id must not be empty"
            )

        if not self.scenario_id.strip():
            raise ValueError(
                "scenario_id must not be empty"
            )

        if self.sequence < 0:
            raise ValueError(
                "step sequence must not be negative"
            )

        if not self.operation.strip():
            raise ValueError(
                "operation must not be empty"
            )


# ============================================================================
# OBSERVATION
# ============================================================================

@dataclass(frozen=True)
class ExperimentObservation:
    observation_id: str
    experiment_id: str
    scope_id: str

    observation_type: ObservationType

    key: str
    value: str

    observed_at: datetime

    confidence: float = 1.0

    source: str = "experiment-engine"

    def __post_init__(self) -> None:

        ensure_aware(self.observed_at)

        if not self.observation_id.strip():
            raise ValueError(
                "observation_id must not be empty"
            )

        if not self.experiment_id.strip():
            raise ValueError(
                "experiment_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id must not be empty"
            )

        if not self.key.strip():
            raise ValueError(
                "observation key must not be empty"
            )

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "observation confidence invalid"
            )


# ============================================================================
# BASELINE
# ============================================================================

@dataclass(frozen=True)
class ExperimentBaseline:
    baseline_id: str
    scope_id: str

    metrics: Tuple[Tuple[str, float], ...]

    created_at: datetime

    description: str = ""

    def __post_init__(self) -> None:

        ensure_aware(self.created_at)

        if not self.baseline_id.strip():
            raise ValueError(
                "baseline_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "baseline scope must not be empty"
            )


# ============================================================================
# SAFETY LIMITS
# ============================================================================

@dataclass(frozen=True)
class ExperimentSafetyLimits:

    maximum_steps: int = 32

    maximum_observations: int = 512

    maximum_targets: int = 32

    allow_external_network: bool = False

    allow_real_target: bool = False

    allow_production_execution: bool = False

    def __post_init__(self) -> None:

        if self.maximum_steps < 1:
            raise ValueError(
                "maximum_steps must be >= 1"
            )

        if self.maximum_observations < 1:
            raise ValueError(
                "maximum_observations must be >= 1"
            )

        if self.maximum_targets < 1:
            raise ValueError(
                "maximum_targets must be >= 1"
            )

        if self.allow_external_network:
            raise ValueError(
                "external network access is forbidden"
            )

        if self.allow_real_target:
            raise ValueError(
                "real targets are forbidden"
            )

        if self.allow_production_execution:
            raise ValueError(
                "production execution is forbidden"
            )


# ============================================================================
# EXPERIMENT DEFINITION
# ============================================================================

@dataclass(frozen=True)
class ExperimentDefinition:

    experiment_id: str
    scope_id: str

    experiment_type: ExperimentType

    scenario_ids: Tuple[str, ...]

    seed: int

    isolation_level: IsolationLevel

    created_at: datetime

    safety_limits: ExperimentSafetyLimits

    description: str = ""

    def __post_init__(self) -> None:

        ensure_aware(self.created_at)

        if not self.experiment_id.strip():
            raise ValueError(
                "experiment_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "experiment scope must not be empty"
            )

        if not self.scenario_ids:
            raise ValueError(
                "experiment requires at least one scenario"
            )

        if self.isolation_level not in {
            IsolationLevel.LOGICAL,
            IsolationLevel.PROCESS,
            IsolationLevel.CONTAINER,
            IsolationLevel.OFFLINE,
        }:
            raise ValueError(
                "invalid isolation level"
            )


# ============================================================================
# STEP RESULT
# ============================================================================

@dataclass(frozen=True)
class ExperimentStepResult:

    step_id: str

    sequence: int

    result: SimulationResult

    expected_result: Optional[str]

    observed_result: str

    observation_ids: FrozenSet[str]

    confidence: float

    reason: str

    result_hash: str

    def __post_init__(self) -> None:

        if not self.step_id.strip():
            raise ValueError(
                "step_id must not be empty"
            )

        if self.sequence < 0:
            raise ValueError(
                "sequence must not be negative"
            )

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "confidence invalid"
            )

        if not self.result_hash.strip():
            raise ValueError(
                "result_hash must not be empty"
            )


# ============================================================================
# EXPERIMENT OUTCOME
# ============================================================================

@dataclass(frozen=True)
class ExperimentOutcome:

    outcome_id: str

    experiment_id: str
    scope_id: str

    status: ExperimentOutcomeStatus

    started_at: datetime
    completed_at: datetime

    step_results: Tuple[
        ExperimentStepResult,
        ...
    ]

    observations: Tuple[
        ExperimentObservation,
        ...
    ]

    baseline_id: Optional[str]

    metrics: Tuple[Tuple[str, float], ...]

    confidence: float

    reason: str

    outcome_hash: str

    def __post_init__(self) -> None:

        ensure_aware(self.started_at)
        ensure_aware(self.completed_at)

        if self.completed_at < self.started_at:
            raise ValueError(
                "completed_at precedes started_at"
            )

        if not self.outcome_id.strip():
            raise ValueError(
                "outcome_id must not be empty"
            )

        if not self.experiment_id.strip():
            raise ValueError(
                "experiment_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id must not be empty"
            )

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "outcome confidence invalid"
            )

        if not self.outcome_hash.strip():
            raise ValueError(
                "outcome_hash must not be empty"
            )


# ============================================================================
# EXPERIMENT RECORD
# ============================================================================

@dataclass
class ExperimentRecord:

    experiment_id: str
    scope_id: str

    definition: ExperimentDefinition

    status: ExperimentStatus = (
        ExperimentStatus.CREATED
    )

    started_at: Optional[datetime] = None

    completed_at: Optional[datetime] = None

    outcome_id: Optional[str] = None

    safety_status: ExperimentSafetyStatus = (
        ExperimentSafetyStatus.SAFE
    )

    failure_reason: Optional[str] = None


# ============================================================================
# CYBER EXPERIMENT ENGINE
# ============================================================================

class CyberExperimentEngine:

    def __init__(self) -> None:

        self._targets: Dict[
            str,
            ExperimentTarget,
        ] = {}

        self._scenarios: Dict[
            str,
            ExperimentScenario,
        ] = {}

        self._steps: Dict[
            str,
            ExperimentStep,
        ] = {}

        self._baselines: Dict[
            str,
            ExperimentBaseline,
        ] = {}

        self._experiments: Dict[
            str,
            ExperimentRecord,
        ] = {}

        self._observations: Dict[
            str,
            ExperimentObservation,
        ] = {}

        self._outcomes: Dict[
            str,
            ExperimentOutcome,
        ] = {}

        self._lock = RLock()

    # ========================================================================
    # TARGETS
    # ========================================================================

    def add_target(
        self,
        target: ExperimentTarget,
    ) -> None:

        with self._lock:

            if target.target_id in self._targets:
                raise ValueError(
                    "duplicate target"
                )

            if not target.simulated_only:
                raise ValueError(
                    "real targets are not permitted"
                )

            self._targets[
                target.target_id
            ] = target

    # ========================================================================
    # SCENARIOS
    # ========================================================================

    def add_scenario(
        self,
        scenario: ExperimentScenario,
    ) -> None:

        with self._lock:

            if scenario.scenario_id in self._scenarios:
                raise ValueError(
                    "duplicate scenario"
                )

            for target_id in scenario.target_ids:

                target = self._targets.get(
                    target_id
                )

                if target is None:
                    raise KeyError(
                        f"target not found: "
                        f"{target_id}"
                    )

                if target.scope_id != scenario.scope_id:
                    raise ValueError(
                        "scenario target scope mismatch"
                    )

            self._scenarios[
                scenario.scenario_id
            ] = scenario

    # ========================================================================
    # STEPS
    # ========================================================================

    def add_step(
        self,
        step: ExperimentStep,
    ) -> None:

        with self._lock:

            if step.step_id in self._steps:
                raise ValueError(
                    "duplicate experiment step"
                )

            scenario = self._scenarios.get(
                step.scenario_id
            )

            if scenario is None:
                raise KeyError(
                    "scenario not found"
                )

            if step.sequence >= scenario.maximum_steps:
                raise ValueError(
                    "step exceeds scenario maximum"
                )

            self._steps[
                step.step_id
            ] = step

    def steps_for(
        self,
        scenario_id: str,
    ) -> Tuple[ExperimentStep, ...]:

        with self._lock:

            return tuple(
                sorted(
                    (
                        step
                        for step
                        in self._steps.values()
                        if step.scenario_id
                        == scenario_id
                    ),
                    key=lambda item: item.sequence,
                )
            )

    # ========================================================================
    # BASELINES
    # ========================================================================

    def add_baseline(
        self,
        baseline: ExperimentBaseline,
    ) -> None:

        with self._lock:

            if baseline.baseline_id in self._baselines:
                raise ValueError(
                    "duplicate baseline"
                )

            self._baselines[
                baseline.baseline_id
            ] = baseline

    # ========================================================================
    # EXPERIMENT CREATION
    # ========================================================================

    def create_experiment(
        self,
        *,
        experiment_id: str,
        scope_id: str,
        experiment_type: ExperimentType,
        scenario_ids: Iterable[str],
        seed: int,
        isolation_level: IsolationLevel = (
            IsolationLevel.OFFLINE
        ),
        safety_limits: Optional[
            ExperimentSafetyLimits
        ] = None,
        description: str = "",
    ) -> ExperimentRecord:

        scenario_ids = tuple(
            scenario_ids
        )

        if not scenario_ids:
            raise ValueError(
                "at least one scenario is required"
            )

        limits = (
            safety_limits
            or ExperimentSafetyLimits()
        )

        if len(scenario_ids) > limits.maximum_targets:
            raise ValueError(
                "experiment exceeds scenario limit"
            )

        with self._lock:

            for scenario_id in scenario_ids:

                scenario = self._scenarios.get(
                    scenario_id
                )

                if scenario is None:
                    raise KeyError(
                        f"scenario not found: "
                        f"{scenario_id}"
                    )

                if scenario.scope_id != scope_id:
                    raise ValueError(
                        "scenario scope mismatch"
                    )

                if len(
                    scenario.target_ids
                ) > limits.maximum_targets:
                    raise ValueError(
                        "scenario exceeds target limit"
                    )

            if experiment_id in self._experiments:
                raise ValueError(
                    "duplicate experiment"
                )

            definition = ExperimentDefinition(
                experiment_id=experiment_id,
                scope_id=scope_id,
                experiment_type=experiment_type,
                scenario_ids=scenario_ids,
                seed=seed,
                isolation_level=isolation_level,
                created_at=utc_now(),
                safety_limits=limits,
                description=description,
            )

            record = ExperimentRecord(
                experiment_id=experiment_id,
                scope_id=scope_id,
                definition=definition,
            )

            self._experiments[
                experiment_id
            ] = record

            return record

    # ========================================================================
    # SAFETY CHECK
    # ========================================================================

    def _safety_check(
        self,
        record: ExperimentRecord,
    ) -> None:

        limits = (
            record.definition.safety_limits
        )

        if (
            record.definition.isolation_level
            not in {
                IsolationLevel.LOGICAL,
                IsolationLevel.PROCESS,
                IsolationLevel.CONTAINER,
                IsolationLevel.OFFLINE,
            }
        ):
            record.safety_status = (
                ExperimentSafetyStatus.BLOCKED
            )

            raise PermissionError(
                "invalid isolation level"
            )

        for scenario_id in (
            record.definition.scenario_ids
        ):

            scenario = self._scenarios[
                scenario_id
            ]

            if len(
                scenario.target_ids
            ) > limits.maximum_targets:

                record.safety_status = (
                    ExperimentSafetyStatus.BLOCKED
                )

                raise PermissionError(
                    "target limit exceeded"
                )

            steps = self.steps_for(
                scenario_id
            )

            if len(steps) > limits.maximum_steps:

                record.safety_status = (
                    ExperimentSafetyStatus.BLOCKED
                )

                raise PermissionError(
                    "step limit exceeded"
                )

            for target_id in scenario.target_ids:

                target = self._targets[
                    target_id
                ]

                if not target.simulated_only:

                    record.safety_status = (
                        ExperimentSafetyStatus.VIOLATION
                    )

                    raise PermissionError(
                        "real target detected"
                    )

    # ========================================================================
    # PREPARE
    # ========================================================================

    def prepare(
        self,
        experiment_id: str,
    ) -> ExperimentRecord:

        with self._lock:

            record = self._experiments.get(
                experiment_id
            )

            if record is None:
                raise KeyError(
                    "experiment not found"
                )

            if record.status != ExperimentStatus.CREATED:
                raise ValueError(
                    "experiment is not in CREATED state"
                )

            self._safety_check(
                record
            )

            record.status = (
                ExperimentStatus.PREPARED
            )

            return record

    # ========================================================================
    # SIMULATED STEP EXECUTION
    # ========================================================================

    @staticmethod
    def _simulate_step(
        step: ExperimentStep,
        rng: random.Random,
    ) -> Tuple[
        SimulationResult,
        str,
        float,
    ]:

        # Phase 16 intentionally models a controlled simulation.
        # No real command, network operation, process operation,
        # endpoint operation, or external action is executed.

        expected = (
            step.expected_result
            or "simulated-success"
        )

        # Deterministic behaviour for a supplied experiment seed.
        roll = rng.random()

        if roll < 0.80:
            result = SimulationResult.PASS
            observed = expected
            confidence = 0.90

        elif roll < 0.95:
            result = SimulationResult.INCONCLUSIVE
            observed = "simulated-inconclusive"
            confidence = 0.50

        else:
            result = SimulationResult.FAIL
            observed = "simulated-failure"
            confidence = 0.85

        return (
            result,
            observed,
            confidence,
        )

    # ========================================================================
    # OBSERVATION
    # ========================================================================

    def _add_observation(
        self,
        observation: ExperimentObservation,
        limit: int,
    ) -> None:

        if len(
            self._observations
        ) >= limit:

            raise RuntimeError(
                "experiment observation limit exceeded"
            )

        if observation.observation_id in self._observations:
            raise ValueError(
                "duplicate experiment observation"
            )

        self._observations[
            observation.observation_id
        ] = observation

    # ========================================================================
    # RUN
    # ========================================================================

    def run(
        self,
        experiment_id: str,
        *,
        baseline_id: Optional[str] = None,
    ) -> ExperimentOutcome:

        with self._lock:

            record = self._experiments.get(
                experiment_id
            )

            if record is None:
                raise KeyError(
                    "experiment not found"
                )

            if record.status == ExperimentStatus.CREATED:
                self.prepare(
                    experiment_id
                )

            if record.status != ExperimentStatus.PREPARED:
                raise ValueError(
                    "experiment must be prepared"
                )

            if baseline_id is not None:

                baseline = self._baselines.get(
                    baseline_id
                )

                if baseline is None:
                    raise KeyError(
                        "baseline not found"
                    )

                if baseline.scope_id != record.scope_id:
                    raise ValueError(
                        "baseline scope mismatch"
                    )

            record.status = (
                ExperimentStatus.RUNNING
            )

            record.started_at = utc_now()

            rng = random.Random(
                record.definition.seed
            )

            step_results: List[
                ExperimentStepResult
            ] = []

            observations: List[
                ExperimentObservation
            ] = []

            try:

                for scenario_id in (
                    record.definition.scenario_ids
                ):

                    scenario = self._scenarios[
                        scenario_id
                    ]

                    steps = self.steps_for(
                        scenario_id
                    )

                    if len(steps) > (
                        record
                        .definition
                        .safety_limits
                        .maximum_steps
                    ):
                        raise RuntimeError(
                            "maximum step limit exceeded"
                        )

                    for step in steps:

                        (
                            result,
                            observed,
                            confidence,
                        ) = self._simulate_step(
                            step,
                            rng,
                        )

                        observation_id = stable_hash(
                            "experiment-observation",
                            experiment_id,
                            step.step_id,
                            step.sequence,
                        )

                        observation = (
                            ExperimentObservation(
                                observation_id=(
                                    observation_id
                                ),
                                experiment_id=(
                                    experiment_id
                                ),
                                scope_id=(
                                    record.scope_id
                                ),
                                observation_type=(
                                    ObservationType.EVENT
                                ),
                                key=(
                                    f"step:{step.step_id}"
                                ),
                                value=observed,
                                observed_at=utc_now(),
                                confidence=confidence,
                            )
                        )

                        self._add_observation(
                            observation,
                            record
                            .definition
                            .safety_limits
                            .maximum_observations,
                        )

                        observations.append(
                            observation
                        )

                        step_hash = stable_hash(
                            step.step_id,
                            step.sequence,
                            result.value,
                            observed,
                            confidence,
                        )

                        step_results.append(
                            ExperimentStepResult(
                                step_id=(
                                    step.step_id
                                ),
                                sequence=(
                                    step.sequence
                                ),
                                result=result,
                                expected_result=(
                                    step.expected_result
                                ),
                                observed_result=(
                                    observed
                                ),
                                observation_ids=frozenset(
                                    {
                                        observation_id
                                    }
                                ),
                                confidence=confidence,
                                reason=(
                                    "controlled "
                                    "simulation result"
                                ),
                                result_hash=step_hash,
                            )
                        )

                if not step_results:

                    status = (
                        ExperimentOutcomeStatus.UNKNOWN
                    )

                    confidence = 0.0

                    reason = (
                        "experiment contained no steps"
                    )

                else:

                    passed = sum(
                        result.result
                        == SimulationResult.PASS
                        for result
                        in step_results
                    )

                    failed = sum(
                        result.result
                        == SimulationResult.FAIL
                        for result
                        in step_results
                    )

                    inconclusive = sum(
                        result.result
                        == SimulationResult.INCONCLUSIVE
                        for result
                        in step_results
                    )

                    total = len(
                        step_results
                    )

                    confidence = (
                        sum(
                            result.confidence
                            for result
                            in step_results
                        )
                        / total
                    )

                    if passed == total:

                        status = (
                            ExperimentOutcomeStatus.SUCCESS
                        )

                        reason = (
                            "all simulated steps passed"
                        )

                    elif failed == total:

                        status = (
                            ExperimentOutcomeStatus.FAILED
                        )

                        reason = (
                            "all simulated steps failed"
                        )

                    elif passed > 0:

                        status = (
                            ExperimentOutcomeStatus.PARTIAL
                        )

                        reason = (
                            "experiment produced "
                            "mixed simulated results"
                        )

                    elif inconclusive == total:

                        status = (
                            ExperimentOutcomeStatus.UNKNOWN
                        )

                        reason = (
                            "all simulated results "
                            "were inconclusive"
                        )

                    else:

                        status = (
                            ExperimentOutcomeStatus.PARTIAL
                        )

                        reason = (
                            "experiment produced "
                            "non-uniform results"
                        )

                metrics = (
                    (
                        "total_steps",
                        float(
                            len(step_results)
                        ),
                    ),
                    (
                        "passed_steps",
                        float(
                            sum(
                                result.result
                                == SimulationResult.PASS
                                for result
                                in step_results
                            )
                        ),
                    ),
                    (
                        "failed_steps",
                        float(
                            sum(
                                result.result
                                == SimulationResult.FAIL
                                for result
                                in step_results
                            )
                        ),
                    ),
                    (
                        "inconclusive_steps",
                        float(
                            sum(
                                result.result
                                == SimulationResult.INCONCLUSIVE
                                for result
                                in step_results
                            )
                        ),
                    ),
                )

                completed_at = utc_now()

                outcome_id = stable_hash(
                    "experiment-outcome",
                    experiment_id,
                    record.definition.seed,
                    completed_at.isoformat(),
                )

                outcome_material = (
                    experiment_id,
                    record.scope_id,
                    status.value,
                    tuple(step_results),
                    tuple(observations),
                    baseline_id,
                    metrics,
                    confidence,
                    reason,
                )

                outcome_hash = stable_hash(
                    *outcome_material
                )

                outcome = ExperimentOutcome(
                    outcome_id=outcome_id,
                    experiment_id=experiment_id,
                    scope_id=record.scope_id,
                    status=status,
                    started_at=record.started_at,
                    completed_at=completed_at,
                    step_results=tuple(
                        step_results
                    ),
                    observations=tuple(
                        observations
                    ),
                    baseline_id=baseline_id,
                    metrics=metrics,
                    confidence=confidence,
                    reason=reason,
                    outcome_hash=outcome_hash,
                )

                self._outcomes[
                    outcome_id
                ] = outcome

                record.status = (
                    ExperimentStatus.COMPLETED
                )

                record.completed_at = (
                    completed_at
                )

                record.outcome_id = (
                    outcome_id
                )

                return outcome

            except Exception as exc:

                record.status = (
                    ExperimentStatus.FAILED
                )

                record.completed_at = (
                    utc_now()
                )

                record.failure_reason = str(
                    exc
                )

                raise

    # ========================================================================
    # OUTCOME LOOKUP
    # ========================================================================

    def get_outcome(
        self,
        outcome_id: str,
    ) -> ExperimentOutcome:

        with self._lock:

            outcome = self._outcomes.get(
                outcome_id
            )

            if outcome is None:
                raise KeyError(
                    "experiment outcome not found"
                )

            return outcome

    # ========================================================================
    # BASELINE COMPARISON
    # ========================================================================

    def compare_baseline(
        self,
        outcome_id: str,
        baseline_id: str,
    ) -> Dict[str, float]:

        with self._lock:

            outcome = self.get_outcome(
                outcome_id
            )

            baseline = self._baselines.get(
                baseline_id
            )

            if baseline is None:
                raise KeyError(
                    "baseline not found"
                )

            if (
                outcome.scope_id
                != baseline.scope_id
            ):
                raise ValueError(
                    "baseline scope mismatch"
                )

            observed = dict(
                outcome.metrics
            )

            baseline_metrics = dict(
                baseline.metrics
            )

            comparison: Dict[
                str,
                float,
            ] = {}

            for key, baseline_value in (
                baseline_metrics.items()
            ):

                current = observed.get(
                    key
                )

                if current is None:
                    continue

                comparison[key] = (
                    current
                    - baseline_value
                )

            return comparison

    # ========================================================================
    # OBSERVATIONS
    # ========================================================================

    def observations_for(
        self,
        experiment_id: str,
    ) -> Tuple[
        ExperimentObservation,
        ...
    ]:

        with self._lock:

            return tuple(
                observation
                for observation
                in self._observations.values()
                if (
                    observation.experiment_id
                    == experiment_id
                )
            )

    # ========================================================================
    # VALIDATION
    # ========================================================================

    @staticmethod
    def validate_step_result_hash(
        result: ExperimentStepResult,
    ) -> bool:

        expected = stable_hash(
            result.step_id,
            result.sequence,
            result.result.value,
            result.observed_result,
            result.confidence,
        )

        return expected == result.result_hash

    @staticmethod
    def validate_outcome_hash(
        outcome: ExperimentOutcome,
    ) -> bool:

        material = (
            outcome.experiment_id,
            outcome.scope_id,
            outcome.status.value,
            outcome.step_results,
            outcome.observations,
            outcome.baseline_id,
            outcome.metrics,
            outcome.confidence,
            outcome.reason,
        )

        expected = stable_hash(
            *material
        )

        return expected == outcome.outcome_hash

    def validate(self) -> List[str]:

        errors: List[str] = []

        with self._lock:

            for target_id, target in (
                self._targets.items()
            ):

                if (
                    target_id
                    != target.target_id
                ):
                    errors.append(
                        f"target key mismatch: "
                        f"{target_id}"
                    )

                if not target.simulated_only:
                    errors.append(
                        f"real target present: "
                        f"{target_id}"
                    )

            for scenario_id, scenario in (
                self._scenarios.items()
            ):

                if (
                    scenario_id
                    != scenario.scenario_id
                ):
                    errors.append(
                        f"scenario key mismatch: "
                        f"{scenario_id}"
                    )

                for target_id in (
                    scenario.target_ids
                ):

                    target = self._targets.get(
                        target_id
                    )

                    if target is None:
                        errors.append(
                            f"unknown scenario target: "
                            f"{target_id}"
                        )

                    elif (
                        target.scope_id
                        != scenario.scope_id
                    ):
                        errors.append(
                            f"scenario target scope mismatch: "
                            f"{target_id}"
                        )

            for experiment_id, record in (
                self._experiments.items()
            ):

                if (
                    experiment_id
                    != record.experiment_id
                ):
                    errors.append(
                        f"experiment key mismatch: "
                        f"{experiment_id}"
                    )

                if (
                    record.scope_id
                    != record.definition.scope_id
                ):
                    errors.append(
                        f"experiment scope mismatch: "
                        f"{experiment_id}"
                    )

            for observation_id, observation in (
                self._observations.items()
            ):

                if (
                    observation_id
                    != observation.observation_id
                ):
                    errors.append(
                        f"observation key mismatch: "
                        f"{observation_id}"
                    )

                experiment = self._experiments.get(
                    observation.experiment_id
                )

                if experiment is None:
                    errors.append(
                        f"observation references "
                        f"unknown experiment: "
                        f"{observation.experiment_id}"
                    )

                elif (
                    observation.scope_id
                    != experiment.scope_id
                ):
                    errors.append(
                        f"observation scope mismatch: "
                        f"{observation_id}"
                    )

            for outcome_id, outcome in (
                self._outcomes.items()
            ):

                if (
                    outcome_id
                    != outcome.outcome_id
                ):
                    errors.append(
                        f"outcome key mismatch: "
                        f"{outcome_id}"
                    )

                if not self.validate_outcome_hash(
                    outcome
                ):
                    errors.append(
                        f"outcome hash mismatch: "
                        f"{outcome_id}"
                    )

                for step_result in (
                    outcome.step_results
                ):

                    if not self.validate_step_result_hash(
                        step_result
                    ):
                        errors.append(
                            f"step result hash mismatch: "
                            f"{step_result.step_id}"
                        )

                    for observation_id in (
                        step_result.observation_ids
                    ):

                        if (
                            observation_id
                            not in self._observations
                        ):
                            errors.append(
                                f"unknown step observation: "
                                f"{observation_id}"
                            )

        return errors


# ============================================================================
# TESTS
# ============================================================================

class Phase16Tests(unittest.TestCase):

    def setUp(self):

        self.engine = (
            CyberExperimentEngine()
        )

        self.target = ExperimentTarget(
            target_id="simulated-endpoint",
            scope_id="scope-a",
            target_type="endpoint",
            simulated_only=True,
        )

        self.engine.add_target(
            self.target
        )

        self.scenario = ExperimentScenario(
            scenario_id="scenario-1",
            scope_id="scope-a",
            scenario_type=ScenarioType.DEFENSIVE_RESPONSE,
            name="Controlled response test",
            description="Simulated defensive response",
            target_ids=(
                "simulated-endpoint",
            ),
            maximum_steps=4,
        )

        self.engine.add_scenario(
            self.scenario
        )

        self.step = ExperimentStep(
            step_id="step-1",
            scenario_id="scenario-1",
            sequence=0,
            operation="SIMULATE_CONTROL",
            expected_result="expected-control-result",
        )

        self.engine.add_step(
            self.step
        )

    # ========================================================================
    # Target safety
    # ========================================================================

    def test_real_target_rejected(self):

        with self.assertRaises(ValueError):

            ExperimentTarget(
                target_id="real",
                scope_id="scope-a",
                target_type="endpoint",
                simulated_only=False,
            )

    # ========================================================================
    # Scenario registration
    # ========================================================================

    def test_scenario_registration(self):

        steps = self.engine.steps_for(
            "scenario-1"
        )

        self.assertEqual(
            len(steps),
            1,
        )

        self.assertEqual(
            steps[0].step_id,
            "step-1",
        )

    # ========================================================================
    # Experiment creation
    # ========================================================================

    def test_create_experiment(self):

        experiment = (
            self.engine.create_experiment(
                experiment_id="experiment-1",
                scope_id="scope-a",
                experiment_type=(
                    ExperimentType.DEFENSE
                ),
                scenario_ids=(
                    "scenario-1",
                ),
                seed=42,
            )
        )

        self.assertEqual(
            experiment.status,
            ExperimentStatus.CREATED,
        )

    # ========================================================================
    # Preparation
    # ========================================================================

    def test_prepare(self):

        experiment = (
            self.engine.create_experiment(
                experiment_id="experiment-prepare",
                scope_id="scope-a",
                experiment_type=(
                    ExperimentType.ATTACK
                ),
                scenario_ids=(
                    "scenario-1",
                ),
                seed=10,
            )
        )

        self.engine.prepare(
            experiment.experiment_id
        )

        self.assertEqual(
            experiment.status,
            ExperimentStatus.PREPARED,
        )

    # ========================================================================
    # Experiment execution
    # ========================================================================

    def test_run(self):

        experiment = (
            self.engine.create_experiment(
                experiment_id="experiment-run",
                scope_id="scope-a",
                experiment_type=(
                    ExperimentType.DEFENSE
                ),
                scenario_ids=(
                    "scenario-1",
                ),
                seed=42,
            )
        )

        outcome = self.engine.run(
            experiment.experiment_id
        )

        self.assertEqual(
            experiment.status,
            ExperimentStatus.COMPLETED,
        )

        self.assertEqual(
            len(outcome.step_results),
            1,
        )

        self.assertEqual(
            len(outcome.observations),
            1,
        )

    # ========================================================================
    # Deterministic seed
    # ========================================================================

    def test_seed_reproducibility(self):

        first = (
            self.engine.create_experiment(
                experiment_id="seed-one",
                scope_id="scope-a",
                experiment_type=(
                    ExperimentType.ATTACK
                ),
                scenario_ids=(
                    "scenario-1",
                ),
                seed=12345,
            )
        )

        second = (
            self.engine.create_experiment(
                experiment_id="seed-two",
                scope_id="scope-a",
                experiment_type=(
                    ExperimentType.ATTACK
                ),
                scenario_ids=(
                    "scenario-1",
                ),
                seed=12345,
            )
        )

        first_outcome = self.engine.run(
            first.experiment_id
        )

        second_outcome = self.engine.run(
            second.experiment_id
        )

        self.assertEqual(
            first_outcome.step_results[0].result,
            second_outcome.step_results[0].result,
        )

        self.assertEqual(
            first_outcome.step_results[0].observed_result,
            second_outcome.step_results[0].observed_result,
        )

    # ========================================================================
    # Scope isolation
    # ========================================================================

    def test_scope_isolation(self):

        with self.assertRaises(ValueError):

            self.engine.create_experiment(
                experiment_id="foreign",
                scope_id="scope-b",
                experiment_type=(
                    ExperimentType.DEFENSE
                ),
                scenario_ids=(
                    "scenario-1",
                ),
                seed=1,
            )

    # ========================================================================
    # Baseline
    # ========================================================================

    def test_baseline_comparison(self):

        baseline = ExperimentBaseline(
            baseline_id="baseline-1",
            scope_id="scope-a",
            metrics=(
                ("total_steps", 1.0),
                ("passed_steps", 0.0),
                ("failed_steps", 0.0),
            ),
            created_at=utc_now(),
        )

        self.engine.add_baseline(
            baseline
        )

        experiment = (
            self.engine.create_experiment(
                experiment_id="baseline-test",
                scope_id="scope-a",
                experiment_type=(
                    ExperimentType.DEFENSE
                ),
                scenario_ids=(
                    "scenario-1",
                ),
                seed=42,
            )
        )

        outcome = self.engine.run(
            experiment.experiment_id,
            baseline_id="baseline-1",
        )

        comparison = (
            self.engine.compare_baseline(
                outcome.outcome_id,
                "baseline-1",
            )
        )

        self.assertIn(
            "total_steps",
            comparison,
        )

    # ========================================================================
    # Safety limits
    # ========================================================================

    def test_step_limit(self):

        limited = (
            ExperimentSafetyLimits(
                maximum_steps=1,
                maximum_observations=10,
                maximum_targets=2,
            )
        )

        experiment = (
            self.engine.create_experiment(
                experiment_id="limited",
                scope_id="scope-a",
                experiment_type=(
                    ExperimentType.DEFENSE
                ),
                scenario_ids=(
                    "scenario-1",
                ),
                seed=1,
                safety_limits=limited,
            )
        )

        self.engine.prepare(
            experiment.experiment_id
        )

        self.assertEqual(
            experiment.status,
            ExperimentStatus.PREPARED,
        )

    # ========================================================================
    # Outcome integrity
    # ========================================================================

    def test_outcome_hash(self):

        experiment = (
            self.engine.create_experiment(
                experiment_id="hash-test",
                scope_id="scope-a",
                experiment_type=(
                    ExperimentType.DEFENSE
                ),
                scenario_ids=(
                    "scenario-1",
                ),
                seed=99,
            )
        )

        outcome = self.engine.run(
            experiment.experiment_id
        )

        self.assertTrue(
            self.engine.validate_outcome_hash(
                outcome
            )
        )

    # ========================================================================
    # Global validation
    # ========================================================================

    def test_validation(self):

        experiment = (
            self.engine.create_experiment(
                experiment_id="validation-test",
                scope_id="scope-a",
                experiment_type=(
                    ExperimentType.DEFENSE
                ),
                scenario_ids=(
                    "scenario-1",
                ),
                seed=5,
            )
        )

        self.engine.run(
            experiment.experiment_id
        )

        self.assertEqual(
            self.engine.validate(),
            [],
        )


# ============================================================================
# TEST RUNNER
# ============================================================================

def run_phase16_tests() -> None:

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        Phase16Tests
    )

    result = unittest.TextTestRunner(
        verbosity=2
    ).run(suite)

    if not result.wasSuccessful():
        raise AssertionError(
            "Phase 16 tests failed"
        )


if __name__ == "__main__":
    run_phase16_tests()
