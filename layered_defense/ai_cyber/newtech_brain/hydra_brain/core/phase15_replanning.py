"""
HYDRA™ — Phase 15
Continuous Replanning Engine

SCOPE
-----
- Observe
- State reference
- Plan reference
- Simulation reference
- Authorization reference
- Action reference
- Verification reference
- Replanning triggers
- Cycle state machine
- Continuous cycle history
- Safe stopping
- Failure containment at orchestration level
- Validation
- Tests

IMPORTANT
---------
This module does NOT implement:

- Cyber Experiment Engine
- Cyber Regeneration
- Adaptive Defense
- Autonomous action implementation
- Authorization implementation
- Verification implementation

Those capabilities belong to later phases or existing interfaces.
Phase 15 only orchestrates references to those capabilities.
"""


from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from threading import RLock
from typing import Dict, FrozenSet, Iterable, List, Optional, Tuple
import hashlib
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

class ReplanCycleStatus(str, Enum):
    CREATED = "CREATED"
    OBSERVED = "OBSERVED"
    STATE_READY = "STATE_READY"
    PLAN_READY = "PLAN_READY"
    SIMULATION_READY = "SIMULATION_READY"
    AUTHORIZATION_READY = "AUTHORIZATION_READY"
    ACTION_RECORDED = "ACTION_RECORDED"
    VERIFIED = "VERIFIED"
    REPLAN_REQUIRED = "REPLAN_REQUIRED"
    COMPLETED = "COMPLETED"
    STOPPED = "STOPPED"
    FAILED = "FAILED"


class ReplanTriggerType(str, Enum):
    STATE_CHANGE = "STATE_CHANGE"
    VERIFICATION_FAILURE = "VERIFICATION_FAILURE"
    VERIFICATION_PARTIAL = "VERIFICATION_PARTIAL"
    NEW_EVIDENCE = "NEW_EVIDENCE"
    PLAN_INVALIDATED = "PLAN_INVALIDATED"
    AUTHORIZATION_CHANGED = "AUTHORIZATION_CHANGED"
    SIMULATION_CHANGED = "SIMULATION_CHANGED"
    MANUAL = "MANUAL"
    UNKNOWN_OUTCOME = "UNKNOWN_OUTCOME"


class ReplanDecision(str, Enum):
    CONTINUE = "CONTINUE"
    REPLAN = "REPLAN"
    STOP = "STOP"


class ReferenceStatus(str, Enum):
    PRESENT = "PRESENT"
    MISSING = "MISSING"
    INVALID = "INVALID"


# ============================================================================
# OBSERVATION
# ============================================================================

@dataclass(frozen=True)
class ObservationReference:
    observation_id: str
    scope_id: str

    source: str
    observed_at: datetime

    summary: str = ""

    def __post_init__(self) -> None:

        ensure_aware(self.observed_at)

        if not self.observation_id.strip():
            raise ValueError(
                "observation_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id must not be empty"
            )

        if not self.source.strip():
            raise ValueError(
                "observation source must not be empty"
            )


# ============================================================================
# STATE REFERENCE
# ============================================================================

@dataclass(frozen=True)
class StateReference:
    state_id: str
    scope_id: str

    version: int

    observed_at: datetime

    state_hash: str

    summary: str = ""

    def __post_init__(self) -> None:

        ensure_aware(self.observed_at)

        if not self.state_id.strip():
            raise ValueError(
                "state_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id must not be empty"
            )

        if self.version < 0:
            raise ValueError(
                "state version must not be negative"
            )

        if not self.state_hash.strip():
            raise ValueError(
                "state_hash must not be empty"
            )


# ============================================================================
# PLAN REFERENCE
# ============================================================================

@dataclass(frozen=True)
class PlanReference:
    plan_id: str
    scope_id: str

    version: int

    created_at: datetime

    plan_hash: str

    action_references: Tuple[str, ...] = ()

    def __post_init__(self) -> None:

        ensure_aware(self.created_at)

        if not self.plan_id.strip():
            raise ValueError(
                "plan_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "plan scope must not be empty"
            )

        if self.version < 0:
            raise ValueError(
                "plan version must not be negative"
            )

        if not self.plan_hash.strip():
            raise ValueError(
                "plan_hash must not be empty"
            )


# ============================================================================
# SIMULATION REFERENCE
# ============================================================================

@dataclass(frozen=True)
class SimulationReference:
    simulation_id: str
    scope_id: str

    plan_id: str

    created_at: datetime

    viable: bool

    simulation_hash: str

    summary: str = ""

    def __post_init__(self) -> None:

        ensure_aware(self.created_at)

        if not self.simulation_id.strip():
            raise ValueError(
                "simulation_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "simulation scope must not be empty"
            )

        if not self.plan_id.strip():
            raise ValueError(
                "simulation plan_id must not be empty"
            )

        if not self.simulation_hash.strip():
            raise ValueError(
                "simulation_hash must not be empty"
            )


# ============================================================================
# AUTHORIZATION REFERENCE
# ============================================================================

@dataclass(frozen=True)
class AuthorizationReference:
    authorization_id: str
    scope_id: str

    plan_id: str

    authorized: bool

    authorized_at: datetime

    authority_reference: str

    reason: str = ""

    def __post_init__(self) -> None:

        ensure_aware(self.authorized_at)

        if not self.authorization_id.strip():
            raise ValueError(
                "authorization_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "authorization scope must not be empty"
            )

        if not self.plan_id.strip():
            raise ValueError(
                "authorization plan_id must not be empty"
            )

        if not self.authority_reference.strip():
            raise ValueError(
                "authority_reference must not be empty"
            )


# ============================================================================
# ACTION REFERENCE
# ============================================================================

@dataclass(frozen=True)
class ActionReference:
    action_id: str
    scope_id: str

    plan_id: str

    recorded_at: datetime

    action_type: str

    execution_reference: str

    def __post_init__(self) -> None:

        ensure_aware(self.recorded_at)

        if not self.action_id.strip():
            raise ValueError(
                "action_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "action scope must not be empty"
            )

        if not self.plan_id.strip():
            raise ValueError(
                "action plan_id must not be empty"
            )

        if not self.action_type.strip():
            raise ValueError(
                "action_type must not be empty"
            )

        if not self.execution_reference.strip():
            raise ValueError(
                "execution_reference must not be empty"
            )


# ============================================================================
# VERIFICATION REFERENCE
# ============================================================================

@dataclass(frozen=True)
class VerificationReference:
    verification_id: str
    scope_id: str

    action_id: str

    verified_at: datetime

    status: str

    confidence: float

    reason: str = ""

    def __post_init__(self) -> None:

        ensure_aware(self.verified_at)

        if not self.verification_id.strip():
            raise ValueError(
                "verification_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "verification scope must not be empty"
            )

        if not self.action_id.strip():
            raise ValueError(
                "verification action_id must not be empty"
            )

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "verification confidence invalid"
            )


# ============================================================================
# REPLAN TRIGGER
# ============================================================================

@dataclass(frozen=True)
class ReplanTrigger:
    trigger_id: str
    scope_id: str

    trigger_type: ReplanTriggerType

    created_at: datetime

    source_reference: str

    severity: int = 1

    reason: str = ""

    def __post_init__(self) -> None:

        ensure_aware(self.created_at)

        if not self.trigger_id.strip():
            raise ValueError(
                "trigger_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "trigger scope must not be empty"
            )

        if not self.source_reference.strip():
            raise ValueError(
                "trigger source_reference must not be empty"
            )

        if not 0 <= self.severity <= 10:
            raise ValueError(
                "severity must be between 0 and 10"
            )


# ============================================================================
# CYCLE RECORD
# ============================================================================

@dataclass
class ReplanCycle:

    cycle_id: str
    scope_id: str

    created_at: datetime

    status: ReplanCycleStatus = (
        ReplanCycleStatus.CREATED
    )

    observation_ids: Tuple[str, ...] = ()

    state_id: Optional[str] = None

    plan_id: Optional[str] = None

    simulation_id: Optional[str] = None

    authorization_id: Optional[str] = None

    action_ids: Tuple[str, ...] = ()

    verification_ids: Tuple[str, ...] = ()

    trigger_ids: Tuple[str, ...] = ()

    decision: Optional[ReplanDecision] = None

    failure_reason: Optional[str] = None

    cycle_hash: Optional[str] = None

    def __post_init__(self) -> None:

        ensure_aware(self.created_at)

        if not self.cycle_id.strip():
            raise ValueError(
                "cycle_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "cycle scope must not be empty"
            )


# ============================================================================
# CONTINUOUS REPLANNING ENGINE
# ============================================================================

class ContinuousReplanningEngine:

    def __init__(
        self,
        *,
        maximum_cycle_depth: int = 32,
    ) -> None:

        if maximum_cycle_depth < 1:
            raise ValueError(
                "maximum_cycle_depth must be >= 1"
            )

        self.maximum_cycle_depth = (
            maximum_cycle_depth
        )

        self._observations: Dict[
            str,
            ObservationReference,
        ] = {}

        self._states: Dict[
            str,
            StateReference,
        ] = {}

        self._plans: Dict[
            str,
            PlanReference,
        ] = {}

        self._simulations: Dict[
            str,
            SimulationReference,
        ] = {}

        self._authorizations: Dict[
            str,
            AuthorizationReference,
        ] = {}

        self._actions: Dict[
            str,
            ActionReference,
        ] = {}

        self._verifications: Dict[
            str,
            VerificationReference,
        ] = {}

        self._triggers: Dict[
            str,
            ReplanTrigger,
        ] = {}

        self._cycles: Dict[
            str,
            ReplanCycle,
        ] = {}

        self._lock = RLock()

    # ========================================================================
    # REGISTRATION
    # ========================================================================

    def add_observation(
        self,
        observation: ObservationReference,
    ) -> None:

        with self._lock:

            if observation.observation_id in self._observations:
                raise ValueError(
                    "duplicate observation"
                )

            self._observations[
                observation.observation_id
            ] = observation

    def add_state(
        self,
        state: StateReference,
    ) -> None:

        with self._lock:

            if state.state_id in self._states:
                raise ValueError(
                    "duplicate state"
                )

            self._states[
                state.state_id
            ] = state

    def add_plan(
        self,
        plan: PlanReference,
    ) -> None:

        with self._lock:

            if plan.plan_id in self._plans:
                raise ValueError(
                    "duplicate plan"
                )

            self._plans[
                plan.plan_id
            ] = plan

    def add_simulation(
        self,
        simulation: SimulationReference,
    ) -> None:

        with self._lock:

            if simulation.simulation_id in self._simulations:
                raise ValueError(
                    "duplicate simulation"
                )

            self._simulations[
                simulation.simulation_id
            ] = simulation

    def add_authorization(
        self,
        authorization: AuthorizationReference,
    ) -> None:

        with self._lock:

            if authorization.authorization_id in self._authorizations:
                raise ValueError(
                    "duplicate authorization"
                )

            self._authorizations[
                authorization.authorization_id
            ] = authorization

    def add_action(
        self,
        action: ActionReference,
    ) -> None:

        with self._lock:

            if action.action_id in self._actions:
                raise ValueError(
                    "duplicate action"
                )

            self._actions[
                action.action_id
            ] = action

    def add_verification(
        self,
        verification: VerificationReference,
    ) -> None:

        with self._lock:

            if verification.verification_id in self._verifications:
                raise ValueError(
                    "duplicate verification"
                )

            self._verifications[
                verification.verification_id
            ] = verification

    def add_trigger(
        self,
        trigger: ReplanTrigger,
    ) -> None:

        with self._lock:

            if trigger.trigger_id in self._triggers:
                raise ValueError(
                    "duplicate trigger"
                )

            self._triggers[
                trigger.trigger_id
            ] = trigger

    # ========================================================================
    # CYCLE CREATION
    # ========================================================================

    def create_cycle(
        self,
        scope_id: str,
    ) -> ReplanCycle:

        if not scope_id.strip():
            raise ValueError(
                "scope_id must not be empty"
            )

        cycle_id = stable_hash(
            "cycle",
            scope_id,
            utc_now().isoformat(),
        )

        cycle = ReplanCycle(
            cycle_id=cycle_id,
            scope_id=scope_id,
            created_at=utc_now(),
        )

        with self._lock:

            self._refresh_hash(cycle)

            self._cycles[
                cycle_id
            ] = cycle

        return cycle

    def get_cycle(
        self,
        cycle_id: str,
    ) -> ReplanCycle:

        with self._lock:

            if cycle_id not in self._cycles:
                raise KeyError(
                    "cycle not found"
                )

            return self._cycles[
                cycle_id
            ]

    # ========================================================================
    # OBSERVE
    # ========================================================================

    def record_observations(
        self,
        cycle_id: str,
        observation_ids: Iterable[str],
    ) -> ReplanCycle:

        with self._lock:

            cycle = self.get_cycle(
                cycle_id
            )

            ids = tuple(
                observation_ids
            )

            for observation_id in ids:

                observation = self._observations.get(
                    observation_id
                )

                if observation is None:
                    raise KeyError(
                        f"observation not found: "
                        f"{observation_id}"
                    )

                if observation.scope_id != cycle.scope_id:
                    raise ValueError(
                        "observation scope mismatch"
                    )

            cycle.observation_ids = ids

            cycle.status = (
                ReplanCycleStatus.OBSERVED
            )

            self._refresh_hash(cycle)

            return cycle

    # ========================================================================
    # STATE
    # ========================================================================

    def attach_state(
        self,
        cycle_id: str,
        state_id: str,
    ) -> ReplanCycle:

        with self._lock:

            cycle = self.get_cycle(
                cycle_id
            )

            state = self._states.get(
                state_id
            )

            if state is None:
                raise KeyError(
                    "state not found"
                )

            if state.scope_id != cycle.scope_id:
                raise ValueError(
                    "state scope mismatch"
                )

            cycle.state_id = state_id

            cycle.status = (
                ReplanCycleStatus.STATE_READY
            )

            self._refresh_hash(cycle)

            return cycle

    # ========================================================================
    # PLAN
    # ========================================================================

    def attach_plan(
        self,
        cycle_id: str,
        plan_id: str,
    ) -> ReplanCycle:

        with self._lock:

            cycle = self.get_cycle(
                cycle_id
            )

            plan = self._plans.get(
                plan_id
            )

            if plan is None:
                raise KeyError(
                    "plan not found"
                )

            if plan.scope_id != cycle.scope_id:
                raise ValueError(
                    "plan scope mismatch"
                )

            cycle.plan_id = plan_id

            cycle.status = (
                ReplanCycleStatus.PLAN_READY
            )

            self._refresh_hash(cycle)

            return cycle

    # ========================================================================
    # SIMULATION
    # ========================================================================

    def attach_simulation(
        self,
        cycle_id: str,
        simulation_id: str,
    ) -> ReplanCycle:

        with self._lock:

            cycle = self.get_cycle(
                cycle_id
            )

            simulation = self._simulations.get(
                simulation_id
            )

            if simulation is None:
                raise KeyError(
                    "simulation not found"
                )

            if simulation.scope_id != cycle.scope_id:
                raise ValueError(
                    "simulation scope mismatch"
                )

            if (
                cycle.plan_id is not None
                and simulation.plan_id
                != cycle.plan_id
            ):
                raise ValueError(
                    "simulation does not match cycle plan"
                )

            cycle.simulation_id = simulation_id

            cycle.status = (
                ReplanCycleStatus.SIMULATION_READY
            )

            self._refresh_hash(cycle)

            return cycle

    # ========================================================================
    # AUTHORIZATION
    # ========================================================================

    def attach_authorization(
        self,
        cycle_id: str,
        authorization_id: str,
    ) -> ReplanCycle:

        with self._lock:

            cycle = self.get_cycle(
                cycle_id
            )

            authorization = self._authorizations.get(
                authorization_id
            )

            if authorization is None:
                raise KeyError(
                    "authorization not found"
                )

            if authorization.scope_id != cycle.scope_id:
                raise ValueError(
                    "authorization scope mismatch"
                )

            if (
                cycle.plan_id is not None
                and authorization.plan_id
                != cycle.plan_id
            ):
                raise ValueError(
                    "authorization does not match cycle plan"
                )

            if not authorization.authorized:

                cycle.status = (
                    ReplanCycleStatus.STOPPED
                )

                cycle.decision = (
                    ReplanDecision.STOP
                )

                cycle.failure_reason = (
                    "authorization denied"
                )

                self._refresh_hash(cycle)

                return cycle

            cycle.authorization_id = (
                authorization_id
            )

            cycle.status = (
                ReplanCycleStatus.AUTHORIZATION_READY
            )

            self._refresh_hash(cycle)

            return cycle

    # ========================================================================
    # ACTION REFERENCE
    # ========================================================================

    def record_action(
        self,
        cycle_id: str,
        action_id: str,
    ) -> ReplanCycle:

        with self._lock:

            cycle = self.get_cycle(
                cycle_id
            )

            action = self._actions.get(
                action_id
            )

            if action is None:
                raise KeyError(
                    "action not found"
                )

            if action.scope_id != cycle.scope_id:
                raise ValueError(
                    "action scope mismatch"
                )

            if (
                cycle.plan_id is not None
                and action.plan_id
                != cycle.plan_id
            ):
                raise ValueError(
                    "action does not match cycle plan"
                )

            cycle.action_ids = (
                *cycle.action_ids,
                action_id,
            )

            cycle.status = (
                ReplanCycleStatus.ACTION_RECORDED
            )

            self._refresh_hash(cycle)

            return cycle

    # ========================================================================
    # VERIFICATION
    # ========================================================================

    def record_verification(
        self,
        cycle_id: str,
        verification_id: str,
    ) -> ReplanCycle:

        with self._lock:

            cycle = self.get_cycle(
                cycle_id
            )

            verification = self._verifications.get(
                verification_id
            )

            if verification is None:
                raise KeyError(
                    "verification not found"
                )

            if verification.scope_id != cycle.scope_id:
                raise ValueError(
                    "verification scope mismatch"
                )

            if (
                verification.action_id
                not in cycle.action_ids
            ):
                raise ValueError(
                    "verification action is not part of cycle"
                )

            cycle.verification_ids = (
                *cycle.verification_ids,
                verification_id,
            )

            status = verification.status.upper()

            if status == "SUCCESS":

                cycle.status = (
                    ReplanCycleStatus.VERIFIED
                )

            elif status in {
                "PARTIAL",
                "UNKNOWN",
                "FAILED",
            }:

                cycle.status = (
                    ReplanCycleStatus.REPLAN_REQUIRED
                )

            else:

                cycle.status = (
                    ReplanCycleStatus.FAILED
                )

                cycle.failure_reason = (
                    "unsupported verification status"
                )

            self._refresh_hash(cycle)

            return cycle

    # ========================================================================
    # TRIGGER
    # ========================================================================

    def register_trigger(
        self,
        cycle_id: str,
        trigger_id: str,
    ) -> ReplanCycle:

        with self._lock:

            cycle = self.get_cycle(
                cycle_id
            )

            trigger = self._triggers.get(
                trigger_id
            )

            if trigger is None:
                raise KeyError(
                    "trigger not found"
                )

            if trigger.scope_id != cycle.scope_id:
                raise ValueError(
                    "trigger scope mismatch"
                )

            cycle.trigger_ids = (
                *cycle.trigger_ids,
                trigger_id,
            )

            cycle.status = (
                ReplanCycleStatus.REPLAN_REQUIRED
            )

            cycle.decision = (
                ReplanDecision.REPLAN
            )

            self._refresh_hash(cycle)

            return cycle

    # ========================================================================
    # REPLAN DECISION
    # ========================================================================

    def decide(
        self,
        cycle_id: str,
        *,
        force_stop: bool = False,
    ) -> ReplanDecision:

        with self._lock:

            cycle = self.get_cycle(
                cycle_id
            )

            if force_stop:

                cycle.decision = (
                    ReplanDecision.STOP
                )

                cycle.status = (
                    ReplanCycleStatus.STOPPED
                )

                self._refresh_hash(cycle)

                return cycle.decision

            if cycle.status == ReplanCycleStatus.REPLAN_REQUIRED:

                cycle.decision = (
                    ReplanDecision.REPLAN
                )

                self._refresh_hash(cycle)

                return cycle.decision

            if cycle.status == ReplanCycleStatus.VERIFIED:

                cycle.decision = (
                    ReplanDecision.CONTINUE
                )

                cycle.status = (
                    ReplanCycleStatus.COMPLETED
                )

                self._refresh_hash(cycle)

                return cycle.decision

            if cycle.status in {
                ReplanCycleStatus.STOPPED,
                ReplanCycleStatus.FAILED,
            }:

                cycle.decision = (
                    ReplanDecision.STOP
                )

                self._refresh_hash(cycle)

                return cycle.decision

            cycle.decision = (
                ReplanDecision.STOP
            )

            cycle.status = (
                ReplanCycleStatus.STOPPED
            )

            cycle.failure_reason = (
                "cycle is incomplete"
            )

            self._refresh_hash(cycle)

            return cycle.decision

    # ========================================================================
    # HASH
    # ========================================================================

    @staticmethod
    def _cycle_material(
        cycle: ReplanCycle,
    ) -> Tuple[object, ...]:

        return (
            cycle.cycle_id,
            cycle.scope_id,
            cycle.status.value,
            cycle.observation_ids,
            cycle.state_id,
            cycle.plan_id,
            cycle.simulation_id,
            cycle.authorization_id,
            cycle.action_ids,
            cycle.verification_ids,
            cycle.trigger_ids,
            (
                cycle.decision.value
                if cycle.decision
                else None
            ),
            cycle.failure_reason,
        )

    def _refresh_hash(
        self,
        cycle: ReplanCycle,
    ) -> None:

        cycle.cycle_hash = stable_hash(
            *self._cycle_material(cycle)
        )

    @classmethod
    def validate_cycle_hash(
        cls,
        cycle: ReplanCycle,
    ) -> bool:

        if not cycle.cycle_hash:
            return False

        expected = stable_hash(
            *cls._cycle_material(cycle)
        )

        return expected == cycle.cycle_hash

    # ========================================================================
    # VALIDATION
    # ========================================================================

    def validate(self) -> List[str]:

        errors: List[str] = []

        with self._lock:

            for cycle_id, cycle in self._cycles.items():

                if cycle_id != cycle.cycle_id:
                    errors.append(
                        f"cycle key mismatch: {cycle_id}"
                    )

                if not self.validate_cycle_hash(cycle):
                    errors.append(
                        f"cycle hash mismatch: {cycle_id}"
                    )

                for observation_id in cycle.observation_ids:

                    observation = self._observations.get(
                        observation_id
                    )

                    if observation is None:
                        errors.append(
                            f"unknown observation: "
                            f"{observation_id}"
                        )

                    elif observation.scope_id != cycle.scope_id:
                        errors.append(
                            f"observation scope mismatch: "
                            f"{observation_id}"
                        )

                if cycle.state_id:

                    state = self._states.get(
                        cycle.state_id
                    )

                    if state is None:
                        errors.append(
                            f"unknown state: "
                            f"{cycle.state_id}"
                        )

                    elif state.scope_id != cycle.scope_id:
                        errors.append(
                            f"state scope mismatch: "
                            f"{cycle.state_id}"
                        )

                if cycle.plan_id:

                    plan = self._plans.get(
                        cycle.plan_id
                    )

                    if plan is None:
                        errors.append(
                            f"unknown plan: "
                            f"{cycle.plan_id}"
                        )

                    elif plan.scope_id != cycle.scope_id:
                        errors.append(
                            f"plan scope mismatch: "
                            f"{cycle.plan_id}"
                        )

                if cycle.simulation_id:

                    simulation = self._simulations.get(
                        cycle.simulation_id
                    )

                    if simulation is None:
                        errors.append(
                            f"unknown simulation: "
                            f"{cycle.simulation_id}"
                        )

                    elif simulation.scope_id != cycle.scope_id:
                        errors.append(
                            f"simulation scope mismatch: "
                            f"{cycle.simulation_id}"
                        )

                if cycle.authorization_id:

                    authorization = self._authorizations.get(
                        cycle.authorization_id
                    )

                    if authorization is None:
                        errors.append(
                            f"unknown authorization: "
                            f"{cycle.authorization_id}"
                        )

                    elif authorization.scope_id != cycle.scope_id:
                        errors.append(
                            f"authorization scope mismatch: "
                            f"{cycle.authorization_id}"
                        )

                for action_id in cycle.action_ids:

                    action = self._actions.get(
                        action_id
                    )

                    if action is None:
                        errors.append(
                            f"unknown action: "
                            f"{action_id}"
                        )

                    elif action.scope_id != cycle.scope_id:
                        errors.append(
                            f"action scope mismatch: "
                            f"{action_id}"
                        )

                for verification_id in cycle.verification_ids:

                    verification = self._verifications.get(
                        verification_id
                    )

                    if verification is None:
                        errors.append(
                            f"unknown verification: "
                            f"{verification_id}"
                        )

                    elif verification.scope_id != cycle.scope_id:
                        errors.append(
                            f"verification scope mismatch: "
                            f"{verification_id}"
                        )

                for trigger_id in cycle.trigger_ids:

                    trigger = self._triggers.get(
                        trigger_id
                    )

                    if trigger is None:
                        errors.append(
                            f"unknown trigger: "
                            f"{trigger_id}"
                        )

                    elif trigger.scope_id != cycle.scope_id:
                        errors.append(
                            f"trigger scope mismatch: "
                            f"{trigger_id}"
                        )

        return errors


# ============================================================================
# TESTS
# ============================================================================

class Phase15Tests(unittest.TestCase):

    def setUp(self):

        self.engine = (
            ContinuousReplanningEngine()
        )

        self.observation = ObservationReference(
            observation_id="obs-1",
            scope_id="scope-a",
            source="sensor-a",
            observed_at=utc_now(),
        )

        self.state = StateReference(
            state_id="state-1",
            scope_id="scope-a",
            version=1,
            observed_at=utc_now(),
            state_hash="statehash",
        )

        self.plan = PlanReference(
            plan_id="plan-1",
            scope_id="scope-a",
            version=1,
            created_at=utc_now(),
            plan_hash="planhash",
            action_references=("action-1",),
        )

        self.simulation = SimulationReference(
            simulation_id="sim-1",
            scope_id="scope-a",
            plan_id="plan-1",
            created_at=utc_now(),
            viable=True,
            simulation_hash="simhash",
        )

        self.authorization = AuthorizationReference(
            authorization_id="auth-1",
            scope_id="scope-a",
            plan_id="plan-1",
            authorized=True,
            authorized_at=utc_now(),
            authority_reference="authority-1",
        )

        self.action = ActionReference(
            action_id="action-1",
            scope_id="scope-a",
            plan_id="plan-1",
            recorded_at=utc_now(),
            action_type="CONTROL",
            execution_reference="execution-1",
        )

        self.verification = VerificationReference(
            verification_id="verification-1",
            scope_id="scope-a",
            action_id="action-1",
            verified_at=utc_now(),
            status="SUCCESS",
            confidence=0.95,
        )

        self.engine.add_observation(
            self.observation
        )

        self.engine.add_state(
            self.state
        )

        self.engine.add_plan(
            self.plan
        )

        self.engine.add_simulation(
            self.simulation
        )

        self.engine.add_authorization(
            self.authorization
        )

        self.engine.add_action(
            self.action
        )

        self.engine.add_verification(
            self.verification
        )

    # ========================================================================
    # Full cycle
    # ========================================================================

    def test_complete_cycle(self):

        cycle = self.engine.create_cycle(
            "scope-a"
        )

        self.engine.record_observations(
            cycle.cycle_id,
            ("obs-1",),
        )

        self.engine.attach_state(
            cycle.cycle_id,
            "state-1",
        )

        self.engine.attach_plan(
            cycle.cycle_id,
            "plan-1",
        )

        self.engine.attach_simulation(
            cycle.cycle_id,
            "sim-1",
        )

        self.engine.attach_authorization(
            cycle.cycle_id,
            "auth-1",
        )

        self.engine.record_action(
            cycle.cycle_id,
            "action-1",
        )

        self.engine.record_verification(
            cycle.cycle_id,
            "verification-1",
        )

        decision = self.engine.decide(
            cycle.cycle_id
        )

        self.assertEqual(
            decision,
            ReplanDecision.CONTINUE,
        )

        self.assertEqual(
            cycle.status,
            ReplanCycleStatus.COMPLETED,
        )

    # ========================================================================
    # Verification failure causes replan
    # ========================================================================

    def test_failed_verification_requires_replan(self):

        failed_verification = VerificationReference(
            verification_id="verification-failed",
            scope_id="scope-a",
            action_id="action-1",
            verified_at=utc_now(),
            status="FAILED",
            confidence=0.90,
        )

        self.engine.add_verification(
            failed_verification
        )

        cycle = self.engine.create_cycle(
            "scope-a"
        )

        self.engine.attach_plan(
            cycle.cycle_id,
            "plan-1",
        )

        self.engine.record_action(
            cycle.cycle_id,
            "action-1",
        )

        self.engine.record_verification(
            cycle.cycle_id,
            "verification-failed",
        )

        decision = self.engine.decide(
            cycle.cycle_id
        )

        self.assertEqual(
            decision,
            ReplanDecision.REPLAN,
        )

    # ========================================================================
    # Trigger causes replan
    # ========================================================================

    def test_trigger_requires_replan(self):

        trigger = ReplanTrigger(
            trigger_id="trigger-1",
            scope_id="scope-a",
            trigger_type=ReplanTriggerType.STATE_CHANGE,
            created_at=utc_now(),
            source_reference="state-2",
            severity=5,
        )

        self.engine.add_trigger(
            trigger
        )

        cycle = self.engine.create_cycle(
            "scope-a"
        )

        self.engine.register_trigger(
            cycle.cycle_id,
            "trigger-1",
        )

        self.assertEqual(
            self.engine.decide(
                cycle.cycle_id
            ),
            ReplanDecision.REPLAN,
        )

    # ========================================================================
    # Authorization denial stops cycle
    # ========================================================================

    def test_authorization_denial_stops_cycle(self):

        denied = AuthorizationReference(
            authorization_id="auth-denied",
            scope_id="scope-a",
            plan_id="plan-1",
            authorized=False,
            authorized_at=utc_now(),
            authority_reference="authority-1",
            reason="denied",
        )

        self.engine.add_authorization(
            denied
        )

        cycle = self.engine.create_cycle(
            "scope-a"
        )

        self.engine.attach_plan(
            cycle.cycle_id,
            "plan-1",
        )

        self.engine.attach_authorization(
            cycle.cycle_id,
            "auth-denied",
        )

        self.assertEqual(
            cycle.status,
            ReplanCycleStatus.STOPPED,
        )

        self.assertEqual(
            self.engine.decide(
                cycle.cycle_id
            ),
            ReplanDecision.STOP,
        )

    # ========================================================================
    # Scope isolation
    # ========================================================================

    def test_scope_isolation(self):

        foreign_state = StateReference(
            state_id="foreign-state",
            scope_id="scope-b",
            version=1,
            observed_at=utc_now(),
            state_hash="foreign",
        )

        self.engine.add_state(
            foreign_state
        )

        cycle = self.engine.create_cycle(
            "scope-a"
        )

        with self.assertRaises(ValueError):

            self.engine.attach_state(
                cycle.cycle_id,
                "foreign-state",
            )

    # ========================================================================
    # Simulation-plan consistency
    # ========================================================================

    def test_simulation_plan_mismatch(self):

        simulation = SimulationReference(
            simulation_id="wrong-sim",
            scope_id="scope-a",
            plan_id="different-plan",
            created_at=utc_now(),
            viable=True,
            simulation_hash="hash",
        )

        self.engine.add_simulation(
            simulation
        )

        cycle = self.engine.create_cycle(
            "scope-a"
        )

        self.engine.attach_plan(
            cycle.cycle_id,
            "plan-1",
        )

        with self.assertRaises(ValueError):

            self.engine.attach_simulation(
                cycle.cycle_id,
                "wrong-sim",
            )

    # ========================================================================
    # Verification must belong to recorded action
    # ========================================================================

    def test_verification_requires_action(self):

        cycle = self.engine.create_cycle(
            "scope-a"
        )

        with self.assertRaises(ValueError):

            self.engine.record_verification(
                cycle.cycle_id,
                "verification-1",
            )

    # ========================================================================
    # Forced stop
    # ========================================================================

    def test_force_stop(self):

        cycle = self.engine.create_cycle(
            "scope-a"
        )

        decision = self.engine.decide(
            cycle.cycle_id,
            force_stop=True,
        )

        self.assertEqual(
            decision,
            ReplanDecision.STOP,
        )

        self.assertEqual(
            cycle.status,
            ReplanCycleStatus.STOPPED,
        )

    # ========================================================================
    # Hash integrity
    # ========================================================================

    def test_cycle_hash(self):

        cycle = self.engine.create_cycle(
            "scope-a"
        )

        self.assertTrue(
            self.engine.validate_cycle_hash(
                cycle
            )
        )

    # ========================================================================
    # Global validation
    # ========================================================================

    def test_validation(self):

        cycle = self.engine.create_cycle(
            "scope-a"
        )

        self.engine.record_observations(
            cycle.cycle_id,
            ("obs-1",),
        )

        self.assertEqual(
            self.engine.validate(),
            [],
        )


# ============================================================================
# TEST RUNNER
# ============================================================================

def run_phase15_tests() -> None:

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        Phase15Tests
    )

    result = unittest.TextTestRunner(
        verbosity=2
    ).run(suite)

    if not result.wasSuccessful():
        raise AssertionError(
            "Phase 15 tests failed"
        )


if __name__ == "__main__":
    run_phase15_tests()
