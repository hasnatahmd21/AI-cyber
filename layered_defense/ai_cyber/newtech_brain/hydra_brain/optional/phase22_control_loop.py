"""
HYDRA™ — Phase 22
Full Autonomous Security Control Loop

SCOPE
-----
Integrates already implemented Phase 4–21 interfaces into:

OBSERVE
   ↓
STATE
   ↓
PLAN
   ↓
SIMULATE
   ↓
AUTHORIZE
   ↓
ACT
   ↓
VERIFY
   ↓
REPLAN / CONTINUE / STOP

This phase is a coordination/control-loop layer.

IMPORTANT
---------
This module does not reimplement:
- Security State Engine
- State Integrity Engine
- Security Graph
- Causal Memory
- Memory Trust
- Attribution
- Intervention Optimization
- Security Invariants
- Authority Graph
- Intent Compiler
- Independent Verification
- Continuous Replanning
- Cyber Experiments
- Regeneration
- Adaptive Defense
- AI Self-Protection
- Defense Fabric
- Resource Resilience

Those capabilities remain owned by their respective phases.

This module coordinates references/interfaces to them.

It does not introduce Phase 23+ functionality.
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


def ensure_aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(
            "datetime must be timezone-aware"
        )


def stable_hash(*parts: object) -> str:
    material = "|".join(
        str(part)
        for part in parts
    )

    return hashlib.sha256(
        material.encode("utf-8")
    ).hexdigest()


# ============================================================================
# ENUMS
# ============================================================================

class ControlLoopStage(str, Enum):

    OBSERVE = "OBSERVE"
    STATE = "STATE"
    PLAN = "PLAN"
    SIMULATE = "SIMULATE"
    AUTHORIZE = "AUTHORIZE"
    ACT = "ACT"
    VERIFY = "VERIFY"
    DECIDE = "DECIDE"


class LoopStatus(str, Enum):

    CREATED = "CREATED"
    OBSERVED = "OBSERVED"
    STATE_READY = "STATE_READY"
    PLAN_READY = "PLAN_READY"
    SIMULATION_READY = "SIMULATION_READY"
    AUTHORIZATION_READY = "AUTHORIZATION_READY"
    ACTION_RECORDED = "ACTION_RECORDED"
    VERIFIED = "VERIFIED"
    REPLANNING = "REPLANNING"
    COMPLETED = "COMPLETED"
    STOPPED = "STOPPED"
    FAILED = "FAILED"


class LoopDecision(str, Enum):

    CONTINUE = "CONTINUE"
    REPLAN = "REPLAN"
    STOP = "STOP"


class AuthorizationStatus(str, Enum):

    UNKNOWN = "UNKNOWN"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"


class SimulationStatus(str, Enum):

    UNKNOWN = "UNKNOWN"
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"


class VerificationStatus(str, Enum):

    UNKNOWN = "UNKNOWN"
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class ActionStatus(str, Enum):

    NOT_RECORDED = "NOT_RECORDED"
    PLANNED = "PLANNED"
    AUTHORIZED = "AUTHORIZED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"


class ControlLoopFailure(str, Enum):

    NONE = "NONE"
    MISSING_OBSERVATION = "MISSING_OBSERVATION"
    MISSING_STATE = "MISSING_STATE"
    MISSING_PLAN = "MISSING_PLAN"
    SIMULATION_FAILED = "SIMULATION_FAILED"
    AUTHORIZATION_FAILED = "AUTHORIZATION_FAILED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    RESOURCE_BLOCKED = "RESOURCE_BLOCKED"
    INVALID_TRANSITION = "INVALID_TRANSITION"


# ============================================================================
# EXISTING COMPONENT REFERENCES
# ============================================================================

@dataclass(frozen=True)
class ComponentReference:

    reference_id: str
    component_type: str
    component_id: str

    created_at: datetime = field(
        default_factory=utc_now
    )

    def __post_init__(self) -> None:

        ensure_aware(self.created_at)

        if not self.reference_id.strip():
            raise ValueError(
                "reference_id required"
            )

        if not self.component_type.strip():
            raise ValueError(
                "component_type required"
            )

        if not self.component_id.strip():
            raise ValueError(
                "component_id required"
            )


# ============================================================================
# OBSERVATION
# ============================================================================

@dataclass(frozen=True)
class LoopObservation:

    observation_id: str
    scope_id: str

    source_reference: str

    observation_type: str
    summary: str

    evidence_references: FrozenSet[str]

    observed_at: datetime

    def __post_init__(self) -> None:

        ensure_aware(self.observed_at)

        if not self.observation_id.strip():
            raise ValueError(
                "observation_id required"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id required"
            )

        if not self.source_reference.strip():
            raise ValueError(
                "source_reference required"
            )

        if not self.observation_type.strip():
            raise ValueError(
                "observation_type required"
            )

        if not self.summary.strip():
            raise ValueError(
                "summary required"
            )


# ============================================================================
# STATE REFERENCE
# ============================================================================

@dataclass(frozen=True)
class LoopStateReference:

    state_reference_id: str
    scope_id: str

    state_component_reference: str
    state_snapshot_reference: str

    integrity_verified: bool
    confidence: float

    created_at: datetime

    def __post_init__(self) -> None:

        ensure_aware(self.created_at)

        if not self.state_reference_id.strip():
            raise ValueError(
                "state_reference_id required"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id required"
            )

        if not self.state_component_reference.strip():
            raise ValueError(
                "state_component_reference required"
            )

        if not self.state_snapshot_reference.strip():
            raise ValueError(
                "state_snapshot_reference required"
            )

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "confidence must be between 0 and 1"
            )


# ============================================================================
# PLAN REFERENCE
# ============================================================================

@dataclass(frozen=True)
class LoopPlanReference:

    plan_reference_id: str
    scope_id: str

    intervention_reference: str
    intent_reference: Optional[str]

    invariant_references: FrozenSet[str]

    expected_outcome: str

    created_at: datetime

    def __post_init__(self) -> None:

        ensure_aware(self.created_at)

        if not self.plan_reference_id.strip():
            raise ValueError(
                "plan_reference_id required"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id required"
            )

        if not self.intervention_reference.strip():
            raise ValueError(
                "intervention_reference required"
            )

        if not self.expected_outcome.strip():
            raise ValueError(
                "expected_outcome required"
            )


# ============================================================================
# SIMULATION REFERENCE
# ============================================================================

@dataclass(frozen=True)
class LoopSimulationReference:

    simulation_reference_id: str
    scope_id: str

    experiment_reference: str
    status: SimulationStatus

    confidence: float
    summary: str

    created_at: datetime

    def __post_init__(self) -> None:

        ensure_aware(self.created_at)

        if not self.simulation_reference_id.strip():
            raise ValueError(
                "simulation_reference_id required"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id required"
            )

        if not self.experiment_reference.strip():
            raise ValueError(
                "experiment_reference required"
            )

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "confidence must be between 0 and 1"
            )

        if not self.summary.strip():
            raise ValueError(
                "summary required"
            )


# ============================================================================
# AUTHORIZATION REFERENCE
# ============================================================================

@dataclass(frozen=True)
class LoopAuthorizationReference:

    authorization_reference_id: str
    scope_id: str

    authority_reference: str
    status: AuthorizationStatus

    approved_action_reference: Optional[str]

    created_at: datetime

    def __post_init__(self) -> None:

        ensure_aware(self.created_at)

        if not self.authorization_reference_id.strip():
            raise ValueError(
                "authorization_reference_id required"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id required"
            )

        if not self.authority_reference.strip():
            raise ValueError(
                "authority_reference required"
            )

        if (
            self.status == AuthorizationStatus.APPROVED
            and not self.approved_action_reference
        ):
            raise ValueError(
                "approved action reference required "
                "for approved authorization"
            )


# ============================================================================
# ACTION REFERENCE
# ============================================================================

@dataclass(frozen=True)
class LoopActionReference:

    action_reference_id: str
    scope_id: str

    authorization_reference: str
    action_reference: str

    status: ActionStatus

    recorded_at: datetime

    def __post_init__(self) -> None:

        ensure_aware(self.recorded_at)

        if not self.action_reference_id.strip():
            raise ValueError(
                "action_reference_id required"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id required"
            )

        if not self.authorization_reference.strip():
            raise ValueError(
                "authorization_reference required"
            )

        if not self.action_reference.strip():
            raise ValueError(
                "action_reference required"
            )


# ============================================================================
# VERIFICATION REFERENCE
# ============================================================================

@dataclass(frozen=True)
class LoopVerificationReference:

    verification_reference_id: str
    scope_id: str

    verification_component_reference: str

    status: VerificationStatus
    confidence: float

    expected_outcome: str
    observed_outcome: str

    independent_evidence_references: FrozenSet[str]

    verified_at: datetime

    def __post_init__(self) -> None:

        ensure_aware(self.verified_at)

        if not self.verification_reference_id.strip():
            raise ValueError(
                "verification_reference_id required"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id required"
            )

        if not self.verification_component_reference.strip():
            raise ValueError(
                "verification_component_reference "
                "required"
            )

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "confidence must be between 0 and 1"
            )


# ============================================================================
# CONTROL LOOP RECORD
# ============================================================================

@dataclass
class SecurityControlLoop:

    loop_id: str
    scope_id: str

    status: LoopStatus = LoopStatus.CREATED
    current_stage: ControlLoopStage = (
        ControlLoopStage.OBSERVE
    )

    observation_ids: List[str] = field(
        default_factory=list
    )

    state_reference_id: Optional[str] = None
    plan_reference_id: Optional[str] = None
    simulation_reference_id: Optional[str] = None
    authorization_reference_id: Optional[str] = None
    action_reference_id: Optional[str] = None
    verification_reference_id: Optional[str] = None

    decision: Optional[LoopDecision] = None
    failure: ControlLoopFailure = (
        ControlLoopFailure.NONE
    )

    iteration: int = 0

    created_at: datetime = field(
        default_factory=utc_now
    )

    updated_at: datetime = field(
        default_factory=utc_now
    )

    loop_hash: str = ""

    def __post_init__(self) -> None:

        ensure_aware(self.created_at)
        ensure_aware(self.updated_at)

        if not self.loop_id.strip():
            raise ValueError(
                "loop_id required"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id required"
            )

        if self.iteration < 0:
            raise ValueError(
                "iteration cannot be negative"
            )


# ============================================================================
# CONTROL LOOP ENGINE
# ============================================================================

class AutonomousSecurityControlLoop:

    """
    Phase 22 orchestration layer.

    Existing engines are referenced by identifiers/interfaces.
    Their internals are deliberately not duplicated here.
    """

    def __init__(
        self,
        *,
        maximum_iterations: int = 32,
    ) -> None:

        if maximum_iterations <= 0:
            raise ValueError(
                "maximum_iterations must be positive"
            )

        self.maximum_iterations = (
            maximum_iterations
        )

        self._components: Dict[
            str,
            ComponentReference,
        ] = {}

        self._observations: Dict[
            str,
            LoopObservation,
        ] = {}

        self._states: Dict[
            str,
            LoopStateReference,
        ] = {}

        self._plans: Dict[
            str,
            LoopPlanReference,
        ] = {}

        self._simulations: Dict[
            str,
            LoopSimulationReference,
        ] = {}

        self._authorizations: Dict[
            str,
            LoopAuthorizationReference,
        ] = {}

        self._actions: Dict[
            str,
            LoopActionReference,
        ] = {}

        self._verifications: Dict[
            str,
            LoopVerificationReference,
        ] = {}

        self._loops: Dict[
            str,
            SecurityControlLoop,
        ] = {}

        self._lock = RLock()

    # ========================================================================
    # COMPONENT REGISTRATION
    # ========================================================================

    def register_component(
        self,
        reference: ComponentReference,
    ) -> None:

        with self._lock:

            if reference.reference_id in (
                self._components
            ):
                raise ValueError(
                    "duplicate component reference"
                )

            self._components[
                reference.reference_id
            ] = reference

    # ========================================================================
    # LOOP CREATION
    # ========================================================================

    def create_loop(
        self,
        scope_id: str,
    ) -> SecurityControlLoop:

        if not scope_id.strip():
            raise ValueError(
                "scope_id required"
            )

        with self._lock:

            timestamp = utc_now()

            loop_id = stable_hash(
                "control-loop",
                scope_id,
                timestamp.isoformat(),
                len(self._loops),
            )

            loop = SecurityControlLoop(
                loop_id=loop_id,
                scope_id=scope_id,
                created_at=timestamp,
                updated_at=timestamp,
            )

            loop.loop_hash = self._calculate_loop_hash(
                loop
            )

            self._loops[
                loop.loop_id
            ] = loop

            return loop

    # ========================================================================
    # OBSERVE
    # ========================================================================

    def record_observation(
        self,
        loop_id: str,
        observation: LoopObservation,
    ) -> SecurityControlLoop:

        with self._lock:

            loop = self._get_loop(
                loop_id
            )

            self._check_scope(
                loop.scope_id,
                observation.scope_id,
            )

            if loop.status in {
                LoopStatus.COMPLETED,
                LoopStatus.STOPPED,
                LoopStatus.FAILED,
            }:
                raise ValueError(
                    "cannot observe a terminal loop"
                )

            if observation.observation_id in (
                self._observations
            ):
                raise ValueError(
                    "duplicate observation"
                )

            self._observations[
                observation.observation_id
            ] = observation

            loop.observation_ids.append(
                observation.observation_id
            )

            loop.status = (
                LoopStatus.OBSERVED
            )

            loop.current_stage = (
                ControlLoopStage.STATE
            )

            self._touch(loop)

            return loop

    # ========================================================================
    # STATE
    # ========================================================================

    def attach_state(
        self,
        loop_id: str,
        state: LoopStateReference,
    ) -> SecurityControlLoop:

        with self._lock:

            loop = self._get_loop(
                loop_id
            )

            self._check_scope(
                loop.scope_id,
                state.scope_id,
            )

            if not loop.observation_ids:
                self._fail(
                    loop,
                    ControlLoopFailure.MISSING_OBSERVATION,
                )
                return loop

            self._states[
                state.state_reference_id
            ] = state

            loop.state_reference_id = (
                state.state_reference_id
            )

            loop.status = (
                LoopStatus.STATE_READY
            )

            loop.current_stage = (
                ControlLoopStage.PLAN
            )

            self._touch(loop)

            return loop

    # ========================================================================
    # PLAN
    # ========================================================================

    def attach_plan(
        self,
        loop_id: str,
        plan: LoopPlanReference,
    ) -> SecurityControlLoop:

        with self._lock:

            loop = self._get_loop(
                loop_id
            )

            self._check_scope(
                loop.scope_id,
                plan.scope_id,
            )

            if not loop.state_reference_id:
                self._fail(
                    loop,
                    ControlLoopFailure.MISSING_STATE,
                )
                return loop

            self._plans[
                plan.plan_reference_id
            ] = plan

            loop.plan_reference_id = (
                plan.plan_reference_id
            )

            loop.status = (
                LoopStatus.PLAN_READY
            )

            loop.current_stage = (
                ControlLoopStage.SIMULATE
            )

            self._touch(loop)

            return loop

    # ========================================================================
    # SIMULATE
    # ========================================================================

    def attach_simulation(
        self,
        loop_id: str,
        simulation: LoopSimulationReference,
    ) -> SecurityControlLoop:

        with self._lock:

            loop = self._get_loop(
                loop_id
            )

            self._check_scope(
                loop.scope_id,
                simulation.scope_id,
            )

            if not loop.plan_reference_id:
                self._fail(
                    loop,
                    ControlLoopFailure.MISSING_PLAN,
                )
                return loop

            self._simulations[
                simulation.simulation_reference_id
            ] = simulation

            loop.simulation_reference_id = (
                simulation.simulation_reference_id
            )

            if simulation.status in {
                SimulationStatus.FAIL,
                SimulationStatus.INCONCLUSIVE,
            }:

                self._fail(
                    loop,
                    ControlLoopFailure.SIMULATION_FAILED,
                )

                return loop

            loop.status = (
                LoopStatus.SIMULATION_READY
            )

            loop.current_stage = (
                ControlLoopStage.AUTHORIZE
            )

            self._touch(loop)

            return loop

    # ========================================================================
    # AUTHORIZE
    # ========================================================================

    def attach_authorization(
        self,
        loop_id: str,
        authorization: LoopAuthorizationReference,
    ) -> SecurityControlLoop:

        with self._lock:

            loop = self._get_loop(
                loop_id
            )

            self._check_scope(
                loop.scope_id,
                authorization.scope_id,
            )

            if not loop.simulation_reference_id:
                self._fail(
                    loop,
                    ControlLoopFailure.SIMULATION_FAILED,
                )
                return loop

            self._authorizations[
                authorization.authorization_reference_id
            ] = authorization

            loop.authorization_reference_id = (
                authorization.authorization_reference_id
            )

            if authorization.status != (
                AuthorizationStatus.APPROVED
            ):

                self._fail(
                    loop,
                    ControlLoopFailure.AUTHORIZATION_FAILED,
                )

                return loop

            loop.status = (
                LoopStatus.AUTHORIZATION_READY
            )

            loop.current_stage = (
                ControlLoopStage.ACT
            )

            self._touch(loop)

            return loop

    # ========================================================================
    # ACT — REFERENCE RECORD ONLY
    # ========================================================================

    def record_action(
        self,
        loop_id: str,
        action: LoopActionReference,
    ) -> SecurityControlLoop:

        with self._lock:

            loop = self._get_loop(
                loop_id
            )

            self._check_scope(
                loop.scope_id,
                action.scope_id,
            )

            if not loop.authorization_reference_id:
                self._fail(
                    loop,
                    ControlLoopFailure.AUTHORIZATION_FAILED,
                )
                return loop

            if (
                action.authorization_reference
                != loop.authorization_reference_id
            ):
                self._fail(
                    loop,
                    ControlLoopFailure.AUTHORIZATION_FAILED,
                )
                return loop

            self._actions[
                action.action_reference_id
            ] = action

            loop.action_reference_id = (
                action.action_reference_id
            )

            if action.status in {
                ActionStatus.FAILED,
                ActionStatus.BLOCKED,
            }:

                self._fail(
                    loop,
                    ControlLoopFailure.AUTHORIZATION_FAILED,
                )

                return loop

            loop.status = (
                LoopStatus.ACTION_RECORDED
            )

            loop.current_stage = (
                ControlLoopStage.VERIFY
            )

            self._touch(loop)

            return loop

    # ========================================================================
    # VERIFY
    # ========================================================================

    def record_verification(
        self,
        loop_id: str,
        verification: LoopVerificationReference,
    ) -> SecurityControlLoop:

        with self._lock:

            loop = self._get_loop(
                loop_id
            )

            self._check_scope(
                loop.scope_id,
                verification.scope_id,
            )

            if not loop.action_reference_id:
                self._fail(
                    loop,
                    ControlLoopFailure.VERIFICATION_FAILED,
                )
                return loop

            self._verifications[
                verification.verification_reference_id
            ] = verification

            loop.verification_reference_id = (
                verification.verification_reference_id
            )

            if verification.status == (
                VerificationStatus.SUCCESS
            ):

                loop.status = (
                    LoopStatus.VERIFIED
                )

            elif verification.status == (
                VerificationStatus.PARTIAL
            ):

                loop.status = (
                    LoopStatus.REPLANNING
                )

            else:

                self._fail(
                    loop,
                    ControlLoopFailure.VERIFICATION_FAILED,
                )

                return loop

            loop.current_stage = (
                ControlLoopStage.DECIDE
            )

            self._touch(loop)

            return loop

    # ========================================================================
    # DECISION
    # ========================================================================

    def decide(
        self,
        loop_id: str,
        decision: LoopDecision,
    ) -> SecurityControlLoop:

        with self._lock:

            loop = self._get_loop(
                loop_id
            )

            if loop.status in {
                LoopStatus.FAILED,
                LoopStatus.STOPPED,
            }:
                return loop

            if decision == LoopDecision.CONTINUE:

                if loop.status != (
                    LoopStatus.VERIFIED
                ):
                    raise ValueError(
                        "CONTINUE requires successful "
                        "verification"
                    )

                loop.decision = decision
                loop.status = (
                    LoopStatus.COMPLETED
                )

            elif decision == LoopDecision.REPLAN:

                if loop.status not in {
                    LoopStatus.VERIFIED,
                    LoopStatus.REPLANNING,
                }:
                    raise ValueError(
                        "REPLAN requires verification "
                        "or replanning state"
                    )

                if loop.iteration + 1 >= (
                    self.maximum_iterations
                ):

                    loop.decision = (
                        LoopDecision.STOP
                    )

                    loop.status = (
                        LoopStatus.STOPPED
                    )

                else:

                    loop.iteration += 1
                    loop.decision = decision
                    loop.status = (
                        LoopStatus.REPLANNING
                    )

                    loop.current_stage = (
                        ControlLoopStage.PLAN
                    )

            elif decision == LoopDecision.STOP:

                loop.decision = decision
                loop.status = (
                    LoopStatus.STOPPED
                )

            else:

                raise ValueError(
                    "unsupported control-loop decision"
                )

            self._touch(loop)

            return loop

    # ========================================================================
    # AUTOMATIC DECISION
    # ========================================================================

    def evaluate_decision(
        self,
        loop_id: str,
    ) -> LoopDecision:

        with self._lock:

            loop = self._get_loop(
                loop_id
            )

            if loop.status == (
                LoopStatus.VERIFIED
            ):
                return LoopDecision.CONTINUE

            if loop.status == (
                LoopStatus.REPLANNING
            ):
                return LoopDecision.REPLAN

            return LoopDecision.STOP

    # ========================================================================
    # FAILURE
    # ========================================================================

    def _fail(
        self,
        loop: SecurityControlLoop,
        failure: ControlLoopFailure,
    ) -> None:

        loop.failure = failure
        loop.status = LoopStatus.FAILED
        loop.decision = LoopDecision.STOP
        loop.current_stage = (
            ControlLoopStage.DECIDE
        )

        self._touch(loop)

    # ========================================================================
    # LOOP LOOKUP
    # ========================================================================

    def get_loop(
        self,
        loop_id: str,
    ) -> SecurityControlLoop:

        with self._lock:
            return self._get_loop(
                loop_id
            )

    def _get_loop(
        self,
        loop_id: str,
    ) -> SecurityControlLoop:

        loop = self._loops.get(
            loop_id
        )

        if loop is None:
            raise KeyError(
                "control loop not found"
            )

        return loop

    # ========================================================================
    # HASH
    # ========================================================================

    @staticmethod
    def _calculate_loop_hash(
        loop: SecurityControlLoop,
    ) -> str:

        return stable_hash(
            loop.loop_id,
            loop.scope_id,
            loop.status.value,
            loop.current_stage.value,
            tuple(loop.observation_ids),
            loop.state_reference_id,
            loop.plan_reference_id,
            loop.simulation_reference_id,
            loop.authorization_reference_id,
            loop.action_reference_id,
            loop.verification_reference_id,
            loop.decision.value
            if loop.decision
            else None,
            loop.failure.value,
            loop.iteration,
        )

    def _touch(
        self,
        loop: SecurityControlLoop,
    ) -> None:

        loop.updated_at = utc_now()
        loop.loop_hash = (
            self._calculate_loop_hash(
                loop
            )
        )

    # ========================================================================
    # SCOPE
    # ========================================================================

    @staticmethod
    def _check_scope(
        expected_scope: str,
        actual_scope: str,
    ) -> None:

        if expected_scope != actual_scope:
            raise ValueError(
                "scope mismatch"
            )

    # ========================================================================
    # VALIDATION
    # ========================================================================

    def validate(self) -> List[str]:

        errors: List[str] = []

        with self._lock:

            for loop_id, loop in (
                self._loops.items()
            ):

                if loop_id != loop.loop_id:
                    errors.append(
                        "loop key mismatch"
                    )

                if loop.iteration > (
                    self.maximum_iterations
                ):
                    errors.append(
                        f"loop exceeds maximum "
                        f"iterations: {loop_id}"
                    )

                if loop.state_reference_id:

                    if (
                        loop.state_reference_id
                        not in self._states
                    ):
                        errors.append(
                            f"missing state reference: "
                            f"{loop_id}"
                        )

                if loop.plan_reference_id:

                    if (
                        loop.plan_reference_id
                        not in self._plans
                    ):
                        errors.append(
                            f"missing plan reference: "
                            f"{loop_id}"
                        )

                if loop.simulation_reference_id:

                    if (
                        loop.simulation_reference_id
                        not in self._simulations
                    ):
                        errors.append(
                            f"missing simulation reference: "
                            f"{loop_id}"
                        )

                if loop.authorization_reference_id:

                    if (
                        loop.authorization_reference_id
                        not in self._authorizations
                    ):
                        errors.append(
                            f"missing authorization "
                            f"reference: {loop_id}"
                        )

                if loop.action_reference_id:

                    if (
                        loop.action_reference_id
                        not in self._actions
                    ):
                        errors.append(
                            f"missing action reference: "
                            f"{loop_id}"
                        )

                if loop.verification_reference_id:

                    if (
                        loop.verification_reference_id
                        not in self._verifications
                    ):
                        errors.append(
                            f"missing verification "
                            f"reference: {loop_id}"
                        )

                expected_hash = (
                    self._calculate_loop_hash(
                        loop
                    )
                )

                if loop.loop_hash != expected_hash:
                    errors.append(
                        f"loop hash mismatch: {loop_id}"
                    )

            for observation_id, observation in (
                self._observations.items()
            ):

                if (
                    observation_id
                    != observation.observation_id
                ):
                    errors.append(
                        "observation key mismatch"
                    )

            for component_id, component in (
                self._components.items()
            ):

                if (
                    component_id
                    != component.reference_id
                ):
                    errors.append(
                        "component key mismatch"
                    )

        return errors


# ============================================================================
# TESTS
# ============================================================================

class Phase22Tests(unittest.TestCase):

    def setUp(self):

        self.scope = "tenant-a"

        self.engine = (
            AutonomousSecurityControlLoop(
                maximum_iterations=4
            )
        )

        self.engine.register_component(
            ComponentReference(
                reference_id="state-engine",
                component_type=(
                    "SecurityStateEngine"
                ),
                component_id="phase4",
            )
        )

        self.engine.register_component(
            ComponentReference(
                reference_id="optimizer",
                component_type=(
                    "InterventionOptimizer"
                ),
                component_id="phase10",
            )
        )

        self.engine.register_component(
            ComponentReference(
                reference_id="verification",
                component_type=(
                    "IndependentVerificationEngine"
                ),
                component_id="phase14",
            )
        )

    # ========================================================================
    # Full successful loop
    # ========================================================================

    def test_full_control_loop(self):

        loop = self.engine.create_loop(
            self.scope
        )

        self.engine.record_observation(
            loop.loop_id,
            LoopObservation(
                observation_id="obs-1",
                scope_id=self.scope,
                source_reference="telemetry",
                observation_type="SECURITY_EVENT",
                summary="security condition observed",
                evidence_references=frozenset(
                    {"evidence-1"}
                ),
                observed_at=utc_now(),
            ),
        )

        self.engine.attach_state(
            loop.loop_id,
            LoopStateReference(
                state_reference_id="state-1",
                scope_id=self.scope,
                state_component_reference=(
                    "state-engine"
                ),
                state_snapshot_reference="snapshot-1",
                integrity_verified=True,
                confidence=0.95,
                created_at=utc_now(),
            ),
        )

        self.engine.attach_plan(
            loop.loop_id,
            LoopPlanReference(
                plan_reference_id="plan-1",
                scope_id=self.scope,
                intervention_reference=(
                    "intervention-1"
                ),
                intent_reference=None,
                invariant_references=frozenset(),
                expected_outcome=(
                    "security risk reduced"
                ),
                created_at=utc_now(),
            ),
        )

        self.engine.attach_simulation(
            loop.loop_id,
            LoopSimulationReference(
                simulation_reference_id="sim-1",
                scope_id=self.scope,
                experiment_reference=(
                    "experiment-1"
                ),
                status=SimulationStatus.PASS,
                confidence=0.90,
                summary="simulation passed",
                created_at=utc_now(),
            ),
        )

        self.engine.attach_authorization(
            loop.loop_id,
            LoopAuthorizationReference(
                authorization_reference_id=(
                    "auth-1"
                ),
                scope_id=self.scope,
                authority_reference=(
                    "authority-graph"
                ),
                status=AuthorizationStatus.APPROVED,
                approved_action_reference=(
                    "action-1"
                ),
                created_at=utc_now(),
            ),
        )

        self.engine.record_action(
            loop.loop_id,
            LoopActionReference(
                action_reference_id="action-record-1",
                scope_id=self.scope,
                authorization_reference="auth-1",
                action_reference="action-1",
                status=ActionStatus.EXECUTED,
                recorded_at=utc_now(),
            ),
        )

        self.engine.record_verification(
            loop.loop_id,
            LoopVerificationReference(
                verification_reference_id=(
                    "verification-1"
                ),
                scope_id=self.scope,
                verification_component_reference=(
                    "verification"
                ),
                status=VerificationStatus.SUCCESS,
                confidence=0.94,
                expected_outcome=(
                    "security risk reduced"
                ),
                observed_outcome=(
                    "security risk reduced"
                ),
                independent_evidence_references=frozenset(
                    {"evidence-2"}
                ),
                verified_at=utc_now(),
            ),
        )

        decision = (
            self.engine.evaluate_decision(
                loop.loop_id
            )
        )

        self.assertEqual(
            decision,
            LoopDecision.CONTINUE,
        )

        self.engine.decide(
            loop.loop_id,
            decision,
        )

        final_loop = (
            self.engine.get_loop(
                loop.loop_id
            )
        )

        self.assertEqual(
            final_loop.status,
            LoopStatus.COMPLETED,
        )

        self.assertEqual(
            final_loop.failure,
            ControlLoopFailure.NONE,
        )

    # ========================================================================
    # Simulation failure
    # ========================================================================

    def test_simulation_failure_stops_loop(self):

        loop = self.engine.create_loop(
            self.scope
        )

        self.engine.record_observation(
            loop.loop_id,
            LoopObservation(
                observation_id="obs-fail",
                scope_id=self.scope,
                source_reference="telemetry",
                observation_type="SECURITY_EVENT",
                summary="event",
                evidence_references=frozenset(),
                observed_at=utc_now(),
            ),
        )

        self.engine.attach_state(
            loop.loop_id,
            LoopStateReference(
                state_reference_id="state-fail",
                scope_id=self.scope,
                state_component_reference="state-engine",
                state_snapshot_reference="snapshot-fail",
                integrity_verified=True,
                confidence=0.90,
                created_at=utc_now(),
            ),
        )

        self.engine.attach_plan(
            loop.loop_id,
            LoopPlanReference(
                plan_reference_id="plan-fail",
                scope_id=self.scope,
                intervention_reference="intervention-fail",
                intent_reference=None,
                invariant_references=frozenset(),
                expected_outcome="safe",
                created_at=utc_now(),
            ),
        )

        self.engine.attach_simulation(
            loop.loop_id,
            LoopSimulationReference(
                simulation_reference_id="sim-fail",
                scope_id=self.scope,
                experiment_reference="experiment-fail",
                status=SimulationStatus.FAIL,
                confidence=0.95,
                summary="simulation failed",
                created_at=utc_now(),
            ),
        )

        result = self.engine.get_loop(
            loop.loop_id
        )

        self.assertEqual(
            result.status,
            LoopStatus.FAILED,
        )

        self.assertEqual(
            result.failure,
            ControlLoopFailure.SIMULATION_FAILED,
        )

    # ========================================================================
    # Authorization failure
    # ========================================================================

    def test_denied_authorization_stops_loop(self):

        loop = self.engine.create_loop(
            self.scope
        )

        self.engine.record_observation(
            loop.loop_id,
            LoopObservation(
                observation_id="obs-auth",
                scope_id=self.scope,
                source_reference="telemetry",
                observation_type="EVENT",
                summary="security event",
                evidence_references=frozenset(),
                observed_at=utc_now(),
            ),
        )

        self.engine.attach_state(
            loop.loop_id,
            LoopStateReference(
                state_reference_id="state-auth",
                scope_id=self.scope,
                state_component_reference="state-engine",
                state_snapshot_reference="snapshot-auth",
                integrity_verified=True,
                confidence=0.90,
                created_at=utc_now(),
            ),
        )

        self.engine.attach_plan(
            loop.loop_id,
            LoopPlanReference(
                plan_reference_id="plan-auth",
                scope_id=self.scope,
                intervention_reference="intervention-auth",
                intent_reference=None,
                invariant_references=frozenset(),
                expected_outcome="safe",
                created_at=utc_now(),
            ),
        )

        self.engine.attach_simulation(
            loop.loop_id,
            LoopSimulationReference(
                simulation_reference_id="sim-auth",
                scope_id=self.scope,
                experiment_reference="experiment-auth",
                status=SimulationStatus.PASS,
                confidence=0.90,
                summary="safe",
                created_at=utc_now(),
            ),
        )

        self.engine.attach_authorization(
            loop.loop_id,
            LoopAuthorizationReference(
                authorization_reference_id="auth-denied",
                scope_id=self.scope,
                authority_reference="authority-graph",
                status=AuthorizationStatus.DENIED,
                approved_action_reference=None,
                created_at=utc_now(),
            ),
        )

        result = self.engine.get_loop(
            loop.loop_id
        )

        self.assertEqual(
            result.status,
            LoopStatus.FAILED,
        )

        self.assertEqual(
            result.failure,
            ControlLoopFailure.AUTHORIZATION_FAILED,
        )

    # ========================================================================
    # Verification failure
    # ========================================================================

    def test_verification_failure_stops_loop(self):

        loop = self.engine.create_loop(
            self.scope
        )

        self.engine.record_observation(
            loop.loop_id,
            LoopObservation(
                observation_id="obs-ver",
                scope_id=self.scope,
                source_reference="telemetry",
                observation_type="EVENT",
                summary="event",
                evidence_references=frozenset(),
                observed_at=utc_now(),
            ),
        )

        self.engine.attach_state(
            loop.loop_id,
            LoopStateReference(
                state_reference_id="state-ver",
                scope_id=self.scope,
                state_component_reference="state-engine",
                state_snapshot_reference="snapshot-ver",
                integrity_verified=True,
                confidence=0.95,
                created_at=utc_now(),
            ),
        )

        self.engine.attach_plan(
            loop.loop_id,
            LoopPlanReference(
                plan_reference_id="plan-ver",
                scope_id=self.scope,
                intervention_reference="intervention-ver",
                intent_reference=None,
                invariant_references=frozenset(),
                expected_outcome="safe",
                created_at=utc_now(),
            ),
        )

        self.engine.attach_simulation(
            loop.loop_id,
            LoopSimulationReference(
                simulation_reference_id="sim-ver",
                scope_id=self.scope,
                experiment_reference="experiment-ver",
                status=SimulationStatus.PASS,
                confidence=0.90,
                summary="safe",
                created_at=utc_now(),
            ),
        )

        self.engine.attach_authorization(
            loop.loop_id,
            LoopAuthorizationReference(
                authorization_reference_id="auth-ver",
                scope_id=self.scope,
                authority_reference="authority-graph",
                status=AuthorizationStatus.APPROVED,
                approved_action_reference="action-ver",
                created_at=utc_now(),
            ),
        )

        self.engine.record_action(
            loop.loop_id,
            LoopActionReference(
                action_reference_id="action-record-ver",
                scope_id=self.scope,
                authorization_reference="auth-ver",
                action_reference="action-ver",
                status=ActionStatus.EXECUTED,
                recorded_at=utc_now(),
            ),
        )

        self.engine.record_verification(
            loop.loop_id,
            LoopVerificationReference(
                verification_reference_id="verification-fail",
                scope_id=self.scope,
                verification_component_reference="verification",
                status=VerificationStatus.FAILED,
                confidence=0.90,
                expected_outcome="safe",
                observed_outcome="unsafe",
                independent_evidence_references=frozenset(),
                verified_at=utc_now(),
            ),
        )

        result = self.engine.get_loop(
            loop.loop_id
        )

        self.assertEqual(
            result.status,
            LoopStatus.FAILED,
        )

        self.assertEqual(
            result.failure,
            ControlLoopFailure.VERIFICATION_FAILED,
        )

    # ========================================================================
    # Replanning
    # ========================================================================

    def test_replanning(self):

        loop = self.engine.create_loop(
            self.scope
        )

        self.engine.record_observation(
            loop.loop_id,
            LoopObservation(
                observation_id="obs-partial",
                scope_id=self.scope,
                source_reference="telemetry",
                observation_type="EVENT",
                summary="event",
                evidence_references=frozenset(),
                observed_at=utc_now(),
            ),
        )

        self.engine.attach_state(
            loop.loop_id,
            LoopStateReference(
                state_reference_id="state-partial",
                scope_id=self.scope,
                state_component_reference="state-engine",
                state_snapshot_reference="snapshot-partial",
                integrity_verified=True,
                confidence=0.90,
                created_at=utc_now(),
            ),
        )

        self.engine.attach_plan(
            loop.loop_id,
            LoopPlanReference(
                plan_reference_id="plan-partial",
                scope_id=self.scope,
                intervention_reference="intervention-partial",
                intent_reference=None,
                invariant_references=frozenset(),
                expected_outcome="improved",
                created_at=utc_now(),
            ),
        )

        self.engine.attach_simulation(
            loop.loop_id,
            LoopSimulationReference(
                simulation_reference_id="sim-partial",
                scope_id=self.scope,
                experiment_reference="experiment-partial",
                status=SimulationStatus.PASS,
                confidence=0.80,
                summary="acceptable",
                created_at=utc_now(),
            ),
        )

        self.engine.attach_authorization(
            loop.loop_id,
            LoopAuthorizationReference(
                authorization_reference_id="auth-partial",
                scope_id=self.scope,
                authority_reference="authority-graph",
                status=AuthorizationStatus.APPROVED,
                approved_action_reference="action-partial",
                created_at=utc_now(),
            ),
        )

        self.engine.record_action(
            loop.loop_id,
            LoopActionReference(
                action_reference_id="action-record-partial",
                scope_id=self.scope,
                authorization_reference="auth-partial",
                action_reference="action-partial",
                status=ActionStatus.EXECUTED,
                recorded_at=utc_now(),
            ),
        )

        self.engine.record_verification(
            loop.loop_id,
            LoopVerificationReference(
                verification_reference_id="verification-partial",
                scope_id=self.scope,
                verification_component_reference="verification",
                status=VerificationStatus.PARTIAL,
                confidence=0.60,
                expected_outcome="improved",
                observed_outcome="partially improved",
                independent_evidence_references=frozenset(),
                verified_at=utc_now(),
            ),
        )

        decision = (
            self.engine.evaluate_decision(
                loop.loop_id
            )
        )

        self.assertEqual(
            decision,
            LoopDecision.REPLAN,
        )

        self.engine.decide(
            loop.loop_id,
            decision,
        )

        result = self.engine.get_loop(
            loop.loop_id
        )

        self.assertEqual(
            result.status,
            LoopStatus.REPLANNING,
        )

        self.assertEqual(
            result.iteration,
            1,
        )

    # ========================================================================
    # Scope isolation
    # ========================================================================

    def test_scope_mismatch_rejected(self):

        loop = self.engine.create_loop(
            self.scope
        )

        with self.assertRaises(
            ValueError
        ):
            self.engine.record_observation(
                loop.loop_id,
                LoopObservation(
                    observation_id="cross-tenant",
                    scope_id="tenant-b",
                    source_reference="telemetry",
                    observation_type="EVENT",
                    summary="invalid scope",
                    evidence_references=frozenset(),
                    observed_at=utc_now(),
                ),
            )

    # ========================================================================
    # Validation
    # ========================================================================

    def test_validation(self):

        self.assertEqual(
            self.engine.validate(),
            [],
        )


# ============================================================================
# TEST RUNNER
# ============================================================================

def run_phase22_tests() -> None:

    suite = (
        unittest.defaultTestLoader
        .loadTestsFromTestCase(
            Phase22Tests
        )
    )

    result = unittest.TextTestRunner(
        verbosity=2
    ).run(suite)

    if not result.wasSuccessful():
        raise AssertionError(
            "Phase 22 tests failed"
        )


if __name__ == "__main__":
    run_phase22_tests()
