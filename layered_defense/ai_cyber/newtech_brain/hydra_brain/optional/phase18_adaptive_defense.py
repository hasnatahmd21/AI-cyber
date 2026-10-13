"""
HYDRA™ — Phase 18
Adaptive Defense Engine

STRICT PHASE SCOPE
------------------
- Lessons -> candidate controls
- Control generation from verified outcomes
- Simulation requirement
- Validation gates
- Approval gate
- Controlled deployment reference
- Post-deployment verification
- Control lifecycle
- Adaptation history
- Failure containment
- Integrity tracking
- Validation
- Tests

NOT IMPLEMENTED
---------------
Phase 19 -> AI/Agent Self-Protection
Phase 20 -> Multi-Layer Defense Fabric
Phase 21 -> Resource & Availability Resilience
Phase 22 -> Full Autonomous Security Control Loop
Phase 23 -> Adversarial Validation
Phase 24 -> Scientific Benchmarking
Phase 25+ -> Enterprise/Production Validation

IMPORTANT
---------
This engine produces and governs adaptive defensive controls.

It does NOT:
- directly execute arbitrary commands
- attack systems
- deploy malware
- bypass authorization
- directly modify production infrastructure
- claim a control succeeded without verification
- implement AI self-protection
- implement the full autonomous loop
"""

from __future__ import annotations

from dataclasses import dataclass
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

class LessonType(str, Enum):
    INCIDENT = "INCIDENT"
    VERIFICATION_FAILURE = "VERIFICATION_FAILURE"
    REGENERATION = "REGENERATION"
    EXPERIMENT = "EXPERIMENT"
    OUTCOME = "OUTCOME"
    OBSERVATION = "OBSERVATION"


class ControlType(str, Enum):
    BLOCK = "BLOCK"
    ISOLATE = "ISOLATE"
    RESTRICT = "RESTRICT"
    REVOKE = "REVOKE"
    SEGMENT = "SEGMENT"
    RATE_LIMIT = "RATE_LIMIT"
    MONITOR = "MONITOR"
    ALERT = "ALERT"
    HARDEN = "HARDEN"


class ControlStatus(str, Enum):
    CANDIDATE = "CANDIDATE"
    SIMULATION_REQUIRED = "SIMULATION_REQUIRED"
    SIMULATION_PASSED = "SIMULATION_PASSED"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    APPROVED = "APPROVED"
    DEPLOYMENT_READY = "DEPLOYMENT_READY"
    DEPLOYED = "DEPLOYED"
    VERIFICATION_REQUIRED = "VERIFICATION_REQUIRED"
    VERIFIED = "VERIFIED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"
    DISABLED = "DISABLED"


class SimulationStatus(str, Enum):
    NOT_RUN = "NOT_RUN"
    PASSED = "PASSED"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"


class ValidationStatus(str, Enum):
    NOT_VALIDATED = "NOT_VALIDATED"
    PASSED = "PASSED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"


class ApprovalStatus(str, Enum):
    NOT_REQUESTED = "NOT_REQUESTED"
    REQUESTED = "REQUESTED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class DeploymentStatus(str, Enum):
    NOT_READY = "NOT_READY"
    READY = "READY"
    REQUESTED = "REQUESTED"
    DEPLOYED = "DEPLOYED"
    FAILED = "FAILED"


class VerificationStatus(str, Enum):
    NOT_VERIFIED = "NOT_VERIFIED"
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class AdaptationOutcome(str, Enum):
    EFFECTIVE = "EFFECTIVE"
    PARTIALLY_EFFECTIVE = "PARTIALLY_EFFECTIVE"
    INEFFECTIVE = "INEFFECTIVE"
    UNKNOWN = "UNKNOWN"


# ============================================================================
# LESSON
# ============================================================================

@dataclass(frozen=True)
class SecurityLesson:
    lesson_id: str
    scope_id: str

    lesson_type: LessonType
    source_reference: str

    observed_problem: str
    desired_outcome: str

    evidence_references: FrozenSet[str]

    confidence: float
    created_at: datetime

    def __post_init__(self) -> None:
        ensure_aware(self.created_at)

        if not self.lesson_id.strip():
            raise ValueError("lesson_id must not be empty")

        if not self.scope_id.strip():
            raise ValueError("scope_id must not be empty")

        if not self.source_reference.strip():
            raise ValueError(
                "source_reference must not be empty"
            )

        if not self.observed_problem.strip():
            raise ValueError(
                "observed_problem must not be empty"
            )

        if not self.desired_outcome.strip():
            raise ValueError(
                "desired_outcome must not be empty"
            )

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "confidence must be between 0 and 1"
            )


# ============================================================================
# DEFENSIVE CONTROL CANDIDATE
# ============================================================================

@dataclass(frozen=True)
class DefensiveControl:
    control_id: str
    scope_id: str

    control_type: ControlType

    target_reference: str
    objective: str

    parameters: Tuple[Tuple[str, str], ...]

    source_lesson_ids: FrozenSet[str]

    expected_risk_reduction: float
    expected_collateral_impact: float
    reversibility: float

    status: ControlStatus

    created_at: datetime

    control_hash: str

    def __post_init__(self) -> None:
        ensure_aware(self.created_at)

        if not self.control_id.strip():
            raise ValueError("control_id must not be empty")

        if not self.scope_id.strip():
            raise ValueError("scope_id must not be empty")

        if not self.target_reference.strip():
            raise ValueError(
                "target_reference must not be empty"
            )

        if not self.objective.strip():
            raise ValueError("objective must not be empty")

        for value in (
            self.expected_risk_reduction,
            self.expected_collateral_impact,
            self.reversibility,
        ):
            if not 0.0 <= value <= 1.0:
                raise ValueError(
                    "control metrics must be between 0 and 1"
                )

        if not self.control_hash.strip():
            raise ValueError(
                "control_hash must not be empty"
            )


# ============================================================================
# SIMULATION RECORD
# ============================================================================

@dataclass(frozen=True)
class ControlSimulation:
    simulation_id: str
    scope_id: str
    control_id: str

    scenario_reference: str

    status: SimulationStatus

    predicted_risk_reduction: float
    predicted_collateral_impact: float

    observations: Tuple[str, ...]

    simulated_at: datetime

    simulation_hash: str

    def __post_init__(self) -> None:
        ensure_aware(self.simulated_at)

        if not self.simulation_id.strip():
            raise ValueError(
                "simulation_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id must not be empty"
            )

        if not self.control_id.strip():
            raise ValueError(
                "control_id must not be empty"
            )

        if not self.scenario_reference.strip():
            raise ValueError(
                "scenario_reference must not be empty"
            )

        if not 0.0 <= self.predicted_risk_reduction <= 1.0:
            raise ValueError(
                "predicted risk reduction must be between 0 and 1"
            )

        if not 0.0 <= self.predicted_collateral_impact <= 1.0:
            raise ValueError(
                "predicted collateral impact must be between 0 and 1"
            )

        if not self.simulation_hash.strip():
            raise ValueError(
                "simulation_hash must not be empty"
            )


# ============================================================================
# VALIDATION RECORD
# ============================================================================

@dataclass(frozen=True)
class ControlValidation:
    validation_id: str
    scope_id: str
    control_id: str

    simulation_id: str

    status: ValidationStatus

    required_risk_reduction: float
    observed_risk_reduction: float

    maximum_collateral_impact: float
    observed_collateral_impact: float

    validated_at: datetime

    validation_hash: str

    reason: str = ""

    def __post_init__(self) -> None:
        ensure_aware(self.validated_at)

        if not self.validation_id.strip():
            raise ValueError(
                "validation_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id must not be empty"
            )

        if not self.control_id.strip():
            raise ValueError(
                "control_id must not be empty"
            )

        if not self.simulation_id.strip():
            raise ValueError(
                "simulation_id must not be empty"
            )

        if not self.validation_hash.strip():
            raise ValueError(
                "validation_hash must not be empty"
            )


# ============================================================================
# APPROVAL
# ============================================================================

@dataclass(frozen=True)
class ControlApproval:
    approval_id: str
    scope_id: str
    control_id: str

    status: ApprovalStatus

    approver_reference: str

    requested_at: datetime
    decided_at: Optional[datetime]

    reason: str

    def __post_init__(self) -> None:
        ensure_aware(self.requested_at)

        if self.decided_at is not None:
            ensure_aware(self.decided_at)

        if not self.approval_id.strip():
            raise ValueError(
                "approval_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id must not be empty"
            )

        if not self.control_id.strip():
            raise ValueError(
                "control_id must not be empty"
            )

        if not self.approver_reference.strip():
            raise ValueError(
                "approver_reference must not be empty"
            )

        if not self.reason.strip():
            raise ValueError(
                "approval reason must not be empty"
            )


# ============================================================================
# DEPLOYMENT RECORD
# ============================================================================

@dataclass(frozen=True)
class ControlDeployment:
    deployment_id: str
    scope_id: str
    control_id: str

    approval_id: str

    status: DeploymentStatus

    deployment_reference: str

    requested_at: datetime
    deployed_at: Optional[datetime]

    reason: str

    def __post_init__(self) -> None:
        ensure_aware(self.requested_at)

        if self.deployed_at is not None:
            ensure_aware(self.deployed_at)

        if not self.deployment_id.strip():
            raise ValueError(
                "deployment_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id must not be empty"
            )

        if not self.control_id.strip():
            raise ValueError(
                "control_id must not be empty"
            )

        if not self.approval_id.strip():
            raise ValueError(
                "approval_id must not be empty"
            )

        if not self.deployment_reference.strip():
            raise ValueError(
                "deployment_reference must not be empty"
            )


# ============================================================================
# POST-DEPLOYMENT VERIFICATION
# ============================================================================

@dataclass(frozen=True)
class ControlVerification:
    verification_id: str
    scope_id: str
    control_id: str

    deployment_id: str

    status: VerificationStatus

    expected_risk_reduction: float
    observed_risk_reduction: float

    expected_behavior_reference: str
    observed_behavior_reference: str

    evidence_references: FrozenSet[str]

    verified_at: datetime

    verification_hash: str

    reason: str = ""

    def __post_init__(self) -> None:
        ensure_aware(self.verified_at)

        if not self.verification_id.strip():
            raise ValueError(
                "verification_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id must not be empty"
            )

        if not self.control_id.strip():
            raise ValueError(
                "control_id must not be empty"
            )

        if not self.deployment_id.strip():
            raise ValueError(
                "deployment_id must not be empty"
            )

        if not self.expected_behavior_reference.strip():
            raise ValueError(
                "expected behavior reference required"
            )

        if not self.observed_behavior_reference.strip():
            raise ValueError(
                "observed behavior reference required"
            )

        if not self.verification_hash.strip():
            raise ValueError(
                "verification_hash must not be empty"
            )


# ============================================================================
# ADAPTATION RECORD
# ============================================================================

@dataclass
class AdaptationRecord:

    adaptation_id: str
    scope_id: str

    created_at: datetime

    lesson_ids: Tuple[str, ...] = ()
    control_ids: Tuple[str, ...] = ()
    simulation_ids: Tuple[str, ...] = ()
    validation_ids: Tuple[str, ...] = ()
    approval_ids: Tuple[str, ...] = ()
    deployment_ids: Tuple[str, ...] = ()
    verification_ids: Tuple[str, ...] = ()

    outcome: AdaptationOutcome = (
        AdaptationOutcome.UNKNOWN
    )

    failure_reason: Optional[str] = None

    adaptation_hash: Optional[str] = None

    def __post_init__(self) -> None:
        ensure_aware(self.created_at)

        if not self.adaptation_id.strip():
            raise ValueError(
                "adaptation_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id must not be empty"
            )


# ============================================================================
# ADAPTIVE DEFENSE ENGINE
# ============================================================================

class AdaptiveDefenseEngine:

    def __init__(
        self,
        *,
        minimum_lesson_confidence: float = 0.70,
        minimum_validation_confidence: float = 0.80,
    ) -> None:

        if not 0.0 <= minimum_lesson_confidence <= 1.0:
            raise ValueError(
                "invalid lesson confidence threshold"
            )

        if not 0.0 <= minimum_validation_confidence <= 1.0:
            raise ValueError(
                "invalid validation confidence threshold"
            )

        self.minimum_lesson_confidence = (
            minimum_lesson_confidence
        )

        self.minimum_validation_confidence = (
            minimum_validation_confidence
        )

        self._lessons: Dict[
            str,
            SecurityLesson,
        ] = {}

        self._controls: Dict[
            str,
            DefensiveControl,
        ] = {}

        self._simulations: Dict[
            str,
            ControlSimulation,
        ] = {}

        self._validations: Dict[
            str,
            ControlValidation,
        ] = {}

        self._approvals: Dict[
            str,
            ControlApproval,
        ] = {}

        self._deployments: Dict[
            str,
            ControlDeployment,
        ] = {}

        self._verifications: Dict[
            str,
            ControlVerification,
        ] = {}

        self._adaptations: Dict[
            str,
            AdaptationRecord,
        ] = {}

        self._lock = RLock()

    # ========================================================================
    # LESSONS
    # ========================================================================

    def add_lesson(
        self,
        lesson: SecurityLesson,
    ) -> None:

        with self._lock:

            if lesson.lesson_id in self._lessons:
                raise ValueError(
                    "duplicate lesson"
                )

            self._lessons[
                lesson.lesson_id
            ] = lesson

    def get_lesson(
        self,
        lesson_id: str,
    ) -> SecurityLesson:

        lesson = self._lessons.get(
            lesson_id
        )

        if lesson is None:
            raise KeyError(
                "lesson not found"
            )

        return lesson

    # ========================================================================
    # ADAPTATION CREATION
    # ========================================================================

    def create_adaptation(
        self,
        *,
        adaptation_id: str,
        scope_id: str,
        lesson_ids: Iterable[str],
    ) -> AdaptationRecord:

        lesson_ids = tuple(lesson_ids)

        if not lesson_ids:
            raise ValueError(
                "at least one lesson is required"
            )

        with self._lock:

            if adaptation_id in self._adaptations:
                raise ValueError(
                    "duplicate adaptation"
                )

            for lesson_id in lesson_ids:

                lesson = self._lessons.get(
                    lesson_id
                )

                if lesson is None:
                    raise KeyError(
                        f"lesson not found: {lesson_id}"
                    )

                if lesson.scope_id != scope_id:
                    raise ValueError(
                        "lesson scope mismatch"
                    )

                if (
                    lesson.confidence
                    < self.minimum_lesson_confidence
                ):
                    raise ValueError(
                        "lesson confidence below threshold"
                    )

            record = AdaptationRecord(
                adaptation_id=adaptation_id,
                scope_id=scope_id,
                created_at=utc_now(),
                lesson_ids=lesson_ids,
            )

            self._adaptations[
                adaptation_id
            ] = record

            self._refresh_adaptation_hash(
                record
            )

            return record

    # ========================================================================
    # CONTROL GENERATION
    # ========================================================================

    def generate_control(
        self,
        adaptation_id: str,
        *,
        control_type: ControlType,
        target_reference: str,
        objective: str,
        parameters: Iterable[Tuple[str, str]],
        expected_risk_reduction: float,
        expected_collateral_impact: float,
        reversibility: float,
    ) -> DefensiveControl:

        with self._lock:

            adaptation = self._adaptations.get(
                adaptation_id
            )

            if adaptation is None:
                raise KeyError(
                    "adaptation not found"
                )

            lesson_ids = frozenset(
                adaptation.lesson_ids
            )

            control_hash = stable_hash(
                "adaptive-control",
                adaptation_id,
                control_type.value,
                target_reference,
                objective,
                tuple(parameters),
                expected_risk_reduction,
                expected_collateral_impact,
                reversibility,
            )

            control = DefensiveControl(
                control_id=stable_hash(
                    "control",
                    adaptation_id,
                    control_hash,
                ),
                scope_id=adaptation.scope_id,
                control_type=control_type,
                target_reference=target_reference,
                objective=objective,
                parameters=tuple(parameters),
                source_lesson_ids=lesson_ids,
                expected_risk_reduction=(
                    expected_risk_reduction
                ),
                expected_collateral_impact=(
                    expected_collateral_impact
                ),
                reversibility=reversibility,
                status=ControlStatus.CANDIDATE,
                created_at=utc_now(),
                control_hash=control_hash,
            )

            self._controls[
                control.control_id
            ] = control

            adaptation.control_ids = (
                *adaptation.control_ids,
                control.control_id,
            )

            self._refresh_adaptation_hash(
                adaptation
            )

            return control

    # ========================================================================
    # SIMULATION
    # ========================================================================

    def record_simulation(
        self,
        adaptation_id: str,
        control_id: str,
        *,
        scenario_reference: str,
        status: SimulationStatus,
        predicted_risk_reduction: float,
        predicted_collateral_impact: float,
        observations: Iterable[str],
    ) -> ControlSimulation:

        with self._lock:

            adaptation = self._adaptations.get(
                adaptation_id
            )

            if adaptation is None:
                raise KeyError(
                    "adaptation not found"
                )

            control = self._controls.get(
                control_id
            )

            if control is None:
                raise KeyError(
                    "control not found"
                )

            if control.scope_id != adaptation.scope_id:
                raise ValueError(
                    "control scope mismatch"
                )

            simulation_hash = stable_hash(
                "control-simulation",
                adaptation_id,
                control_id,
                scenario_reference,
                status.value,
                predicted_risk_reduction,
                predicted_collateral_impact,
                tuple(observations),
            )

            simulation = ControlSimulation(
                simulation_id=stable_hash(
                    "simulation",
                    adaptation_id,
                    control_id,
                    simulation_hash,
                ),
                scope_id=adaptation.scope_id,
                control_id=control_id,
                scenario_reference=scenario_reference,
                status=status,
                predicted_risk_reduction=(
                    predicted_risk_reduction
                ),
                predicted_collateral_impact=(
                    predicted_collateral_impact
                ),
                observations=tuple(observations),
                simulated_at=utc_now(),
                simulation_hash=simulation_hash,
            )

            self._simulations[
                simulation.simulation_id
            ] = simulation

            adaptation.simulation_ids = (
                *adaptation.simulation_ids,
                simulation.simulation_id,
            )

            if status == SimulationStatus.PASSED:

                self._replace_control_status(
                    control_id,
                    ControlStatus.SIMULATION_PASSED,
                )

            elif status in (
                SimulationStatus.FAILED,
                SimulationStatus.INCONCLUSIVE,
            ):

                self._replace_control_status(
                    control_id,
                    ControlStatus.VALIDATION_FAILED,
                )

            self._refresh_adaptation_hash(
                adaptation
            )

            return simulation

    # ========================================================================
    # VALIDATION
    # ========================================================================

    def validate_control(
        self,
        adaptation_id: str,
        control_id: str,
        *,
        simulation_id: str,
        observed_risk_reduction: float,
        observed_collateral_impact: float,
        minimum_risk_reduction: float,
        maximum_collateral_impact: float,
        reason: str = "",
    ) -> ControlValidation:

        with self._lock:

            adaptation = self._adaptations.get(
                adaptation_id
            )

            if adaptation is None:
                raise KeyError(
                    "adaptation not found"
                )

            control = self._controls.get(
                control_id
            )

            if control is None:
                raise KeyError(
                    "control not found"
                )

            simulation = self._simulations.get(
                simulation_id
            )

            if simulation is None:
                raise KeyError(
                    "simulation not found"
                )

            if simulation.control_id != control_id:
                raise ValueError(
                    "simulation/control mismatch"
                )

            if (
                simulation.status
                != SimulationStatus.PASSED
            ):

                raise ValueError(
                    "control requires passed simulation"
                )

            risk_ok = (
                observed_risk_reduction
                >= minimum_risk_reduction
            )

            collateral_ok = (
                observed_collateral_impact
                <= maximum_collateral_impact
            )

            if risk_ok and collateral_ok:

                status = ValidationStatus.PASSED

            elif (
                observed_risk_reduction > 0
                and collateral_ok
            ):

                status = ValidationStatus.PARTIAL

            else:

                status = ValidationStatus.FAILED

            validation_hash = stable_hash(
                "control-validation",
                adaptation_id,
                control_id,
                simulation_id,
                observed_risk_reduction,
                observed_collateral_impact,
                minimum_risk_reduction,
                maximum_collateral_impact,
                status.value,
            )

            validation = ControlValidation(
                validation_id=stable_hash(
                    "validation",
                    adaptation_id,
                    control_id,
                    validation_hash,
                ),
                scope_id=adaptation.scope_id,
                control_id=control_id,
                simulation_id=simulation_id,
                status=status,
                required_risk_reduction=(
                    minimum_risk_reduction
                ),
                observed_risk_reduction=(
                    observed_risk_reduction
                ),
                maximum_collateral_impact=(
                    maximum_collateral_impact
                ),
                observed_collateral_impact=(
                    observed_collateral_impact
                ),
                validated_at=utc_now(),
                validation_hash=validation_hash,
                reason=reason,
            )

            self._validations[
                validation.validation_id
            ] = validation

            adaptation.validation_ids = (
                *adaptation.validation_ids,
                validation.validation_id,
            )

            if status == ValidationStatus.PASSED:

                self._replace_control_status(
                    control_id,
                    ControlStatus.APPROVAL_REQUIRED,
                )

            elif status == ValidationStatus.PARTIAL:

                self._replace_control_status(
                    control_id,
                    ControlStatus.PARTIAL,
                )

            else:

                self._replace_control_status(
                    control_id,
                    ControlStatus.VALIDATION_FAILED,
                )

            self._refresh_adaptation_hash(
                adaptation
            )

            return validation

    # ========================================================================
    # APPROVAL
    # ========================================================================

    def request_approval(
        self,
        adaptation_id: str,
        control_id: str,
        *,
        approver_reference: str,
        reason: str,
    ) -> ControlApproval:

        with self._lock:

            adaptation = self._adaptations.get(
                adaptation_id
            )

            if adaptation is None:
                raise KeyError(
                    "adaptation not found"
                )

            control = self._controls.get(
                control_id
            )

            if control is None:
                raise KeyError(
                    "control not found"
                )

            if control.status != (
                ControlStatus.APPROVAL_REQUIRED
            ):
                raise ValueError(
                    "control is not ready for approval"
                )

            approval = ControlApproval(
                approval_id=stable_hash(
                    "approval",
                    adaptation_id,
                    control_id,
                    approver_reference,
                    utc_now().isoformat(),
                ),
                scope_id=adaptation.scope_id,
                control_id=control_id,
                status=ApprovalStatus.REQUESTED,
                approver_reference=approver_reference,
                requested_at=utc_now(),
                decided_at=None,
                reason=reason,
            )

            self._approvals[
                approval.approval_id
            ] = approval

            adaptation.approval_ids = (
                *adaptation.approval_ids,
                approval.approval_id,
            )

            self._refresh_adaptation_hash(
                adaptation
            )

            return approval

    def decide_approval(
        self,
        adaptation_id: str,
        approval_id: str,
        *,
        approved: bool,
        reason: str,
    ) -> ControlApproval:

        with self._lock:

            adaptation = self._adaptations.get(
                adaptation_id
            )

            if adaptation is None:
                raise KeyError(
                    "adaptation not found"
                )

            approval = self._approvals.get(
                approval_id
            )

            if approval is None:
                raise KeyError(
                    "approval not found"
                )

            status = (
                ApprovalStatus.APPROVED
                if approved
                else ApprovalStatus.REJECTED
            )

            updated = ControlApproval(
                approval_id=approval.approval_id,
                scope_id=approval.scope_id,
                control_id=approval.control_id,
                status=status,
                approver_reference=(
                    approval.approver_reference
                ),
                requested_at=approval.requested_at,
                decided_at=utc_now(),
                reason=reason,
            )

            self._approvals[
                approval_id
            ] = updated

            if approved:

                self._replace_control_status(
                    approval.control_id,
                    ControlStatus.DEPLOYMENT_READY,
                )

            else:

                self._replace_control_status(
                    approval.control_id,
                    ControlStatus.DISABLED,
                )

            self._refresh_adaptation_hash(
                adaptation
            )

            return updated

    # ========================================================================
    # DEPLOYMENT REFERENCE
    # ========================================================================

    def request_deployment(
        self,
        adaptation_id: str,
        control_id: str,
        *,
        approval_id: str,
        deployment_reference: str,
    ) -> ControlDeployment:

        with self._lock:

            adaptation = self._adaptations.get(
                adaptation_id
            )

            if adaptation is None:
                raise KeyError(
                    "adaptation not found"
                )

            control = self._controls.get(
                control_id
            )

            if control is None:
                raise KeyError(
                    "control not found"
                )

            approval = self._approvals.get(
                approval_id
            )

            if approval is None:
                raise ValueError(
                    "deployment requires approval: approval not found"
                )

            if approval.status != (
                ApprovalStatus.APPROVED
            ):
                raise ValueError(
                    "deployment requires approved control"
                )

            if control.status != (
                ControlStatus.DEPLOYMENT_READY
            ):
                raise ValueError(
                    "control is not deployment ready"
                )

            deployment = ControlDeployment(
                deployment_id=stable_hash(
                    "deployment",
                    adaptation_id,
                    control_id,
                    approval_id,
                    deployment_reference,
                ),
                scope_id=adaptation.scope_id,
                control_id=control_id,
                approval_id=approval_id,
                status=DeploymentStatus.REQUESTED,
                deployment_reference=(
                    deployment_reference
                ),
                requested_at=utc_now(),
                deployed_at=None,
                reason="approved controlled deployment",
            )

            self._deployments[
                deployment.deployment_id
            ] = deployment

            adaptation.deployment_ids = (
                *adaptation.deployment_ids,
                deployment.deployment_id,
            )

            self._refresh_adaptation_hash(
                adaptation
            )

            return deployment

    def confirm_deployment(
        self,
        adaptation_id: str,
        deployment_id: str,
        *,
        successful: bool,
        reason: str,
    ) -> ControlDeployment:

        with self._lock:

            adaptation = self._adaptations.get(
                adaptation_id
            )

            if adaptation is None:
                raise KeyError(
                    "adaptation not found"
                )

            deployment = self._deployments.get(
                deployment_id
            )

            if deployment is None:
                raise KeyError(
                    "deployment not found"
                )

            if successful:

                updated = ControlDeployment(
                    deployment_id=deployment.deployment_id,
                    scope_id=deployment.scope_id,
                    control_id=deployment.control_id,
                    approval_id=deployment.approval_id,
                    status=DeploymentStatus.DEPLOYED,
                    deployment_reference=(
                        deployment.deployment_reference
                    ),
                    requested_at=deployment.requested_at,
                    deployed_at=utc_now(),
                    reason=reason,
                )

                self._deployments[
                    deployment_id
                ] = updated

                self._replace_control_status(
                    deployment.control_id,
                    ControlStatus.VERIFICATION_REQUIRED,
                )

            else:

                updated = ControlDeployment(
                    deployment_id=deployment.deployment_id,
                    scope_id=deployment.scope_id,
                    control_id=deployment.control_id,
                    approval_id=deployment.approval_id,
                    status=DeploymentStatus.FAILED,
                    deployment_reference=(
                        deployment.deployment_reference
                    ),
                    requested_at=deployment.requested_at,
                    deployed_at=None,
                    reason=reason,
                )

                self._deployments[
                    deployment_id
                ] = updated

                self._replace_control_status(
                    deployment.control_id,
                    ControlStatus.FAILED,
                )

            self._refresh_adaptation_hash(
                adaptation
            )

            return updated

    # ========================================================================
    # POST-DEPLOYMENT VERIFICATION
    # ========================================================================

    def verify_deployment(
        self,
        adaptation_id: str,
        control_id: str,
        *,
        deployment_id: str,
        expected_risk_reduction: float,
        observed_risk_reduction: float,
        expected_behavior_reference: str,
        observed_behavior_reference: str,
        evidence_references: Iterable[str],
        status: VerificationStatus,
        reason: str = "",
    ) -> ControlVerification:

        with self._lock:

            adaptation = self._adaptations.get(
                adaptation_id
            )

            if adaptation is None:
                raise KeyError(
                    "adaptation not found"
                )

            deployment = self._deployments.get(
                deployment_id
            )

            if deployment is None:
                raise KeyError(
                    "deployment not found"
                )

            if deployment.status != (
                DeploymentStatus.DEPLOYED
            ):
                raise ValueError(
                    "deployment is not confirmed deployed"
                )

            verification_hash = stable_hash(
                "post-deployment-verification",
                adaptation_id,
                control_id,
                deployment_id,
                expected_risk_reduction,
                observed_risk_reduction,
                expected_behavior_reference,
                observed_behavior_reference,
                tuple(sorted(evidence_references)),
                status.value,
            )

            verification = ControlVerification(
                verification_id=stable_hash(
                    "verification",
                    adaptation_id,
                    control_id,
                    deployment_id,
                    verification_hash,
                ),
                scope_id=adaptation.scope_id,
                control_id=control_id,
                deployment_id=deployment_id,
                status=status,
                expected_risk_reduction=(
                    expected_risk_reduction
                ),
                observed_risk_reduction=(
                    observed_risk_reduction
                ),
                expected_behavior_reference=(
                    expected_behavior_reference
                ),
                observed_behavior_reference=(
                    observed_behavior_reference
                ),
                evidence_references=frozenset(
                    evidence_references
                ),
                verified_at=utc_now(),
                verification_hash=verification_hash,
                reason=reason,
            )

            self._verifications[
                verification.verification_id
            ] = verification

            adaptation.verification_ids = (
                *adaptation.verification_ids,
                verification.verification_id,
            )

            if status == VerificationStatus.SUCCESS:

                self._replace_control_status(
                    control_id,
                    ControlStatus.VERIFIED,
                )

                adaptation.outcome = (
                    AdaptationOutcome.EFFECTIVE
                )

            elif status == VerificationStatus.PARTIAL:

                self._replace_control_status(
                    control_id,
                    ControlStatus.PARTIAL,
                )

                adaptation.outcome = (
                    AdaptationOutcome.PARTIALLY_EFFECTIVE
                )

            elif status == VerificationStatus.FAILED:

                self._replace_control_status(
                    control_id,
                    ControlStatus.FAILED,
                )

                adaptation.outcome = (
                    AdaptationOutcome.INEFFECTIVE
                )

                adaptation.failure_reason = (
                    reason or
                    "post-deployment verification failed"
                )

            else:

                adaptation.outcome = (
                    AdaptationOutcome.UNKNOWN
                )

            self._refresh_adaptation_hash(
                adaptation
            )

            return verification

    # ========================================================================
    # FAILURE CONTAINMENT / ROLLBACK RECORD
    # ========================================================================

    def record_rollback(
        self,
        adaptation_id: str,
        control_id: str,
        *,
        reason: str,
    ) -> None:

        with self._lock:

            adaptation = self._adaptations.get(
                adaptation_id
            )

            if adaptation is None:
                raise KeyError(
                    "adaptation not found"
                )

            if control_id not in adaptation.control_ids:
                raise ValueError(
                    "control not part of adaptation"
                )

            self._replace_control_status(
                control_id,
                ControlStatus.ROLLED_BACK,
            )

            adaptation.outcome = (
                AdaptationOutcome.INEFFECTIVE
            )

            adaptation.failure_reason = reason

            self._refresh_adaptation_hash(
                adaptation
            )

    # ========================================================================
    # INTERNAL CONTROL STATUS UPDATE
    # ========================================================================

    def _replace_control_status(
        self,
        control_id: str,
        status: ControlStatus,
    ) -> None:

        control = self._controls.get(
            control_id
        )

        if control is None:
            raise KeyError(
                "control not found"
            )

        updated = DefensiveControl(
            control_id=control.control_id,
            scope_id=control.scope_id,
            control_type=control.control_type,
            target_reference=control.target_reference,
            objective=control.objective,
            parameters=control.parameters,
            source_lesson_ids=(
                control.source_lesson_ids
            ),
            expected_risk_reduction=(
                control.expected_risk_reduction
            ),
            expected_collateral_impact=(
                control.expected_collateral_impact
            ),
            reversibility=control.reversibility,
            status=status,
            created_at=control.created_at,
            control_hash=control.control_hash,
        )

        self._controls[
            control_id
        ] = updated

    # ========================================================================
    # HASHING
    # ========================================================================

    @staticmethod
    def _adaptation_hash_material(
        record: AdaptationRecord,
    ) -> Tuple[object, ...]:

        return (
            record.adaptation_id,
            record.scope_id,
            record.created_at.isoformat(),
            record.lesson_ids,
            record.control_ids,
            record.simulation_ids,
            record.validation_ids,
            record.approval_ids,
            record.deployment_ids,
            record.verification_ids,
            record.outcome.value,
            record.failure_reason,
        )

    def _refresh_adaptation_hash(
        self,
        record: AdaptationRecord,
    ) -> None:

        record.adaptation_hash = stable_hash(
            *self._adaptation_hash_material(record)
        )

    @classmethod
    def validate_adaptation_hash(
        cls,
        record: AdaptationRecord,
    ) -> bool:

        if not record.adaptation_hash:
            return False

        return (
            record.adaptation_hash
            == stable_hash(
                *cls._adaptation_hash_material(record)
            )
        )

    # ========================================================================
    # VALIDATION
    # ========================================================================

    def validate(self) -> List[str]:

        errors: List[str] = []

        with self._lock:

            for lesson_id, lesson in self._lessons.items():

                if lesson_id != lesson.lesson_id:
                    errors.append(
                        f"lesson key mismatch: {lesson_id}"
                    )

            for control_id, control in self._controls.items():

                if control_id != control.control_id:
                    errors.append(
                        f"control key mismatch: {control_id}"
                    )

                for lesson_id in (
                    control.source_lesson_ids
                ):
                    if lesson_id not in self._lessons:
                        errors.append(
                            f"unknown source lesson: {lesson_id}"
                        )

            for simulation_id, simulation in (
                self._simulations.items()
            ):

                if simulation_id != simulation.simulation_id:
                    errors.append(
                        f"simulation key mismatch: "
                        f"{simulation_id}"
                    )

                if simulation.control_id not in self._controls:
                    errors.append(
                        f"simulation references "
                        f"unknown control: "
                        f"{simulation.control_id}"
                    )

            for validation_id, validation in (
                self._validations.items()
            ):

                if validation_id != validation.validation_id:
                    errors.append(
                        f"validation key mismatch: "
                        f"{validation_id}"
                    )

                if validation.control_id not in self._controls:
                    errors.append(
                        f"validation references "
                        f"unknown control: "
                        f"{validation.control_id}"
                    )

                if validation.simulation_id not in self._simulations:
                    errors.append(
                        f"validation references "
                        f"unknown simulation: "
                        f"{validation.simulation_id}"
                    )

            for approval_id, approval in (
                self._approvals.items()
            ):

                if approval_id != approval.approval_id:
                    errors.append(
                        f"approval key mismatch: "
                        f"{approval_id}"
                    )

                if approval.control_id not in self._controls:
                    errors.append(
                        f"approval references "
                        f"unknown control: "
                        f"{approval.control_id}"
                    )

            for deployment_id, deployment in (
                self._deployments.items()
            ):

                if deployment_id != deployment.deployment_id:
                    errors.append(
                        f"deployment key mismatch: "
                        f"{deployment_id}"
                    )

                if deployment.control_id not in self._controls:
                    errors.append(
                        f"deployment references "
                        f"unknown control: "
                        f"{deployment.control_id}"
                    )

                if deployment.approval_id not in self._approvals:
                    errors.append(
                        f"deployment references "
                        f"unknown approval: "
                        f"{deployment.approval_id}"
                    )

            for verification_id, verification in (
                self._verifications.items()
            ):

                if verification_id != verification.verification_id:
                    errors.append(
                        f"verification key mismatch: "
                        f"{verification_id}"
                    )

                if verification.control_id not in self._controls:
                    errors.append(
                        f"verification references "
                        f"unknown control: "
                        f"{verification.control_id}"
                    )

                if verification.deployment_id not in self._deployments:
                    errors.append(
                        f"verification references "
                        f"unknown deployment: "
                        f"{verification.deployment_id}"
                    )

            for adaptation_id, adaptation in (
                self._adaptations.items()
            ):

                if adaptation_id != adaptation.adaptation_id:
                    errors.append(
                        f"adaptation key mismatch: "
                        f"{adaptation_id}"
                    )

                if not self.validate_adaptation_hash(
                    adaptation
                ):
                    errors.append(
                        f"adaptation hash mismatch: "
                        f"{adaptation_id}"
                    )

                for lesson_id in adaptation.lesson_ids:
                    if lesson_id not in self._lessons:
                        errors.append(
                            f"adaptation references "
                            f"unknown lesson: {lesson_id}"
                        )

                for control_id in adaptation.control_ids:
                    if control_id not in self._controls:
                        errors.append(
                            f"adaptation references "
                            f"unknown control: {control_id}"
                        )

                for simulation_id in adaptation.simulation_ids:
                    if simulation_id not in self._simulations:
                        errors.append(
                            f"adaptation references "
                            f"unknown simulation: "
                            f"{simulation_id}"
                        )

                for validation_id in adaptation.validation_ids:
                    if validation_id not in self._validations:
                        errors.append(
                            f"adaptation references "
                            f"unknown validation: "
                            f"{validation_id}"
                        )

                for approval_id in adaptation.approval_ids:
                    if approval_id not in self._approvals:
                        errors.append(
                            f"adaptation references "
                            f"unknown approval: "
                            f"{approval_id}"
                        )

                for deployment_id in adaptation.deployment_ids:
                    if deployment_id not in self._deployments:
                        errors.append(
                            f"adaptation references "
                            f"unknown deployment: "
                            f"{deployment_id}"
                        )

                for verification_id in adaptation.verification_ids:
                    if verification_id not in self._verifications:
                        errors.append(
                            f"adaptation references "
                            f"unknown verification: "
                            f"{verification_id}"
                        )

        return errors


# ============================================================================
# TESTS
# ============================================================================

class Phase18Tests(unittest.TestCase):

    def setUp(self):

        self.engine = AdaptiveDefenseEngine()

        self.lesson = SecurityLesson(
            lesson_id="lesson-1",
            scope_id="scope-a",
            lesson_type=LessonType.INCIDENT,
            source_reference="incident-1",
            observed_problem="unauthorized access",
            desired_outcome="reduce unauthorized access",
            evidence_references=frozenset(
                {"evidence-1"}
            ),
            confidence=0.95,
            created_at=utc_now(),
        )

        self.engine.add_lesson(
            self.lesson
        )

        self.adaptation = (
            self.engine.create_adaptation(
                adaptation_id="adapt-1",
                scope_id="scope-a",
                lesson_ids=("lesson-1",),
            )
        )

        self.control = (
            self.engine.generate_control(
                "adapt-1",
                control_type=ControlType.RESTRICT,
                target_reference="service-1",
                objective="restrict suspicious access",
                parameters=(
                    ("mode", "restricted"),
                ),
                expected_risk_reduction=0.80,
                expected_collateral_impact=0.10,
                reversibility=0.90,
            )
        )

    # ========================================================================
    # Creation
    # ========================================================================

    def test_adaptation_creation(self):

        self.assertEqual(
            self.adaptation.adaptation_id,
            "adapt-1",
        )

        self.assertTrue(
            self.engine.validate_adaptation_hash(
                self.adaptation
            )
        )

    # ========================================================================
    # Control generation
    # ========================================================================

    def test_control_generation(self):

        self.assertEqual(
            self.control.status,
            ControlStatus.CANDIDATE,
        )

        self.assertEqual(
            self.control.control_type,
            ControlType.RESTRICT,
        )

    # ========================================================================
    # Simulation
    # ========================================================================

    def test_simulation_pass(self):

        simulation = (
            self.engine.record_simulation(
                "adapt-1",
                self.control.control_id,
                scenario_reference="scenario-1",
                status=SimulationStatus.PASSED,
                predicted_risk_reduction=0.82,
                predicted_collateral_impact=0.08,
                observations=("expected behavior",),
            )
        )

        self.assertEqual(
            simulation.status,
            SimulationStatus.PASSED,
        )

        self.assertEqual(
            self.engine._controls[
                self.control.control_id
            ].status,
            ControlStatus.SIMULATION_PASSED,
        )

    # ========================================================================
    # Failed simulation blocks validation
    # ========================================================================

    def test_failed_simulation(self):

        simulation = (
            self.engine.record_simulation(
                "adapt-1",
                self.control.control_id,
                scenario_reference="scenario-fail",
                status=SimulationStatus.FAILED,
                predicted_risk_reduction=0.20,
                predicted_collateral_impact=0.50,
                observations=("unsafe",),
            )
        )

        self.assertEqual(
            simulation.status,
            SimulationStatus.FAILED,
        )

        with self.assertRaises(ValueError):

            self.engine.validate_control(
                "adapt-1",
                self.control.control_id,
                simulation_id=simulation.simulation_id,
                observed_risk_reduction=0.20,
                observed_collateral_impact=0.50,
                minimum_risk_reduction=0.70,
                maximum_collateral_impact=0.20,
            )

    # ========================================================================
    # Validation
    # ========================================================================

    def test_validation_pass(self):

        simulation = (
            self.engine.record_simulation(
                "adapt-1",
                self.control.control_id,
                scenario_reference="scenario-valid",
                status=SimulationStatus.PASSED,
                predicted_risk_reduction=0.85,
                predicted_collateral_impact=0.05,
                observations=("safe",),
            )
        )

        validation = (
            self.engine.validate_control(
                "adapt-1",
                self.control.control_id,
                simulation_id=simulation.simulation_id,
                observed_risk_reduction=0.82,
                observed_collateral_impact=0.08,
                minimum_risk_reduction=0.70,
                maximum_collateral_impact=0.20,
            )
        )

        self.assertEqual(
            validation.status,
            ValidationStatus.PASSED,
        )

        self.assertEqual(
            self.engine._controls[
                self.control.control_id
            ].status,
            ControlStatus.APPROVAL_REQUIRED,
        )

    # ========================================================================
    # Approval gate
    # ========================================================================

    def test_approval_gate(self):

        simulation = (
            self.engine.record_simulation(
                "adapt-1",
                self.control.control_id,
                scenario_reference="scenario-approval",
                status=SimulationStatus.PASSED,
                predicted_risk_reduction=0.85,
                predicted_collateral_impact=0.05,
                observations=("safe",),
            )
        )

        self.engine.validate_control(
            "adapt-1",
            self.control.control_id,
            simulation_id=simulation.simulation_id,
            observed_risk_reduction=0.82,
            observed_collateral_impact=0.08,
            minimum_risk_reduction=0.70,
            maximum_collateral_impact=0.20,
        )

        approval = self.engine.request_approval(
            "adapt-1",
            self.control.control_id,
            approver_reference="security-authority",
            reason="validated defensive control",
        )

        self.assertEqual(
            approval.status,
            ApprovalStatus.REQUESTED,
        )

        decided = self.engine.decide_approval(
            "adapt-1",
            approval.approval_id,
            approved=True,
            reason="approved",
        )

        self.assertEqual(
            decided.status,
            ApprovalStatus.APPROVED,
        )

        self.assertEqual(
            self.engine._controls[
                self.control.control_id
            ].status,
            ControlStatus.DEPLOYMENT_READY,
        )

    # ========================================================================
    # Deployment cannot bypass approval
    # ========================================================================

    def test_deployment_requires_approval(self):

        with self.assertRaises(ValueError):

            self.engine.request_deployment(
                "adapt-1",
                self.control.control_id,
                approval_id="missing",
                deployment_reference="deployment-1",
            )

    # ========================================================================
    # Deployment + verification
    # ========================================================================

    def test_deployment_and_verification(self):

        simulation = (
            self.engine.record_simulation(
                "adapt-1",
                self.control.control_id,
                scenario_reference="scenario-full",
                status=SimulationStatus.PASSED,
                predicted_risk_reduction=0.85,
                predicted_collateral_impact=0.05,
                observations=("safe",),
            )
        )

        self.engine.validate_control(
            "adapt-1",
            self.control.control_id,
            simulation_id=simulation.simulation_id,
            observed_risk_reduction=0.82,
            observed_collateral_impact=0.08,
            minimum_risk_reduction=0.70,
            maximum_collateral_impact=0.20,
        )

        approval = self.engine.request_approval(
            "adapt-1",
            self.control.control_id,
            approver_reference="authority",
            reason="validated",
        )

        self.engine.decide_approval(
            "adapt-1",
            approval.approval_id,
            approved=True,
            reason="approved",
        )

        deployment = (
            self.engine.request_deployment(
                "adapt-1",
                self.control.control_id,
                approval_id=approval.approval_id,
                deployment_reference="deployment-ref",
            )
        )

        self.assertEqual(
            deployment.status,
            DeploymentStatus.REQUESTED,
        )

        deployed = self.engine.confirm_deployment(
            "adapt-1",
            deployment.deployment_id,
            successful=True,
            reason="deployment confirmed",
        )

        self.assertEqual(
            deployed.status,
            DeploymentStatus.DEPLOYED,
        )

        verification = (
            self.engine.verify_deployment(
                "adapt-1",
                self.control.control_id,
                deployment_id=deployment.deployment_id,
                expected_risk_reduction=0.80,
                observed_risk_reduction=0.85,
                expected_behavior_reference="expected-state",
                observed_behavior_reference="observed-state",
                evidence_references=("evidence-final",),
                status=VerificationStatus.SUCCESS,
                reason="control effective",
            )
        )

        self.assertEqual(
            verification.status,
            VerificationStatus.SUCCESS,
        )

        self.assertEqual(
            self.engine._controls[
                self.control.control_id
            ].status,
            ControlStatus.VERIFIED,
        )

        self.assertEqual(
            self.adaptation.outcome,
            AdaptationOutcome.EFFECTIVE,
        )

    # ========================================================================
    # Failed post-deployment verification
    # ========================================================================

    def test_failed_post_deployment_verification(self):

        simulation = (
            self.engine.record_simulation(
                "adapt-1",
                self.control.control_id,
                scenario_reference="scenario-failure",
                status=SimulationStatus.PASSED,
                predicted_risk_reduction=0.85,
                predicted_collateral_impact=0.05,
                observations=("safe",),
            )
        )

        self.engine.validate_control(
            "adapt-1",
            self.control.control_id,
            simulation_id=simulation.simulation_id,
            observed_risk_reduction=0.82,
            observed_collateral_impact=0.08,
            minimum_risk_reduction=0.70,
            maximum_collateral_impact=0.20,
        )

        approval = self.engine.request_approval(
            "adapt-1",
            self.control.control_id,
            approver_reference="authority",
            reason="validated",
        )

        self.engine.decide_approval(
            "adapt-1",
            approval.approval_id,
            approved=True,
            reason="approved",
        )

        deployment = (
            self.engine.request_deployment(
                "adapt-1",
                self.control.control_id,
                approval_id=approval.approval_id,
                deployment_reference="deployment-failure",
            )
        )

        self.engine.confirm_deployment(
            "adapt-1",
            deployment.deployment_id,
            successful=True,
            reason="deployed",
        )

        verification = (
            self.engine.verify_deployment(
                "adapt-1",
                self.control.control_id,
                deployment_id=deployment.deployment_id,
                expected_risk_reduction=0.80,
                observed_risk_reduction=0.10,
                expected_behavior_reference="expected",
                observed_behavior_reference="unexpected",
                evidence_references=("failure-evidence",),
                status=VerificationStatus.FAILED,
                reason="control ineffective",
            )
        )

        self.assertEqual(
            verification.status,
            VerificationStatus.FAILED,
        )

        self.assertEqual(
            self.adaptation.outcome,
            AdaptationOutcome.INEFFECTIVE,
        )

    # ========================================================================
    # Rollback
    # ========================================================================

    def test_rollback(self):

        self.engine.record_rollback(
            "adapt-1",
            self.control.control_id,
            reason="collateral impact detected",
        )

        self.assertEqual(
            self.engine._controls[
                self.control.control_id
            ].status,
            ControlStatus.ROLLED_BACK,
        )

        self.assertEqual(
            self.adaptation.outcome,
            AdaptationOutcome.INEFFECTIVE,
        )

    # ========================================================================
    # Scope enforcement
    # ========================================================================

    def test_scope_enforcement(self):

        foreign_lesson = SecurityLesson(
            lesson_id="foreign-lesson",
            scope_id="scope-b",
            lesson_type=LessonType.OUTCOME,
            source_reference="source-b",
            observed_problem="problem",
            desired_outcome="desired",
            evidence_references=frozenset(),
            confidence=0.95,
            created_at=utc_now(),
        )

        self.engine.add_lesson(
            foreign_lesson
        )

        with self.assertRaises(ValueError):

            self.engine.create_adaptation(
                adaptation_id="foreign-adaptation",
                scope_id="scope-a",
                lesson_ids=("foreign-lesson",),
            )

    # ========================================================================
    # Global validation
    # ========================================================================

    def test_global_validation(self):

        self.assertEqual(
            self.engine.validate(),
            [],
        )


# ============================================================================
# TEST RUNNER
# ============================================================================

def run_phase18_tests() -> None:

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        Phase18Tests
    )

    result = unittest.TextTestRunner(
        verbosity=2
    ).run(suite)

    if not result.wasSuccessful():
        raise AssertionError(
            "Phase 18 tests failed"
        )


if __name__ == "__main__":
    run_phase18_tests()
