"""
HYDRA™ — Phase 13
Security Intent Compiler

STRICT SCOPE
------------
Phase 13 ONLY:

    Intent
        ↓
    Constraints
        ↓
    Policies
        ↓
    Invariants
        ↓
    Monitoring
        ↓
    Response
        ↓
    Verification Requirements
        ↓
    Recovery Requirements

Implemented:
    - Security intent definitions
    - Intent constraints
    - Policy generation
    - Invariant references
    - Monitoring requirements
    - Response requirements
    - Verification requirements as DECLARATIONS
    - Recovery requirements as DECLARATIONS
    - Deterministic compilation
    - Compilation validation
    - Scope isolation
    - Compilation history
    - Tests

NOT IMPLEMENTED:
    - Real authorization
    - Action execution
    - Independent verification
    - Continuous replanning
    - Cyber experiments
    - Regeneration
    - Adaptive deployment
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


def stable_id(*parts: object) -> str:
    material = "|".join(str(part) for part in parts)
    return hashlib.sha256(
        material.encode("utf-8")
    ).hexdigest()


# ============================================================================
# ENUMS
# ============================================================================

class IntentPriority(str, Enum):
    LOW = "LOW"
    NORMAL = "NORMAL"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IntentStatus(str, Enum):
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"


class ConstraintType(str, Enum):
    MUST = "MUST"
    MUST_NOT = "MUST_NOT"
    MAXIMUM = "MAXIMUM"
    MINIMUM = "MINIMUM"
    ALLOWED_SET = "ALLOWED_SET"
    DENIED_SET = "DENIED_SET"


class PolicyEffect(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_REVIEW = "REQUIRE_REVIEW"
    REQUIRE_CONTAINMENT = "REQUIRE_CONTAINMENT"


class MonitoringMode(str, Enum):
    CONTINUOUS = "CONTINUOUS"
    PERIODIC = "PERIODIC"
    EVENT_DRIVEN = "EVENT_DRIVEN"


class ResponseMode(str, Enum):
    ALERT = "ALERT"
    INVESTIGATE = "INVESTIGATE"
    CONTAIN = "CONTAIN"
    ISOLATE = "ISOLATE"
    RESTRICT = "RESTRICT"


class VerificationRequirement(str, Enum):
    STATE_CONFIRMATION = "STATE_CONFIRMATION"
    EVIDENCE_CONFIRMATION = "EVIDENCE_CONFIRMATION"
    OUTCOME_CONFIRMATION = "OUTCOME_CONFIRMATION"


class RecoveryRequirement(str, Enum):
    RESTORE_SAFE_STATE = "RESTORE_SAFE_STATE"
    REASSESS_STATE = "REASSESS_STATE"
    PRESERVE_EVIDENCE = "PRESERVE_EVIDENCE"
    CONTROLLED_REINTRODUCTION = "CONTROLLED_REINTRODUCTION"


class CompilationStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


# ============================================================================
# SECURITY INTENT
# ============================================================================

@dataclass(frozen=True)
class SecurityIntent:
    """
    High-level security objective.

    Example:
        Keep critical database resources protected from
        unauthorized access.
    """

    intent_id: str
    scope_id: str
    name: str
    objective: str

    priority: IntentPriority = IntentPriority.NORMAL

    status: IntentStatus = IntentStatus.ACTIVE

    tags: FrozenSet[str] = frozenset()

    metadata: Tuple[Tuple[str, str], ...] = ()

    created_at: datetime = field(
        default_factory=utc_now
    )

    def __post_init__(self) -> None:
        ensure_aware(self.created_at)

        if not self.intent_id.strip():
            raise ValueError(
                "intent_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id must not be empty"
            )

        if not self.name.strip():
            raise ValueError(
                "intent name must not be empty"
            )

        if not self.objective.strip():
            raise ValueError(
                "intent objective must not be empty"
            )


# ============================================================================
# CONSTRAINT
# ============================================================================

@dataclass(frozen=True)
class IntentConstraint:
    constraint_id: str
    intent_id: str

    key: str
    constraint_type: ConstraintType

    value: object

    description: str = ""

    def __post_init__(self) -> None:
        if not self.constraint_id.strip():
            raise ValueError(
                "constraint_id must not be empty"
            )

        if not self.intent_id.strip():
            raise ValueError(
                "intent_id must not be empty"
            )

        if not self.key.strip():
            raise ValueError(
                "constraint key must not be empty"
            )


# ============================================================================
# POLICY
# ============================================================================

@dataclass(frozen=True)
class CompiledPolicy:
    policy_id: str
    intent_id: str
    scope_id: str

    effect: PolicyEffect

    target_key: str

    conditions: Tuple[
        IntentConstraint,
        ...
    ]

    priority: IntentPriority

    description: str


# ============================================================================
# MONITORING REQUIREMENT
# ============================================================================

@dataclass(frozen=True)
class MonitoringRequirement:
    requirement_id: str
    intent_id: str
    scope_id: str

    target_key: str

    mode: MonitoringMode

    indicators: Tuple[str, ...]

    threshold: Optional[float] = None

    description: str = ""

    def __post_init__(self) -> None:
        if not self.requirement_id.strip():
            raise ValueError(
                "requirement_id must not be empty"
            )

        if not self.target_key.strip():
            raise ValueError(
                "target_key must not be empty"
            )

        if not self.indicators:
            raise ValueError(
                "monitoring requirement needs indicators"
            )

        if (
            self.threshold is not None
            and self.threshold < 0
        ):
            raise ValueError(
                "threshold cannot be negative"
            )


# ============================================================================
# RESPONSE REQUIREMENT
# ============================================================================

@dataclass(frozen=True)
class ResponseRequirement:
    response_id: str
    intent_id: str
    scope_id: str

    mode: ResponseMode

    trigger_conditions: Tuple[str, ...]

    priority: IntentPriority

    description: str = ""

    def __post_init__(self) -> None:
        if not self.response_id.strip():
            raise ValueError(
                "response_id must not be empty"
            )

        if not self.trigger_conditions:
            raise ValueError(
                "response needs trigger conditions"
            )


# ============================================================================
# COMPILED PLAN
# ============================================================================

@dataclass(frozen=True)
class CompiledSecurityPlan:
    """
    Output of Phase 13.

    Verification and recovery entries are requirements only.
    They are not implementations of those future phases.
    """

    plan_id: str

    intent_id: str
    scope_id: str

    compiled_at: datetime

    constraints: Tuple[
        IntentConstraint,
        ...
    ]

    policies: Tuple[
        CompiledPolicy,
        ...
    ]

    invariant_ids: Tuple[str, ...]

    monitoring: Tuple[
        MonitoringRequirement,
        ...
    ]

    responses: Tuple[
        ResponseRequirement,
        ...
    ]

    verification_requirements: Tuple[
        VerificationRequirement,
        ...
    ]

    recovery_requirements: Tuple[
        RecoveryRequirement,
        ...
    ]

    compilation_hash: str

    def __post_init__(self) -> None:
        ensure_aware(self.compiled_at)

        if not self.plan_id.strip():
            raise ValueError(
                "plan_id must not be empty"
            )

        if not self.intent_id.strip():
            raise ValueError(
                "intent_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id must not be empty"
            )

        if not self.compilation_hash.strip():
            raise ValueError(
                "compilation_hash must not be empty"
            )


# ============================================================================
# COMPILATION RESULT
# ============================================================================

@dataclass(frozen=True)
class CompilationResult:
    compilation_id: str

    intent_id: str
    scope_id: str

    status: CompilationStatus

    plan: Optional[CompiledSecurityPlan]

    errors: Tuple[str, ...]

    warnings: Tuple[str, ...]

    compiled_at: datetime

    def __post_init__(self) -> None:
        ensure_aware(self.compiled_at)

        if (
            self.status == CompilationStatus.SUCCESS
            and self.plan is None
        ):
            raise ValueError(
                "successful compilation requires a plan"
            )

        if (
            self.status == CompilationStatus.FAILED
            and not self.errors
        ):
            raise ValueError(
                "failed compilation requires errors"
            )


# ============================================================================
# SECURITY INTENT COMPILER
# ============================================================================

class SecurityIntentCompiler:

    def __init__(self) -> None:

        self._intents: Dict[
            str,
            SecurityIntent,
        ] = {}

        self._constraints: Dict[
            str,
            IntentConstraint,
        ] = {}

        self._invariant_links: Dict[
            str,
            Tuple[str, ...],
        ] = {}

        self._monitoring: Dict[
            str,
            MonitoringRequirement,
        ] = {}

        self._responses: Dict[
            str,
            ResponseRequirement,
        ] = {}

        self._compilations: Dict[
            str,
            CompilationResult,
        ] = {}

        self._lock = RLock()

    # ========================================================================
    # INTENT
    # ========================================================================

    def add_intent(
        self,
        intent: SecurityIntent,
    ) -> None:

        with self._lock:

            if intent.intent_id in self._intents:
                raise ValueError(
                    f"duplicate intent: "
                    f"{intent.intent_id}"
                )

            self._intents[
                intent.intent_id
            ] = intent

            self._invariant_links[
                intent.intent_id
            ] = ()

    def get_intent(
        self,
        intent_id: str,
    ) -> SecurityIntent:

        with self._lock:

            if intent_id not in self._intents:
                raise KeyError(
                    f"intent not found: "
                    f"{intent_id}"
                )

            return self._intents[intent_id]

    # ========================================================================
    # CONSTRAINTS
    # ========================================================================

    def add_constraint(
        self,
        constraint: IntentConstraint,
    ) -> None:

        with self._lock:

            self.get_intent(
                constraint.intent_id
            )

            if (
                constraint.constraint_id
                in self._constraints
            ):
                raise ValueError(
                    f"duplicate constraint: "
                    f"{constraint.constraint_id}"
                )

            self._constraints[
                constraint.constraint_id
            ] = constraint

    def constraints_for(
        self,
        intent_id: str,
    ) -> Tuple[IntentConstraint, ...]:

        with self._lock:

            return tuple(
                constraint
                for constraint
                in self._constraints.values()
                if constraint.intent_id == intent_id
            )

    # ========================================================================
    # INVARIANT LINKS
    # ========================================================================

    def link_invariants(
        self,
        intent_id: str,
        invariant_ids: Iterable[str],
    ) -> None:

        with self._lock:

            self.get_intent(intent_id)

            normalized = tuple(
                dict.fromkeys(
                    invariant_id.strip()
                    for invariant_id
                    in invariant_ids
                    if invariant_id.strip()
                )
            )

            self._invariant_links[
                intent_id
            ] = normalized

    def invariants_for(
        self,
        intent_id: str,
    ) -> Tuple[str, ...]:

        with self._lock:

            self.get_intent(intent_id)

            return self._invariant_links.get(
                intent_id,
                (),
            )

    # ========================================================================
    # MONITORING
    # ========================================================================

    def add_monitoring_requirement(
        self,
        requirement: MonitoringRequirement,
    ) -> None:

        with self._lock:

            self.get_intent(
                requirement.intent_id
            )

            if (
                requirement.requirement_id
                in self._monitoring
            ):
                raise ValueError(
                    f"duplicate monitoring requirement: "
                    f"{requirement.requirement_id}"
                )

            self._monitoring[
                requirement.requirement_id
            ] = requirement

    def monitoring_for(
        self,
        intent_id: str,
    ) -> Tuple[
        MonitoringRequirement,
        ...
    ]:

        with self._lock:

            return tuple(
                requirement
                for requirement
                in self._monitoring.values()
                if requirement.intent_id == intent_id
            )

    # ========================================================================
    # RESPONSE
    # ========================================================================

    def add_response_requirement(
        self,
        response: ResponseRequirement,
    ) -> None:

        with self._lock:

            self.get_intent(
                response.intent_id
            )

            if response.response_id in self._responses:
                raise ValueError(
                    f"duplicate response: "
                    f"{response.response_id}"
                )

            self._responses[
                response.response_id
            ] = response

    def responses_for(
        self,
        intent_id: str,
    ) -> Tuple[
        ResponseRequirement,
        ...
    ]:

        with self._lock:

            return tuple(
                response
                for response
                in self._responses.values()
                if response.intent_id == intent_id
            )

    # ========================================================================
    # POLICY COMPILATION
    # ========================================================================

    @staticmethod
    def _compile_policy(
        intent: SecurityIntent,
        constraint: IntentConstraint,
    ) -> CompiledPolicy:

        if constraint.constraint_type == (
            ConstraintType.MUST_NOT
        ):
            effect = PolicyEffect.DENY

        elif constraint.constraint_type == (
            ConstraintType.DENIED_SET
        ):
            effect = PolicyEffect.DENY

        elif constraint.constraint_type == (
            ConstraintType.MUST
        ):
            effect = PolicyEffect.ALLOW

        else:
            effect = PolicyEffect.REQUIRE_REVIEW

        return CompiledPolicy(
            policy_id=stable_id(
                "policy",
                intent.intent_id,
                constraint.constraint_id,
            ),
            intent_id=intent.intent_id,
            scope_id=intent.scope_id,
            effect=effect,
            target_key=constraint.key,
            conditions=(constraint,),
            priority=intent.priority,
            description=(
                f"Compiled policy for constraint "
                f"{constraint.constraint_id}"
            ),
        )

    # ========================================================================
    # HASH
    # ========================================================================

    @staticmethod
    def _plan_hash(
        intent: SecurityIntent,
        constraints: Tuple[IntentConstraint, ...],
        policies: Tuple[CompiledPolicy, ...],
        invariant_ids: Tuple[str, ...],
        monitoring: Tuple[MonitoringRequirement, ...],
        responses: Tuple[ResponseRequirement, ...],
        verification: Tuple[VerificationRequirement, ...],
        recovery: Tuple[RecoveryRequirement, ...],
    ) -> str:

        material = repr(
            (
                intent,
                constraints,
                policies,
                invariant_ids,
                monitoring,
                responses,
                verification,
                recovery,
            )
        )

        return hashlib.sha256(
            material.encode("utf-8")
        ).hexdigest()

    # ========================================================================
    # VALIDATION BEFORE COMPILATION
    # ========================================================================

    def _validate_intent(
        self,
        intent: SecurityIntent,
    ) -> Tuple[List[str], List[str]]:

        errors: List[str] = []
        warnings: List[str] = []

        constraints = self.constraints_for(
            intent.intent_id
        )

        monitoring = self.monitoring_for(
            intent.intent_id
        )

        responses = self.responses_for(
            intent.intent_id
        )

        invariants = self.invariants_for(
            intent.intent_id
        )

        if not constraints:
            warnings.append(
                "intent has no explicit constraints"
            )

        if not invariants:
            warnings.append(
                "intent has no linked security invariants"
            )

        if not monitoring:
            warnings.append(
                "intent has no monitoring requirements"
            )

        if not responses:
            warnings.append(
                "intent has no response requirements"
            )

        for constraint in constraints:

            if (
                constraint.intent_id
                != intent.intent_id
            ):
                errors.append(
                    f"constraint belongs to another intent: "
                    f"{constraint.constraint_id}"
                )

        for requirement in monitoring:

            if (
                requirement.scope_id
                != intent.scope_id
            ):
                errors.append(
                    f"monitoring scope mismatch: "
                    f"{requirement.requirement_id}"
                )

        for response in responses:

            if (
                response.scope_id
                != intent.scope_id
            ):
                errors.append(
                    f"response scope mismatch: "
                    f"{response.response_id}"
                )

        if any(
            not invariant_id.strip()
            for invariant_id
            in invariants
        ):
            errors.append(
                "empty invariant reference detected"
            )

        return errors, warnings

    # ========================================================================
    # COMPILE
    # ========================================================================

    def compile(
        self,
        intent_id: str,
    ) -> CompilationResult:

        with self._lock:

            intent = self.get_intent(
                intent_id
            )

            compilation_id = stable_id(
                "compilation",
                intent_id,
                utc_now().isoformat(),
            )

            if intent.status == IntentStatus.DISABLED:

                result = CompilationResult(
                    compilation_id=compilation_id,
                    intent_id=intent_id,
                    scope_id=intent.scope_id,
                    status=CompilationStatus.FAILED,
                    plan=None,
                    errors=(
                        "cannot compile disabled intent",
                    ),
                    warnings=(),
                    compiled_at=utc_now(),
                )

                self._compilations[
                    compilation_id
                ] = result

                return result

            errors, warnings = (
                self._validate_intent(
                    intent
                )
            )

            if errors:

                result = CompilationResult(
                    compilation_id=compilation_id,
                    intent_id=intent_id,
                    scope_id=intent.scope_id,
                    status=CompilationStatus.FAILED,
                    plan=None,
                    errors=tuple(errors),
                    warnings=tuple(warnings),
                    compiled_at=utc_now(),
                )

                self._compilations[
                    compilation_id
                ] = result

                return result

            constraints = tuple(
                sorted(
                    self.constraints_for(
                        intent_id
                    ),
                    key=lambda item:
                    item.constraint_id,
                )
            )

            policies = tuple(
                self._compile_policy(
                    intent,
                    constraint,
                )
                for constraint in constraints
            )

            invariant_ids = tuple(
                sorted(
                    self.invariants_for(
                        intent_id
                    )
                )
            )

            monitoring = tuple(
                sorted(
                    self.monitoring_for(
                        intent_id
                    ),
                    key=lambda item:
                    item.requirement_id,
                )
            )

            responses = tuple(
                sorted(
                    self.responses_for(
                        intent_id
                    ),
                    key=lambda item:
                    item.response_id,
                )
            )

            # These are REQUIREMENTS only.
            verification = (
                VerificationRequirement.STATE_CONFIRMATION,
                VerificationRequirement.EVIDENCE_CONFIRMATION,
            )

            recovery = (
                RecoveryRequirement.PRESERVE_EVIDENCE,
                RecoveryRequirement.REASSESS_STATE,
                RecoveryRequirement.RESTORE_SAFE_STATE,
            )

            compiled_at = utc_now()

            compilation_hash = self._plan_hash(
                intent,
                constraints,
                policies,
                invariant_ids,
                monitoring,
                responses,
                verification,
                recovery,
            )

            plan = CompiledSecurityPlan(
                plan_id=stable_id(
                    "plan",
                    intent_id,
                    compilation_hash,
                ),
                intent_id=intent_id,
                scope_id=intent.scope_id,
                compiled_at=compiled_at,
                constraints=constraints,
                policies=policies,
                invariant_ids=invariant_ids,
                monitoring=monitoring,
                responses=responses,
                verification_requirements=verification,
                recovery_requirements=recovery,
                compilation_hash=compilation_hash,
            )

            result = CompilationResult(
                compilation_id=compilation_id,
                intent_id=intent_id,
                scope_id=intent.scope_id,
                status=CompilationStatus.SUCCESS,
                plan=plan,
                errors=(),
                warnings=tuple(warnings),
                compiled_at=compiled_at,
            )

            self._compilations[
                compilation_id
            ] = result

            return result

    # ========================================================================
    # LOOKUP
    # ========================================================================

    def get_compilation(
        self,
        compilation_id: str,
    ) -> CompilationResult:

        with self._lock:

            if compilation_id not in self._compilations:
                raise KeyError(
                    f"compilation not found: "
                    f"{compilation_id}"
                )

            return self._compilations[
                compilation_id
            ]

    def compilation_history(
        self,
        intent_id: str,
    ) -> Tuple[CompilationResult, ...]:

        with self._lock:

            return tuple(
                result
                for result
                in self._compilations.values()
                if result.intent_id == intent_id
            )

    # ========================================================================
    # VALIDATION
    # ========================================================================

    def validate(self) -> List[str]:

        errors: List[str] = []

        with self._lock:

            for intent_id, intent in (
                self._intents.items()
            ):

                if intent_id != intent.intent_id:
                    errors.append(
                        f"intent key mismatch: "
                        f"{intent_id}"
                    )

                if intent_id not in self._invariant_links:
                    errors.append(
                        f"missing invariant index: "
                        f"{intent_id}"
                    )

            for constraint_id, constraint in (
                self._constraints.items()
            ):

                if (
                    constraint_id
                    != constraint.constraint_id
                ):
                    errors.append(
                        f"constraint key mismatch: "
                        f"{constraint_id}"
                    )

                if (
                    constraint.intent_id
                    not in self._intents
                ):
                    errors.append(
                        f"constraint references "
                        f"unknown intent: "
                        f"{constraint_id}"
                    )

            for requirement_id, requirement in (
                self._monitoring.items()
            ):

                if (
                    requirement.intent_id
                    not in self._intents
                ):
                    errors.append(
                        f"monitoring references "
                        f"unknown intent: "
                        f"{requirement_id}"
                    )

            for response_id, response in (
                self._responses.items()
            ):

                if (
                    response.intent_id
                    not in self._intents
                ):
                    errors.append(
                        f"response references "
                        f"unknown intent: "
                        f"{response_id}"
                    )

            for compilation_id, result in (
                self._compilations.items()
            ):

                if (
                    compilation_id
                    != result.compilation_id
                ):
                    errors.append(
                        f"compilation key mismatch: "
                        f"{compilation_id}"
                    )

                if (
                    result.intent_id
                    not in self._intents
                ):
                    errors.append(
                        f"compilation references "
                        f"unknown intent: "
                        f"{compilation_id}"
                    )

        return errors


# ============================================================================
# TESTS
# ============================================================================

class Phase13Tests(unittest.TestCase):

    def setUp(self):

        self.compiler = SecurityIntentCompiler()

        self.intent = SecurityIntent(
            intent_id="intent-1",
            scope_id="tenant-a",
            name="Protect critical resources",
            objective=(
                "Prevent unauthorized access to "
                "critical resources."
            ),
            priority=IntentPriority.CRITICAL,
        )

        self.compiler.add_intent(
            self.intent
        )

    # ========================================================================
    # Intent
    # ========================================================================

    def test_intent_registration(self):

        result = self.compiler.get_intent(
            "intent-1"
        )

        self.assertEqual(
            result.scope_id,
            "tenant-a",
        )

    def test_duplicate_intent_rejected(self):

        with self.assertRaises(ValueError):
            self.compiler.add_intent(
                self.intent
            )

    # ========================================================================
    # Constraints
    # ========================================================================

    def test_constraint_registration(self):

        constraint = IntentConstraint(
            constraint_id="constraint-1",
            intent_id="intent-1",
            key="privileged_access",
            constraint_type=ConstraintType.MUST_NOT,
            value=True,
        )

        self.compiler.add_constraint(
            constraint
        )

        constraints = (
            self.compiler.constraints_for(
                "intent-1"
            )
        )

        self.assertEqual(
            len(constraints),
            1,
        )

    # ========================================================================
    # Invariants
    # ========================================================================

    def test_invariant_linkage(self):

        self.compiler.link_invariants(
            "intent-1",
            (
                "inv-1",
                "inv-2",
            ),
        )

        self.assertEqual(
            self.compiler.invariants_for(
                "intent-1"
            ),
            (
                "inv-1",
                "inv-2",
            ),
        )

    # ========================================================================
    # Monitoring
    # ========================================================================

    def test_monitoring_requirement(self):

        requirement = MonitoringRequirement(
            requirement_id="monitor-1",
            intent_id="intent-1",
            scope_id="tenant-a",
            target_key="database",
            mode=MonitoringMode.CONTINUOUS,
            indicators=(
                "unauthorized_access",
                "integrity_change",
            ),
            threshold=0.5,
        )

        self.compiler.add_monitoring_requirement(
            requirement
        )

        self.assertEqual(
            len(
                self.compiler.monitoring_for(
                    "intent-1"
                )
            ),
            1,
        )

    # ========================================================================
    # Response
    # ========================================================================

    def test_response_requirement(self):

        response = ResponseRequirement(
            response_id="response-1",
            intent_id="intent-1",
            scope_id="tenant-a",
            mode=ResponseMode.CONTAIN,
            trigger_conditions=(
                "critical invariant violation",
            ),
            priority=IntentPriority.CRITICAL,
        )

        self.compiler.add_response_requirement(
            response
        )

        self.assertEqual(
            len(
                self.compiler.responses_for(
                    "intent-1"
                )
            ),
            1,
        )

    # ========================================================================
    # Compilation
    # ========================================================================

    def test_successful_compilation(self):

        self.compiler.add_constraint(
            IntentConstraint(
                constraint_id="constraint-1",
                intent_id="intent-1",
                key="privileged_access",
                constraint_type=ConstraintType.MUST_NOT,
                value=True,
            )
        )

        self.compiler.link_invariants(
            "intent-1",
            ("inv-1",),
        )

        self.compiler.add_monitoring_requirement(
            MonitoringRequirement(
                requirement_id="monitor-1",
                intent_id="intent-1",
                scope_id="tenant-a",
                target_key="database",
                mode=MonitoringMode.CONTINUOUS,
                indicators=(
                    "unauthorized_access",
                ),
            )
        )

        self.compiler.add_response_requirement(
            ResponseRequirement(
                response_id="response-1",
                intent_id="intent-1",
                scope_id="tenant-a",
                mode=ResponseMode.CONTAIN,
                trigger_conditions=(
                    "invariant violation",
                ),
                priority=IntentPriority.CRITICAL,
            )
        )

        result = self.compiler.compile(
            "intent-1"
        )

        self.assertEqual(
            result.status,
            CompilationStatus.SUCCESS,
        )

        self.assertIsNotNone(
            result.plan
        )

        self.assertEqual(
            len(result.plan.policies),
            1,
        )

        self.assertEqual(
            result.plan.invariant_ids,
            ("inv-1",),
        )

    # ========================================================================
    # Policy effect
    # ========================================================================

    def test_must_not_compiles_to_deny(self):

        self.compiler.add_constraint(
            IntentConstraint(
                constraint_id="deny-1",
                intent_id="intent-1",
                key="admin_access",
                constraint_type=ConstraintType.MUST_NOT,
                value=True,
            )
        )

        result = self.compiler.compile(
            "intent-1"
        )

        self.assertEqual(
            result.status,
            CompilationStatus.SUCCESS,
        )

        self.assertEqual(
            result.plan.policies[0].effect,
            PolicyEffect.DENY,
        )

    # ========================================================================
    # Scope
    # ========================================================================

    def test_monitoring_scope_mismatch_fails(self):

        self.compiler.add_monitoring_requirement(
            MonitoringRequirement(
                requirement_id="bad-monitor",
                intent_id="intent-1",
                scope_id="tenant-b",
                target_key="database",
                mode=MonitoringMode.CONTINUOUS,
                indicators=("integrity",),
            )
        )

        result = self.compiler.compile(
            "intent-1"
        )

        self.assertEqual(
            result.status,
            CompilationStatus.FAILED,
        )

        self.assertTrue(
            any(
                "scope mismatch" in error
                for error in result.errors
            )
        )

    # ========================================================================
    # Disabled intent
    # ========================================================================

    def test_disabled_intent_rejected(self):

        disabled = SecurityIntent(
            intent_id="intent-disabled",
            scope_id="tenant-a",
            name="Disabled Intent",
            objective="No longer active.",
            status=IntentStatus.DISABLED,
        )

        self.compiler.add_intent(
            disabled
        )

        result = self.compiler.compile(
            "intent-disabled"
        )

        self.assertEqual(
            result.status,
            CompilationStatus.FAILED,
        )

    # ========================================================================
    # Compilation hash
    # ========================================================================

    def test_compilation_hash_present(self):

        result = self.compiler.compile(
            "intent-1"
        )

        self.assertTrue(
            result.plan.compilation_hash
        )

        self.assertEqual(
            len(result.plan.compilation_hash),
            64,
        )

    # ========================================================================
    # Future-phase requirements are declarations
    # ========================================================================

    def test_verification_and_recovery_are_requirements(self):

        result = self.compiler.compile(
            "intent-1"
        )

        self.assertIn(
            VerificationRequirement.STATE_CONFIRMATION,
            result.plan.verification_requirements,
        )

        self.assertIn(
            RecoveryRequirement.REASSESS_STATE,
            result.plan.recovery_requirements,
        )

    # ========================================================================
    # History
    # ========================================================================

    def test_compilation_history(self):

        self.compiler.compile(
            "intent-1"
        )

        self.compiler.compile(
            "intent-1"
        )

        history = (
            self.compiler.compilation_history(
                "intent-1"
            )
        )

        self.assertEqual(
            len(history),
            2,
        )

    # ========================================================================
    # Validation
    # ========================================================================

    def test_validation_clean(self):

        self.assertEqual(
            self.compiler.validate(),
            [],
        )


# ============================================================================
# TEST RUNNER
# ============================================================================

def run_phase13_tests() -> None:

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        Phase13Tests
    )

    result = unittest.TextTestRunner(
        verbosity=2
    ).run(suite)

    if not result.wasSuccessful():
        raise AssertionError(
            "Phase 13 verification failed"
        )


if __name__ == "__main__":
    run_phase13_tests()
