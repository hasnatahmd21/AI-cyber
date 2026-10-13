"""
HYDRA™ — Phase 11
Security Invariants Engine

STRICT SCOPE
------------
Phase 11 ONLY:

    - Security invariant definitions
    - Invariant conditions
    - State evaluation
    - Violation detection
    - Severity
    - Evidence references
    - Remediation linkage
    - Pre-action invariant checks
    - Evaluation history
    - Validation
    - Tests

NOT IMPLEMENTED
---------------
    Phase 12  -> Dynamic Authority Graph
    Phase 13  -> Security Intent Compiler
    Phase 14  -> Independent Verification
    Phase 15  -> Continuous Replanning
    Phase 16  -> Cyber Experiment Engine
    Phase 17  -> Cyber Regeneration
    Phase 18  -> Adaptive Defense

IMPORTANT
---------
An invariant is a security condition that must remain true.

This engine evaluates and reports invariant state.
It does NOT execute remediation.
It does NOT authorize actions.
It does NOT verify execution results.
"""


from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from threading import RLock
from typing import Dict, FrozenSet, Iterable, List, Optional, Tuple
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


# ============================================================================
# ENUMERATIONS
# ============================================================================

class InvariantSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class InvariantStatus(str, Enum):
    UNKNOWN = "UNKNOWN"
    SATISFIED = "SATISFIED"
    VIOLATED = "VIOLATED"
    DEGRADED = "DEGRADED"


class InvariantConditionType(str, Enum):
    EQUALS = "EQUALS"
    NOT_EQUALS = "NOT_EQUALS"
    EXISTS = "EXISTS"
    NOT_EXISTS = "NOT_EXISTS"
    GREATER_THAN = "GREATER_THAN"
    GREATER_THAN_OR_EQUAL = "GREATER_THAN_OR_EQUAL"
    LESS_THAN = "LESS_THAN"
    LESS_THAN_OR_EQUAL = "LESS_THAN_OR_EQUAL"
    IN_SET = "IN_SET"
    NOT_IN_SET = "NOT_IN_SET"
    BOOLEAN_TRUE = "BOOLEAN_TRUE"
    BOOLEAN_FALSE = "BOOLEAN_FALSE"


class RemediationType(str, Enum):
    NONE = "NONE"
    INVESTIGATE = "INVESTIGATE"
    CONTAIN = "CONTAIN"
    RESTRICT = "RESTRICT"
    ISOLATE = "ISOLATE"
    ROTATE = "ROTATE"
    PATCH = "PATCH"
    RESTORE = "RESTORE"


# ============================================================================
# STATE VALUE
# ============================================================================

@dataclass(frozen=True)
class StateValue:
    """
    A value supplied to invariant evaluation.

    Values are intentionally generic because Phase 11 evaluates
    security conditions without owning the Phase 4 state engine.
    """

    key: str
    value: object
    observed_at: datetime
    source_id: Optional[str] = None
    confidence: float = 1.0

    def __post_init__(self) -> None:
        ensure_aware(self.observed_at)

        if not self.key.strip():
            raise ValueError("state key must not be empty")

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "state confidence must be between 0 and 1"
            )


# ============================================================================
# INVARIANT CONDITION
# ============================================================================

@dataclass(frozen=True)
class InvariantCondition:
    """
    Atomic condition evaluated against one state value.

    Examples:

        privileged_access == False
        endpoint_exists == True
        risk_score <= 0.70
        identity_state IN {"healthy", "verified"}
    """

    key: str
    condition_type: InvariantConditionType
    expected_value: object = None

    def __post_init__(self) -> None:
        if not self.key.strip():
            raise ValueError(
                "condition key must not be empty"
            )


# ============================================================================
# INVARIANT
# ============================================================================

@dataclass(frozen=True)
class SecurityInvariant:
    """
    Security invariant definition.

    Multiple conditions are combined using condition_mode:

        ALL -> every condition must hold
        ANY -> at least one condition must hold
    """

    invariant_id: str
    scope_id: str
    name: str
    description: str

    conditions: Tuple[
        InvariantCondition,
        ...
    ]

    severity: InvariantSeverity = (
        InvariantSeverity.HIGH
    )

    condition_mode: str = "ALL"

    remediation_types: Tuple[
        RemediationType,
        ...
    ] = ()

    remediation_references: Tuple[str, ...] = ()

    enabled: bool = True

    metadata: Tuple[Tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not self.invariant_id.strip():
            raise ValueError(
                "invariant_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id must not be empty"
            )

        if not self.name.strip():
            raise ValueError(
                "invariant name must not be empty"
            )

        if not self.description.strip():
            raise ValueError(
                "invariant description must not be empty"
            )

        if not self.conditions:
            raise ValueError(
                "invariant must contain at least one condition"
            )

        if self.condition_mode not in {
            "ALL",
            "ANY",
        }:
            raise ValueError(
                "condition_mode must be ALL or ANY"
            )


# ============================================================================
# CONDITION RESULT
# ============================================================================

@dataclass(frozen=True)
class ConditionEvaluation:
    key: str
    condition_type: InvariantConditionType
    observed_value: object
    expected_value: object
    satisfied: bool
    state_present: bool
    confidence: float


# ============================================================================
# INVARIANT EVALUATION
# ============================================================================

@dataclass(frozen=True)
class InvariantEvaluation:
    evaluation_id: str
    invariant_id: str
    scope_id: str

    evaluated_at: datetime

    status: InvariantStatus
    severity: InvariantSeverity

    condition_results: Tuple[
        ConditionEvaluation,
        ...
    ]

    evidence_ids: FrozenSet[str] = frozenset()

    remediation_types: Tuple[
        RemediationType,
        ...
    ] = ()

    remediation_references: Tuple[
        str,
        ...
    ] = ()

    reason: str = ""

    def __post_init__(self) -> None:
        ensure_aware(self.evaluated_at)

        if not self.evaluation_id.strip():
            raise ValueError(
                "evaluation_id must not be empty"
            )

        if not self.invariant_id.strip():
            raise ValueError(
                "invariant_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id must not be empty"
            )


# ============================================================================
# PRE-ACTION CHECK
# ============================================================================

@dataclass(frozen=True)
class PreActionInvariantCheck:
    """
    Result of evaluating relevant invariants before a proposed action.

    This is a CHECK only.

    It does not authorize or execute the action.
    """

    check_id: str
    scope_id: str
    action_reference: str

    checked_at: datetime

    blocking: bool

    evaluations: Tuple[
        InvariantEvaluation,
        ...
    ]

    violated_invariant_ids: Tuple[str, ...] = ()

    reason: str = ""

    def __post_init__(self) -> None:
        ensure_aware(self.checked_at)

        if not self.check_id.strip():
            raise ValueError(
                "check_id must not be empty"
            )

        if not self.action_reference.strip():
            raise ValueError(
                "action_reference must not be empty"
            )


# ============================================================================
# ENGINE
# ============================================================================

class SecurityInvariantEngine:
    """
    Phase 11 Security Invariant Engine.

    Responsibilities:

        define invariants
        evaluate invariants
        detect violations
        preserve evaluation history
        perform pre-action invariant checks
        expose remediation linkage

    Explicit non-responsibilities:

        action execution
        authorization
        independent verification
        automatic remediation
        replanning
        regeneration
    """

    def __init__(self) -> None:
        self._invariants: Dict[
            str,
            SecurityInvariant,
        ] = {}

        self._evaluations: Dict[
            str,
            InvariantEvaluation,
        ] = {}

        self._history: Dict[
            str,
            List[str],
        ] = {}

        self._checks: Dict[
            str,
            PreActionInvariantCheck,
        ] = {}

        self._lock = RLock()

    # ========================================================================
    # INVARIANT REGISTRATION
    # ========================================================================

    def add_invariant(
        self,
        invariant: SecurityInvariant,
    ) -> None:

        with self._lock:
            if invariant.invariant_id in self._invariants:
                raise ValueError(
                    f"duplicate invariant: "
                    f"{invariant.invariant_id}"
                )

            self._invariants[
                invariant.invariant_id
            ] = invariant

            self._history[
                invariant.invariant_id
            ] = []

    def get_invariant(
        self,
        invariant_id: str,
    ) -> SecurityInvariant:

        with self._lock:
            try:
                return self._invariants[
                    invariant_id
                ]
            except KeyError:
                raise KeyError(
                    f"invariant not found: "
                    f"{invariant_id}"
                )

    # ========================================================================
    # CONDITION EVALUATION
    # ========================================================================

    @staticmethod
    def _evaluate_condition(
        condition: InvariantCondition,
        state: Dict[str, StateValue],
    ) -> ConditionEvaluation:

        state_value = state.get(
            condition.key
        )

        if state_value is None:
            return ConditionEvaluation(
                key=condition.key,
                condition_type=condition.condition_type,
                observed_value=None,
                expected_value=condition.expected_value,
                satisfied=(
                    condition.condition_type
                    == InvariantConditionType.NOT_EXISTS
                ),
                state_present=False,
                confidence=0.0,
            )

        observed = state_value.value
        expected = condition.expected_value

        condition_type = (
            condition.condition_type
        )

        if condition_type == (
            InvariantConditionType.EQUALS
        ):
            satisfied = observed == expected

        elif condition_type == (
            InvariantConditionType.NOT_EQUALS
        ):
            satisfied = observed != expected

        elif condition_type == (
            InvariantConditionType.EXISTS
        ):
            satisfied = True

        elif condition_type == (
            InvariantConditionType.NOT_EXISTS
        ):
            satisfied = False

        elif condition_type == (
            InvariantConditionType.GREATER_THAN
        ):
            satisfied = observed > expected

        elif condition_type == (
            InvariantConditionType.GREATER_THAN_OR_EQUAL
        ):
            satisfied = observed >= expected

        elif condition_type == (
            InvariantConditionType.LESS_THAN
        ):
            satisfied = observed < expected

        elif condition_type == (
            InvariantConditionType.LESS_THAN_OR_EQUAL
        ):
            satisfied = observed <= expected

        elif condition_type == (
            InvariantConditionType.IN_SET
        ):
            satisfied = observed in expected

        elif condition_type == (
            InvariantConditionType.NOT_IN_SET
        ):
            satisfied = observed not in expected

        elif condition_type == (
            InvariantConditionType.BOOLEAN_TRUE
        ):
            satisfied = observed is True

        elif condition_type == (
            InvariantConditionType.BOOLEAN_FALSE
        ):
            satisfied = observed is False

        else:
            raise ValueError(
                f"unsupported condition type: "
                f"{condition_type}"
            )

        return ConditionEvaluation(
            key=condition.key,
            condition_type=condition_type,
            observed_value=observed,
            expected_value=expected,
            satisfied=satisfied,
            state_present=True,
            confidence=state_value.confidence,
        )

    # ========================================================================
    # EVALUATION
    # ========================================================================

    def evaluate(
        self,
        invariant_id: str,
        state: Dict[str, StateValue],
        *,
        evidence_ids: Iterable[str] = (),
    ) -> InvariantEvaluation:

        with self._lock:

            invariant = self.get_invariant(
                invariant_id
            )

            now = utc_now()

            if not invariant.enabled:
                evaluation = InvariantEvaluation(
                    evaluation_id=self._evaluation_id(
                        invariant_id,
                        now,
                    ),
                    invariant_id=invariant_id,
                    scope_id=invariant.scope_id,
                    evaluated_at=now,
                    status=InvariantStatus.UNKNOWN,
                    severity=invariant.severity,
                    condition_results=(),
                    evidence_ids=frozenset(
                        evidence_ids
                    ),
                    remediation_types=(
                        invariant.remediation_types
                    ),
                    remediation_references=(
                        invariant.remediation_references
                    ),
                    reason="invariant disabled",
                )

                self._store_evaluation(
                    evaluation
                )

                return evaluation

            results = tuple(
                self._evaluate_condition(
                    condition,
                    state,
                )
                for condition in invariant.conditions
            )

            if invariant.condition_mode == "ALL":
                satisfied = all(
                    result.satisfied
                    for result in results
                )
            else:
                satisfied = any(
                    result.satisfied
                    for result in results
                )

            missing_state = any(
                not result.state_present
                for result in results
            )

            if satisfied:
                status = InvariantStatus.SATISFIED

            elif missing_state:
                status = InvariantStatus.UNKNOWN

            else:
                status = InvariantStatus.VIOLATED

            if status == InvariantStatus.VIOLATED:
                reason = (
                    "one or more invariant conditions "
                    "are violated"
                )

            elif status == InvariantStatus.UNKNOWN:
                reason = (
                    "required state information is missing"
                )

            else:
                reason = (
                    "all invariant conditions satisfied"
                )

            evaluation = InvariantEvaluation(
                evaluation_id=self._evaluation_id(
                    invariant_id,
                    now,
                ),
                invariant_id=invariant_id,
                scope_id=invariant.scope_id,
                evaluated_at=now,
                status=status,
                severity=invariant.severity,
                condition_results=results,
                evidence_ids=frozenset(
                    evidence_ids
                ),
                remediation_types=(
                    invariant.remediation_types
                ),
                remediation_references=(
                    invariant.remediation_references
                ),
                reason=reason,
            )

            self._store_evaluation(
                evaluation
            )

            return evaluation

    # ========================================================================
    # EVALUATION STORAGE
    # ========================================================================

    def _store_evaluation(
        self,
        evaluation: InvariantEvaluation,
    ) -> None:

        self._evaluations[
            evaluation.evaluation_id
        ] = evaluation

        self._history[
            evaluation.invariant_id
        ].append(
            evaluation.evaluation_id
        )

    # ========================================================================
    # CURRENT STATUS
    # ========================================================================

    def current_status(
        self,
        invariant_id: str,
    ) -> InvariantStatus:

        with self._lock:

            history = self._history.get(
                invariant_id
            )

            if not history:
                return InvariantStatus.UNKNOWN

            evaluation = self._evaluations[
                history[-1]
            ]

            return evaluation.status

    # ========================================================================
    # VIOLATION QUERY
    # ========================================================================

    def violated_invariants(
        self,
        scope_id: str,
    ) -> Tuple[InvariantEvaluation, ...]:

        with self._lock:

            result = []

            for invariant_id, history in (
                self._history.items()
            ):

                if not history:
                    continue

                invariant = self._invariants[
                    invariant_id
                ]

                if invariant.scope_id != scope_id:
                    continue

                evaluation = self._evaluations[
                    history[-1]
                ]

                if (
                    evaluation.status
                    == InvariantStatus.VIOLATED
                ):
                    result.append(
                        evaluation
                    )

            result.sort(
                key=lambda item: (
                    item.severity.value,
                    item.invariant_id,
                )
            )

            return tuple(result)

    # ========================================================================
    # PRE-ACTION CHECK
    # ========================================================================

    def pre_action_check(
        self,
        scope_id: str,
        action_reference: str,
        state: Dict[str, StateValue],
        *,
        invariant_ids: Optional[
            Iterable[str]
        ] = None,
        evidence_ids: Iterable[str] = (),
        block_on_unknown: bool = True,
    ) -> PreActionInvariantCheck:

        with self._lock:

            if invariant_ids is None:
                selected = [
                    invariant
                    for invariant in (
                        self._invariants.values()
                    )
                    if (
                        invariant.scope_id
                        == scope_id
                        and invariant.enabled
                    )
                ]
            else:
                selected = []

                for invariant_id in invariant_ids:
                    invariant = self.get_invariant(
                        invariant_id
                    )

                    if invariant.scope_id != scope_id:
                        raise ValueError(
                            "invariant scope mismatch"
                        )

                    selected.append(
                        invariant
                    )

            evaluations = tuple(
                self.evaluate(
                    invariant.invariant_id,
                    state,
                    evidence_ids=evidence_ids,
                )
                for invariant in selected
            )

            violated = tuple(
                evaluation.invariant_id
                for evaluation in evaluations
                if (
                    evaluation.status
                    == InvariantStatus.VIOLATED
                )
            )

            unknown = tuple(
                evaluation.invariant_id
                for evaluation in evaluations
                if (
                    evaluation.status
                    == InvariantStatus.UNKNOWN
                )
            )

            blocking = bool(
                violated
                or (
                    block_on_unknown
                    and unknown
                )
            )

            reasons = []

            if violated:
                reasons.append(
                    "security invariant violation detected"
                )

            if unknown and block_on_unknown:
                reasons.append(
                    "invariant state is unknown"
                )

            if not reasons:
                reasons.append(
                    "pre-action invariant conditions satisfied"
                )

            check = PreActionInvariantCheck(
                check_id=self._check_id(
                    scope_id,
                    action_reference,
                ),
                scope_id=scope_id,
                action_reference=action_reference,
                checked_at=utc_now(),
                blocking=blocking,
                evaluations=evaluations,
                violated_invariant_ids=violated,
                reason="; ".join(reasons),
            )

            self._checks[
                check.check_id
            ] = check

            return check

    # ========================================================================
    # HISTORY
    # ========================================================================

    def history(
        self,
        invariant_id: str,
    ) -> Tuple[InvariantEvaluation, ...]:

        with self._lock:

            if invariant_id not in self._history:
                raise KeyError(
                    f"invariant not found: "
                    f"{invariant_id}"
                )

            return tuple(
                self._evaluations[evaluation_id]
                for evaluation_id in (
                    self._history[invariant_id]
                )
            )

    # ========================================================================
    # LOOKUP
    # ========================================================================

    def get_evaluation(
        self,
        evaluation_id: str,
    ) -> InvariantEvaluation:

        with self._lock:

            try:
                return self._evaluations[
                    evaluation_id
                ]
            except KeyError:
                raise KeyError(
                    f"evaluation not found: "
                    f"{evaluation_id}"
                )

    # ========================================================================
    # IDS
    # ========================================================================

    @staticmethod
    def _evaluation_id(
        invariant_id: str,
        timestamp: datetime,
    ) -> str:

        material = (
            f"{invariant_id}|"
            f"{timestamp.isoformat()}"
        )

        import hashlib

        return hashlib.sha256(
            material.encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _check_id(
        scope_id: str,
        action_reference: str,
    ) -> str:

        import hashlib

        material = (
            f"{scope_id}|"
            f"{action_reference}|"
            f"{utc_now().isoformat()}"
        )

        return hashlib.sha256(
            material.encode("utf-8")
        ).hexdigest()

    # ========================================================================
    # VALIDATION
    # ========================================================================

    def validate(self) -> List[str]:

        errors: List[str] = []

        with self._lock:

            for invariant_id, invariant in (
                self._invariants.items()
            ):

                if (
                    invariant_id
                    != invariant.invariant_id
                ):
                    errors.append(
                        f"invariant key mismatch: "
                        f"{invariant_id}"
                    )

                if not invariant.conditions:
                    errors.append(
                        f"invariant has no conditions: "
                        f"{invariant_id}"
                    )

                if invariant.condition_mode not in {
                    "ALL",
                    "ANY",
                }:
                    errors.append(
                        f"invalid condition mode: "
                        f"{invariant_id}"
                    )

                if invariant_id not in self._history:
                    errors.append(
                        f"missing history index: "
                        f"{invariant_id}"
                    )

            for evaluation_id, evaluation in (
                self._evaluations.items()
            ):

                if (
                    evaluation_id
                    != evaluation.evaluation_id
                ):
                    errors.append(
                        f"evaluation key mismatch: "
                        f"{evaluation_id}"
                    )

                if (
                    evaluation.invariant_id
                    not in self._invariants
                ):
                    errors.append(
                        f"evaluation references "
                        f"unknown invariant: "
                        f"{evaluation_id}"
                    )

        return errors


# ============================================================================
# TESTS
# ============================================================================

class Phase11Tests(unittest.TestCase):

    def setUp(self):

        self.engine = SecurityInvariantEngine()

        self.invariant = SecurityInvariant(
            invariant_id="inv-1",
            scope_id="scope-a",
            name="No unauthorized privileged access",
            description=(
                "Privileged access must remain disabled "
                "unless explicitly represented as safe state."
            ),
            conditions=(
                InvariantCondition(
                    key="privileged_access",
                    condition_type=(
                        InvariantConditionType.BOOLEAN_FALSE
                    ),
                ),
            ),
            severity=InvariantSeverity.CRITICAL,
            remediation_types=(
                RemediationType.INVESTIGATE,
                RemediationType.RESTRICT,
            ),
            remediation_references=(
                "remediation-policy-1",
            ),
        )

        self.engine.add_invariant(
            self.invariant
        )

    def state(
        self,
        key: str,
        value: object,
        confidence: float = 1.0,
    ) -> Dict[str, StateValue]:

        return {
            key: StateValue(
                key=key,
                value=value,
                observed_at=utc_now(),
                confidence=confidence,
            )
        }

    # ========================================================================
    # Registration
    # ========================================================================

    def test_invariant_registration(self):

        result = self.engine.get_invariant(
            "inv-1"
        )

        self.assertEqual(
            result.name,
            "No unauthorized privileged access",
        )

    def test_duplicate_invariant_rejected(self):

        with self.assertRaises(ValueError):
            self.engine.add_invariant(
                self.invariant
            )

    # ========================================================================
    # Basic evaluation
    # ========================================================================

    def test_satisfied_invariant(self):

        evaluation = self.engine.evaluate(
            "inv-1",
            self.state(
                "privileged_access",
                False,
            ),
        )

        self.assertEqual(
            evaluation.status,
            InvariantStatus.SATISFIED,
        )

    def test_violated_invariant(self):

        evaluation = self.engine.evaluate(
            "inv-1",
            self.state(
                "privileged_access",
                True,
            ),
        )

        self.assertEqual(
            evaluation.status,
            InvariantStatus.VIOLATED,
        )

    def test_missing_state_is_unknown(self):

        evaluation = self.engine.evaluate(
            "inv-1",
            {},
        )

        self.assertEqual(
            evaluation.status,
            InvariantStatus.UNKNOWN,
        )

    # ========================================================================
    # Numeric conditions
    # ========================================================================

    def test_numeric_condition(self):

        numeric = SecurityInvariant(
            invariant_id="inv-risk",
            scope_id="scope-a",
            name="Risk threshold",
            description="Risk must remain below threshold.",
            conditions=(
                InvariantCondition(
                    key="risk_score",
                    condition_type=(
                        InvariantConditionType
                        .LESS_THAN_OR_EQUAL
                    ),
                    expected_value=0.70,
                ),
            ),
        )

        self.engine.add_invariant(
            numeric
        )

        evaluation = self.engine.evaluate(
            "inv-risk",
            self.state(
                "risk_score",
                0.50,
            ),
        )

        self.assertEqual(
            evaluation.status,
            InvariantStatus.SATISFIED,
        )

    # ========================================================================
    # ALL / ANY
    # ========================================================================

    def test_all_conditions(self):

        invariant = SecurityInvariant(
            invariant_id="inv-all",
            scope_id="scope-a",
            name="Multiple controls",
            description="All controls must remain healthy.",
            conditions=(
                InvariantCondition(
                    key="endpoint",
                    condition_type=(
                        InvariantConditionType.EQUALS
                    ),
                    expected_value="healthy",
                ),
                InvariantCondition(
                    key="network",
                    condition_type=(
                        InvariantConditionType.EQUALS
                    ),
                    expected_value="segmented",
                ),
            ),
            condition_mode="ALL",
        )

        self.engine.add_invariant(
            invariant
        )

        evaluation = self.engine.evaluate(
            "inv-all",
            {
                "endpoint": StateValue(
                    "endpoint",
                    "healthy",
                    utc_now(),
                ),
                "network": StateValue(
                    "network",
                    "segmented",
                    utc_now(),
                ),
            },
        )

        self.assertEqual(
            evaluation.status,
            InvariantStatus.SATISFIED,
        )

    def test_any_condition(self):

        invariant = SecurityInvariant(
            invariant_id="inv-any",
            scope_id="scope-a",
            name="At least one control",
            description="At least one safe condition must hold.",
            conditions=(
                InvariantCondition(
                    key="control_a",
                    condition_type=(
                        InvariantConditionType.BOOLEAN_TRUE
                    ),
                ),
                InvariantCondition(
                    key="control_b",
                    condition_type=(
                        InvariantConditionType.BOOLEAN_TRUE
                    ),
                ),
            ),
            condition_mode="ANY",
        )

        self.engine.add_invariant(
            invariant
        )

        evaluation = self.engine.evaluate(
            "inv-any",
            self.state(
                "control_b",
                True,
            ),
        )

        self.assertEqual(
            evaluation.status,
            InvariantStatus.SATISFIED,
        )

    # ========================================================================
    # Evidence
    # ========================================================================

    def test_evidence_is_preserved(self):

        evaluation = self.engine.evaluate(
            "inv-1",
            self.state(
                "privileged_access",
                True,
            ),
            evidence_ids={
                "evidence-1",
                "evidence-2",
            },
        )

        self.assertEqual(
            evaluation.evidence_ids,
            frozenset(
                {
                    "evidence-1",
                    "evidence-2",
                }
            ),
        )

    # ========================================================================
    # Remediation linkage
    # ========================================================================

    def test_remediation_linkage(self):

        evaluation = self.engine.evaluate(
            "inv-1",
            self.state(
                "privileged_access",
                True,
            ),
        )

        self.assertEqual(
            evaluation.remediation_types,
            (
                RemediationType.INVESTIGATE,
                RemediationType.RESTRICT,
            ),
        )

        self.assertEqual(
            evaluation.remediation_references,
            ("remediation-policy-1",),
        )

    # ========================================================================
    # History
    # ========================================================================

    def test_evaluation_history(self):

        self.engine.evaluate(
            "inv-1",
            self.state(
                "privileged_access",
                False,
            ),
        )

        self.engine.evaluate(
            "inv-1",
            self.state(
                "privileged_access",
                True,
            ),
        )

        history = self.engine.history(
            "inv-1"
        )

        self.assertEqual(
            len(history),
            2,
        )

        self.assertEqual(
            history[-1].status,
            InvariantStatus.VIOLATED,
        )

    def test_current_status(self):

        self.engine.evaluate(
            "inv-1",
            self.state(
                "privileged_access",
                True,
            ),
        )

        self.assertEqual(
            self.engine.current_status(
                "inv-1"
            ),
            InvariantStatus.VIOLATED,
        )

    # ========================================================================
    # Violations
    # ========================================================================

    def test_violation_query(self):

        self.engine.evaluate(
            "inv-1",
            self.state(
                "privileged_access",
                True,
            ),
        )

        violations = (
            self.engine.violated_invariants(
                "scope-a"
            )
        )

        self.assertEqual(
            len(violations),
            1,
        )

        self.assertEqual(
            violations[0].invariant_id,
            "inv-1",
        )

    # ========================================================================
    # Pre-action checks
    # ========================================================================

    def test_pre_action_check_blocks_violation(self):

        check = self.engine.pre_action_check(
            scope_id="scope-a",
            action_reference="candidate-action-1",
            state=self.state(
                "privileged_access",
                True,
            ),
        )

        self.assertTrue(
            check.blocking
        )

        self.assertIn(
            "inv-1",
            check.violated_invariant_ids,
        )

    def test_pre_action_check_passes_safe_state(self):

        check = self.engine.pre_action_check(
            scope_id="scope-a",
            action_reference="candidate-action-2",
            state=self.state(
                "privileged_access",
                False,
            ),
        )

        self.assertFalse(
            check.blocking
        )

        self.assertEqual(
            check.violated_invariant_ids,
            (),
        )

    def test_unknown_can_block(self):

        check = self.engine.pre_action_check(
            scope_id="scope-a",
            action_reference="candidate-action-3",
            state={},
            block_on_unknown=True,
        )

        self.assertTrue(
            check.blocking
        )

    def test_unknown_can_be_nonblocking_when_explicitly_configured(self):

        check = self.engine.pre_action_check(
            scope_id="scope-a",
            action_reference="candidate-action-4",
            state={},
            block_on_unknown=False,
        )

        self.assertFalse(
            check.blocking
        )

    # ========================================================================
    # Scope isolation
    # ========================================================================

    def test_scope_mismatch_rejected(self):

        foreign = SecurityInvariant(
            invariant_id="inv-foreign",
            scope_id="scope-b",
            name="Foreign invariant",
            description="Different tenant/scope.",
            conditions=(
                InvariantCondition(
                    key="x",
                    condition_type=(
                        InvariantConditionType.BOOLEAN_TRUE
                    ),
                ),
            ),
        )

        self.engine.add_invariant(
            foreign
        )

        with self.assertRaises(ValueError):
            self.engine.pre_action_check(
                scope_id="scope-a",
                action_reference="action",
                state=self.state(
                    "x",
                    True,
                ),
                invariant_ids=(
                    "inv-foreign",
                ),
            )

    # ========================================================================
    # Disabled invariant
    # ========================================================================

    def test_disabled_invariant_unknown(self):

        disabled = SecurityInvariant(
            invariant_id="inv-disabled",
            scope_id="scope-a",
            name="Disabled",
            description="Disabled invariant.",
            conditions=(
                InvariantCondition(
                    key="x",
                    condition_type=(
                        InvariantConditionType.BOOLEAN_TRUE
                    ),
                ),
            ),
            enabled=False,
        )

        self.engine.add_invariant(
            disabled
        )

        evaluation = self.engine.evaluate(
            "inv-disabled",
            self.state(
                "x",
                True,
            ),
        )

        self.assertEqual(
            evaluation.status,
            InvariantStatus.UNKNOWN,
        )

    # ========================================================================
    # Validation
    # ========================================================================

    def test_validation_clean(self):

        self.engine.evaluate(
            "inv-1",
            self.state(
                "privileged_access",
                False,
            ),
        )

        self.assertEqual(
            self.engine.validate(),
            [],
        )


# ============================================================================
# TEST RUNNER
# ============================================================================

def run_phase11_tests() -> None:

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        Phase11Tests
    )

    result = unittest.TextTestRunner(
        verbosity=2
    ).run(suite)

    if not result.wasSuccessful():
        raise AssertionError(
            "Phase 11 verification failed"
        )


if __name__ == "__main__":
    run_phase11_tests()
