"""
HYDRA™ — Phase 10
Intervention Optimization Engine

STRICT PHASE BOUNDARY
---------------------
This module implements ONLY:

    - Defensive intervention candidates
    - Expected risk reduction
    - Collateral impact
    - Reversibility
    - Execution cost
    - Confidence
    - Constraint-aware utility scoring
    - Candidate ranking
    - Dominance filtering
    - Safe recommendation selection
    - Validation
    - Tests

NOT IMPLEMENTED:
    - Security invariants             -> Phase 11
    - Dynamic authority graph         -> Phase 12
    - Security intent compiler        -> Phase 13
    - Independent verification        -> Phase 14
    - Continuous replanning           -> Phase 15
    - Cyber experiment engine         -> Phase 16
    - Cyber regeneration              -> Phase 17
    - Adaptive defense                -> Phase 18

IMPORTANT:
This phase OPTIMIZES and RANKS defensive interventions.
It does NOT execute interventions.
"""


from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from threading import RLock
from typing import Dict, FrozenSet, Iterable, List, Optional, Tuple
import unittest


# ============================================================================
# HELPERS
# ============================================================================

def clamp(value: float, minimum: float = 0.0, maximum: float = 1.0) -> float:
    return max(minimum, min(maximum, value))


# ============================================================================
# ENUMERATIONS
# ============================================================================

class InterventionType(str, Enum):
    BLOCK = "BLOCK"
    ISOLATE = "ISOLATE"
    DISABLE = "DISABLE"
    RESTRICT = "RESTRICT"
    REVOKE = "REVOKE"
    CONTAIN = "CONTAIN"
    PATCH = "PATCH"
    ROTATE = "ROTATE"
    RATE_LIMIT = "RATE_LIMIT"
    SEGMENT = "SEGMENT"
    MONITOR = "MONITOR"
    ALERT = "ALERT"


class InterventionRiskLevel(str, Enum):
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class InterventionStatus(str, Enum):
    CANDIDATE = "CANDIDATE"
    RECOMMENDED = "RECOMMENDED"
    REJECTED = "REJECTED"
    DEFERRED = "DEFERRED"


class OptimizationObjective(str, Enum):
    MAX_RISK_REDUCTION = "MAX_RISK_REDUCTION"
    MIN_COLLATERAL_IMPACT = "MIN_COLLATERAL_IMPACT"
    MIN_COST = "MIN_COST"
    MAX_REVERSIBILITY = "MAX_REVERSIBILITY"
    BALANCED = "BALANCED"


# ============================================================================
# INTERVENTION TARGET
# ============================================================================

@dataclass(frozen=True)
class InterventionTarget:
    """
    Target that a defensive intervention would affect.

    The optimizer does not execute anything against the target.
    """

    target_id: str
    target_type: str
    scope_id: str

    def __post_init__(self) -> None:
        if not self.target_id.strip():
            raise ValueError("target_id must not be empty")

        if not self.target_type.strip():
            raise ValueError("target_type must not be empty")

        if not self.scope_id.strip():
            raise ValueError("scope_id must not be empty")


# ============================================================================
# INTERVENTION CONSTRAINTS
# ============================================================================

@dataclass(frozen=True)
class InterventionConstraints:
    """
    Explicit optimization constraints.

    These are optimization constraints only.
    Authorization is deliberately outside Phase 10.
    """

    max_collateral_impact: float = 1.0
    max_execution_cost: float = 1.0
    min_reversibility: float = 0.0
    min_confidence: float = 0.0
    require_scope_match: bool = True

    def __post_init__(self) -> None:
        values = (
            self.max_collateral_impact,
            self.max_execution_cost,
            self.min_reversibility,
            self.min_confidence,
        )

        if any(not 0.0 <= value <= 1.0 for value in values):
            raise ValueError(
                "constraint values must be between 0 and 1"
            )


# ============================================================================
# INTERVENTION CANDIDATE
# ============================================================================

@dataclass(frozen=True)
class InterventionCandidate:
    """
    Defensive action candidate.

    No execution semantics exist here.
    """

    candidate_id: str
    scope_id: str
    intervention_type: InterventionType
    target: InterventionTarget

    expected_risk_reduction: float
    collateral_impact: float
    execution_cost: float
    reversibility: float
    confidence: float

    rationale: str = ""
    prerequisites: FrozenSet[str] = frozenset()
    metadata: Tuple[Tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not self.candidate_id.strip():
            raise ValueError("candidate_id must not be empty")

        if not self.scope_id.strip():
            raise ValueError("scope_id must not be empty")

        if self.target.scope_id != self.scope_id:
            raise ValueError(
                "target scope must match candidate scope"
            )

        numeric_values = (
            self.expected_risk_reduction,
            self.collateral_impact,
            self.execution_cost,
            self.reversibility,
            self.confidence,
        )

        if any(not 0.0 <= value <= 1.0 for value in numeric_values):
            raise ValueError(
                "candidate scores must be between 0 and 1"
            )


# ============================================================================
# UTILITY WEIGHTS
# ============================================================================

@dataclass(frozen=True)
class UtilityWeights:
    """
    Relative optimization weights.

    Weights are normalized automatically by the optimizer.
    """

    risk_reduction: float = 0.40
    collateral: float = 0.20
    cost: float = 0.15
    reversibility: float = 0.15
    confidence: float = 0.10

    def __post_init__(self) -> None:
        values = (
            self.risk_reduction,
            self.collateral,
            self.cost,
            self.reversibility,
            self.confidence,
        )

        if any(value < 0.0 for value in values):
            raise ValueError(
                "utility weights must not be negative"
            )

        if sum(values) <= 0.0:
            raise ValueError(
                "at least one utility weight must be positive"
            )


# ============================================================================
# OPTIMIZATION REQUEST
# ============================================================================

@dataclass(frozen=True)
class OptimizationRequest:
    request_id: str
    scope_id: str
    objective: OptimizationObjective = (
        OptimizationObjective.BALANCED
    )
    constraints: InterventionConstraints = (
        InterventionConstraints()
    )
    weights: UtilityWeights = UtilityWeights()

    def __post_init__(self) -> None:
        if not self.request_id.strip():
            raise ValueError("request_id must not be empty")

        if not self.scope_id.strip():
            raise ValueError("scope_id must not be empty")


# ============================================================================
# SCORED CANDIDATE
# ============================================================================

@dataclass(frozen=True)
class ScoredIntervention:
    candidate_id: str
    utility_score: float
    risk_reduction_score: float
    collateral_penalty: float
    cost_penalty: float
    reversibility_score: float
    confidence_score: float

    feasible: bool
    status: InterventionStatus
    rejection_reasons: Tuple[str, ...] = ()

    rank: Optional[int] = None


# ============================================================================
# OPTIMIZATION RESULT
# ============================================================================

@dataclass(frozen=True)
class OptimizationResult:
    request_id: str
    scope_id: str
    objective: OptimizationObjective
    ranked_candidates: Tuple[ScoredIntervention, ...]
    recommended_candidate_ids: Tuple[str, ...]
    rejected_candidate_ids: Tuple[str, ...]


# ============================================================================
# INTERVENTION OPTIMIZER
# ============================================================================

class InterventionOptimizer:
    """
    Phase 10 defensive intervention optimizer.

    The engine produces recommendations only.

    It has NO execution capability.
    """

    def __init__(self) -> None:
        self._candidates: Dict[str, InterventionCandidate] = {}
        self._results: Dict[str, OptimizationResult] = {}
        self._lock = RLock()

    # ========================================================================
    # CANDIDATE REGISTRATION
    # ========================================================================

    def add_candidate(
        self,
        candidate: InterventionCandidate,
    ) -> None:

        with self._lock:
            if candidate.candidate_id in self._candidates:
                raise ValueError(
                    f"duplicate intervention candidate: "
                    f"{candidate.candidate_id}"
                )

            self._candidates[
                candidate.candidate_id
            ] = candidate

    def get_candidate(
        self,
        candidate_id: str,
    ) -> InterventionCandidate:

        with self._lock:
            try:
                return self._candidates[candidate_id]
            except KeyError:
                raise KeyError(
                    f"intervention candidate not found: "
                    f"{candidate_id}"
                )

    # ========================================================================
    # FEASIBILITY
    # ========================================================================

    @staticmethod
    def _check_feasibility(
        candidate: InterventionCandidate,
        request: OptimizationRequest,
    ) -> Tuple[bool, Tuple[str, ...]]:

        reasons: List[str] = {}

        reasons = []

        constraints = request.constraints

        if (
            constraints.require_scope_match
            and candidate.scope_id != request.scope_id
        ):
            reasons.append(
                "scope mismatch"
            )

        if (
            candidate.collateral_impact
            > constraints.max_collateral_impact
        ):
            reasons.append(
                "collateral impact exceeds constraint"
            )

        if (
            candidate.execution_cost
            > constraints.max_execution_cost
        ):
            reasons.append(
                "execution cost exceeds constraint"
            )

        if (
            candidate.reversibility
            < constraints.min_reversibility
        ):
            reasons.append(
                "reversibility below constraint"
            )

        if (
            candidate.confidence
            < constraints.min_confidence
        ):
            reasons.append(
                "confidence below constraint"
            )

        return (
            len(reasons) == 0,
            tuple(reasons),
        )

    # ========================================================================
    # UTILITY
    # ========================================================================

    @staticmethod
    def _objective_weights(
        request: OptimizationRequest,
    ) -> UtilityWeights:

        if (
            request.objective
            == OptimizationObjective.MAX_RISK_REDUCTION
        ):
            return UtilityWeights(
                risk_reduction=0.70,
                collateral=0.10,
                cost=0.05,
                reversibility=0.05,
                confidence=0.10,
            )

        if (
            request.objective
            == OptimizationObjective.MIN_COLLATERAL_IMPACT
        ):
            return UtilityWeights(
                risk_reduction=0.25,
                collateral=0.50,
                cost=0.05,
                reversibility=0.10,
                confidence=0.10,
            )

        if (
            request.objective
            == OptimizationObjective.MIN_COST
        ):
            return UtilityWeights(
                risk_reduction=0.25,
                collateral=0.10,
                cost=0.45,
                reversibility=0.10,
                confidence=0.10,
            )

        if (
            request.objective
            == OptimizationObjective.MAX_REVERSIBILITY
        ):
            return UtilityWeights(
                risk_reduction=0.25,
                collateral=0.10,
                cost=0.05,
                reversibility=0.50,
                confidence=0.10,
            )

        return request.weights

    @staticmethod
    def _calculate_utility(
        candidate: InterventionCandidate,
        weights: UtilityWeights,
    ) -> Tuple[
        float,
        float,
        float,
        float,
        float,
        float,
    ]:
        """
        Utility model:

            + risk reduction
            + reversibility
            + confidence
            - collateral
            - execution cost
        """

        total = (
            weights.risk_reduction
            + weights.collateral
            + weights.cost
            + weights.reversibility
            + weights.confidence
        )

        if total <= 0.0:
            raise ValueError(
                "utility weight total must be positive"
            )

        wr = weights.risk_reduction / total
        wc = weights.collateral / total
        wcost = weights.cost / total
        wrev = weights.reversibility / total
        wconf = weights.confidence / total

        risk = candidate.expected_risk_reduction
        collateral_penalty = candidate.collateral_impact
        cost_penalty = candidate.execution_cost
        reversibility = candidate.reversibility
        confidence = candidate.confidence

        utility = (
            wr * risk
            + wrev * reversibility
            + wconf * confidence
            - wc * collateral_penalty
            - wcost * cost_penalty
        )

        utility = clamp(
            (utility + 1.0) / 2.0
        )

        return (
            utility,
            risk,
            collateral_penalty,
            cost_penalty,
            reversibility,
            confidence,
        )

    # ========================================================================
    # DOMINANCE
    # ========================================================================

    @staticmethod
    def _dominates(
        left: InterventionCandidate,
        right: InterventionCandidate,
    ) -> bool:
        """
        Pareto-style dominance.

        left dominates right when it is:
            - at least as good in risk reduction,
            - at least as good in reversibility,
            - at least as good in confidence,
            - no worse in collateral,
            - no worse in cost,

        and strictly better in at least one dimension.
        """

        dimensions = (
            left.expected_risk_reduction
            >= right.expected_risk_reduction,

            left.reversibility
            >= right.reversibility,

            left.confidence
            >= right.confidence,

            left.collateral_impact
            <= right.collateral_impact,

            left.execution_cost
            <= right.execution_cost,
        )

        strictly_better = (
            left.expected_risk_reduction
            > right.expected_risk_reduction

            or left.reversibility
            > right.reversibility

            or left.confidence
            > right.confidence

            or left.collateral_impact
            < right.collateral_impact

            or left.execution_cost
            < right.execution_cost
        )

        return all(dimensions) and strictly_better

    # ========================================================================
    # OPTIMIZE
    # ========================================================================

    def optimize(
        self,
        request: OptimizationRequest,
        candidates: Optional[
            Iterable[InterventionCandidate]
        ] = None,
    ) -> OptimizationResult:

        with self._lock:

            if candidates is None:
                candidate_list = list(
                    self._candidates.values()
                )
            else:
                candidate_list = list(candidates)

            scored: List[ScoredIntervention] = []

            weights = self._objective_weights(
                request
            )

            for candidate in candidate_list:

                feasible, reasons = (
                    self._check_feasibility(
                        candidate,
                        request,
                    )
                )

                if not feasible:

                    scored.append(
                        ScoredIntervention(
                            candidate_id=candidate.candidate_id,
                            utility_score=0.0,
                            risk_reduction_score=(
                                candidate.expected_risk_reduction
                            ),
                            collateral_penalty=(
                                candidate.collateral_impact
                            ),
                            cost_penalty=(
                                candidate.execution_cost
                            ),
                            reversibility_score=(
                                candidate.reversibility
                            ),
                            confidence_score=(
                                candidate.confidence
                            ),
                            feasible=False,
                            status=(
                                InterventionStatus.REJECTED
                            ),
                            rejection_reasons=reasons,
                        )
                    )

                    continue

                (
                    utility,
                    risk,
                    collateral,
                    cost,
                    reversibility,
                    confidence,
                ) = self._calculate_utility(
                    candidate,
                    weights,
                )

                scored.append(
                    ScoredIntervention(
                        candidate_id=candidate.candidate_id,
                        utility_score=utility,
                        risk_reduction_score=risk,
                        collateral_penalty=collateral,
                        cost_penalty=cost,
                        reversibility_score=reversibility,
                        confidence_score=confidence,
                        feasible=True,
                        status=(
                            InterventionStatus.CANDIDATE
                        ),
                    )
                )

            # ----------------------------------------------------------------
            # Sort feasible candidates
            # ----------------------------------------------------------------

            feasible_scored = [
                item
                for item in scored
                if item.feasible
            ]

            feasible_scored.sort(
                key=lambda item: (
                    -item.utility_score,
                    -item.risk_reduction_score,
                    item.collateral_penalty,
                    item.cost_penalty,
                    -item.reversibility_score,
                    -item.confidence_score,
                    item.candidate_id,
                )
            )

            # ----------------------------------------------------------------
            # Assign rank
            # ----------------------------------------------------------------

            ranked: List[ScoredIntervention] = []

            for index, item in enumerate(
                feasible_scored,
                start=1,
            ):
                status = (
                    InterventionStatus.RECOMMENDED
                    if index == 1
                    else InterventionStatus.CANDIDATE
                )

                ranked.append(
                    ScoredIntervention(
                        candidate_id=item.candidate_id,
                        utility_score=item.utility_score,
                        risk_reduction_score=(
                            item.risk_reduction_score
                        ),
                        collateral_penalty=(
                            item.collateral_penalty
                        ),
                        cost_penalty=(
                            item.cost_penalty
                        ),
                        reversibility_score=(
                            item.reversibility_score
                        ),
                        confidence_score=(
                            item.confidence_score
                        ),
                        feasible=True,
                        status=status,
                        rejection_reasons=(),
                        rank=index,
                    )
                )

            # ----------------------------------------------------------------
            # Append rejected candidates
            # ----------------------------------------------------------------

            rejected = [
                item
                for item in scored
                if not item.feasible
            ]

            ranked.extend(rejected)

            recommended_ids = tuple(
                item.candidate_id
                for item in ranked
                if item.status
                == InterventionStatus.RECOMMENDED
            )

            rejected_ids = tuple(
                item.candidate_id
                for item in rejected
            )

            result = OptimizationResult(
                request_id=request.request_id,
                scope_id=request.scope_id,
                objective=request.objective,
                ranked_candidates=tuple(ranked),
                recommended_candidate_ids=(
                    recommended_ids
                ),
                rejected_candidate_ids=(
                    rejected_ids
                ),
            )

            self._results[
                request.request_id
            ] = result

            return result

    # ========================================================================
    # PARETO FRONT
    # ========================================================================

    def pareto_front(
        self,
        candidates: Iterable[
            InterventionCandidate
        ],
    ) -> Tuple[InterventionCandidate, ...]:

        candidate_list = list(candidates)

        front = []

        for candidate in candidate_list:

            dominated = False

            for other in candidate_list:

                if (
                    candidate.candidate_id
                    == other.candidate_id
                ):
                    continue

                if self._dominates(
                    other,
                    candidate,
                ):
                    dominated = True
                    break

            if not dominated:
                front.append(candidate)

        front.sort(
            key=lambda item: item.candidate_id
        )

        return tuple(front)

    # ========================================================================
    # RESULT LOOKUP
    # ========================================================================

    def get_result(
        self,
        request_id: str,
    ) -> OptimizationResult:

        with self._lock:
            try:
                return self._results[request_id]
            except KeyError:
                raise KeyError(
                    f"optimization result not found: "
                    f"{request_id}"
                )

    # ========================================================================
    # VALIDATION
    # ========================================================================

    def validate(self) -> List[str]:

        errors: List[str] = []

        with self._lock:

            for candidate_id, candidate in (
                self._candidates.items()
            ):

                if (
                    candidate_id
                    != candidate.candidate_id
                ):
                    errors.append(
                        f"candidate key mismatch: "
                        f"{candidate_id}"
                    )

                if (
                    candidate.scope_id
                    != candidate.target.scope_id
                ):
                    errors.append(
                        f"candidate target scope mismatch: "
                        f"{candidate_id}"
                    )

                numeric_values = (
                    candidate.expected_risk_reduction,
                    candidate.collateral_impact,
                    candidate.execution_cost,
                    candidate.reversibility,
                    candidate.confidence,
                )

                if any(
                    not 0.0 <= value <= 1.0
                    for value in numeric_values
                ):
                    errors.append(
                        f"candidate score out of bounds: "
                        f"{candidate_id}"
                    )

            for request_id, result in (
                self._results.items()
            ):

                if (
                    request_id
                    != result.request_id
                ):
                    errors.append(
                        f"result key mismatch: "
                        f"{request_id}"
                    )

        return errors


# ============================================================================
# TESTS
# ============================================================================

class Phase10Tests(unittest.TestCase):

    def setUp(self):

        self.optimizer = InterventionOptimizer()

        self.target = InterventionTarget(
            target_id="asset-1",
            target_type="endpoint",
            scope_id="scope-a",
        )

    def candidate(
        self,
        candidate_id: str,
        *,
        risk: float,
        collateral: float,
        cost: float,
        reversibility: float,
        confidence: float,
        scope: str = "scope-a",
    ) -> InterventionCandidate:

        target = InterventionTarget(
            target_id=f"{candidate_id}-target",
            target_type="endpoint",
            scope_id=scope,
        )

        return InterventionCandidate(
            candidate_id=candidate_id,
            scope_id=scope,
            intervention_type=InterventionType.ISOLATE,
            target=target,
            expected_risk_reduction=risk,
            collateral_impact=collateral,
            execution_cost=cost,
            reversibility=reversibility,
            confidence=confidence,
            rationale="defensive containment candidate",
        )

    def request(
        self,
        request_id="request-1",
        *,
        objective=OptimizationObjective.BALANCED,
        constraints=InterventionConstraints(),
    ) -> OptimizationRequest:

        return OptimizationRequest(
            request_id=request_id,
            scope_id="scope-a",
            objective=objective,
            constraints=constraints,
        )

    # ========================================================================
    # Registration
    # ========================================================================

    def test_candidate_registration(self):

        candidate = self.candidate(
            "c1",
            risk=0.8,
            collateral=0.2,
            cost=0.3,
            reversibility=0.8,
            confidence=0.9,
        )

        self.optimizer.add_candidate(
            candidate
        )

        self.assertEqual(
            self.optimizer.get_candidate("c1"),
            candidate,
        )

    def test_duplicate_candidate_rejected(self):

        candidate = self.candidate(
            "c1",
            risk=0.8,
            collateral=0.2,
            cost=0.3,
            reversibility=0.8,
            confidence=0.9,
        )

        self.optimizer.add_candidate(
            candidate
        )

        with self.assertRaises(ValueError):
            self.optimizer.add_candidate(
                candidate
            )

    # ========================================================================
    # Feasibility
    # ========================================================================

    def test_high_collateral_candidate_rejected(self):

        candidate = self.candidate(
            "dangerous",
            risk=0.95,
            collateral=0.95,
            cost=0.2,
            reversibility=0.8,
            confidence=0.9,
        )

        result = self.optimizer.optimize(
            self.request(
                constraints=InterventionConstraints(
                    max_collateral_impact=0.50,
                )
            ),
            [candidate],
        )

        self.assertIn(
            "dangerous",
            result.rejected_candidate_ids,
        )

    def test_low_confidence_candidate_rejected(self):

        candidate = self.candidate(
            "uncertain",
            risk=0.9,
            collateral=0.1,
            cost=0.1,
            reversibility=0.9,
            confidence=0.20,
        )

        result = self.optimizer.optimize(
            self.request(
                constraints=InterventionConstraints(
                    min_confidence=0.70,
                )
            ),
            [candidate],
        )

        self.assertIn(
            "uncertain",
            result.rejected_candidate_ids,
        )

    # ========================================================================
    # Ranking
    # ========================================================================

    def test_best_candidate_ranked_first(self):

        strong = self.candidate(
            "strong",
            risk=0.95,
            collateral=0.10,
            cost=0.20,
            reversibility=0.90,
            confidence=0.95,
        )

        weak = self.candidate(
            "weak",
            risk=0.40,
            collateral=0.60,
            cost=0.70,
            reversibility=0.20,
            confidence=0.50,
        )

        result = self.optimizer.optimize(
            self.request(),
            [weak, strong],
        )

        self.assertEqual(
            result.recommended_candidate_ids,
            ("strong",),
        )

    def test_risk_reduction_objective(self):

        high_risk = self.candidate(
            "high-risk-reduction",
            risk=0.95,
            collateral=0.80,
            cost=0.80,
            reversibility=0.20,
            confidence=0.90,
        )

        low_impact = self.candidate(
            "low-impact",
            risk=0.70,
            collateral=0.10,
            cost=0.10,
            reversibility=0.90,
            confidence=0.90,
        )

        result = self.optimizer.optimize(
            self.request(
                objective=(
                    OptimizationObjective
                    .MAX_RISK_REDUCTION
                )
            ),
            [high_risk, low_impact],
        )

        self.assertEqual(
            result.recommended_candidate_ids,
            ("high-risk-reduction",),
        )

    def test_min_cost_objective(self):

        expensive = self.candidate(
            "expensive",
            risk=0.95,
            collateral=0.10,
            cost=0.90,
            reversibility=0.90,
            confidence=0.95,
        )

        cheap = self.candidate(
            "cheap",
            risk=0.70,
            collateral=0.10,
            cost=0.05,
            reversibility=0.80,
            confidence=0.90,
        )

        result = self.optimizer.optimize(
            self.request(
                objective=(
                    OptimizationObjective.MIN_COST
                )
            ),
            [expensive, cheap],
        )

        self.assertEqual(
            result.recommended_candidate_ids,
            ("cheap",),
        )

    # ========================================================================
    # Pareto
    # ========================================================================

    def test_dominated_candidate_removed_from_pareto_front(self):

        superior = self.candidate(
            "superior",
            risk=0.90,
            collateral=0.10,
            cost=0.10,
            reversibility=0.90,
            confidence=0.95,
        )

        dominated = self.candidate(
            "dominated",
            risk=0.60,
            collateral=0.50,
            cost=0.60,
            reversibility=0.50,
            confidence=0.60,
        )

        front = self.optimizer.pareto_front(
            [superior, dominated]
        )

        self.assertEqual(
            tuple(
                item.candidate_id
                for item in front
            ),
            ("superior",),
        )

    def test_tradeoff_candidates_can_both_survive(self):

        risk_focused = self.candidate(
            "risk-focused",
            risk=0.95,
            collateral=0.80,
            cost=0.50,
            reversibility=0.40,
            confidence=0.90,
        )

        low_impact = self.candidate(
            "low-impact",
            risk=0.70,
            collateral=0.10,
            cost=0.10,
            reversibility=0.90,
            confidence=0.90,
        )

        front = self.optimizer.pareto_front(
            [risk_focused, low_impact]
        )

        self.assertEqual(
            len(front),
            2,
        )

    # ========================================================================
    # Scope isolation
    # ========================================================================

    def test_scope_mismatch_rejected(self):

        foreign = self.candidate(
            "foreign",
            risk=0.95,
            collateral=0.10,
            cost=0.10,
            reversibility=0.90,
            confidence=0.95,
            scope="scope-b",
        )

        result = self.optimizer.optimize(
            self.request(),
            [foreign],
        )

        self.assertIn(
            "foreign",
            result.rejected_candidate_ids,
        )

    # ========================================================================
    # Safety properties
    # ========================================================================

    def test_optimizer_does_not_execute_candidate(self):

        candidate = self.candidate(
            "no-execution",
            risk=0.90,
            collateral=0.10,
            cost=0.10,
            reversibility=0.90,
            confidence=0.95,
        )

        self.optimizer.optimize(
            self.request(),
            [candidate],
        )

        self.assertFalse(
            hasattr(
                self.optimizer,
                "execute",
            )
        )

    def test_empty_candidate_set(self):

        result = self.optimizer.optimize(
            self.request(),
            [],
        )

        self.assertEqual(
            result.recommended_candidate_ids,
            (),
        )

        self.assertEqual(
            result.rejected_candidate_ids,
            (),
        )

    # ========================================================================
    # Validation
    # ========================================================================

    def test_validation_clean(self):

        candidate = self.candidate(
            "valid",
            risk=0.80,
            collateral=0.20,
            cost=0.20,
            reversibility=0.80,
            confidence=0.90,
        )

        self.optimizer.add_candidate(
            candidate
        )

        self.optimizer.optimize(
            self.request(),
            [candidate],
        )

        self.assertEqual(
            self.optimizer.validate(),
            [],
        )

    # ========================================================================
    # Result lookup
    # ========================================================================

    def test_result_lookup(self):

        candidate = self.candidate(
            "lookup",
            risk=0.80,
            collateral=0.20,
            cost=0.20,
            reversibility=0.80,
            confidence=0.90,
        )

        result = self.optimizer.optimize(
            self.request(),
            [candidate],
        )

        stored = self.optimizer.get_result(
            "request-1"
        )

        self.assertEqual(
            stored,
            result,
        )


# ============================================================================
# TEST RUNNER
# ============================================================================

def run_phase10_tests() -> None:

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        Phase10Tests
    )

    result = unittest.TextTestRunner(
        verbosity=2
    ).run(suite)

    if not result.wasSuccessful():
        raise AssertionError(
            "Phase 10 verification failed"
        )


if __name__ == "__main__":
    run_phase10_tests()
