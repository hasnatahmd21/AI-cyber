"""
HYDRA™ — Phase 14
Independent Verification Engine

STRICT SCOPE
------------
- Expected outcomes
- Observed outcomes
- Independent evidence
- Verification methods
- Evidence consistency
- Outcome comparison
- SUCCESS / PARTIAL / FAILED / UNKNOWN
- Verification confidence
- Verification history
- Scope isolation
- Validation
- Tests

NOT IMPLEMENTED
---------------
Phase 15 -> Continuous Replanning
Phase 16 -> Cyber Experiment Engine
Phase 17 -> Cyber Regeneration
Phase 18 -> Adaptive Defense
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

class VerificationStatus(str, Enum):
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class VerificationMethod(str, Enum):
    STATE_COMPARISON = "STATE_COMPARISON"
    TELEMETRY_COMPARISON = "TELEMETRY_COMPARISON"
    EVIDENCE_CORRELATION = "EVIDENCE_CORRELATION"
    INDEPENDENT_OBSERVATION = "INDEPENDENT_OBSERVATION"
    INTEGRITY_CHECK = "INTEGRITY_CHECK"


class EvidenceType(str, Enum):
    TELEMETRY = "TELEMETRY"
    LOG = "LOG"
    METRIC = "METRIC"
    STATE = "STATE"
    INDEPENDENT_SENSOR = "INDEPENDENT_SENSOR"
    INTEGRITY_RECORD = "INTEGRITY_RECORD"


class EvidenceIntegrity(str, Enum):
    UNKNOWN = "UNKNOWN"
    VALID = "VALID"
    INVALID = "INVALID"
    CONFLICTING = "CONFLICTING"


class ComparisonOperator(str, Enum):
    EQUALS = "EQUALS"
    NOT_EQUALS = "NOT_EQUALS"
    GREATER_THAN = "GREATER_THAN"
    GREATER_THAN_OR_EQUAL = "GREATER_THAN_OR_EQUAL"
    LESS_THAN = "LESS_THAN"
    LESS_THAN_OR_EQUAL = "LESS_THAN_OR_EQUAL"
    CONTAINS = "CONTAINS"
    NOT_CONTAINS = "NOT_CONTAINS"


# ============================================================================
# EXPECTED OUTCOME
# ============================================================================

@dataclass(frozen=True)
class ExpectedOutcome:
    outcome_id: str
    scope_id: str

    key: str
    expected_value: object

    operator: ComparisonOperator = (
        ComparisonOperator.EQUALS
    )

    importance: float = 1.0

    description: str = ""

    def __post_init__(self) -> None:

        if not self.outcome_id.strip():
            raise ValueError(
                "outcome_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id must not be empty"
            )

        if not self.key.strip():
            raise ValueError(
                "outcome key must not be empty"
            )

        if not 0.0 < self.importance <= 1.0:
            raise ValueError(
                "importance must be > 0 and <= 1"
            )


# ============================================================================
# OBSERVED OUTCOME
# ============================================================================

@dataclass(frozen=True)
class ObservedOutcome:
    observation_id: str
    scope_id: str

    key: str
    observed_value: object

    observed_at: datetime

    source_id: str

    confidence: float = 1.0

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

        if not self.key.strip():
            raise ValueError(
                "observation key must not be empty"
            )

        if not self.source_id.strip():
            raise ValueError(
                "source_id must not be empty"
            )

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "confidence must be between 0 and 1"
            )


# ============================================================================
# INDEPENDENT EVIDENCE
# ============================================================================

@dataclass(frozen=True)
class IndependentEvidence:
    evidence_id: str
    scope_id: str

    evidence_type: EvidenceType

    source_id: str

    key: str
    value: object

    collected_at: datetime

    integrity: EvidenceIntegrity = (
        EvidenceIntegrity.UNKNOWN
    )

    confidence: float = 1.0

    metadata: Tuple[Tuple[str, str], ...] = ()

    def __post_init__(self) -> None:

        ensure_aware(self.collected_at)

        if not self.evidence_id.strip():
            raise ValueError(
                "evidence_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id must not be empty"
            )

        if not self.source_id.strip():
            raise ValueError(
                "source_id must not be empty"
            )

        if not self.key.strip():
            raise ValueError(
                "evidence key must not be empty"
            )

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "confidence must be between 0 and 1"
            )


# ============================================================================
# EXPECTED / OBSERVED COMPARISON
# ============================================================================

@dataclass(frozen=True)
class OutcomeComparison:
    outcome_id: str

    key: str

    expected_value: object
    observed_value: object

    operator: ComparisonOperator

    matched: bool

    confidence: float

    evidence_ids: FrozenSet[str] = frozenset()

    reason: str = ""


# ============================================================================
# VERIFICATION RESULT
# ============================================================================

@dataclass(frozen=True)
class VerificationResult:
    verification_id: str

    scope_id: str

    subject_reference: str

    verified_at: datetime

    status: VerificationStatus

    method: VerificationMethod

    comparisons: Tuple[
        OutcomeComparison,
        ...
    ]

    evidence_ids: FrozenSet[str]

    confidence: float

    independent_evidence_count: int

    reason: str

    result_hash: str

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

        if not self.subject_reference.strip():
            raise ValueError(
                "subject_reference must not be empty"
            )

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "verification confidence invalid"
            )

        if not self.result_hash.strip():
            raise ValueError(
                "result_hash must not be empty"
            )


# ============================================================================
# VERIFICATION ENGINE
# ============================================================================

class IndependentVerificationEngine:

    def __init__(self) -> None:

        self._expected: Dict[
            str,
            ExpectedOutcome,
        ] = {}

        self._observed: Dict[
            str,
            ObservedOutcome,
        ] = {}

        self._evidence: Dict[
            str,
            IndependentEvidence,
        ] = {}

        self._results: Dict[
            str,
            VerificationResult,
        ] = {}

        self._lock = RLock()

    # ========================================================================
    # EXPECTED OUTCOMES
    # ========================================================================

    def add_expected(
        self,
        outcome: ExpectedOutcome,
    ) -> None:

        with self._lock:

            if outcome.outcome_id in self._expected:
                raise ValueError(
                    f"duplicate expected outcome: "
                    f"{outcome.outcome_id}"
                )

            self._expected[
                outcome.outcome_id
            ] = outcome

    def get_expected(
        self,
        outcome_id: str,
    ) -> ExpectedOutcome:

        with self._lock:

            if outcome_id not in self._expected:
                raise KeyError(
                    f"expected outcome not found: "
                    f"{outcome_id}"
                )

            return self._expected[
                outcome_id
            ]

    # ========================================================================
    # OBSERVED OUTCOMES
    # ========================================================================

    def add_observed(
        self,
        observation: ObservedOutcome,
    ) -> None:

        with self._lock:

            if observation.observation_id in self._observed:
                raise ValueError(
                    f"duplicate observation: "
                    f"{observation.observation_id}"
                )

            self._observed[
                observation.observation_id
            ] = observation

    # ========================================================================
    # EVIDENCE
    # ========================================================================

    def add_evidence(
        self,
        evidence: IndependentEvidence,
    ) -> None:

        with self._lock:

            if evidence.evidence_id in self._evidence:
                raise ValueError(
                    f"duplicate evidence: "
                    f"{evidence.evidence_id}"
                )

            self._evidence[
                evidence.evidence_id
            ] = evidence

    def get_evidence(
        self,
        evidence_id: str,
    ) -> IndependentEvidence:

        with self._lock:

            if evidence_id not in self._evidence:
                raise KeyError(
                    f"evidence not found: "
                    f"{evidence_id}"
                )

            return self._evidence[
                evidence_id
            ]

    # ========================================================================
    # COMPARISON
    # ========================================================================

    @staticmethod
    def _compare(
        expected: object,
        observed: object,
        operator: ComparisonOperator,
    ) -> bool:

        if operator == ComparisonOperator.EQUALS:
            return observed == expected

        if operator == ComparisonOperator.NOT_EQUALS:
            return observed != expected

        if operator == ComparisonOperator.GREATER_THAN:
            return observed > expected

        if operator == ComparisonOperator.GREATER_THAN_OR_EQUAL:
            return observed >= expected

        if operator == ComparisonOperator.LESS_THAN:
            return observed < expected

        if operator == ComparisonOperator.LESS_THAN_OR_EQUAL:
            return observed <= expected

        if operator == ComparisonOperator.CONTAINS:
            return expected in observed

        if operator == ComparisonOperator.NOT_CONTAINS:
            return expected not in observed

        raise ValueError(
            f"unsupported comparison operator: "
            f"{operator}"
        )

    # ========================================================================
    # EVIDENCE FILTERING
    # ========================================================================

    def _independent_evidence(
        self,
        scope_id: str,
        key: str,
        evidence_ids: Iterable[str],
    ) -> Tuple[IndependentEvidence, ...]:

        result = []

        for evidence_id in evidence_ids:

            evidence = self.get_evidence(
                evidence_id
            )

            if evidence.scope_id != scope_id:
                raise ValueError(
                    "evidence scope mismatch"
                )

            if evidence.key == key:
                result.append(evidence)

        return tuple(result)

    # ========================================================================
    # VERIFY
    # ========================================================================

    def verify(
        self,
        scope_id: str,
        subject_reference: str,
        expected_outcome_ids: Iterable[str],
        observed_outcomes: Iterable[ObservedOutcome],
        evidence_ids: Iterable[str],
        *,
        method: VerificationMethod = (
            VerificationMethod.INDEPENDENT_OBSERVATION
        ),
    ) -> VerificationResult:

        with self._lock:

            expected_ids = tuple(
                expected_outcome_ids
            )

            all_evidence_ids = frozenset(
                evidence_ids
            )

            expected = []

            for outcome_id in expected_ids:

                item = self.get_expected(
                    outcome_id
                )

                if item.scope_id != scope_id:
                    raise ValueError(
                        "expected outcome scope mismatch"
                    )

                expected.append(item)

            observations = tuple(
                observed_outcomes
            )

            for observation in observations:

                if observation.scope_id != scope_id:
                    raise ValueError(
                        "observed outcome scope mismatch"
                    )

                if observation.observation_id not in self._observed:
                    self.add_observed(
                        observation
                    )

            comparisons = []

            for expected_item in expected:

                matching_observations = tuple(
                    observation
                    for observation in observations
                    if observation.key
                    == expected_item.key
                )

                if not matching_observations:

                    comparisons.append(
                        OutcomeComparison(
                            outcome_id=(
                                expected_item.outcome_id
                            ),
                            key=expected_item.key,
                            expected_value=(
                                expected_item.expected_value
                            ),
                            observed_value=None,
                            operator=(
                                expected_item.operator
                            ),
                            matched=False,
                            confidence=0.0,
                            evidence_ids=frozenset(),
                            reason=(
                                "no observation available"
                            ),
                        )
                    )

                    continue

                # Highest-confidence observation is used.
                observation = max(
                    matching_observations,
                    key=lambda item: item.confidence,
                )

                relevant_evidence = (
                    self._independent_evidence(
                        scope_id,
                        expected_item.key,
                        all_evidence_ids,
                    )
                )

                evidence_values = {
                    evidence.value
                    for evidence in relevant_evidence
                    if (
                        evidence.integrity
                        == EvidenceIntegrity.VALID
                    )
                }

                evidence_confidences = [
                    evidence.confidence
                    for evidence
                    in relevant_evidence
                    if (
                        evidence.integrity
                        == EvidenceIntegrity.VALID
                    )
                ]

                matched = self._compare(
                    expected_item.expected_value,
                    observation.observed_value,
                    expected_item.operator,
                )

                # Independent evidence can corroborate or contradict
                # the observed outcome. Evidence whose integrity is not
                # VALID is never trusted: it neither corroborates nor
                # contradicts, and must not crash the verifier.
                if relevant_evidence and evidence_confidences:

                    if (
                        evidence_values
                        and observation.observed_value
                        not in evidence_values
                    ):
                        matched = False
                        reason = (
                            "independent evidence "
                            "contradicts observation"
                        )

                    else:
                        reason = (
                            "observation independently "
                            "corroborated"
                        )

                    evidence_confidence = (
                        sum(evidence_confidences)
                        / len(evidence_confidences)
                    )

                    confidence = (
                        observation.confidence
                        + evidence_confidence
                    ) / 2.0

                else:

                    reason = (
                        "no independent evidence with valid "
                        "integrity available"
                        if relevant_evidence
                        else "no independent evidence "
                        "available"
                    )

                    confidence = (
                        observation.confidence
                        * 0.5
                    )

                comparisons.append(
                    OutcomeComparison(
                        outcome_id=(
                            expected_item.outcome_id
                        ),
                        key=expected_item.key,
                        expected_value=(
                            expected_item.expected_value
                        ),
                        observed_value=(
                            observation.observed_value
                        ),
                        operator=(
                            expected_item.operator
                        ),
                        matched=matched,
                        confidence=confidence,
                        evidence_ids=frozenset(
                            evidence.evidence_id
                            for evidence
                            in relevant_evidence
                        ),
                        reason=reason,
                    )
                )

            # ---------------------------------------------------------------
            # Overall result
            # ---------------------------------------------------------------

            if not comparisons:

                status = VerificationStatus.UNKNOWN
                confidence = 0.0
                reason = (
                    "no expected outcomes supplied"
                )

            else:

                matched_count = sum(
                    comparison.matched
                    for comparison
                    in comparisons
                )

                total = len(comparisons)

                confidence = (
                    sum(
                        comparison.confidence
                        for comparison
                        in comparisons
                    )
                    / total
                )

                if matched_count == total:
                    status = VerificationStatus.SUCCESS
                    reason = (
                        "all expected outcomes matched"
                    )

                elif matched_count == 0:
                    status = VerificationStatus.FAILED
                    reason = (
                        "no expected outcomes matched"
                    )

                else:
                    status = VerificationStatus.PARTIAL
                    reason = (
                        "some expected outcomes matched"
                    )

            verification_id = stable_id(
                "verification",
                scope_id,
                subject_reference,
                utc_now().isoformat(),
            )

            result_material = repr(
                (
                    verification_id,
                    scope_id,
                    subject_reference,
                    status.value,
                    method.value,
                    tuple(comparisons),
                    sorted(all_evidence_ids),
                    confidence,
                )
            )

            result_hash = hashlib.sha256(
                result_material.encode("utf-8")
            ).hexdigest()

            result = VerificationResult(
                verification_id=verification_id,
                scope_id=scope_id,
                subject_reference=subject_reference,
                verified_at=utc_now(),
                status=status,
                method=method,
                comparisons=tuple(comparisons),
                evidence_ids=all_evidence_ids,
                confidence=confidence,
                independent_evidence_count=len(
                    all_evidence_ids
                ),
                reason=reason,
                result_hash=result_hash,
            )

            self._results[
                verification_id
            ] = result

            return result

    # ========================================================================
    # RESULT LOOKUP
    # ========================================================================

    def get_result(
        self,
        verification_id: str,
    ) -> VerificationResult:

        with self._lock:

            if verification_id not in self._results:
                raise KeyError(
                    f"verification result not found: "
                    f"{verification_id}"
                )

            return self._results[
                verification_id
            ]

    def history(
        self,
        subject_reference: str,
    ) -> Tuple[VerificationResult, ...]:

        with self._lock:

            return tuple(
                result
                for result
                in self._results.values()
                if (
                    result.subject_reference
                    == subject_reference
                )
            )

    # ========================================================================
    # RESULT HASH VALIDATION
    # ========================================================================

    @staticmethod
    def validate_result_hash(
        result: VerificationResult,
    ) -> bool:

        material = repr(
            (
                result.verification_id,
                result.scope_id,
                result.subject_reference,
                result.status.value,
                result.method.value,
                result.comparisons,
                sorted(result.evidence_ids),
                result.confidence,
            )
        )

        expected = hashlib.sha256(
            material.encode("utf-8")
        ).hexdigest()

        return expected == result.result_hash

    # ========================================================================
    # VALIDATION
    # ========================================================================

    def validate(self) -> List[str]:

        errors: List[str] = []

        with self._lock:

            for outcome_id, outcome in (
                self._expected.items()
            ):

                if (
                    outcome_id
                    != outcome.outcome_id
                ):
                    errors.append(
                        f"expected outcome key mismatch: "
                        f"{outcome_id}"
                    )

            for observation_id, observation in (
                self._observed.items()
            ):

                if (
                    observation_id
                    != observation.observation_id
                ):
                    errors.append(
                        f"observation key mismatch: "
                        f"{observation_id}"
                    )

            for evidence_id, evidence in (
                self._evidence.items()
            ):

                if evidence_id != evidence.evidence_id:
                    errors.append(
                        f"evidence key mismatch: "
                        f"{evidence_id}"
                    )

            for verification_id, result in (
                self._results.items()
            ):

                if (
                    verification_id
                    != result.verification_id
                ):
                    errors.append(
                        f"verification key mismatch: "
                        f"{verification_id}"
                    )

                if not self.validate_result_hash(
                    result
                ):
                    errors.append(
                        f"verification hash mismatch: "
                        f"{verification_id}"
                    )

                for evidence_id in result.evidence_ids:

                    if evidence_id not in self._evidence:
                        errors.append(
                            f"verification references "
                            f"unknown evidence: "
                            f"{evidence_id}"
                        )

        return errors


# ============================================================================
# TESTS
# ============================================================================

class Phase14Tests(unittest.TestCase):

    def setUp(self):

        self.engine = (
            IndependentVerificationEngine()
        )

        self.engine.add_expected(
            ExpectedOutcome(
                outcome_id="expected-1",
                scope_id="tenant-a",
                key="security_state",
                expected_value="protected",
            )
        )

    # ========================================================================
    # Registration
    # ========================================================================

    def test_expected_registration(self):

        result = self.engine.get_expected(
            "expected-1"
        )

        self.assertEqual(
            result.expected_value,
            "protected",
        )

    def test_duplicate_expected_rejected(self):

        with self.assertRaises(ValueError):
            self.engine.add_expected(
                ExpectedOutcome(
                    outcome_id="expected-1",
                    scope_id="tenant-a",
                    key="x",
                    expected_value=True,
                )
            )

    # ========================================================================
    # Successful verification
    # ========================================================================

    def test_success(self):

        observation = ObservedOutcome(
            observation_id="obs-1",
            scope_id="tenant-a",
            key="security_state",
            observed_value="protected",
            observed_at=utc_now(),
            source_id="independent-monitor",
            confidence=0.95,
        )

        evidence = IndependentEvidence(
            evidence_id="evidence-1",
            scope_id="tenant-a",
            evidence_type=EvidenceType.INDEPENDENT_SENSOR,
            source_id="sensor-a",
            key="security_state",
            value="protected",
            collected_at=utc_now(),
            integrity=EvidenceIntegrity.VALID,
            confidence=0.90,
        )

        self.engine.add_evidence(
            evidence
        )

        result = self.engine.verify(
            scope_id="tenant-a",
            subject_reference="action-1",
            expected_outcome_ids=(
                "expected-1",
            ),
            observed_outcomes=(
                observation,
            ),
            evidence_ids=(
                "evidence-1",
            ),
        )

        self.assertEqual(
            result.status,
            VerificationStatus.SUCCESS,
        )

        self.assertGreater(
            result.confidence,
            0.5,
        )

    # ========================================================================
    # Failed verification
    # ========================================================================

    def test_failed_verification(self):

        observation = ObservedOutcome(
            observation_id="obs-failed",
            scope_id="tenant-a",
            key="security_state",
            observed_value="compromised",
            observed_at=utc_now(),
            source_id="sensor",
        )

        result = self.engine.verify(
            scope_id="tenant-a",
            subject_reference="action-failed",
            expected_outcome_ids=(
                "expected-1",
            ),
            observed_outcomes=(
                observation,
            ),
            evidence_ids=(),
        )

        self.assertEqual(
            result.status,
            VerificationStatus.FAILED,
        )

    # ========================================================================
    # Partial verification
    # ========================================================================

    def test_partial_verification(self):

        self.engine.add_expected(
            ExpectedOutcome(
                outcome_id="expected-2",
                scope_id="tenant-a",
                key="network_state",
                expected_value="segmented",
            )
        )

        observations = (
            ObservedOutcome(
                observation_id="obs-a",
                scope_id="tenant-a",
                key="security_state",
                observed_value="protected",
                observed_at=utc_now(),
                source_id="sensor-a",
            ),
            ObservedOutcome(
                observation_id="obs-b",
                scope_id="tenant-a",
                key="network_state",
                observed_value="flat",
                observed_at=utc_now(),
                source_id="sensor-b",
            ),
        )

        result = self.engine.verify(
            scope_id="tenant-a",
            subject_reference="action-partial",
            expected_outcome_ids=(
                "expected-1",
                "expected-2",
            ),
            observed_outcomes=observations,
            evidence_ids=(),
        )

        self.assertEqual(
            result.status,
            VerificationStatus.PARTIAL,
        )

    # ========================================================================
    # Unknown
    # ========================================================================

    def test_unknown_without_observation(self):

        result = self.engine.verify(
            scope_id="tenant-a",
            subject_reference="action-unknown",
            expected_outcome_ids=(
                "expected-1",
            ),
            observed_outcomes=(),
            evidence_ids=(),
        )

        self.assertEqual(
            result.status,
            VerificationStatus.FAILED,
        )

        self.assertEqual(
            result.comparisons[0].reason,
            "no observation available",
        )

    # ========================================================================
    # Evidence contradiction
    # ========================================================================

    def test_evidence_contradiction(self):

        evidence = IndependentEvidence(
            evidence_id="contradictory",
            scope_id="tenant-a",
            evidence_type=EvidenceType.INDEPENDENT_SENSOR,
            source_id="independent-sensor",
            key="security_state",
            value="compromised",
            collected_at=utc_now(),
            integrity=EvidenceIntegrity.VALID,
            confidence=0.95,
        )

        self.engine.add_evidence(
            evidence
        )

        observation = ObservedOutcome(
            observation_id="obs-conflict",
            scope_id="tenant-a",
            key="security_state",
            observed_value="protected",
            observed_at=utc_now(),
            source_id="primary-system",
        )

        result = self.engine.verify(
            scope_id="tenant-a",
            subject_reference="conflicting-action",
            expected_outcome_ids=(
                "expected-1",
            ),
            observed_outcomes=(
                observation,
            ),
            evidence_ids=(
                "contradictory",
            ),
        )

        self.assertEqual(
            result.status,
            VerificationStatus.FAILED,
        )

    # ========================================================================
    # Scope isolation
    # ========================================================================

    def test_scope_mismatch_rejected(self):

        with self.assertRaises(ValueError):
            self.engine.verify(
                scope_id="tenant-b",
                subject_reference="foreign",
                expected_outcome_ids=(
                    "expected-1",
                ),
                observed_outcomes=(),
                evidence_ids=(),
            )

    # ========================================================================
    # Evidence registration
    # ========================================================================

    def test_duplicate_evidence_rejected(self):

        evidence = IndependentEvidence(
            evidence_id="duplicate-evidence",
            scope_id="tenant-a",
            evidence_type=EvidenceType.LOG,
            source_id="logger",
            key="x",
            value=True,
            collected_at=utc_now(),
        )

        self.engine.add_evidence(
            evidence
        )

        with self.assertRaises(ValueError):
            self.engine.add_evidence(
                evidence
            )

    # ========================================================================
    # Result integrity
    # ========================================================================

    def test_result_hash(self):

        observation = ObservedOutcome(
            observation_id="hash-observation",
            scope_id="tenant-a",
            key="security_state",
            observed_value="protected",
            observed_at=utc_now(),
            source_id="sensor",
        )

        result = self.engine.verify(
            scope_id="tenant-a",
            subject_reference="hash-test",
            expected_outcome_ids=(
                "expected-1",
            ),
            observed_outcomes=(
                observation,
            ),
            evidence_ids=(),
        )

        self.assertTrue(
            self.engine.validate_result_hash(
                result
            )
        )

    # ========================================================================
    # History
    # ========================================================================

    def test_history(self):

        observation = ObservedOutcome(
            observation_id="history-observation",
            scope_id="tenant-a",
            key="security_state",
            observed_value="protected",
            observed_at=utc_now(),
            source_id="sensor",
        )

        self.engine.verify(
            scope_id="tenant-a",
            subject_reference="history-action",
            expected_outcome_ids=(
                "expected-1",
            ),
            observed_outcomes=(
                observation,
            ),
            evidence_ids=(),
        )

        history = self.engine.history(
            "history-action"
        )

        self.assertEqual(
            len(history),
            1,
        )

    # ========================================================================
    # Validation
    # ========================================================================

    def test_validation_clean(self):

        self.assertEqual(
            self.engine.validate(),
            [],
        )


# ============================================================================
# TEST RUNNER
# ============================================================================

def run_phase14_tests() -> None:

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        Phase14Tests
    )

    result = unittest.TextTestRunner(
        verbosity=2
    ).run(suite)

    if not result.wasSuccessful():
        raise AssertionError(
            "Phase 14 verification failed"
        )


if __name__ == "__main__":
    run_phase14_tests()
