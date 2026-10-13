"""
HYDRA™
PHASE 5 — STATE INTEGRITY ENGINE

Scope ONLY:
    - State consistency validation
    - Contradiction detection
    - Stale-state detection
    - Replay detection
    - Telemetry integrity checks
    - State confidence
    - Integrity assessment
    - Phase-5 tests

Explicitly NOT implemented:
    - Attack-path reconstruction
    - Causal memory
    - Memory trust/quarantine
    - Attribution
    - Intervention optimization
    - Authority graph
    - Intent compiler
    - Verification engine
    - Replanning
    - Regeneration
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from hashlib import sha256
from typing import Any, Mapping, Optional
import copy
import json
import threading
import unittest


# ============================================================================
# ENUMS
# ============================================================================


class IntegrityStatus(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    UNKNOWN = "unknown"


class IntegrityIssueType(str, Enum):
    CONSISTENCY = "consistency"
    CONTRADICTION = "contradiction"
    STALE_STATE = "stale_state"
    REPLAY = "replay"
    TELEMETRY_INTEGRITY = "telemetry_integrity"


class ConfidenceBand(str, Enum):
    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


# ============================================================================
# EXCEPTIONS
# ============================================================================


class StateIntegrityError(Exception):
    """Base exception for Phase-5 failures."""


class InvalidIntegrityInput(StateIntegrityError):
    """Raised for invalid Phase-5 input."""


# ============================================================================
# UTILITIES
# ============================================================================


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def canonicalize(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()

    if isinstance(value, Mapping):
        return {
            str(k): canonicalize(value[k])
            for k in sorted(value, key=lambda x: str(x))
        }

    if isinstance(value, (list, tuple)):
        return [canonicalize(v) for v in value]

    if isinstance(value, set):
        return sorted(
            [canonicalize(v) for v in value],
            key=lambda v: json.dumps(
                v,
                sort_keys=True,
                separators=(",", ":"),
            ),
        )

    if isinstance(value, (str, int, float, bool)) or value is None:
        return value

    raise TypeError(
        f"Unsupported integrity value type: {type(value)!r}"
    )


def canonical_json(value: Any) -> str:
    return json.dumps(
        canonicalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def payload_hash(value: Any) -> str:
    return sha256(
        canonical_json(value).encode("utf-8")
    ).hexdigest()


# ============================================================================
# INTEGRITY ISSUE
# ============================================================================


@dataclass(frozen=True)
class IntegrityIssue:
    issue_type: IntegrityIssueType
    message: str
    field_path: Optional[str] = None
    expected: Any = None
    observed: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "issue_type": self.issue_type.value,
            "message": self.message,
            "field_path": self.field_path,
            "expected": canonicalize(self.expected),
            "observed": canonicalize(self.observed),
        }


# ============================================================================
# TELEMETRY RECORD
# ============================================================================


@dataclass(frozen=True)
class TelemetryRecord:
    telemetry_id: str
    scope_id: str
    sequence: int
    observed_at: datetime
    payload: Mapping[str, Any]
    payload_hash: str
    source_id: str
    nonce: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.telemetry_id:
            raise InvalidIntegrityInput(
                "telemetry_id cannot be empty"
            )

        if not self.scope_id:
            raise InvalidIntegrityInput(
                "scope_id cannot be empty"
            )

        if self.sequence < 0:
            raise InvalidIntegrityInput(
                "sequence cannot be negative"
            )

        if self.observed_at.tzinfo is None:
            raise InvalidIntegrityInput(
                "observed_at must be timezone-aware"
            )

        computed = payload_hash(self.payload)

        if self.payload_hash != computed:
            raise InvalidIntegrityInput(
                "Telemetry payload hash mismatch"
            )

        object.__setattr__(
            self,
            "payload",
            copy.deepcopy(dict(self.payload)),
        )

    @classmethod
    def create(
        cls,
        *,
        telemetry_id: str,
        scope_id: str,
        sequence: int,
        payload: Mapping[str, Any],
        source_id: str,
        observed_at: Optional[datetime] = None,
        nonce: Optional[str] = None,
    ) -> "TelemetryRecord":

        return cls(
            telemetry_id=telemetry_id,
            scope_id=scope_id,
            sequence=sequence,
            observed_at=observed_at or utc_now(),
            payload=copy.deepcopy(dict(payload)),
            payload_hash=payload_hash(payload),
            source_id=source_id,
            nonce=nonce,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "telemetry_id": self.telemetry_id,
            "scope_id": self.scope_id,
            "sequence": self.sequence,
            "observed_at": self.observed_at.astimezone(
                timezone.utc
            ).isoformat(),
            "payload": canonicalize(self.payload),
            "payload_hash": self.payload_hash,
            "source_id": self.source_id,
            "nonce": self.nonce,
        }


# ============================================================================
# STATE CONFIDENCE
# ============================================================================


@dataclass(frozen=True)
class StateConfidence:
    score: float
    band: ConfidenceBand
    factors: Mapping[str, float] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        if not 0.0 <= self.score <= 1.0:
            raise InvalidIntegrityInput(
                "Confidence score must be between 0 and 1"
            )

        object.__setattr__(
            self,
            "factors",
            dict(self.factors),
        )

    @staticmethod
    def band_for(score: float) -> ConfidenceBand:
        if score < 0.20:
            return ConfidenceBand.VERY_LOW
        if score < 0.40:
            return ConfidenceBand.LOW
        if score < 0.60:
            return ConfidenceBand.MEDIUM
        if score < 0.80:
            return ConfidenceBand.HIGH

        return ConfidenceBand.VERY_HIGH

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "band": self.band.value,
            "factors": dict(self.factors),
        }


# ============================================================================
# INTEGRITY RESULT
# ============================================================================


@dataclass(frozen=True)
class IntegrityAssessment:
    status: IntegrityStatus
    confidence: StateConfidence
    issues: tuple[IntegrityIssue, ...]
    checked_at: datetime

    @property
    def valid(self) -> bool:
        return self.status == IntegrityStatus.VALID

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "confidence": self.confidence.to_dict(),
            "issues": [
                issue.to_dict()
                for issue in self.issues
            ],
            "checked_at": self.checked_at.astimezone(
                timezone.utc
            ).isoformat(),
        }


# ============================================================================
# STATE INTEGRITY ENGINE
# ============================================================================


class StateIntegrityEngine:
    """
    Phase-5-only integrity layer.

    It operates on state-shaped mappings and telemetry records.
    It does not implement future HYDRA reasoning/control functions.
    """

    def __init__(
        self,
        *,
        stale_after: timedelta = timedelta(minutes=15),
    ) -> None:

        if stale_after.total_seconds() < 0:
            raise ValueError(
                "stale_after cannot be negative"
            )

        self._stale_after = stale_after
        self._seen_telemetry: dict[
            tuple[str, int, str],
            str,
        ] = {}

        self._lock = threading.RLock()

    # ------------------------------------------------------------------------
    # CONSISTENCY
    # ------------------------------------------------------------------------

    def check_consistency(
        self,
        state: Mapping[str, Any],
        *,
        required_fields: tuple[str, ...] = (),
    ) -> tuple[IntegrityIssue, ...]:

        issues: list[IntegrityIssue] = []

        if not isinstance(state, Mapping):
            return (
                IntegrityIssue(
                    issue_type=IntegrityIssueType.CONSISTENCY,
                    message="State must be a mapping",
                ),
            )

        for field_name in required_fields:
            if field_name not in state:
                issues.append(
                    IntegrityIssue(
                        issue_type=IntegrityIssueType.CONSISTENCY,
                        message=(
                            f"Required state field missing: "
                            f"{field_name}"
                        ),
                        field_path=field_name,
                    )
                )

        return tuple(issues)

    # ------------------------------------------------------------------------
    # CONTRADICTION DETECTION
    # ------------------------------------------------------------------------

    def detect_contradictions(
        self,
        state: Mapping[str, Any],
        *,
        mutually_exclusive: tuple[
            tuple[str, Any, str, Any],
            ...,
        ] = (),
    ) -> tuple[IntegrityIssue, ...]:

        issues: list[IntegrityIssue] = []

        for (
            field_a,
            value_a,
            field_b,
            value_b,
        ) in mutually_exclusive:

            if (
                state.get(field_a) == value_a
                and state.get(field_b) == value_b
            ):
                issues.append(
                    IntegrityIssue(
                        issue_type=IntegrityIssueType.CONTRADICTION,
                        message=(
                            f"Contradictory values detected: "
                            f"{field_a}={value_a!r} and "
                            f"{field_b}={value_b!r}"
                        ),
                        field_path=(
                            f"{field_a},{field_b}"
                        ),
                        expected=(
                            f"not ({field_a}={value_a!r} "
                            f"AND {field_b}={value_b!r})"
                        ),
                        observed={
                            field_a: state.get(field_a),
                            field_b: state.get(field_b),
                        },
                    )
                )

        return tuple(issues)

    # ------------------------------------------------------------------------
    # STALE STATE
    # ------------------------------------------------------------------------

    def detect_staleness(
        self,
        observed_at: datetime,
        *,
        now: Optional[datetime] = None,
    ) -> Optional[IntegrityIssue]:

        if observed_at.tzinfo is None:
            return IntegrityIssue(
                issue_type=IntegrityIssueType.STALE_STATE,
                message="State timestamp is not timezone-aware",
            )

        current = now or utc_now()

        if current.tzinfo is None:
            raise InvalidIntegrityInput(
                "now must be timezone-aware"
            )

        age = current - observed_at

        if age > self._stale_after:
            return IntegrityIssue(
                issue_type=IntegrityIssueType.STALE_STATE,
                message="State is stale",
                field_path="observed_at",
                expected=(
                    f"age <= "
                    f"{self._stale_after.total_seconds()} seconds"
                ),
                observed=age.total_seconds(),
            )

        return None

    # ------------------------------------------------------------------------
    # REPLAY DETECTION
    # ------------------------------------------------------------------------

    def detect_replay(
        self,
        telemetry: TelemetryRecord,
    ) -> Optional[IntegrityIssue]:

        key = (
            telemetry.scope_id,
            telemetry.sequence,
            telemetry.source_id,
        )

        with self._lock:
            existing_hash = self._seen_telemetry.get(key)

            if existing_hash is None:
                self._seen_telemetry[key] = (
                    telemetry.payload_hash
                )
                return None

            if existing_hash == telemetry.payload_hash:
                return IntegrityIssue(
                    issue_type=IntegrityIssueType.REPLAY,
                    message="Duplicate telemetry replay detected",
                    field_path="telemetry.sequence",
                    expected="previously unseen telemetry",
                    observed=telemetry.sequence,
                )

            return IntegrityIssue(
                issue_type=IntegrityIssueType.REPLAY,
                message=(
                    "Sequence collision with different telemetry payload"
                ),
                field_path="telemetry.sequence",
                expected=existing_hash,
                observed=telemetry.payload_hash,
            )

    # ------------------------------------------------------------------------
    # TELEMETRY INTEGRITY
    # ------------------------------------------------------------------------

    def verify_telemetry(
        self,
        telemetry: TelemetryRecord,
    ) -> tuple[IntegrityIssue, ...]:

        issues: list[IntegrityIssue] = []

        calculated = payload_hash(
            telemetry.payload
        )

        if calculated != telemetry.payload_hash:
            issues.append(
                IntegrityIssue(
                    issue_type=IntegrityIssueType.TELEMETRY_INTEGRITY,
                    message="Telemetry payload hash mismatch",
                    field_path="payload_hash",
                    expected=calculated,
                    observed=telemetry.payload_hash,
                )
            )

        if not telemetry.source_id:
            issues.append(
                IntegrityIssue(
                    issue_type=IntegrityIssueType.TELEMETRY_INTEGRITY,
                    message="Telemetry source_id is empty",
                    field_path="source_id",
                )
            )

        if telemetry.observed_at.tzinfo is None:
            issues.append(
                IntegrityIssue(
                    issue_type=IntegrityIssueType.TELEMETRY_INTEGRITY,
                    message="Telemetry timestamp is invalid",
                    field_path="observed_at",
                )
            )

        return tuple(issues)

    # ------------------------------------------------------------------------
    # CONFIDENCE
    # ------------------------------------------------------------------------

    def calculate_confidence(
        self,
        *,
        issue_count: int,
        telemetry_valid: bool = True,
        stale: bool = False,
        contradiction_count: int = 0,
        replay_count: int = 0,
    ) -> StateConfidence:

        score = 1.0

        consistency_penalty = min(
            0.50,
            issue_count * 0.10,
        )

        telemetry_penalty = (
            0.25
            if not telemetry_valid
            else 0.0
        )

        stale_penalty = (
            0.20
            if stale
            else 0.0
        )

        contradiction_penalty = min(
            0.30,
            contradiction_count * 0.15,
        )

        replay_penalty = min(
            0.30,
            replay_count * 0.15,
        )

        score -= (
            consistency_penalty
            + telemetry_penalty
            + stale_penalty
            + contradiction_penalty
            + replay_penalty
        )

        score = max(0.0, min(1.0, score))

        factors = {
            "consistency_penalty": consistency_penalty,
            "telemetry_penalty": telemetry_penalty,
            "stale_penalty": stale_penalty,
            "contradiction_penalty": contradiction_penalty,
            "replay_penalty": replay_penalty,
        }

        return StateConfidence(
            score=score,
            band=StateConfidence.band_for(score),
            factors=factors,
        )

    # ------------------------------------------------------------------------
    # COMPLETE ASSESSMENT
    # ------------------------------------------------------------------------

    def assess(
        self,
        state: Mapping[str, Any],
        *,
        required_fields: tuple[str, ...] = (),
        mutually_exclusive: tuple[
            tuple[str, Any, str, Any],
            ...,
        ] = (),
        observed_at: Optional[datetime] = None,
        now: Optional[datetime] = None,
        telemetry: Optional[TelemetryRecord] = None,
    ) -> IntegrityAssessment:

        issues: list[IntegrityIssue] = []

        consistency = self.check_consistency(
            state,
            required_fields=required_fields,
        )

        contradictions = self.detect_contradictions(
            state,
            mutually_exclusive=mutually_exclusive,
        )

        issues.extend(consistency)
        issues.extend(contradictions)

        stale = False

        if observed_at is not None:
            stale_issue = self.detect_staleness(
                observed_at,
                now=now,
            )

            if stale_issue:
                stale = True
                issues.append(stale_issue)

        telemetry_valid = True
        replay_count = 0

        if telemetry is not None:
            telemetry_issues = self.verify_telemetry(
                telemetry
            )

            issues.extend(telemetry_issues)

            telemetry_valid = not bool(
                telemetry_issues
            )

            replay_issue = self.detect_replay(
                telemetry
            )

            if replay_issue:
                replay_count = 1
                issues.append(replay_issue)

        confidence = self.calculate_confidence(
            issue_count=len(consistency),
            telemetry_valid=telemetry_valid,
            stale=stale,
            contradiction_count=len(contradictions),
            replay_count=replay_count,
        )

        status = (
            IntegrityStatus.INVALID
            if issues
            else IntegrityStatus.VALID
        )

        return IntegrityAssessment(
            status=status,
            confidence=confidence,
            issues=tuple(issues),
            checked_at=now or utc_now(),
        )


# ============================================================================
# PHASE 5 TESTS
# ============================================================================


class TestStateIntegrityEngine(unittest.TestCase):

    def setUp(self) -> None:
        self.engine = StateIntegrityEngine(
            stale_after=timedelta(minutes=5)
        )

    def test_consistent_state(self) -> None:
        issues = self.engine.check_consistency(
            {
                "asset_count": 10,
                "status": "healthy",
            },
            required_fields=(
                "asset_count",
                "status",
            ),
        )

        self.assertEqual(issues, ())

    def test_missing_required_field(self) -> None:
        issues = self.engine.check_consistency(
            {
                "asset_count": 10,
            },
            required_fields=(
                "asset_count",
                "status",
            ),
        )

        self.assertEqual(len(issues), 1)
        self.assertEqual(
            issues[0].issue_type,
            IntegrityIssueType.CONSISTENCY,
        )

    def test_contradiction_detection(self) -> None:
        issues = self.engine.detect_contradictions(
            {
                "firewall_enabled": True,
                "firewall_status": "disabled",
            },
            mutually_exclusive=(
                (
                    "firewall_enabled",
                    True,
                    "firewall_status",
                    "disabled",
                ),
            ),
        )

        self.assertEqual(len(issues), 1)
        self.assertEqual(
            issues[0].issue_type,
            IntegrityIssueType.CONTRADICTION,
        )

    def test_fresh_state_is_not_stale(self) -> None:
        now = datetime(
            2026,
            9,
            7,
            12,
            0,
            tzinfo=timezone.utc,
        )

        issue = self.engine.detect_staleness(
            now - timedelta(minutes=2),
            now=now,
        )

        self.assertIsNone(issue)

    def test_old_state_is_stale(self) -> None:
        now = datetime(
            2026,
            9,
            7,
            12,
            0,
            tzinfo=timezone.utc,
        )

        issue = self.engine.detect_staleness(
            now - timedelta(minutes=10),
            now=now,
        )

        self.assertIsNotNone(issue)
        self.assertEqual(
            issue.issue_type,
            IntegrityIssueType.STALE_STATE,
        )

    def test_telemetry_integrity(self) -> None:
        telemetry = TelemetryRecord.create(
            telemetry_id="tel-001",
            scope_id="scope-A",
            sequence=1,
            payload={
                "cpu": 42,
                "status": "healthy",
            },
            source_id="sensor-A",
        )

        issues = self.engine.verify_telemetry(
            telemetry
        )

        self.assertEqual(issues, ())

    def test_replay_detection(self) -> None:
        telemetry = TelemetryRecord.create(
            telemetry_id="tel-001",
            scope_id="scope-A",
            sequence=1,
            payload={"status": "healthy"},
            source_id="sensor-A",
        )

        first = self.engine.detect_replay(
            telemetry
        )

        second = self.engine.detect_replay(
            telemetry
        )

        self.assertIsNone(first)
        self.assertIsNotNone(second)
        self.assertEqual(
            second.issue_type,
            IntegrityIssueType.REPLAY,
        )

    def test_sequence_collision_with_different_payload(self) -> None:
        first = TelemetryRecord.create(
            telemetry_id="tel-001",
            scope_id="scope-A",
            sequence=5,
            payload={"status": "healthy"},
            source_id="sensor-A",
        )

        second = TelemetryRecord.create(
            telemetry_id="tel-002",
            scope_id="scope-A",
            sequence=5,
            payload={"status": "compromised"},
            source_id="sensor-A",
        )

        self.assertIsNone(
            self.engine.detect_replay(first)
        )

        issue = self.engine.detect_replay(second)

        self.assertIsNotNone(issue)
        self.assertEqual(
            issue.issue_type,
            IntegrityIssueType.REPLAY,
        )

    def test_confidence_for_clean_state(self) -> None:
        confidence = self.engine.calculate_confidence(
            issue_count=0,
            telemetry_valid=True,
        )

        self.assertEqual(
            confidence.score,
            1.0,
        )
        self.assertEqual(
            confidence.band,
            ConfidenceBand.VERY_HIGH,
        )

    def test_confidence_decreases_for_integrity_problems(
        self,
    ) -> None:
        confidence = self.engine.calculate_confidence(
            issue_count=2,
            telemetry_valid=False,
            stale=True,
            contradiction_count=1,
            replay_count=1,
        )

        self.assertLess(
            confidence.score,
            1.0,
        )

    def test_clean_assessment(self) -> None:
        now = datetime(
            2026,
            9,
            7,
            12,
            0,
            tzinfo=timezone.utc,
        )

        assessment = self.engine.assess(
            {
                "status": "healthy",
                "asset_count": 5,
            },
            required_fields=(
                "status",
                "asset_count",
            ),
            observed_at=now,
            now=now,
        )

        self.assertTrue(assessment.valid)
        self.assertEqual(
            assessment.status,
            IntegrityStatus.VALID,
        )
        self.assertEqual(
            assessment.confidence.score,
            1.0,
        )

    def test_invalid_assessment(self) -> None:
        now = datetime(
            2026,
            9,
            7,
            12,
            0,
            tzinfo=timezone.utc,
        )

        assessment = self.engine.assess(
            {
                "firewall_enabled": True,
                "firewall_status": "disabled",
            },
            required_fields=(
                "firewall_enabled",
                "firewall_status",
            ),
            mutually_exclusive=(
                (
                    "firewall_enabled",
                    True,
                    "firewall_status",
                    "disabled",
                ),
            ),
            observed_at=now - timedelta(minutes=30),
            now=now,
        )

        self.assertFalse(assessment.valid)
        self.assertEqual(
            assessment.status,
            IntegrityStatus.INVALID,
        )
        self.assertGreater(
            len(assessment.issues),
            0,
        )

    def test_telemetry_integrated_assessment(self) -> None:
        telemetry = TelemetryRecord.create(
            telemetry_id="tel-100",
            scope_id="scope-A",
            sequence=1,
            payload={
                "network": "normal",
            },
            source_id="sensor-A",
        )

        assessment = self.engine.assess(
            {
                "status": "healthy",
            },
            required_fields=("status",),
            telemetry=telemetry,
        )

        self.assertTrue(assessment.valid)
        self.assertEqual(
            assessment.confidence.score,
            1.0,
        )


# ============================================================================
# PHASE 5 TEST RUNNER
# ============================================================================


def run_phase5_tests() -> unittest.result.TestResult:
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        TestStateIntegrityEngine
    )

    runner = unittest.TextTestRunner(
        verbosity=2
    )

    return runner.run(suite)


if __name__ == "__main__":
    run_phase5_tests()
