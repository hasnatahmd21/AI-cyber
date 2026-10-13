"""
HYDRA™
Phase 4 — Security State Engine

Scope:
    - Security state model
    - State snapshots
    - State transitions
    - State diff
    - Expected vs observed state
    - Temporal state
    - State validation
    - Serialization / deserialization
    - Phase-4 tests

No Phase-5+ implementation is included.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
from typing import Any, Dict, Iterable, Mapping, Optional
import copy
import json
import threading
import unittest
import uuid


# ============================================================================
# PHASE 4 — ENUMS
# ============================================================================


class SecurityStateStatus(str, Enum):
    EXPECTED = "expected"
    OBSERVED = "observed"
    TRANSITIONING = "transitioning"


class StateTransitionType(str, Enum):
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    REPLACE = "replace"


class StateDiffType(str, Enum):
    ADDED = "added"
    REMOVED = "removed"
    CHANGED = "changed"
    UNCHANGED = "unchanged"


# ============================================================================
# PHASE 4 — EXCEPTIONS
# ============================================================================


class SecurityStateError(Exception):
    """Base exception for Phase-4 state-engine failures."""


class InvalidSecurityState(SecurityStateError):
    """Raised when a security state violates Phase-4 state rules."""


class StateNotFound(SecurityStateError):
    """Raised when a requested state or snapshot does not exist."""


class InvalidStateTransition(SecurityStateError):
    """Raised when a state transition is invalid."""


# ============================================================================
# PHASE 4 — UTILITY FUNCTIONS
# ============================================================================


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _canonicalize(value: Any) -> Any:
    """
    Convert supported values into deterministic JSON-compatible structures.
    """

    if isinstance(value, Enum):
        return value.value

    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()

    if isinstance(value, Mapping):
        return {
            str(key): _canonicalize(value[key])
            for key in sorted(value, key=lambda item: str(item))
        }

    if isinstance(value, (list, tuple)):
        return [_canonicalize(item) for item in value]

    if isinstance(value, set):
        return sorted(
            (_canonicalize(item) for item in value),
            key=lambda item: json.dumps(
                item,
                sort_keys=True,
                separators=(",", ":"),
            ),
        )

    if isinstance(value, (str, int, float, bool)) or value is None:
        return value

    raise TypeError(f"Unsupported state value type: {type(value)!r}")


def canonical_json(value: Any) -> str:
    return json.dumps(
        _canonicalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def calculate_state_hash(state: Mapping[str, Any]) -> str:
    return sha256(canonical_json(state).encode("utf-8")).hexdigest()


# ============================================================================
# PHASE 4 — SECURITY STATE
# ============================================================================


@dataclass(frozen=True)
class SecurityState:
    """
    Immutable representation of a point-in-time security state.

    The state payload is deliberately generic so later HYDRA phases can
    build domain-specific state consumers without changing this engine.
    """

    state_id: str
    scope_id: str
    sequence: int
    observed_at: datetime
    status: SecurityStateStatus
    data: Mapping[str, Any]
    parent_state_id: Optional[str] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    state_hash: str = ""

    def __post_init__(self) -> None:
        if not self.state_id:
            raise InvalidSecurityState("state_id cannot be empty")

        if not self.scope_id:
            raise InvalidSecurityState("scope_id cannot be empty")

        if self.sequence < 0:
            raise InvalidSecurityState("sequence cannot be negative")

        if self.observed_at.tzinfo is None:
            raise InvalidSecurityState(
                "observed_at must be timezone-aware"
            )

        if not isinstance(self.data, Mapping):
            raise InvalidSecurityState("data must be a mapping")

        computed_hash = calculate_state_hash(self.data)

        if self.state_hash and self.state_hash != computed_hash:
            raise InvalidSecurityState(
                "state_hash does not match state data"
            )

        object.__setattr__(
            self,
            "state_hash",
            computed_hash,
        )

        object.__setattr__(
            self,
            "data",
            copy.deepcopy(dict(self.data)),
        )

        object.__setattr__(
            self,
            "metadata",
            copy.deepcopy(dict(self.metadata)),
        )

    @classmethod
    def create(
        cls,
        *,
        scope_id: str,
        data: Mapping[str, Any],
        sequence: int = 0,
        status: SecurityStateStatus = SecurityStateStatus.OBSERVED,
        parent_state_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        state_id: Optional[str] = None,
        observed_at: Optional[datetime] = None,
    ) -> "SecurityState":

        return cls(
            state_id=state_id or str(uuid.uuid4()),
            scope_id=scope_id,
            sequence=sequence,
            observed_at=observed_at or utc_now(),
            status=status,
            data=copy.deepcopy(dict(data)),
            parent_state_id=parent_state_id,
            metadata=copy.deepcopy(dict(metadata or {})),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state_id": self.state_id,
            "scope_id": self.scope_id,
            "sequence": self.sequence,
            "observed_at": self.observed_at.astimezone(
                timezone.utc
            ).isoformat(),
            "status": self.status.value,
            "data": _canonicalize(self.data),
            "parent_state_id": self.parent_state_id,
            "metadata": _canonicalize(self.metadata),
            "state_hash": self.state_hash,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "SecurityState":
        observed_at = datetime.fromisoformat(
            str(payload["observed_at"])
        )

        return cls(
            state_id=str(payload["state_id"]),
            scope_id=str(payload["scope_id"]),
            sequence=int(payload["sequence"]),
            observed_at=observed_at,
            status=SecurityStateStatus(payload["status"]),
            data=dict(payload["data"]),
            parent_state_id=payload.get("parent_state_id"),
            metadata=dict(payload.get("metadata", {})),
            state_hash=str(payload.get("state_hash", "")),
        )


# ============================================================================
# PHASE 4 — STATE SNAPSHOT
# ============================================================================


@dataclass(frozen=True)
class StateSnapshot:
    """
    Point-in-time reference to a SecurityState.
    """

    snapshot_id: str
    state_id: str
    scope_id: str
    captured_at: datetime
    sequence: int
    state_hash: str

    @classmethod
    def from_state(
        cls,
        state: SecurityState,
        *,
        snapshot_id: Optional[str] = None,
        captured_at: Optional[datetime] = None,
    ) -> "StateSnapshot":

        return cls(
            snapshot_id=snapshot_id or str(uuid.uuid4()),
            state_id=state.state_id,
            scope_id=state.scope_id,
            captured_at=captured_at or utc_now(),
            sequence=state.sequence,
            state_hash=state.state_hash,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "state_id": self.state_id,
            "scope_id": self.scope_id,
            "captured_at": self.captured_at.astimezone(
                timezone.utc
            ).isoformat(),
            "sequence": self.sequence,
            "state_hash": self.state_hash,
        }


# ============================================================================
# PHASE 4 — STATE DIFF
# ============================================================================


@dataclass(frozen=True)
class StateChange:
    path: str
    change_type: StateDiffType
    before: Any = None
    after: Any = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "change_type": self.change_type.value,
            "before": _canonicalize(self.before),
            "after": _canonicalize(self.after),
        }


@dataclass(frozen=True)
class StateDiff:
    source_state_id: str
    target_state_id: str
    source_hash: str
    target_hash: str
    changes: tuple[StateChange, ...]

    @property
    def changed(self) -> bool:
        return bool(self.changes)

    @property
    def change_count(self) -> int:
        return len(self.changes)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_state_id": self.source_state_id,
            "target_state_id": self.target_state_id,
            "source_hash": self.source_hash,
            "target_hash": self.target_hash,
            "changes": [
                change.to_dict()
                for change in self.changes
            ],
        }


def _diff_values(
    before: Any,
    after: Any,
    path: str,
    changes: list[StateChange],
) -> None:

    if isinstance(before, Mapping) and isinstance(after, Mapping):
        before_keys = set(before.keys())
        after_keys = set(after.keys())

        for key in sorted(
            before_keys - after_keys,
            key=lambda item: str(item),
        ):
            changes.append(
                StateChange(
                    path=f"{path}.{key}",
                    change_type=StateDiffType.REMOVED,
                    before=before[key],
                )
            )

        for key in sorted(
            after_keys - before_keys,
            key=lambda item: str(item),
        ):
            changes.append(
                StateChange(
                    path=f"{path}.{key}",
                    change_type=StateDiffType.ADDED,
                    after=after[key],
                )
            )

        for key in sorted(
            before_keys & after_keys,
            key=lambda item: str(item),
        ):
            _diff_values(
                before[key],
                after[key],
                f"{path}.{key}",
                changes,
            )

        return

    if before != after:
        changes.append(
            StateChange(
                path=path,
                change_type=StateDiffType.CHANGED,
                before=before,
                after=after,
            )
        )


def diff_states(
    source: SecurityState,
    target: SecurityState,
) -> StateDiff:

    if source.scope_id != target.scope_id:
        raise InvalidSecurityState(
            "Cannot diff states belonging to different scopes"
        )

    changes: list[StateChange] = []

    _diff_values(
        source.data,
        target.data,
        "$",
        changes,
    )

    return StateDiff(
        source_state_id=source.state_id,
        target_state_id=target.state_id,
        source_hash=source.state_hash,
        target_hash=target.state_hash,
        changes=tuple(changes),
    )


# ============================================================================
# PHASE 4 — EXPECTED VS OBSERVED STATE
# ============================================================================


@dataclass(frozen=True)
class StateComparison:
    expected_state_id: str
    observed_state_id: str
    matching: bool
    diff: StateDiff

    @property
    def mismatch_count(self) -> int:
        return self.diff.change_count

    def to_dict(self) -> Dict[str, Any]:
        return {
            "expected_state_id": self.expected_state_id,
            "observed_state_id": self.observed_state_id,
            "matching": self.matching,
            "mismatch_count": self.mismatch_count,
            "diff": self.diff.to_dict(),
        }


def compare_expected_observed(
    expected: SecurityState,
    observed: SecurityState,
) -> StateComparison:

    if expected.scope_id != observed.scope_id:
        raise InvalidSecurityState(
            "Expected and observed states must share scope_id"
        )

    if expected.status != SecurityStateStatus.EXPECTED:
        raise InvalidSecurityState(
            "Expected state must have EXPECTED status"
        )

    if observed.status != SecurityStateStatus.OBSERVED:
        raise InvalidSecurityState(
            "Observed state must have OBSERVED status"
        )

    state_diff = diff_states(expected, observed)

    return StateComparison(
        expected_state_id=expected.state_id,
        observed_state_id=observed.state_id,
        matching=not state_diff.changed,
        diff=state_diff,
    )


# ============================================================================
# PHASE 4 — STATE TRANSITION
# ============================================================================


@dataclass(frozen=True)
class StateTransition:
    transition_id: str
    scope_id: str
    transition_type: StateTransitionType
    source_state_id: Optional[str]
    target_state_id: str
    sequence: int
    created_at: datetime
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transition_id": self.transition_id,
            "scope_id": self.scope_id,
            "transition_type": self.transition_type.value,
            "source_state_id": self.source_state_id,
            "target_state_id": self.target_state_id,
            "sequence": self.sequence,
            "created_at": self.created_at.astimezone(
                timezone.utc
            ).isoformat(),
            "reason": self.reason,
        }


# ============================================================================
# PHASE 4 — TEMPORAL STATE
# ============================================================================


@dataclass(frozen=True)
class TemporalState:
    """
    Ordered state history for one scope.
    """

    scope_id: str
    states: tuple[SecurityState, ...]

    @property
    def latest(self) -> Optional[SecurityState]:
        if not self.states:
            return None

        return max(
            self.states,
            key=lambda state: (
                state.sequence,
                state.observed_at,
            ),
        )

    def between(
        self,
        start: datetime,
        end: datetime,
    ) -> tuple[SecurityState, ...]:

        if start.tzinfo is None or end.tzinfo is None:
            raise ValueError(
                "Temporal boundaries must be timezone-aware"
            )

        return tuple(
            state
            for state in self.states
            if start <= state.observed_at <= end
        )


# ============================================================================
# PHASE 4 — SECURITY STATE ENGINE
# ============================================================================


class SecurityStateEngine:
    """
    In-memory Security State Engine.

    Responsibilities are intentionally restricted to Phase 4.
    """

    def __init__(self) -> None:
        self._states: Dict[str, SecurityState] = {}
        self._snapshots: Dict[str, StateSnapshot] = {}
        self._transitions: list[StateTransition] = []
        self._scope_sequences: Dict[str, int] = {}
        self._lock = threading.RLock()

    # ---------------------------------------------------------------------
    # STATE CREATION
    # ---------------------------------------------------------------------

    def create_state(
        self,
        *,
        scope_id: str,
        data: Mapping[str, Any],
        status: SecurityStateStatus = SecurityStateStatus.OBSERVED,
        reason: str = "state-created",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> SecurityState:

        with self._lock:
            sequence = self._scope_sequences.get(
                scope_id,
                -1,
            ) + 1

            state = SecurityState.create(
                scope_id=scope_id,
                data=data,
                sequence=sequence,
                status=status,
                metadata=metadata,
            )

            self._states[state.state_id] = state
            self._scope_sequences[scope_id] = sequence

            self._transitions.append(
                StateTransition(
                    transition_id=str(uuid.uuid4()),
                    scope_id=scope_id,
                    transition_type=StateTransitionType.CREATE,
                    source_state_id=None,
                    target_state_id=state.state_id,
                    sequence=sequence,
                    created_at=utc_now(),
                    reason=reason,
                )
            )

            return state

    # ---------------------------------------------------------------------
    # STATE UPDATE
    # ---------------------------------------------------------------------

    def update_state(
        self,
        state_id: str,
        data: Mapping[str, Any],
        *,
        reason: str = "state-updated",
        status: Optional[SecurityStateStatus] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> SecurityState:

        with self._lock:
            source = self.get_state(state_id)

            next_sequence = (
                self._scope_sequences[source.scope_id] + 1
            )

            target = SecurityState.create(
                scope_id=source.scope_id,
                data=data,
                sequence=next_sequence,
                status=status or source.status,
                parent_state_id=source.state_id,
                metadata=(
                    metadata
                    if metadata is not None
                    else source.metadata
                ),
            )

            self._states[target.state_id] = target
            self._scope_sequences[source.scope_id] = next_sequence

            self._transitions.append(
                StateTransition(
                    transition_id=str(uuid.uuid4()),
                    scope_id=source.scope_id,
                    transition_type=StateTransitionType.UPDATE,
                    source_state_id=source.state_id,
                    target_state_id=target.state_id,
                    sequence=next_sequence,
                    created_at=utc_now(),
                    reason=reason,
                )
            )

            return target

    # ---------------------------------------------------------------------
    # SNAPSHOTS
    # ---------------------------------------------------------------------

    def snapshot(
        self,
        state_id: str,
    ) -> StateSnapshot:

        with self._lock:
            state = self.get_state(state_id)

            snapshot = StateSnapshot.from_state(state)

            self._snapshots[snapshot.snapshot_id] = snapshot

            return snapshot

    # ---------------------------------------------------------------------
    # LOOKUPS
    # ---------------------------------------------------------------------

    def get_state(
        self,
        state_id: str,
    ) -> SecurityState:

        try:
            return self._states[state_id]
        except KeyError as exc:
            raise StateNotFound(
                f"State not found: {state_id}"
            ) from exc

    def get_snapshot(
        self,
        snapshot_id: str,
    ) -> StateSnapshot:

        try:
            return self._snapshots[snapshot_id]
        except KeyError as exc:
            raise StateNotFound(
                f"Snapshot not found: {snapshot_id}"
            ) from exc

    # ---------------------------------------------------------------------
    # TEMPORAL HISTORY
    # ---------------------------------------------------------------------

    def temporal_state(
        self,
        scope_id: str,
    ) -> TemporalState:

        with self._lock:
            states = tuple(
                sorted(
                    (
                        state
                        for state in self._states.values()
                        if state.scope_id == scope_id
                    ),
                    key=lambda state: (
                        state.sequence,
                        state.observed_at,
                    ),
                )
            )

            return TemporalState(
                scope_id=scope_id,
                states=states,
            )

    # ---------------------------------------------------------------------
    # DIFF
    # ---------------------------------------------------------------------

    def diff(
        self,
        source_state_id: str,
        target_state_id: str,
    ) -> StateDiff:

        with self._lock:
            source = self.get_state(source_state_id)
            target = self.get_state(target_state_id)

            return diff_states(source, target)

    # ---------------------------------------------------------------------
    # EXPECTED / OBSERVED COMPARISON
    # ---------------------------------------------------------------------

    def compare(
        self,
        expected_state_id: str,
        observed_state_id: str,
    ) -> StateComparison:

        with self._lock:
            expected = self.get_state(expected_state_id)
            observed = self.get_state(observed_state_id)

            return compare_expected_observed(
                expected,
                observed,
            )

    # ---------------------------------------------------------------------
    # STATE VALIDATION
    # ---------------------------------------------------------------------

    def validate_state(
        self,
        state_id: str,
    ) -> bool:

        with self._lock:
            state = self.get_state(state_id)

            recalculated = calculate_state_hash(
                state.data
            )

            if recalculated != state.state_hash:
                raise InvalidSecurityState(
                    f"State integrity mismatch: {state_id}"
                )

            if state.sequence < 0:
                raise InvalidSecurityState(
                    "State sequence cannot be negative"
                )

            if state.observed_at.tzinfo is None:
                raise InvalidSecurityState(
                    "State timestamp must be timezone-aware"
                )

            if state.parent_state_id:
                parent = self.get_state(
                    state.parent_state_id
                )

                if parent.scope_id != state.scope_id:
                    raise InvalidSecurityState(
                        "Parent and child states have different scopes"
                    )

                if parent.sequence >= state.sequence:
                    raise InvalidSecurityState(
                        "Child state sequence must be greater than parent"
                    )

            return True

    # ---------------------------------------------------------------------
    # TRANSITION HISTORY
    # ---------------------------------------------------------------------

    def transitions(
        self,
        scope_id: Optional[str] = None,
    ) -> tuple[StateTransition, ...]:

        with self._lock:
            if scope_id is None:
                return tuple(self._transitions)

            return tuple(
                transition
                for transition in self._transitions
                if transition.scope_id == scope_id
            )

    # ---------------------------------------------------------------------
    # EXPORT
    # ---------------------------------------------------------------------

    def export_state(
        self,
        state_id: str,
    ) -> str:

        state = self.get_state(state_id)

        return json.dumps(
            state.to_dict(),
            sort_keys=True,
            ensure_ascii=False,
            indent=2,
        )

    def import_state(
        self,
        payload: str,
    ) -> SecurityState:

        data = json.loads(payload)
        state = SecurityState.from_dict(data)

        with self._lock:
            existing_sequence = self._scope_sequences.get(
                state.scope_id,
                -1,
            )

            if state.sequence <= existing_sequence:
                raise InvalidStateTransition(
                    "Imported state sequence is not newer "
                    "than the current scope sequence"
                )

            self._states[state.state_id] = state
            self._scope_sequences[
                state.scope_id
            ] = state.sequence

        return state


# ============================================================================
# PHASE 4 — TESTS
# ============================================================================


class TestSecurityStateEngine(unittest.TestCase):

    def setUp(self) -> None:
        self.engine = SecurityStateEngine()

    def test_create_state(self) -> None:
        state = self.engine.create_state(
            scope_id="tenant-A",
            data={
                "asset_count": 10,
                "network_status": "normal",
            },
        )

        self.assertEqual(state.scope_id, "tenant-A")
        self.assertEqual(state.sequence, 0)
        self.assertTrue(state.state_hash)
        self.assertTrue(
            self.engine.validate_state(state.state_id)
        )

    def test_state_update_creates_new_sequence(self) -> None:
        first = self.engine.create_state(
            scope_id="tenant-A",
            data={"risk": "low"},
        )

        second = self.engine.update_state(
            first.state_id,
            {"risk": "high"},
        )

        self.assertEqual(first.sequence, 0)
        self.assertEqual(second.sequence, 1)
        self.assertEqual(
            second.parent_state_id,
            first.state_id,
        )

    def test_state_diff_detects_change(self) -> None:
        first = self.engine.create_state(
            scope_id="tenant-A",
            data={
                "risk": "low",
                "assets": 10,
            },
        )

        second = self.engine.update_state(
            first.state_id,
            {
                "risk": "high",
                "assets": 10,
            },
        )

        result = self.engine.diff(
            first.state_id,
            second.state_id,
        )

        self.assertTrue(result.changed)
        self.assertEqual(result.change_count, 1)
        self.assertEqual(
            result.changes[0].path,
            "$.risk",
        )

    def test_state_diff_detects_added_and_removed(self) -> None:
        first = self.engine.create_state(
            scope_id="tenant-A",
            data={
                "a": 1,
                "b": 2,
            },
        )

        second = self.engine.update_state(
            first.state_id,
            {
                "a": 1,
                "c": 3,
            },
        )

        result = self.engine.diff(
            first.state_id,
            second.state_id,
        )

        paths = {
            change.path
            for change in result.changes
        }

        self.assertEqual(
            paths,
            {"$.b", "$.c"},
        )

    def test_expected_observed_match(self) -> None:
        expected = self.engine.create_state(
            scope_id="tenant-A",
            data={"firewall": "enabled"},
            status=SecurityStateStatus.EXPECTED,
        )

        observed = self.engine.create_state(
            scope_id="tenant-A",
            data={"firewall": "enabled"},
            status=SecurityStateStatus.OBSERVED,
        )

        comparison = self.engine.compare(
            expected.state_id,
            observed.state_id,
        )

        self.assertTrue(comparison.matching)
        self.assertEqual(
            comparison.mismatch_count,
            0,
        )

    def test_expected_observed_mismatch(self) -> None:
        expected = self.engine.create_state(
            scope_id="tenant-A",
            data={"firewall": "enabled"},
            status=SecurityStateStatus.EXPECTED,
        )

        observed = self.engine.create_state(
            scope_id="tenant-A",
            data={"firewall": "disabled"},
            status=SecurityStateStatus.OBSERVED,
        )

        comparison = self.engine.compare(
            expected.state_id,
            observed.state_id,
        )

        self.assertFalse(comparison.matching)
        self.assertEqual(
            comparison.mismatch_count,
            1,
        )

    def test_snapshot(self) -> None:
        state = self.engine.create_state(
            scope_id="tenant-A",
            data={"status": "healthy"},
        )

        snapshot = self.engine.snapshot(
            state.state_id
        )

        self.assertEqual(
            snapshot.state_id,
            state.state_id,
        )
        self.assertEqual(
            snapshot.state_hash,
            state.state_hash,
        )

    def test_temporal_state(self) -> None:
        first = self.engine.create_state(
            scope_id="tenant-A",
            data={"value": 1},
        )

        second = self.engine.update_state(
            first.state_id,
            {"value": 2},
        )

        temporal = self.engine.temporal_state(
            "tenant-A"
        )

        self.assertEqual(
            len(temporal.states),
            2,
        )

        self.assertEqual(
            temporal.latest.state_id,
            second.state_id,
        )

    def test_invalid_scope_diff(self) -> None:
        first = self.engine.create_state(
            scope_id="tenant-A",
            data={"x": 1},
        )

        second = self.engine.create_state(
            scope_id="tenant-B",
            data={"x": 1},
        )

        with self.assertRaises(InvalidSecurityState):
            self.engine.diff(
                first.state_id,
                second.state_id,
            )

    def test_missing_state(self) -> None:
        with self.assertRaises(StateNotFound):
            self.engine.get_state("does-not-exist")

    def test_serialization_round_trip(self) -> None:
        original = self.engine.create_state(
            scope_id="tenant-A",
            data={
                "asset": {
                    "id": "srv-01",
                    "status": "online",
                },
            },
        )

        payload = self.engine.export_state(
            original.state_id
        )

        restored = SecurityState.from_dict(
            json.loads(payload)
        )

        self.assertEqual(
            restored.state_hash,
            original.state_hash,
        )
        self.assertEqual(
            dict(restored.data),
            dict(original.data),
        )

    def test_parent_sequence_validation(self) -> None:
        first = self.engine.create_state(
            scope_id="tenant-A",
            data={"x": 1},
        )

        second = self.engine.update_state(
            first.state_id,
            {"x": 2},
        )

        self.assertTrue(
            self.engine.validate_state(
                second.state_id
            )
        )


# ============================================================================
# PHASE 4 — TEST RUNNER
# ============================================================================


def run_phase4_tests() -> unittest.result.TestResult:
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        TestSecurityStateEngine
    )

    runner = unittest.TextTestRunner(
        verbosity=2
    )

    return runner.run(suite)


# ============================================================================
# PHASE 4 — BASIC EXECUTION
# ============================================================================


if __name__ == "__main__":
    run_phase4_tests()
