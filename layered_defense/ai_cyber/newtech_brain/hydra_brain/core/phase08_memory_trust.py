"""
HYDRA™ — Phase 8
Memory Trust / Quarantine Engine

Scope:
    - Provenance
    - Trust states
    - Trust promotion / demotion
    - Quarantine
    - Revocation
    - Poisoning detection
    - Impact tracing
    - Validation
    - Testing

Strict boundary:
    This module implements ONLY Phase 8 functionality.

    Phase 7 is consumed through its existing public interface.
    No Phase 9+ functionality is implemented here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
from threading import RLock
from typing import Dict, FrozenSet, Iterable, List, Optional, Tuple
import unittest


# ============================================================================
# COMMON HELPERS
# ============================================================================

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def ensure_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware")
    return value


# ============================================================================
# TRUST STATE
# ============================================================================

class MemoryTrustState(str, Enum):
    """
    Lifecycle state of a memory from a trust perspective.
    """

    UNASSESSED = "UNASSESSED"
    PROVISIONAL = "PROVISIONAL"
    TRUSTED = "TRUSTED"
    DEGRADED = "DEGRADED"
    QUARANTINED = "QUARANTINED"
    REVOKED = "REVOKED"


# ============================================================================
# PROVENANCE
# ============================================================================

@dataclass(frozen=True)
class MemoryProvenance:
    """
    Immutable provenance information associated with a memory.
    """

    source_id: str
    source_type: str
    collection_method: str
    collected_at: datetime
    collector_id: Optional[str] = None
    parent_evidence_ids: FrozenSet[str] = frozenset()
    source_integrity: float = 1.0
    metadata: Tuple[Tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        ensure_aware(self.collected_at)

        if not self.source_id.strip():
            raise ValueError("source_id must not be empty")

        if not self.source_type.strip():
            raise ValueError("source_type must not be empty")

        if not self.collection_method.strip():
            raise ValueError("collection_method must not be empty")

        if not 0.0 <= self.source_integrity <= 1.0:
            raise ValueError("source_integrity must be between 0 and 1")


# ============================================================================
# TRUST ASSESSMENT
# ============================================================================

@dataclass(frozen=True)
class TrustAssessment:
    """
    Evidence-backed trust assessment.

    The engine does not automatically assume that a high score means
    trustworthy memory. State transitions are governed by explicit policy.
    """

    assessed_at: datetime
    score: float
    reasons: Tuple[str, ...] = ()
    assessor_id: Optional[str] = None

    def __post_init__(self) -> None:
        ensure_aware(self.assessed_at)

        if not 0.0 <= self.score <= 1.0:
            raise ValueError("trust score must be between 0 and 1")


# ============================================================================
# POISONING INDICATOR
# ============================================================================

class PoisoningIndicatorType(str, Enum):
    HASH_MISMATCH = "HASH_MISMATCH"
    PROVENANCE_GAP = "PROVENANCE_GAP"
    CONTRADICTION = "CONTRADICTION"
    UNEXPECTED_MUTATION = "UNEXPECTED_MUTATION"
    REPLAY = "REPLAY"
    SOURCE_INTEGRITY_FAILURE = "SOURCE_INTEGRITY_FAILURE"
    TRUST_ANOMALY = "TRUST_ANOMALY"


@dataclass(frozen=True)
class PoisoningIndicator:
    indicator_id: str
    memory_id: str
    indicator_type: PoisoningIndicatorType
    severity: float
    detected_at: datetime
    description: str
    evidence_ids: FrozenSet[str] = frozenset()

    def __post_init__(self) -> None:
        ensure_aware(self.detected_at)

        if not self.indicator_id.strip():
            raise ValueError("indicator_id must not be empty")

        if not self.memory_id.strip():
            raise ValueError("memory_id must not be empty")

        if not 0.0 <= self.severity <= 1.0:
            raise ValueError("severity must be between 0 and 1")

        if not self.description.strip():
            raise ValueError("description must not be empty")


# ============================================================================
# TRUST EVENT
# ============================================================================

class TrustEventType(str, Enum):
    ASSESSED = "ASSESSED"
    PROMOTED = "PROMOTED"
    DEMOTED = "DEMOTED"
    QUARANTINED = "QUARANTINED"
    REVOKED = "REVOKED"
    RESTORED = "RESTORED"
    POISONING_DETECTED = "POISONING_DETECTED"


@dataclass(frozen=True)
class TrustEvent:
    event_id: str
    memory_id: str
    event_type: TrustEventType
    occurred_at: datetime
    previous_state: MemoryTrustState
    new_state: MemoryTrustState
    reason: str
    actor_id: Optional[str] = None

    def __post_init__(self) -> None:
        ensure_aware(self.occurred_at)

        if not self.event_id.strip():
            raise ValueError("event_id must not be empty")

        if not self.memory_id.strip():
            raise ValueError("memory_id must not be empty")

        if not self.reason.strip():
            raise ValueError("reason must not be empty")


# ============================================================================
# TRUST RECORD
# ============================================================================

@dataclass
class MemoryTrustRecord:
    """
    Runtime trust record associated with a Phase 7 memory.
    """

    memory_id: str
    scope_id: str
    provenance: MemoryProvenance
    state: MemoryTrustState = MemoryTrustState.UNASSESSED
    assessment: Optional[TrustAssessment] = None
    indicators: List[PoisoningIndicator] = field(default_factory=list)
    events: List[TrustEvent] = field(default_factory=list)
    quarantined_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    baseline_hash: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.memory_id.strip():
            raise ValueError("memory_id must not be empty")

        if not self.scope_id.strip():
            raise ValueError("scope_id must not be empty")

        if self.quarantined_at is not None:
            ensure_aware(self.quarantined_at)

        if self.revoked_at is not None:
            ensure_aware(self.revoked_at)


# ============================================================================
# MEMORY TRUST ENGINE
# ============================================================================

class MemoryTrustQuarantineEngine:
    """
    Phase 8 trust boundary around Phase 7 causal security memory.

    Important:
        This engine does not modify the Phase 7 memory itself.

    It maintains independent trust state around existing memory IDs.
    """

    PROMOTION_THRESHOLD = 0.80
    PROVISIONAL_THRESHOLD = 0.50
    DEMOTION_THRESHOLD = 0.40
    QUARANTINE_THRESHOLD = 0.75

    def __init__(self, memory_engine) -> None:
        if memory_engine is None:
            raise ValueError("memory_engine is required")

        self._memory_engine = memory_engine
        self._records: Dict[str, MemoryTrustRecord] = {}
        self._lock = RLock()

    # ------------------------------------------------------------------------
    # INTERNAL MEMORY ACCESS
    # ------------------------------------------------------------------------

    def _get_phase7_memory(self, memory_id: str):
        """
        Resolve memory only through Phase 7's existing public interface.
        """
        memory = self._memory_engine.get_memory(memory_id)

        if memory is None:
            raise KeyError(f"memory does not exist: {memory_id}")

        return memory

    # ------------------------------------------------------------------------
    # REGISTRATION
    # ------------------------------------------------------------------------

    def register_memory(
        self,
        memory_id: str,
        *,
        scope_id: str,
        provenance: MemoryProvenance,
        baseline_hash: Optional[str] = None,
    ) -> MemoryTrustRecord:
        """
        Register an existing Phase 7 memory into the Phase 8 trust boundary.
        """

        with self._lock:
            memory = self._get_phase7_memory(memory_id)

            memory_scope = getattr(memory, "scope_id", None)

            if memory_scope is not None and memory_scope != scope_id:
                raise ValueError("memory scope does not match trust scope")

            if memory_id in self._records:
                raise ValueError(f"memory already registered: {memory_id}")

            record = MemoryTrustRecord(
                memory_id=memory_id,
                scope_id=scope_id,
                provenance=provenance,
                baseline_hash=baseline_hash,
            )

            self._records[memory_id] = record
            return record

    # ------------------------------------------------------------------------
    # LOOKUP
    # ------------------------------------------------------------------------

    def get_record(self, memory_id: str) -> MemoryTrustRecord:
        with self._lock:
            try:
                return self._records[memory_id]
            except KeyError:
                raise KeyError(f"memory trust record not found: {memory_id}")

    def get_state(self, memory_id: str) -> MemoryTrustState:
        return self.get_record(memory_id).state

    # ------------------------------------------------------------------------
    # HASH VALIDATION
    # ------------------------------------------------------------------------

    def verify_memory_integrity(self, memory_id: str) -> bool:
        """
        Ask Phase 7 memory to validate itself when the interface provides
        validate_hash().
        """

        memory = self._get_phase7_memory(memory_id)

        validator = getattr(memory, "validate_hash", None)

        if validator is None:
            return False

        return bool(validator())

    # ------------------------------------------------------------------------
    # TRUST ASSESSMENT
    # ------------------------------------------------------------------------

    def assess(
        self,
        memory_id: str,
        assessment: TrustAssessment,
    ) -> TrustEvent:
        """
        Assess trust and transition to an appropriate non-terminal state.
        """

        with self._lock:
            record = self.get_record(memory_id)

            if record.state in (
                MemoryTrustState.REVOKED,
                MemoryTrustState.QUARANTINED,
            ):
                raise ValueError(
                    f"cannot directly assess memory in state {record.state.value}"
                )

            previous = record.state
            record.assessment = assessment

            if assessment.score >= self.PROMOTION_THRESHOLD:
                new_state = MemoryTrustState.TRUSTED

            elif assessment.score >= self.PROVISIONAL_THRESHOLD:
                new_state = MemoryTrustState.PROVISIONAL

            else:
                new_state = MemoryTrustState.DEGRADED

            return self._record_transition(
                record,
                TrustEventType.ASSESSED,
                previous,
                new_state,
                reason="trust assessment applied",
            )

    # ------------------------------------------------------------------------
    # PROMOTION
    # ------------------------------------------------------------------------

    def promote(
        self,
        memory_id: str,
        *,
        reason: str,
        actor_id: Optional[str] = None,
    ) -> TrustEvent:
        with self._lock:
            record = self.get_record(memory_id)

            if record.state in (
                MemoryTrustState.QUARANTINED,
                MemoryTrustState.REVOKED,
            ):
                raise ValueError(
                    f"cannot promote memory in state {record.state.value}"
                )

            if record.assessment is None:
                raise ValueError("memory requires a trust assessment before promotion")

            if record.assessment.score < self.PROMOTION_THRESHOLD:
                raise ValueError("trust score is below promotion threshold")

            previous = record.state

            return self._record_transition(
                record,
                TrustEventType.PROMOTED,
                previous,
                MemoryTrustState.TRUSTED,
                reason=reason,
                actor_id=actor_id,
            )

    # ------------------------------------------------------------------------
    # DEMOTION
    # ------------------------------------------------------------------------

    def demote(
        self,
        memory_id: str,
        *,
        reason: str,
        actor_id: Optional[str] = None,
    ) -> TrustEvent:
        with self._lock:
            record = self.get_record(memory_id)

            if record.state == MemoryTrustState.REVOKED:
                raise ValueError("revoked memory cannot be demoted")

            if record.state == MemoryTrustState.QUARANTINED:
                raise ValueError("quarantined memory cannot be demoted")

            previous = record.state

            return self._record_transition(
                record,
                TrustEventType.DEMOTED,
                previous,
                MemoryTrustState.DEGRADED,
                reason=reason,
                actor_id=actor_id,
            )

    # ------------------------------------------------------------------------
    # QUARANTINE
    # ------------------------------------------------------------------------

    def quarantine(
        self,
        memory_id: str,
        *,
        reason: str,
        actor_id: Optional[str] = None,
    ) -> TrustEvent:
        with self._lock:
            record = self.get_record(memory_id)

            if record.state == MemoryTrustState.REVOKED:
                raise ValueError("revoked memory cannot be quarantined")

            previous = record.state
            now = utc_now()

            record.quarantined_at = now

            return self._record_transition(
                record,
                TrustEventType.QUARANTINED,
                previous,
                MemoryTrustState.QUARANTINED,
                reason=reason,
                actor_id=actor_id,
            )

    # ------------------------------------------------------------------------
    # REVOCATION
    # ------------------------------------------------------------------------

    def revoke(
        self,
        memory_id: str,
        *,
        reason: str,
        actor_id: Optional[str] = None,
    ) -> TrustEvent:
        with self._lock:
            record = self.get_record(memory_id)

            if record.state == MemoryTrustState.REVOKED:
                raise ValueError("memory already revoked")

            previous = record.state
            record.revoked_at = utc_now()

            return self._record_transition(
                record,
                TrustEventType.REVOKED,
                previous,
                MemoryTrustState.REVOKED,
                reason=reason,
                actor_id=actor_id,
            )

    # ------------------------------------------------------------------------
    # RESTORATION FROM QUARANTINE
    # ------------------------------------------------------------------------

    def restore_from_quarantine(
        self,
        memory_id: str,
        *,
        assessment: TrustAssessment,
        reason: str,
        actor_id: Optional[str] = None,
    ) -> TrustEvent:
        """
        Controlled restoration.

        A quarantined memory must receive a sufficiently strong assessment.
        """

        with self._lock:
            record = self.get_record(memory_id)

            if record.state != MemoryTrustState.QUARANTINED:
                raise ValueError("memory is not quarantined")

            if assessment.score < self.PROMOTION_THRESHOLD:
                raise ValueError(
                    "quarantined memory requires a strong trust assessment"
                )

            record.assessment = assessment

            previous = record.state
            record.quarantined_at = None

            return self._record_transition(
                record,
                TrustEventType.RESTORED,
                previous,
                MemoryTrustState.TRUSTED,
                reason=reason,
                actor_id=actor_id,
            )

    # ------------------------------------------------------------------------
    # POISONING DETECTION
    # ------------------------------------------------------------------------

    def detect_poisoning(
        self,
        memory_id: str,
        indicators: Iterable[PoisoningIndicator],
        *,
        quarantine_on_high_severity: bool = True,
    ) -> Tuple[PoisoningIndicator, ...]:
        """
        Register poisoning indicators.

        Detection is deterministic:
            indicators are recorded;
            high-severity indicators can trigger quarantine.

        No attacker attribution is performed.
        """

        with self._lock:
            record = self.get_record(memory_id)

            collected = []

            for indicator in indicators:
                if indicator.memory_id != memory_id:
                    raise ValueError(
                        "poisoning indicator references another memory"
                    )

                record.indicators.append(indicator)
                collected.append(indicator)

            high_severity = any(
                indicator.severity >= self.QUARANTINE_THRESHOLD
                for indicator in collected
            )

            if (
                high_severity
                and quarantine_on_high_severity
                and record.state != MemoryTrustState.REVOKED
                and record.state != MemoryTrustState.QUARANTINED
            ):
                self.quarantine(
                    memory_id,
                    reason="high-severity poisoning indicator detected",
                )

                for indicator in collected:
                    self._append_poisoning_event(
                        record,
                        indicator,
                    )

            else:
                for indicator in collected:
                    self._append_poisoning_event(
                        record,
                        indicator,
                    )

            return tuple(collected)

    def _append_poisoning_event(
        self,
        record: MemoryTrustRecord,
        indicator: PoisoningIndicator,
    ) -> None:
        previous = record.state

        event = TrustEvent(
            event_id=self._event_id(
                record.memory_id,
                TrustEventType.POISONING_DETECTED,
                len(record.events),
            ),
            memory_id=record.memory_id,
            event_type=TrustEventType.POISONING_DETECTED,
            occurred_at=utc_now(),
            previous_state=previous,
            new_state=record.state,
            reason=indicator.description,
        )

        record.events.append(event)

    # ------------------------------------------------------------------------
    # IMPACT TRACING
    # ------------------------------------------------------------------------

    def trace_impact(self, memory_id: str) -> Tuple[str, ...]:
        """
        Trace direct and causal downstream memory impact using Phase 7's
        existing causal retrieval interface.

        This is trust-impact tracing, not adversary attribution.
        """

        self.get_record(memory_id)

        impacted = set()

        effects_of = getattr(
            self._memory_engine,
            "effects_of",
            None,
        )

        if effects_of is None:
            return ()

        queue = list(effects_of(memory_id))
        visited = set()

        while queue:
            current = queue.pop(0)

            if current in visited:
                continue

            visited.add(current)

            if current != memory_id:
                impacted.add(current)

            queue.extend(effects_of(current))

        return tuple(sorted(impacted))

    # ------------------------------------------------------------------------
    # TRUSTED / USABLE MEMORY FILTER
    # ------------------------------------------------------------------------

    def is_trusted(self, memory_id: str) -> bool:
        return self.get_state(memory_id) == MemoryTrustState.TRUSTED

    def is_usable_for_trusted_decision(self, memory_id: str) -> bool:
        """
        Phase 8 safety boundary.

        Only explicitly TRUSTED memory is considered usable for trusted
        decision input.

        Provisional/degraded/quarantined/revoked memory is excluded.
        """

        return self.is_trusted(memory_id)

    # ------------------------------------------------------------------------
    # TRANSITION RECORDING
    # ------------------------------------------------------------------------

    def _record_transition(
        self,
        record: MemoryTrustRecord,
        event_type: TrustEventType,
        previous: MemoryTrustState,
        new_state: MemoryTrustState,
        *,
        reason: str,
        actor_id: Optional[str] = None,
    ) -> TrustEvent:

        if not reason.strip():
            raise ValueError("transition reason must not be empty")

        record.state = new_state

        event = TrustEvent(
            event_id=self._event_id(
                record.memory_id,
                event_type,
                len(record.events),
            ),
            memory_id=record.memory_id,
            event_type=event_type,
            occurred_at=utc_now(),
            previous_state=previous,
            new_state=new_state,
            reason=reason,
            actor_id=actor_id,
        )

        record.events.append(event)

        return event

    @staticmethod
    def _event_id(
        memory_id: str,
        event_type: TrustEventType,
        sequence: int,
    ) -> str:
        material = f"{memory_id}|{event_type.value}|{sequence}"
        return sha256(material.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------------
    # VALIDATION
    # ------------------------------------------------------------------------

    def validate(self) -> List[str]:
        """
        Validate Phase 8 trust invariants.
        """

        errors: List[str] = []

        with self._lock:
            for memory_id, record in self._records.items():

                if memory_id != record.memory_id:
                    errors.append(
                        f"record key mismatch: {memory_id}"
                    )

                try:
                    self._get_phase7_memory(memory_id)
                except KeyError:
                    errors.append(
                        f"missing Phase 7 memory: {memory_id}"
                    )

                if record.state == MemoryTrustState.QUARANTINED:
                    if record.quarantined_at is None:
                        errors.append(
                            f"quarantined memory lacks timestamp: {memory_id}"
                        )

                if record.state == MemoryTrustState.REVOKED:
                    if record.revoked_at is None:
                        errors.append(
                            f"revoked memory lacks timestamp: {memory_id}"
                        )

                if record.assessment is not None:
                    if not 0.0 <= record.assessment.score <= 1.0:
                        errors.append(
                            f"invalid trust score: {memory_id}"
                        )

                for indicator in record.indicators:
                    if indicator.memory_id != memory_id:
                        errors.append(
                            f"indicator memory mismatch: {indicator.indicator_id}"
                        )

                for event in record.events:
                    if event.memory_id != memory_id:
                        errors.append(
                            f"event memory mismatch: {event.event_id}"
                        )

        return errors

    # ------------------------------------------------------------------------
    # EXPORT
    # ------------------------------------------------------------------------

    def export_record(self, memory_id: str) -> dict:
        record = self.get_record(memory_id)

        return {
            "memory_id": record.memory_id,
            "scope_id": record.scope_id,
            "state": record.state.value,
            "provenance": {
                "source_id": record.provenance.source_id,
                "source_type": record.provenance.source_type,
                "collection_method": record.provenance.collection_method,
                "collected_at": record.provenance.collected_at.isoformat(),
                "collector_id": record.provenance.collector_id,
                "parent_evidence_ids": sorted(
                    record.provenance.parent_evidence_ids
                ),
                "source_integrity": record.provenance.source_integrity,
                "metadata": dict(record.provenance.metadata),
            },
            "assessment": (
                None
                if record.assessment is None
                else {
                    "assessed_at": record.assessment.assessed_at.isoformat(),
                    "score": record.assessment.score,
                    "reasons": list(record.assessment.reasons),
                    "assessor_id": record.assessment.assessor_id,
                }
            ),
            "indicators": [
                {
                    "indicator_id": item.indicator_id,
                    "type": item.indicator_type.value,
                    "severity": item.severity,
                    "detected_at": item.detected_at.isoformat(),
                    "description": item.description,
                    "evidence_ids": sorted(item.evidence_ids),
                }
                for item in record.indicators
            ],
            "events": [
                {
                    "event_id": event.event_id,
                    "type": event.event_type.value,
                    "occurred_at": event.occurred_at.isoformat(),
                    "previous_state": event.previous_state.value,
                    "new_state": event.new_state.value,
                    "reason": event.reason,
                    "actor_id": event.actor_id,
                }
                for event in record.events
            ],
            "quarantined_at": (
                record.quarantined_at.isoformat()
                if record.quarantined_at
                else None
            ),
            "revoked_at": (
                record.revoked_at.isoformat()
                if record.revoked_at
                else None
            ),
            "baseline_hash": record.baseline_hash,
        }


# ============================================================================
# PHASE 8 TEST DOUBLE
# ============================================================================

class _FakeMemory:
    """
    Minimal Phase 7-compatible test double.

    Only existing public Phase 7-style interfaces required by Phase 8
    are represented here.
    """

    def __init__(
        self,
        memory_id: str,
        scope_id: str,
        *,
        valid_hash: bool = True,
    ):
        self.memory_id = memory_id
        self.scope_id = scope_id
        self._valid_hash = valid_hash

    def validate_hash(self) -> bool:
        return self._valid_hash


class _FakePhase7MemoryEngine:
    """
    Test double representing the Phase 7 public interface.
    """

    def __init__(self):
        self.memories: Dict[str, _FakeMemory] = {}
        self.effects: Dict[str, List[str]] = {}

    def add(self, memory: _FakeMemory) -> None:
        self.memories[memory.memory_id] = memory

    def get_memory(self, memory_id: str):
        if memory_id not in self.memories:
            raise KeyError(memory_id)

        return self.memories[memory_id]

    def effects_of(self, memory_id: str):
        return tuple(self.effects.get(memory_id, ()))


# ============================================================================
# TESTS
# ============================================================================

class Phase8Tests(unittest.TestCase):

    def setUp(self):
        self.phase7 = _FakePhase7MemoryEngine()

        self.phase7.add(
            _FakeMemory("mem-1", "scope-a")
        )
        self.phase7.add(
            _FakeMemory("mem-2", "scope-a")
        )
        self.phase7.add(
            _FakeMemory("mem-3", "scope-a")
        )

        self.phase7.effects["mem-1"] = ["mem-2"]
        self.phase7.effects["mem-2"] = ["mem-3"]

        self.engine = MemoryTrustQuarantineEngine(
            self.phase7
        )

        self.provenance = MemoryProvenance(
            source_id="sensor-01",
            source_type="telemetry",
            collection_method="signed_ingestion",
            collected_at=utc_now(),
            collector_id="collector-01",
            source_integrity=1.0,
        )

    def register(self, memory_id="mem-1"):
        return self.engine.register_memory(
            memory_id,
            scope_id="scope-a",
            provenance=self.provenance,
        )

    # ------------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------------

    def test_registration(self):
        record = self.register()

        self.assertEqual(
            record.state,
            MemoryTrustState.UNASSESSED,
        )

    def test_duplicate_registration_rejected(self):
        self.register()

        with self.assertRaises(ValueError):
            self.register()

    def test_scope_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            self.engine.register_memory(
                "mem-1",
                scope_id="scope-b",
                provenance=self.provenance,
            )

    # ------------------------------------------------------------------------
    # Assessment
    # ------------------------------------------------------------------------

    def test_high_trust_assessment(self):
        self.register()

        self.engine.assess(
            "mem-1",
            TrustAssessment(
                assessed_at=utc_now(),
                score=0.95,
                reasons=("strong provenance",),
            ),
        )

        self.assertEqual(
            self.engine.get_state("mem-1"),
            MemoryTrustState.TRUSTED,
        )

    def test_medium_trust_assessment(self):
        self.register()

        self.engine.assess(
            "mem-1",
            TrustAssessment(
                assessed_at=utc_now(),
                score=0.65,
            ),
        )

        self.assertEqual(
            self.engine.get_state("mem-1"),
            MemoryTrustState.PROVISIONAL,
        )

    def test_low_trust_assessment(self):
        self.register()

        self.engine.assess(
            "mem-1",
            TrustAssessment(
                assessed_at=utc_now(),
                score=0.20,
            ),
        )

        self.assertEqual(
            self.engine.get_state("mem-1"),
            MemoryTrustState.DEGRADED,
        )

    # ------------------------------------------------------------------------
    # Promotion / Demotion
    # ------------------------------------------------------------------------

    def test_promotion(self):
        self.register()

        self.engine.assess(
            "mem-1",
            TrustAssessment(
                assessed_at=utc_now(),
                score=0.90,
            ),
        )

        self.engine.promote(
            "mem-1",
            reason="independent evidence confirmed source",
        )

        self.assertEqual(
            self.engine.get_state("mem-1"),
            MemoryTrustState.TRUSTED,
        )

    def test_promotion_without_assessment_rejected(self):
        self.register()

        with self.assertRaises(ValueError):
            self.engine.promote(
                "mem-1",
                reason="invalid shortcut",
            )

    def test_demotion(self):
        self.register()

        self.engine.assess(
            "mem-1",
            TrustAssessment(
                assessed_at=utc_now(),
                score=0.95,
            ),
        )

        self.engine.demote(
            "mem-1",
            reason="new contradiction discovered",
        )

        self.assertEqual(
            self.engine.get_state("mem-1"),
            MemoryTrustState.DEGRADED,
        )

    # ------------------------------------------------------------------------
    # Quarantine
    # ------------------------------------------------------------------------

    def test_quarantine(self):
        self.register()

        self.engine.quarantine(
            "mem-1",
            reason="source integrity concern",
        )

        self.assertEqual(
            self.engine.get_state("mem-1"),
            MemoryTrustState.QUARANTINED,
        )

        self.assertIsNotNone(
            self.engine.get_record("mem-1").quarantined_at
        )

    def test_quarantine_blocks_promotion(self):
        self.register()

        self.engine.quarantine(
            "mem-1",
            reason="poisoning suspicion",
        )

        with self.assertRaises(ValueError):
            self.engine.promote(
                "mem-1",
                reason="unsafe promotion",
            )

    # ------------------------------------------------------------------------
    # Revocation
    # ------------------------------------------------------------------------

    def test_revocation(self):
        self.register()

        self.engine.revoke(
            "mem-1",
            reason="memory source permanently invalidated",
        )

        self.assertEqual(
            self.engine.get_state("mem-1"),
            MemoryTrustState.REVOKED,
        )

        self.assertIsNotNone(
            self.engine.get_record("mem-1").revoked_at
        )

    def test_revocation_is_terminal(self):
        self.register()

        self.engine.revoke(
            "mem-1",
            reason="source invalidated",
        )

        with self.assertRaises(ValueError):
            self.engine.demote(
                "mem-1",
                reason="should fail",
            )

    # ------------------------------------------------------------------------
    # Restoration
    # ------------------------------------------------------------------------

    def test_quarantine_restoration(self):
        self.register()

        self.engine.quarantine(
            "mem-1",
            reason="temporary uncertainty",
        )

        self.engine.restore_from_quarantine(
            "mem-1",
            assessment=TrustAssessment(
                assessed_at=utc_now(),
                score=0.92,
                reasons=("independent validation",),
            ),
            reason="validation completed",
        )

        self.assertEqual(
            self.engine.get_state("mem-1"),
            MemoryTrustState.TRUSTED,
        )

    def test_weak_restoration_rejected(self):
        self.register()

        self.engine.quarantine(
            "mem-1",
            reason="temporary uncertainty",
        )

        with self.assertRaises(ValueError):
            self.engine.restore_from_quarantine(
                "mem-1",
                assessment=TrustAssessment(
                    assessed_at=utc_now(),
                    score=0.30,
                ),
                reason="insufficient validation",
            )

    # ------------------------------------------------------------------------
    # Poisoning
    # ------------------------------------------------------------------------

    def test_high_severity_poisoning_quarantines(self):
        self.register()

        indicator = PoisoningIndicator(
            indicator_id="pi-1",
            memory_id="mem-1",
            indicator_type=PoisoningIndicatorType.HASH_MISMATCH,
            severity=0.95,
            detected_at=utc_now(),
            description="memory integrity hash mismatch",
        )

        self.engine.detect_poisoning(
            "mem-1",
            [indicator],
        )

        self.assertEqual(
            self.engine.get_state("mem-1"),
            MemoryTrustState.QUARANTINED,
        )

    def test_low_severity_poisoning_does_not_auto_quarantine(self):
        self.register()

        indicator = PoisoningIndicator(
            indicator_id="pi-2",
            memory_id="mem-1",
            indicator_type=PoisoningIndicatorType.TRUST_ANOMALY,
            severity=0.20,
            detected_at=utc_now(),
            description="weak trust anomaly",
        )

        self.engine.detect_poisoning(
            "mem-1",
            [indicator],
        )

        self.assertNotEqual(
            self.engine.get_state("mem-1"),
            MemoryTrustState.QUARANTINED,
        )

    def test_poisoning_memory_id_mismatch_rejected(self):
        self.register()

        indicator = PoisoningIndicator(
            indicator_id="pi-3",
            memory_id="mem-2",
            indicator_type=PoisoningIndicatorType.CONTRADICTION,
            severity=0.80,
            detected_at=utc_now(),
            description="wrong memory reference",
        )

        with self.assertRaises(ValueError):
            self.engine.detect_poisoning(
                "mem-1",
                [indicator],
            )

    # ------------------------------------------------------------------------
    # Integrity
    # ------------------------------------------------------------------------

    def test_phase7_hash_validation_interface(self):
        self.register()

        self.assertTrue(
            self.engine.verify_memory_integrity("mem-1")
        )

    # ------------------------------------------------------------------------
    # Impact
    # ------------------------------------------------------------------------

    def test_impact_tracing(self):
        self.register("mem-1")

        self.register("mem-2")
        self.register("mem-3")

        impacted = self.engine.trace_impact("mem-1")

        self.assertEqual(
            impacted,
            ("mem-2", "mem-3"),
        )

    # ------------------------------------------------------------------------
    # Trusted boundary
    # ------------------------------------------------------------------------

    def test_only_trusted_memory_is_usable(self):
        self.register()

        self.assertFalse(
            self.engine.is_usable_for_trusted_decision("mem-1")
        )

        self.engine.assess(
            "mem-1",
            TrustAssessment(
                assessed_at=utc_now(),
                score=0.95,
            ),
        )

        self.assertTrue(
            self.engine.is_usable_for_trusted_decision("mem-1")
        )

    def test_quarantined_memory_is_not_usable(self):
        self.register()

        self.engine.quarantine(
            "mem-1",
            reason="suspected poisoning",
        )

        self.assertFalse(
            self.engine.is_usable_for_trusted_decision("mem-1")
        )

    def test_revoked_memory_is_not_usable(self):
        self.register()

        self.engine.revoke(
            "mem-1",
            reason="revoked provenance",
        )

        self.assertFalse(
            self.engine.is_usable_for_trusted_decision("mem-1")
        )

    # ------------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------------

    def test_validation_clean(self):
        self.register()

        self.assertEqual(
            self.engine.validate(),
            [],
        )

    # ------------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------------

    def test_export(self):
        self.register()

        exported = self.engine.export_record("mem-1")

        self.assertEqual(
            exported["memory_id"],
            "mem-1",
        )

        self.assertEqual(
            exported["state"],
            MemoryTrustState.UNASSESSED.value,
        )


# ============================================================================
# TEST RUNNER
# ============================================================================

def run_phase8_tests() -> None:
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        Phase8Tests
    )

    result = unittest.TextTestRunner(
        verbosity=2
    ).run(suite)

    if not result.wasSuccessful():
        raise AssertionError(
            "Phase 8 verification failed"
        )


if __name__ == "__main__":
    run_phase8_tests()
