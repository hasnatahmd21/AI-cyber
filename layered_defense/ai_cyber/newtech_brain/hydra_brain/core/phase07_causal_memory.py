"""
HYDRA™
PHASE 7 — CAUSAL SECURITY MEMORY

Scope ONLY:
    - Evidence-linked security memory
    - Causal relationships
    - Causal hypotheses
    - Alternative explanations
    - Security outcomes
    - Memory lineage
    - Causal retrieval
    - Validation
    - Tests

No Phase 8+ functionality is implemented.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, Optional
import copy
import hashlib
import json
import threading
import unittest
import uuid


# ============================================================================
# ENUMS
# ============================================================================


class MemoryType(str, Enum):
    OBSERVATION = "observation"
    CAUSAL = "causal"
    HYPOTHESIS = "hypothesis"
    ALTERNATIVE = "alternative"
    OUTCOME = "outcome"


class CausalRelationType(str, Enum):
    CAUSED = "caused"
    CONTRIBUTED_TO = "contributed_to"
    ENABLED = "enabled"
    PRECEDED = "preceded"
    CORRELATED_WITH = "correlated_with"


class HypothesisStatus(str, Enum):
    OPEN = "open"
    SUPPORTED = "supported"
    WEAKENED = "weakened"
    REJECTED = "rejected"


# ============================================================================
# EXCEPTIONS
# ============================================================================


class CausalMemoryError(Exception):
    """Base Phase-7 exception."""


class InvalidCausalMemory(CausalMemoryError):
    """Invalid Phase-7 memory."""


class MemoryNotFound(CausalMemoryError):
    """Requested memory does not exist."""


class CausalRelationNotFound(CausalMemoryError):
    """Requested causal relation does not exist."""


# ============================================================================
# UTILITIES
# ============================================================================


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def ensure_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise InvalidCausalMemory(
            "Timestamp must be timezone-aware"
        )

    return value.astimezone(timezone.utc)


def canonicalize(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value

    if isinstance(value, datetime):
        return value.astimezone(
            timezone.utc
        ).isoformat()

    if isinstance(value, Mapping):
        return {
            str(key): canonicalize(value[key])
            for key in sorted(
                value,
                key=lambda item: str(item),
            )
        }

    if isinstance(value, (list, tuple)):
        return [
            canonicalize(item)
            for item in value
        ]

    if isinstance(value, set):
        return sorted(
            (
                canonicalize(item)
                for item in value
            ),
            key=lambda item: json.dumps(
                item,
                sort_keys=True,
                separators=(",", ":"),
            ),
        )

    if isinstance(value, (str, int, float, bool)) or value is None:
        return value

    raise TypeError(
        f"Unsupported value type: {type(value)!r}"
    )


def canonical_json(value: Any) -> str:
    return json.dumps(
        canonicalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def content_hash(value: Any) -> str:
    return hashlib.sha256(
        canonical_json(value).encode("utf-8")
    ).hexdigest()


# ============================================================================
# EVIDENCE REFERENCE
# ============================================================================


@dataclass(frozen=True)
class EvidenceReference:
    evidence_id: str
    evidence_type: str
    source_id: str
    observed_at: datetime
    fingerprint: str
    metadata: Mapping[str, Any] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        if not self.evidence_id:
            raise InvalidCausalMemory(
                "evidence_id cannot be empty"
            )

        if not self.source_id:
            raise InvalidCausalMemory(
                "source_id cannot be empty"
            )

        ensure_aware(self.observed_at)

        if not self.fingerprint:
            raise InvalidCausalMemory(
                "Evidence fingerprint cannot be empty"
            )

        object.__setattr__(
            self,
            "metadata",
            copy.deepcopy(
                dict(self.metadata)
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "evidence_type": self.evidence_type,
            "source_id": self.source_id,
            "observed_at": self.observed_at.isoformat(),
            "fingerprint": self.fingerprint,
            "metadata": canonicalize(
                self.metadata
            ),
        }


# ============================================================================
# MEMORY LINEAGE
# ============================================================================


@dataclass(frozen=True)
class MemoryLineage:
    lineage_id: str
    parent_memory_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    created_at: datetime
    derivation: str

    def __post_init__(self) -> None:
        ensure_aware(self.created_at)

        if not self.derivation:
            raise InvalidCausalMemory(
                "Lineage derivation cannot be empty"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "lineage_id": self.lineage_id,
            "parent_memory_ids": list(
                self.parent_memory_ids
            ),
            "evidence_ids": list(
                self.evidence_ids
            ),
            "created_at": self.created_at.isoformat(),
            "derivation": self.derivation,
        }


# ============================================================================
# SECURITY MEMORY
# ============================================================================


@dataclass(frozen=True)
class SecurityMemory:
    memory_id: str
    scope_id: str
    memory_type: MemoryType
    subject: str
    statement: str
    confidence: float
    created_at: datetime
    valid_from: datetime
    valid_until: Optional[datetime]
    evidence: tuple[EvidenceReference, ...]
    lineage: Optional[MemoryLineage]
    attributes: Mapping[str, Any] = field(
        default_factory=dict
    )
    content_hash: str = ""

    def __post_init__(self) -> None:
        if not self.memory_id:
            raise InvalidCausalMemory(
                "memory_id cannot be empty"
            )

        if not self.scope_id:
            raise InvalidCausalMemory(
                "scope_id cannot be empty"
            )

        if not self.subject:
            raise InvalidCausalMemory(
                "subject cannot be empty"
            )

        if not self.statement:
            raise InvalidCausalMemory(
                "statement cannot be empty"
            )

        if not 0.0 <= self.confidence <= 1.0:
            raise InvalidCausalMemory(
                "confidence must be between 0 and 1"
            )

        created_at = ensure_aware(
            self.created_at
        )

        valid_from = ensure_aware(
            self.valid_from
        )

        if (
            self.valid_until is not None
            and ensure_aware(
                self.valid_until
            ) < valid_from
        ):
            raise InvalidCausalMemory(
                "valid_until cannot precede valid_from"
            )

        object.__setattr__(
            self,
            "created_at",
            created_at,
        )

        object.__setattr__(
            self,
            "valid_from",
            valid_from,
        )

        object.__setattr__(
            self,
            "evidence",
            tuple(self.evidence),
        )

        object.__setattr__(
            self,
            "attributes",
            copy.deepcopy(
                dict(self.attributes)
            ),
        )

        hash_payload = {
            "scope_id": self.scope_id,
            "memory_type": self.memory_type.value,
            "subject": self.subject,
            "statement": self.statement,
            "confidence": self.confidence,
            "created_at": created_at,
            "valid_from": valid_from,
            "valid_until": self.valid_until,
            "evidence": [
                evidence.to_dict()
                for evidence in self.evidence
            ],
            "attributes": self.attributes,
        }

        computed = content_hash(
            hash_payload
        )

        if self.content_hash and (
            self.content_hash != computed
        ):
            raise InvalidCausalMemory(
                "Memory content hash mismatch"
            )

        object.__setattr__(
            self,
            "content_hash",
            computed,
        )

    @classmethod
    def create(
        cls,
        *,
        scope_id: str,
        memory_type: MemoryType,
        subject: str,
        statement: str,
        confidence: float,
        evidence: tuple[
            EvidenceReference, ...
        ] = (),
        lineage: Optional[
            MemoryLineage
        ] = None,
        attributes: Optional[
            Mapping[str, Any]
        ] = None,
        created_at: Optional[
            datetime
        ] = None,
        valid_from: Optional[
            datetime
        ] = None,
        valid_until: Optional[
            datetime
        ] = None,
        memory_id: Optional[str] = None,
    ) -> "SecurityMemory":

        timestamp = created_at or utc_now()

        return cls(
            memory_id=memory_id or str(
                uuid.uuid4()
            ),
            scope_id=scope_id,
            memory_type=memory_type,
            subject=subject,
            statement=statement,
            confidence=confidence,
            created_at=timestamp,
            valid_from=(
                valid_from or timestamp
            ),
            valid_until=valid_until,
            evidence=evidence,
            lineage=lineage,
            attributes=(
                attributes or {}
            ),
        )

    def active_at(
        self,
        moment: datetime,
    ) -> bool:

        moment = ensure_aware(moment)

        if moment < self.valid_from:
            return False

        if (
            self.valid_until is not None
            and moment > self.valid_until
        ):
            return False

        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "memory_id": self.memory_id,
            "scope_id": self.scope_id,
            "memory_type": self.memory_type.value,
            "subject": self.subject,
            "statement": self.statement,
            "confidence": self.confidence,
            "created_at": self.created_at.isoformat(),
            "valid_from": self.valid_from.isoformat(),
            "valid_until": (
                self.valid_until.isoformat()
                if self.valid_until
                else None
            ),
            "evidence": [
                item.to_dict()
                for item in self.evidence
            ],
            "lineage": (
                self.lineage.to_dict()
                if self.lineage
                else None
            ),
            "attributes": canonicalize(
                self.attributes
            ),
            "content_hash": self.content_hash,
        }


# ============================================================================
# CAUSAL RELATION
# ============================================================================


@dataclass(frozen=True)
class CausalRelation:
    relation_id: str
    scope_id: str
    cause_memory_id: str
    effect_memory_id: str
    relation_type: CausalRelationType
    confidence: float
    evidence_ids: tuple[str, ...]
    created_at: datetime
    attributes: Mapping[str, Any] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        if not self.relation_id:
            raise InvalidCausalMemory(
                "relation_id cannot be empty"
            )

        if not self.scope_id:
            raise InvalidCausalMemory(
                "scope_id cannot be empty"
            )

        if (
            not self.cause_memory_id
            or not self.effect_memory_id
        ):
            raise InvalidCausalMemory(
                "Causal relation endpoints cannot be empty"
            )

        if not 0.0 <= self.confidence <= 1.0:
            raise InvalidCausalMemory(
                "Relation confidence must be between 0 and 1"
            )

        ensure_aware(self.created_at)

        object.__setattr__(
            self,
            "evidence_ids",
            tuple(self.evidence_ids),
        )

        object.__setattr__(
            self,
            "attributes",
            copy.deepcopy(
                dict(self.attributes)
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "relation_id": self.relation_id,
            "scope_id": self.scope_id,
            "cause_memory_id": self.cause_memory_id,
            "effect_memory_id": self.effect_memory_id,
            "relation_type": self.relation_type.value,
            "confidence": self.confidence,
            "evidence_ids": list(
                self.evidence_ids
            ),
            "created_at": self.created_at.isoformat(),
            "attributes": canonicalize(
                self.attributes
            ),
        }


# ============================================================================
# CAUSAL HYPOTHESIS
# ============================================================================


@dataclass(frozen=True)
class CausalHypothesis:
    hypothesis_id: str
    scope_id: str
    statement: str
    status: HypothesisStatus
    confidence: float
    supporting_memory_ids: tuple[str, ...]
    supporting_evidence_ids: tuple[str, ...]
    alternative_memory_ids: tuple[str, ...]
    created_at: datetime
    updated_at: datetime

    def __post_init__(self) -> None:
        if not self.hypothesis_id:
            raise InvalidCausalMemory(
                "hypothesis_id cannot be empty"
            )

        if not self.statement:
            raise InvalidCausalMemory(
                "Hypothesis statement cannot be empty"
            )

        if not 0.0 <= self.confidence <= 1.0:
            raise InvalidCausalMemory(
                "Hypothesis confidence must be between 0 and 1"
            )

        ensure_aware(self.created_at)
        ensure_aware(self.updated_at)

        object.__setattr__(
            self,
            "supporting_memory_ids",
            tuple(
                self.supporting_memory_ids
            ),
        )

        object.__setattr__(
            self,
            "supporting_evidence_ids",
            tuple(
                self.supporting_evidence_ids
            ),
        )

        object.__setattr__(
            self,
            "alternative_memory_ids",
            tuple(
                self.alternative_memory_ids
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "scope_id": self.scope_id,
            "statement": self.statement,
            "status": self.status.value,
            "confidence": self.confidence,
            "supporting_memory_ids": list(
                self.supporting_memory_ids
            ),
            "supporting_evidence_ids": list(
                self.supporting_evidence_ids
            ),
            "alternative_memory_ids": list(
                self.alternative_memory_ids
            ),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


# ============================================================================
# SECURITY OUTCOME
# ============================================================================


@dataclass(frozen=True)
class SecurityOutcome:
    outcome_id: str
    scope_id: str
    subject: str
    result: str
    success: bool
    confidence: float
    observed_at: datetime
    evidence_ids: tuple[str, ...]
    related_memory_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.outcome_id:
            raise InvalidCausalMemory(
                "outcome_id cannot be empty"
            )

        if not self.subject:
            raise InvalidCausalMemory(
                "Outcome subject cannot be empty"
            )

        if not self.result:
            raise InvalidCausalMemory(
                "Outcome result cannot be empty"
            )

        if not 0.0 <= self.confidence <= 1.0:
            raise InvalidCausalMemory(
                "Outcome confidence must be between 0 and 1"
            )

        ensure_aware(self.observed_at)

        object.__setattr__(
            self,
            "evidence_ids",
            tuple(self.evidence_ids),
        )

        object.__setattr__(
            self,
            "related_memory_ids",
            tuple(
                self.related_memory_ids
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome_id": self.outcome_id,
            "scope_id": self.scope_id,
            "subject": self.subject,
            "result": self.result,
            "success": self.success,
            "confidence": self.confidence,
            "observed_at": self.observed_at.isoformat(),
            "evidence_ids": list(
                self.evidence_ids
            ),
            "related_memory_ids": list(
                self.related_memory_ids
            ),
        }


# ============================================================================
# CAUSAL MEMORY ENGINE
# ============================================================================


class CausalSecurityMemoryEngine:
    """
    Phase-7-only causal memory layer.

    Responsibilities:
        - store evidence-linked memories
        - store causal relationships
        - store hypotheses and alternatives
        - store outcomes
        - maintain lineage
        - retrieve causal relationships

    Trust/quarantine/revocation is deliberately outside this phase.
    """

    def __init__(self) -> None:
        self._memories: dict[
            str,
            SecurityMemory,
        ] = {}

        self._relations: dict[
            str,
            CausalRelation,
        ] = {}

        self._hypotheses: dict[
            str,
            CausalHypothesis,
        ] = {}

        self._outcomes: dict[
            str,
            SecurityOutcome,
        ] = {}

        self._lock = threading.RLock()

    # ------------------------------------------------------------------------
    # MEMORY
    # ------------------------------------------------------------------------

    def add_memory(
        self,
        memory: SecurityMemory,
    ) -> None:

        with self._lock:
            if memory.memory_id in self._memories:
                raise InvalidCausalMemory(
                    f"Memory already exists: "
                    f"{memory.memory_id}"
                )

            if memory.lineage:
                for parent_id in (
                    memory.lineage.parent_memory_ids
                ):
                    if parent_id not in self._memories:
                        raise MemoryNotFound(
                            f"Lineage parent not found: "
                            f"{parent_id}"
                        )

            for evidence in memory.evidence:
                if not evidence.evidence_id:
                    raise InvalidCausalMemory(
                        "Evidence reference is invalid"
                    )

            self._memories[
                memory.memory_id
            ] = memory

    def get_memory(
        self,
        memory_id: str,
    ) -> SecurityMemory:

        try:
            return self._memories[memory_id]
        except KeyError as exc:
            raise MemoryNotFound(
                f"Memory not found: {memory_id}"
            ) from exc

    # ------------------------------------------------------------------------
    # CAUSAL RELATIONS
    # ------------------------------------------------------------------------

    def add_causal_relation(
        self,
        relation: CausalRelation,
    ) -> None:

        with self._lock:
            cause = self.get_memory(
                relation.cause_memory_id
            )

            effect = self.get_memory(
                relation.effect_memory_id
            )

            if (
                cause.scope_id
                != relation.scope_id
                or effect.scope_id
                != relation.scope_id
            ):
                raise InvalidCausalMemory(
                    "Causal relation scope mismatch"
                )

            if relation.relation_id in self._relations:
                raise InvalidCausalMemory(
                    f"Relation already exists: "
                    f"{relation.relation_id}"
                )

            self._relations[
                relation.relation_id
            ] = relation

    def get_relation(
        self,
        relation_id: str,
    ) -> CausalRelation:

        try:
            return self._relations[
                relation_id
            ]
        except KeyError as exc:
            raise CausalRelationNotFound(
                f"Relation not found: {relation_id}"
            ) from exc

    # ------------------------------------------------------------------------
    # HYPOTHESES
    # ------------------------------------------------------------------------

    def add_hypothesis(
        self,
        hypothesis: CausalHypothesis,
    ) -> None:

        with self._lock:
            for memory_id in (
                hypothesis.supporting_memory_ids
            ):
                self.get_memory(memory_id)

            for memory_id in (
                hypothesis.alternative_memory_ids
            ):
                self.get_memory(memory_id)

            if (
                hypothesis.hypothesis_id
                in self._hypotheses
            ):
                raise InvalidCausalMemory(
                    "Hypothesis already exists"
                )

            self._hypotheses[
                hypothesis.hypothesis_id
            ] = hypothesis

    # ------------------------------------------------------------------------
    # OUTCOMES
    # ------------------------------------------------------------------------

    def add_outcome(
        self,
        outcome: SecurityOutcome,
    ) -> None:

        with self._lock:
            for memory_id in (
                outcome.related_memory_ids
            ):
                self.get_memory(memory_id)

            if outcome.outcome_id in self._outcomes:
                raise InvalidCausalMemory(
                    "Outcome already exists"
                )

            self._outcomes[
                outcome.outcome_id
            ] = outcome

    # ------------------------------------------------------------------------
    # CAUSAL RETRIEVAL
    # ------------------------------------------------------------------------

    def causes_of(
        self,
        memory_id: str,
    ) -> tuple[SecurityMemory, ...]:

        self.get_memory(memory_id)

        with self._lock:
            relation_ids = [
                relation
                for relation in self._relations.values()
                if relation.effect_memory_id
                == memory_id
            ]

            return tuple(
                self.get_memory(
                    relation.cause_memory_id
                )
                for relation in relation_ids
            )

    def effects_of(
        self,
        memory_id: str,
    ) -> tuple[SecurityMemory, ...]:

        self.get_memory(memory_id)

        with self._lock:
            relation_ids = [
                relation
                for relation in self._relations.values()
                if relation.cause_memory_id
                == memory_id
            ]

            return tuple(
                self.get_memory(
                    relation.effect_memory_id
                )
                for relation in relation_ids
            )

    def causal_chain(
        self,
        root_memory_id: str,
        *,
        max_depth: int = 32,
    ) -> tuple[SecurityMemory, ...]:

        if max_depth < 0:
            raise InvalidCausalMemory(
                "max_depth cannot be negative"
            )

        self.get_memory(root_memory_id)

        visited: set[str] = set()
        result: list[SecurityMemory] = []

        queue: list[
            tuple[str, int]
        ] = [
            (root_memory_id, 0)
        ]

        while queue:
            memory_id, depth = queue.pop(0)

            if memory_id in visited:
                continue

            visited.add(memory_id)

            result.append(
                self.get_memory(memory_id)
            )

            if depth >= max_depth:
                continue

            for effect in self.effects_of(
                memory_id
            ):
                queue.append(
                    (
                        effect.memory_id,
                        depth + 1,
                    )
                )

        return tuple(result)

    # ------------------------------------------------------------------------
    # VALIDATION
    # ------------------------------------------------------------------------

    def validate(self) -> tuple[str, ...]:

        issues: list[str] = []

        with self._lock:
            for memory in self._memories.values():

                try:
                    recalculated = content_hash(
                        {
                            "scope_id": memory.scope_id,
                            "memory_type":
                                memory.memory_type.value,
                            "subject": memory.subject,
                            "statement":
                                memory.statement,
                            "confidence":
                                memory.confidence,
                            "created_at":
                                memory.created_at,
                            "valid_from":
                                memory.valid_from,
                            "valid_until":
                                memory.valid_until,
                            "evidence": [
                                evidence.to_dict()
                                for evidence
                                in memory.evidence
                            ],
                            "attributes":
                                memory.attributes,
                        }
                    )

                    if recalculated != memory.content_hash:
                        issues.append(
                            f"hash-mismatch:"
                            f"{memory.memory_id}"
                        )

                except Exception as exc:
                    issues.append(
                        f"memory-validation-error:"
                        f"{memory.memory_id}:"
                        f"{type(exc).__name__}"
                    )

            for relation in (
                self._relations.values()
            ):
                if (
                    relation.cause_memory_id
                    not in self._memories
                ):
                    issues.append(
                        f"missing-cause:"
                        f"{relation.relation_id}"
                    )

                if (
                    relation.effect_memory_id
                    not in self._memories
                ):
                    issues.append(
                        f"missing-effect:"
                        f"{relation.relation_id}"
                    )

                if (
                    relation.scope_id
                    != self._memories[
                        relation.cause_memory_id
                    ].scope_id
                    if relation.cause_memory_id
                    in self._memories
                    else False
                ):
                    issues.append(
                        f"relation-scope:"
                        f"{relation.relation_id}"
                    )

        return tuple(issues)

    # ------------------------------------------------------------------------
    # EXPORT
    # ------------------------------------------------------------------------

    def export_memory(
        self,
        memory_id: str,
    ) -> str:

        return json.dumps(
            self.get_memory(
                memory_id
            ).to_dict(),
            sort_keys=True,
            ensure_ascii=False,
            indent=2,
        )


# ============================================================================
# TESTS
# ============================================================================


class TestCausalSecurityMemoryEngine(
    unittest.TestCase
):

    def setUp(self) -> None:
        self.engine = (
            CausalSecurityMemoryEngine()
        )

        self.now = datetime(
            2026,
            9,
            7,
            12,
            0,
            tzinfo=timezone.utc,
        )

        self.evidence = EvidenceReference(
            evidence_id="ev-001",
            evidence_type="telemetry",
            source_id="sensor-A",
            observed_at=self.now,
            fingerprint="fingerprint-001",
        )

    def memory(
        self,
        memory_id: str,
        statement: str,
        *,
        memory_type: MemoryType = (
            MemoryType.OBSERVATION
        ),
        confidence: float = 0.8,
        evidence: tuple[
            EvidenceReference, ...
        ] = (),
    ) -> SecurityMemory:

        return SecurityMemory.create(
            memory_id=memory_id,
            scope_id="scope-A",
            memory_type=memory_type,
            subject="asset-A",
            statement=statement,
            confidence=confidence,
            evidence=evidence,
            created_at=self.now,
            valid_from=self.now,
        )

    def test_evidence_linked_memory(self) -> None:
        memory = self.memory(
            "m1",
            "Authentication failure observed",
            evidence=(self.evidence,),
        )

        self.engine.add_memory(memory)

        stored = self.engine.get_memory(
            "m1"
        )

        self.assertEqual(
            len(stored.evidence),
            1,
        )

        self.assertEqual(
            stored.evidence[0].evidence_id,
            "ev-001",
        )

    def test_memory_hash(self) -> None:
        memory = self.memory(
            "m1",
            "Event observed",
        )

        self.engine.add_memory(memory)

        self.assertTrue(
            memory.content_hash
        )

        self.assertEqual(
            self.engine.validate(),
            (),
        )

    def test_causal_relation(self) -> None:
        cause = self.memory(
            "m1",
            "Credential compromise observed",
        )

        effect = self.memory(
            "m2",
            "Unauthorized access observed",
        )

        self.engine.add_memory(cause)
        self.engine.add_memory(effect)

        relation = CausalRelation(
            relation_id="r1",
            scope_id="scope-A",
            cause_memory_id="m1",
            effect_memory_id="m2",
            relation_type=(
                CausalRelationType.CAUSED
            ),
            confidence=0.9,
            evidence_ids=("ev-001",),
            created_at=self.now,
        )

        self.engine.add_causal_relation(
            relation
        )

        causes = self.engine.causes_of(
            "m2"
        )

        self.assertEqual(
            [m.memory_id for m in causes],
            ["m1"],
        )

    def test_effect_retrieval(self) -> None:
        cause = self.memory(
            "m1",
            "Initial compromise",
        )

        effect = self.memory(
            "m2",
            "Privilege escalation",
        )

        self.engine.add_memory(cause)
        self.engine.add_memory(effect)

        self.engine.add_causal_relation(
            CausalRelation(
                relation_id="r1",
                scope_id="scope-A",
                cause_memory_id="m1",
                effect_memory_id="m2",
                relation_type=(
                    CausalRelationType.ENABLED
                ),
                confidence=0.7,
                evidence_ids=(),
                created_at=self.now,
            )
        )

        effects = self.engine.effects_of(
            "m1"
        )

        self.assertEqual(
            len(effects),
            1,
        )

        self.assertEqual(
            effects[0].memory_id,
            "m2",
        )

    def test_causal_chain(self) -> None:
        memories = [
            self.memory(
                "m1",
                "Initial event",
            ),
            self.memory(
                "m2",
                "Intermediate event",
            ),
            self.memory(
                "m3",
                "Resulting event",
            ),
        ]

        for memory in memories:
            self.engine.add_memory(memory)

        self.engine.add_causal_relation(
            CausalRelation(
                relation_id="r1",
                scope_id="scope-A",
                cause_memory_id="m1",
                effect_memory_id="m2",
                relation_type=(
                    CausalRelationType.CAUSED
                ),
                confidence=0.8,
                evidence_ids=(),
                created_at=self.now,
            )
        )

        self.engine.add_causal_relation(
            CausalRelation(
                relation_id="r2",
                scope_id="scope-A",
                cause_memory_id="m2",
                effect_memory_id="m3",
                relation_type=(
                    CausalRelationType.CAUSED
                ),
                confidence=0.8,
                evidence_ids=(),
                created_at=self.now,
            )
        )

        chain = self.engine.causal_chain(
            "m1"
        )

        self.assertEqual(
            [m.memory_id for m in chain],
            ["m1", "m2", "m3"],
        )

    def test_hypothesis_with_alternative(
        self,
    ) -> None:
        primary = self.memory(
            "m1",
            "Credential theft caused access",
            memory_type=(
                MemoryType.HYPOTHESIS
            ),
        )

        alternative = self.memory(
            "m2",
            "Misconfiguration caused access",
            memory_type=(
                MemoryType.ALTERNATIVE
            ),
        )

        self.engine.add_memory(primary)
        self.engine.add_memory(alternative)

        hypothesis = CausalHypothesis(
            hypothesis_id="h1",
            scope_id="scope-A",
            statement=(
                "Credential theft is the most likely "
                "cause of unauthorized access"
            ),
            status=HypothesisStatus.OPEN,
            confidence=0.75,
            supporting_memory_ids=("m1",),
            supporting_evidence_ids=(
                "ev-001",
            ),
            alternative_memory_ids=("m2",),
            created_at=self.now,
            updated_at=self.now,
        )

        self.engine.add_hypothesis(
            hypothesis
        )

        self.assertEqual(
            hypothesis.status,
            HypothesisStatus.OPEN,
        )

        self.assertEqual(
            hypothesis.alternative_memory_ids,
            ("m2",),
        )

    def test_lineage(self) -> None:
        parent = self.memory(
            "m1",
            "Source observation",
        )

        self.engine.add_memory(parent)

        lineage = MemoryLineage(
            lineage_id="l1",
            parent_memory_ids=("m1",),
            evidence_ids=("ev-001",),
            created_at=self.now,
            derivation=(
                "Derived from source observation"
            ),
        )

        child = self.memory(
            "m2",
            "Derived causal observation",
            memory_type=MemoryType.CAUSAL,
        )

        child = SecurityMemory.create(
            memory_id=child.memory_id,
            scope_id=child.scope_id,
            memory_type=child.memory_type,
            subject=child.subject,
            statement=child.statement,
            confidence=child.confidence,
            evidence=(self.evidence,),
            lineage=lineage,
            created_at=self.now,
            valid_from=self.now,
        )

        self.engine.add_memory(child)

        self.assertEqual(
            child.lineage.parent_memory_ids,
            ("m1",),
        )

    def test_outcome(self) -> None:
        memory = self.memory(
            "m1",
            "Control was applied",
        )

        self.engine.add_memory(memory)

        outcome = SecurityOutcome(
            outcome_id="o1",
            scope_id="scope-A",
            subject="control-001",
            result="Threat activity reduced",
            success=True,
            confidence=0.95,
            observed_at=self.now,
            evidence_ids=("ev-001",),
            related_memory_ids=("m1",),
        )

        self.engine.add_outcome(
            outcome
        )

        self.assertTrue(
            outcome.success
        )

    def test_missing_lineage_parent_rejected(
        self,
    ) -> None:
        lineage = MemoryLineage(
            lineage_id="l1",
            parent_memory_ids=("missing",),
            evidence_ids=(),
            created_at=self.now,
            derivation="Invalid parent",
        )

        memory = SecurityMemory.create(
            scope_id="scope-A",
            memory_type=MemoryType.CAUSAL,
            subject="asset-A",
            statement="Derived memory",
            confidence=0.5,
            lineage=lineage,
            created_at=self.now,
            valid_from=self.now,
        )

        with self.assertRaises(
            MemoryNotFound
        ):
            self.engine.add_memory(memory)

    def test_scope_mismatch_rejected(self) -> None:
        first = self.memory(
            "m1",
            "Cause",
        )

        second = SecurityMemory.create(
            memory_id="m2",
            scope_id="scope-B",
            memory_type=MemoryType.OBSERVATION,
            subject="asset-B",
            statement="Effect",
            confidence=0.8,
            created_at=self.now,
            valid_from=self.now,
        )

        self.engine.add_memory(first)
        self.engine.add_memory(second)

        relation = CausalRelation(
            relation_id="r1",
            scope_id="scope-A",
            cause_memory_id="m1",
            effect_memory_id="m2",
            relation_type=(
                CausalRelationType.CAUSED
            ),
            confidence=0.8,
            evidence_ids=(),
            created_at=self.now,
        )

        with self.assertRaises(
            InvalidCausalMemory
        ):
            self.engine.add_causal_relation(
                relation
            )

    def test_duplicate_memory_rejected(self) -> None:
        memory = self.memory(
            "m1",
            "Repeated event",
        )

        self.engine.add_memory(memory)

        with self.assertRaises(
            InvalidCausalMemory
        ):
            self.engine.add_memory(memory)

    def test_invalid_confidence_rejected(
        self,
    ) -> None:
        with self.assertRaises(
            InvalidCausalMemory
        ):
            self.memory(
                "m1",
                "Invalid",
                confidence=1.5,
            )

    def test_export(self) -> None:
        memory = self.memory(
            "m1",
            "Exportable event",
        )

        self.engine.add_memory(memory)

        exported = self.engine.export_memory(
            "m1"
        )

        self.assertIn(
            "Exportable event",
            exported,
        )


# ============================================================================
# TEST RUNNER
# ============================================================================


def run_phase7_tests() -> unittest.result.TestResult:
    suite = (
        unittest.defaultTestLoader
        .loadTestsFromTestCase(
            TestCausalSecurityMemoryEngine
        )
    )

    runner = unittest.TextTestRunner(
        verbosity=2
    )

    return runner.run(suite)


if __name__ == "__main__":
    run_phase7_tests()
