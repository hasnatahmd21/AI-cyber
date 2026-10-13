"""
hydra_brain.brain
=================

``HydraBrain`` wires the independent "New Tech" engines (phases 4-16) into
one working decision pipeline. The engines themselves stay untouched and
independent; this module only provides the adapters between them.

Pipeline
--------
    telemetry
      -> P5  integrity assessment (hash / replay / stale / contradiction)
      -> P8  memory trust (poisoned or replayed data is quarantined)
      -> P4  security state (only trustworthy telemetry updates state)
      -> P7  causal memory (events linked via causation ids)
      -> P11 invariant evaluation (violations reported)
    topology
      -> P6  temporal security graph -> attack path -> intervention points
    response
      -> P10 intervention optimisation (ranked candidates)
      -> P11 pre-action safety gate
      -> P12 authority check (permission + no unresolved drift)
      -> P16 offline simulation (dry run of the action)
      -> P15 re-planning cycle  <->  P14 independent verification
    intent
      -> P13 intent compiler -> P11 invariants (auto-installed)
    attribution
      -> P9  adversary hypotheses (only TRUSTED memory is used as evidence)

Everything is in-memory and standard-library only. Every decision is
appended to a hash-chained audit log (``brain.audit``).

IMPORTANT: this module never performs a real-world action. ``respond()``
only calls an ``executor`` callback that *you* supply; with no executor it
stops at the planned stage (dry run).
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
)

from .audit import AuditChain
from .core.phase04_security_state import SecurityStateEngine
from .core.phase05_state_integrity import (
    IntegrityIssue,
    IntegrityIssueType,
    IntegrityStatus,
    StateIntegrityEngine,
    TelemetryRecord,
)
from .core.phase06_security_graph import (
    AttackPath,
    GraphEdgeType,
    GraphNodeType,
    InterventionPoint,
    PathStatus,
    SecurityGraphEdge,
    SecurityGraphNode,
    TemporalSecurityGraph,
)
from .core.phase07_causal_memory import (
    CausalRelation,
    CausalRelationType,
    CausalSecurityMemoryEngine,
    EvidenceReference,
    MemoryType,
    SecurityMemory,
)
from .core.phase08_memory_trust import (
    MemoryProvenance,
    MemoryTrustQuarantineEngine,
    MemoryTrustState,
    PoisoningIndicator,
    PoisoningIndicatorType,
    TrustAssessment,
)
from .core.phase09_attribution import (
    AdversaryAttributionEngine,
    AdversaryCampaign,
    AdversaryHypothesis,
    AdversaryInfrastructure,
    AdversaryTTP,
    AttributionAssessment,
    AttributionEvidence,
    AttributionEvidenceType,
    CorrelationResult,
    TimeWindow,
)
from .core.phase10_intervention import (
    InterventionCandidate,
    InterventionConstraints,
    InterventionOptimizer,
    InterventionTarget,
    InterventionType,
    OptimizationObjective,
    OptimizationRequest,
    ScoredIntervention,
)
from .core.phase11_invariants import (
    InvariantCondition,
    InvariantConditionType,
    InvariantSeverity,
    InvariantStatus,
    RemediationType,
    SecurityInvariant,
    SecurityInvariantEngine,
    StateValue,
)
from .core.phase12_authority_graph import (
    AuthorityBaseline,
    AuthorityDrift,
    AuthorityEdge,
    AuthorityEdgeType,
    AuthorityNode,
    AuthorityNodeType,
    DynamicAuthorityGraph,
)
from .core.phase13_intent_compiler import (
    CompilationResult,
    ConstraintType,
    IntentConstraint,
    IntentPriority,
    MonitoringRequirement,
    ResponseMode,
    ResponseRequirement,
    SecurityIntent,
    SecurityIntentCompiler,
)
from .core.phase14_verification import (
    EvidenceIntegrity,
    EvidenceType,
    ExpectedOutcome,
    IndependentEvidence,
    IndependentVerificationEngine,
    ObservedOutcome,
    VerificationResult,
    VerificationStatus,
)
from .core.phase15_replanning import (
    ActionReference,
    AuthorizationReference,
    ContinuousReplanningEngine,
    ObservationReference,
    PlanReference,
    ReplanDecision,
    ReplanTrigger,
    ReplanTriggerType,
    SimulationReference,
    StateReference,
    VerificationReference,
)
from .core.phase16_cyber_experiment import (
    CyberExperimentEngine,
    ExperimentOutcomeStatus,
    ExperimentScenario,
    ExperimentStep,
    ExperimentTarget,
    ExperimentType,
    ScenarioType,
)


# ============================================================================
# HELPERS
# ============================================================================

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: Optional[datetime]) -> datetime:
    if value is None:
        return _utc_now()
    if value.tzinfo is None:
        raise ValueError("datetime must be timezone-aware")
    return value


def _enum(enum_cls: type, value: Any) -> Any:
    if isinstance(value, enum_cls):
        return value
    key = str(value).strip().upper()
    try:
        return enum_cls[key]
    except KeyError:
        valid = ", ".join(member.name for member in enum_cls)
        raise ValueError(
            f"unknown {enum_cls.__name__} {value!r}; valid: {valid}"
        ) from None


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, float(value)))


def _short_hash(*parts: Any) -> str:
    material = "|".join(str(part) for part in parts)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


# ============================================================================
# CONFIG + RESULT TYPES
# ============================================================================

@dataclass
class BrainConfig:
    """Tunable behaviour of the wired brain."""

    default_scope_id: str = "default"

    # P5 integrity
    stale_after_seconds: int = 900
    required_fields: Tuple[str, ...] = ()
    mutually_exclusive: Tuple[Tuple[str, Any, str, Any], ...] = ()

    # P12 authority: deny actions while the actor has unresolved drift.
    block_on_authority_drift: bool = True

    # P10 -> response: confidence assumed before any telemetry was ingested.
    default_confidence: float = 0.7


@dataclass(frozen=True)
class IngestResult:
    accepted: bool
    telemetry_id: str
    scope_id: str
    deduplicated: bool = False
    state_id: Optional[str] = None
    integrity_status: str = "UNKNOWN"
    confidence: float = 0.0
    issues: Tuple[str, ...] = ()
    memory_id: Optional[str] = None
    trust_state: Optional[str] = None
    violated_invariants: Tuple[str, ...] = ()
    audit_hash: str = ""


@dataclass(frozen=True)
class AttackPathReport:
    scope_id: str
    path: AttackPath
    intervention_points: Tuple[InterventionPoint, ...]

    @property
    def found(self) -> bool:
        return self.path.status != PathStatus.NOT_FOUND


@dataclass(frozen=True)
class ResponsePlan:
    scope_id: str
    request_id: str
    ranked: Tuple[ScoredIntervention, ...]
    candidates: Mapping[str, InterventionCandidate]
    recommended_ids: Tuple[str, ...]
    selectable_ids: Tuple[str, ...]
    blocked: Mapping[str, str]


@dataclass(frozen=True)
class AuthorizationDecision:
    allowed: bool
    actor_id: str
    permission: str
    reasons: Tuple[str, ...] = ()


@dataclass(frozen=True)
class AttributionReport:
    hypothesis_id: str
    assessment: AttributionAssessment
    matched_ttps: Tuple[str, ...]
    unmatched_ttps: Tuple[str, ...]
    matched_infrastructure: Tuple[str, ...]
    unmatched_infrastructure: Tuple[str, ...]
    used_evidence_memory_ids: Tuple[str, ...]
    excluded_evidence_memory_ids: Mapping[str, str]


@dataclass(frozen=True)
class ResponseReport:
    status: str
    scope_id: str
    candidate_id: Optional[str] = None
    intervention: Optional[str] = None
    target_id: Optional[str] = None
    authorization: Optional[AuthorizationDecision] = None
    simulation_status: Optional[str] = None
    verification_status: Optional[str] = None
    replan_decision: Optional[str] = None
    cycle_id: Optional[str] = None
    blocked: Mapping[str, str] = field(default_factory=dict)
    notes: Tuple[str, ...] = ()


Executor = Callable[[InterventionCandidate], Mapping[str, Any]]
Simulator = Callable[[InterventionCandidate], bool]
IndependentObserver = Callable[[InterventionCandidate], Mapping[str, Any]]
CandidateBuilder = Callable[
    [AttackPathReport, "HydraBrain"], Sequence[InterventionCandidate]
]

# P13 constraint types -> P11 condition types
_CONSTRAINT_TO_CONDITION = {
    ConstraintType.MUST: InvariantConditionType.EQUALS,
    ConstraintType.MUST_NOT: InvariantConditionType.NOT_EQUALS,
    ConstraintType.MAXIMUM: InvariantConditionType.LESS_THAN_OR_EQUAL,
    ConstraintType.MINIMUM: InvariantConditionType.GREATER_THAN_OR_EQUAL,
    ConstraintType.ALLOWED_SET: InvariantConditionType.IN_SET,
    ConstraintType.DENIED_SET: InvariantConditionType.NOT_IN_SET,
}

_PRIORITY_TO_SEVERITY = {
    IntentPriority.LOW: InvariantSeverity.LOW,
    IntentPriority.NORMAL: InvariantSeverity.MODERATE,
    IntentPriority.HIGH: InvariantSeverity.HIGH,
    IntentPriority.CRITICAL: InvariantSeverity.CRITICAL,
}

_RESPONSE_TO_REMEDIATION = {
    ResponseMode.ALERT: RemediationType.INVESTIGATE,
    ResponseMode.INVESTIGATE: RemediationType.INVESTIGATE,
    ResponseMode.CONTAIN: RemediationType.CONTAIN,
    ResponseMode.ISOLATE: RemediationType.ISOLATE,
    ResponseMode.RESTRICT: RemediationType.RESTRICT,
}

# P5 issue type -> (P8 poisoning indicator type, severity)
_ISSUE_TO_INDICATOR = {
    IntegrityIssueType.TELEMETRY_INTEGRITY: (
        PoisoningIndicatorType.HASH_MISMATCH, 0.95),
    IntegrityIssueType.REPLAY: (PoisoningIndicatorType.REPLAY, 0.85),
    IntegrityIssueType.CONTRADICTION: (
        PoisoningIndicatorType.CONTRADICTION, 0.80),
    IntegrityIssueType.STALE_STATE: (
        PoisoningIndicatorType.TRUST_ANOMALY, 0.50),
    IntegrityIssueType.CONSISTENCY: (
        PoisoningIndicatorType.PROVENANCE_GAP, 0.50),
}


# ============================================================================
# THE BRAIN
# ============================================================================

class HydraBrain:
    """Wires phases 4-16 into one pipeline. Thread-safe (coarse lock)."""

    GATE_METADATA = ("gate", "pre_action")

    def __init__(self, config: Optional[BrainConfig] = None) -> None:
        self.config = config or BrainConfig()
        self._lock = threading.RLock()

        # Engines (public so advanced callers can reach them directly)
        self.state = SecurityStateEngine()
        self.integrity = StateIntegrityEngine(
            stale_after=timedelta(seconds=self.config.stale_after_seconds)
        )
        self.memory = CausalSecurityMemoryEngine()
        self.trust = MemoryTrustQuarantineEngine(self.memory)
        self.attribution = AdversaryAttributionEngine()
        self.optimizer = InterventionOptimizer()
        self.invariants = SecurityInvariantEngine()
        self.authority = DynamicAuthorityGraph()
        self.intents = SecurityIntentCompiler()
        self.verifier = IndependentVerificationEngine()
        self.replanner = ContinuousReplanningEngine()
        self.experiments = CyberExperimentEngine()
        self.audit = AuditChain()

        self._graphs: Dict[str, TemporalSecurityGraph] = {}
        self._sequences: Dict[Tuple[str, str], int] = {}
        self._seen_ids: set = set()
        self._latest_state: Dict[str, str] = {}
        self._latest_values: Dict[str, Dict[str, StateValue]] = {}
        self._latest_confidence: Dict[str, float] = {}
        self._latest_telemetry: Dict[str, str] = {}
        self._gate_ids: Dict[str, List[str]] = {}
        self._baselines: Dict[str, List[str]] = {}
        self._adversaries: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # internal
    # ------------------------------------------------------------------

    def _scope(self, scope_id: Optional[str]) -> str:
        scope = scope_id or self.config.default_scope_id
        if not scope or not scope.strip():
            raise ValueError("scope_id must not be empty")
        return scope

    def _log(self, kind: str, data: Mapping[str, Any]) -> str:
        return self.audit.append(kind, data).entry_hash

    def graph(self, scope_id: Optional[str] = None) -> TemporalSecurityGraph:
        scope = self._scope(scope_id)
        with self._lock:
            if scope not in self._graphs:
                self._graphs[scope] = TemporalSecurityGraph(scope)
            return self._graphs[scope]

    # ------------------------------------------------------------------
    # 1. TELEMETRY INGEST  (P5 -> P8 -> P4 -> P7 -> P11)
    # ------------------------------------------------------------------

    def ingest(
        self,
        *,
        source_id: str,
        payload: Mapping[str, Any],
        telemetry_id: Optional[str] = None,
        scope_id: Optional[str] = None,
        sequence: Optional[int] = None,
        observed_at: Optional[datetime] = None,
        nonce: Optional[str] = None,
        causation_id: Optional[str] = None,
    ) -> IngestResult:
        """
        Run one telemetry record through integrity, trust, state, causal
        memory and invariant checks.

        * Invalid telemetry (tampered / replayed / stale / contradictory)
          never updates state; its memory is quarantined or degraded.
        * Re-delivering the same ``telemetry_id`` is dropped as a replay.
        """
        with self._lock:
            scope = self._scope(scope_id)
            tid = telemetry_id or f"tel-{uuid.uuid4().hex}"
            when = _aware(observed_at)

            if (scope, tid) in self._seen_ids:
                digest = self._log(
                    "ingest.duplicate",
                    {"scope_id": scope, "telemetry_id": tid},
                )
                return IngestResult(
                    accepted=False,
                    telemetry_id=tid,
                    scope_id=scope,
                    deduplicated=True,
                    integrity_status="INVALID",
                    issues=("duplicate telemetry_id: replay dropped",),
                    audit_hash=digest,
                )
            self._seen_ids.add((scope, tid))

            if sequence is None:
                key = (scope, source_id)
                sequence = self._sequences.get(key, -1) + 1
                self._sequences[key] = sequence

            telemetry = TelemetryRecord.create(
                telemetry_id=tid,
                scope_id=scope,
                sequence=sequence,
                payload=payload,
                source_id=source_id,
                observed_at=when,
                nonce=nonce,
            )

            assessment = self.integrity.assess(
                dict(payload),
                required_fields=tuple(self.config.required_fields),
                mutually_exclusive=tuple(self.config.mutually_exclusive),
                observed_at=when,
                telemetry=telemetry,
            )
            confidence = _clamp(assessment.confidence.score)
            valid = assessment.status == IntegrityStatus.VALID
            issue_text = tuple(i.message for i in assessment.issues)

            # ---- memory + trust (always recorded, even when invalid) ----
            memory_id = tid
            keys = ", ".join(sorted(str(k) for k in payload)[:12])
            memory = SecurityMemory(
                memory_id=memory_id,
                scope_id=scope,
                memory_type=MemoryType.OBSERVATION,
                subject=source_id,
                statement=f"telemetry from {source_id}: [{keys}]",
                confidence=confidence,
                created_at=when,
                valid_from=when,
                valid_until=None,
                evidence=(
                    EvidenceReference(
                        evidence_id=tid,
                        evidence_type="telemetry",
                        source_id=source_id,
                        observed_at=when,
                        fingerprint=telemetry.payload_hash,
                    ),
                ),
                lineage=None,
                attributes={
                    "payload_hash": telemetry.payload_hash,
                    "sequence": sequence,
                    "integrity_status": assessment.status.name,
                },
            )
            self.memory.add_memory(memory)
            self.trust.register_memory(
                memory_id,
                scope_id=scope,
                provenance=MemoryProvenance(
                    source_id=source_id,
                    source_type="telemetry",
                    collection_method="ingest",
                    collected_at=when,
                    source_integrity=confidence,
                ),
            )

            if not valid:
                indicators = []
                for index, issue in enumerate(assessment.issues):
                    kind, severity = _ISSUE_TO_INDICATOR.get(
                        issue.issue_type,
                        (PoisoningIndicatorType.TRUST_ANOMALY, 0.5),
                    )
                    indicators.append(
                        PoisoningIndicator(
                            indicator_id=f"{tid}:ind{index}",
                            memory_id=memory_id,
                            indicator_type=kind,
                            severity=severity,
                            detected_at=_utc_now(),
                            description=issue.message,
                            evidence_ids=frozenset({tid}),
                        )
                    )
                if indicators:
                    self.trust.detect_poisoning(memory_id, indicators)

            if (
                self.trust.get_state(memory_id)
                != MemoryTrustState.QUARANTINED
            ):
                self.trust.assess(
                    memory_id,
                    TrustAssessment(
                        assessed_at=_utc_now(),
                        score=confidence if valid else min(confidence, 0.45),
                        reasons=issue_text or ("integrity valid",),
                        assessor_id="hydra_brain.ingest",
                    ),
                )
            trust_state = self.trust.get_state(memory_id)

            # ---- causal link ----
            if causation_id:
                try:
                    self.memory.get_memory(causation_id)
                except KeyError:
                    pass
                else:
                    self.memory.add_causal_relation(
                        CausalRelation(
                            relation_id=f"rel:{causation_id}->{memory_id}",
                            scope_id=scope,
                            cause_memory_id=causation_id,
                            effect_memory_id=memory_id,
                            relation_type=CausalRelationType.CAUSED,
                            confidence=0.8,
                            evidence_ids=(tid,),
                            created_at=when,
                        )
                    )

            # ---- state + invariants (only for valid telemetry) ----
            state_id = self._latest_state.get(scope)
            violated: Tuple[str, ...] = ()
            if valid:
                if state_id is None:
                    created = self.state.create_state(
                        scope_id=scope, data=dict(payload)
                    )
                else:
                    merged = dict(self.state.get_state(state_id).data)
                    merged.update(payload)
                    created = self.state.update_state(
                        state_id, merged, reason=f"telemetry:{tid}"
                    )
                state_id = created.state_id
                self._latest_state[scope] = state_id
                self._latest_confidence[scope] = confidence
                self._latest_telemetry[scope] = tid

                values = self._latest_values.setdefault(scope, {})
                for key, value in created.data.items():
                    values[str(key)] = StateValue(
                        key=str(key),
                        value=value,
                        observed_at=when,
                        source_id=source_id,
                        confidence=confidence,
                    )
                violated = self._evaluate_posture(scope, values)

            digest = self._log(
                "ingest",
                {
                    "scope_id": scope,
                    "telemetry_id": tid,
                    "source_id": source_id,
                    "accepted": valid,
                    "integrity": assessment.status.name,
                    "issues": list(issue_text),
                    "trust_state": trust_state.name,
                    "violated_invariants": list(violated),
                },
            )
            return IngestResult(
                accepted=valid,
                telemetry_id=tid,
                scope_id=scope,
                state_id=state_id,
                integrity_status=assessment.status.name,
                confidence=confidence,
                issues=issue_text,
                memory_id=memory_id,
                trust_state=trust_state.name,
                violated_invariants=violated,
                audit_hash=digest,
            )

    def _evaluate_posture(
        self, scope: str, values: Dict[str, StateValue]
    ) -> Tuple[str, ...]:
        """Evaluate every non-gate invariant of the scope against state."""
        gate = set(self._gate_ids.get(scope, ()))
        violated: List[str] = []
        for invariant in self._scope_invariants(scope):
            if invariant.invariant_id in gate:
                continue
            relevant = {
                c.key for c in invariant.conditions
            }
            if not relevant.issubset(values.keys()):
                continue  # state not known yet: do not guess
            evaluation = self.invariants.evaluate(
                invariant.invariant_id, dict(values)
            )
            if evaluation.status == InvariantStatus.VIOLATED:
                violated.append(invariant.invariant_id)
        return tuple(violated)

    def _scope_invariants(self, scope: str) -> List[SecurityInvariant]:
        return [
            inv
            for inv in self._all_invariants()
            if inv.scope_id == scope and inv.enabled
        ]

    def _all_invariants(self) -> List[SecurityInvariant]:
        # SecurityInvariantEngine keeps invariants in a private dict.
        store = getattr(self.invariants, "_invariants", {})
        return list(store.values())

    # ------------------------------------------------------------------
    # 2. INVARIANTS (P11) + INTENTS (P13)
    # ------------------------------------------------------------------

    def add_invariant(
        self, invariant: SecurityInvariant, *, gate: bool = False
    ) -> SecurityInvariant:
        """
        Register an invariant.

        ``gate=False``  posture invariant: evaluated on every accepted
                        telemetry record, violations are reported.
        ``gate=True``   action-safety invariant: checked *before* any
                        response action; a violation blocks the action.
        """
        with self._lock:
            if gate:
                invariant = dataclasses.replace(
                    invariant,
                    metadata=tuple(invariant.metadata)
                    + (self.GATE_METADATA,),
                )
            self.invariants.add_invariant(invariant)
            if gate:
                self._gate_ids.setdefault(invariant.scope_id, []).append(
                    invariant.invariant_id
                )
            self._log(
                "invariant.add",
                {
                    "invariant_id": invariant.invariant_id,
                    "scope_id": invariant.scope_id,
                    "gate": gate,
                },
            )
            return invariant

    def check_gate(
        self, action_reference: str, *, scope_id: Optional[str] = None
    ) -> Tuple[bool, str]:
        """Return (allowed, reason) from the pre-action invariant gate."""
        scope = self._scope(scope_id)
        gate_ids = list(self._gate_ids.get(scope, ()))
        if not gate_ids:
            return True, "no gate invariants defined"
        values = dict(self._latest_values.get(scope, {}))
        check = self.invariants.pre_action_check(
            scope,
            action_reference,
            values,
            invariant_ids=gate_ids,
        )
        if check.blocking:
            return False, check.reason or "blocked by gate invariant"
        return True, "gate invariants satisfied"

    def define_intent(
        self,
        intent: SecurityIntent,
        *,
        constraints: Iterable[IntentConstraint] = (),
        monitoring: Iterable[MonitoringRequirement] = (),
        responses: Iterable[ResponseRequirement] = (),
    ) -> SecurityIntent:
        with self._lock:
            self.intents.add_intent(intent)
            for item in constraints:
                self.intents.add_constraint(item)
            for item in monitoring:
                self.intents.add_monitoring_requirement(item)
            for item in responses:
                self.intents.add_response_requirement(item)
            self._log(
                "intent.define",
                {"intent_id": intent.intent_id, "scope_id": intent.scope_id},
            )
            return intent

    def activate_intent(
        self, intent_id: str, *, gate: bool = False
    ) -> CompilationResult:
        """
        Compile an intent and install its constraints as P11 invariants
        (P13 -> P11 wiring), then link them back so the compiled plan
        references them.
        """
        with self._lock:
            intent = self.intents.get_intent(intent_id)
            responses = self.intents.responses_for(intent_id)
            remediation = (
                _RESPONSE_TO_REMEDIATION.get(
                    responses[0].mode, RemediationType.INVESTIGATE
                )
                if responses
                else RemediationType.INVESTIGATE
            )
            severity = _PRIORITY_TO_SEVERITY.get(
                intent.priority, InvariantSeverity.MODERATE
            )
            installed: List[str] = []
            for constraint in self.intents.constraints_for(intent_id):
                condition_type = _CONSTRAINT_TO_CONDITION[
                    constraint.constraint_type
                ]
                value = constraint.value
                if condition_type in (
                    InvariantConditionType.IN_SET,
                    InvariantConditionType.NOT_IN_SET,
                ) and isinstance(value, (list, set, frozenset)):
                    value = tuple(value)
                invariant_id = f"inv:{intent_id}:{constraint.constraint_id}"
                if invariant_id in {
                    i.invariant_id for i in self._all_invariants()
                }:
                    installed.append(invariant_id)
                    continue
                self.add_invariant(
                    SecurityInvariant(
                        invariant_id=invariant_id,
                        scope_id=intent.scope_id,
                        name=f"{intent.name}: {constraint.key}",
                        description=(
                            constraint.description
                            or f"compiled from intent {intent_id}"
                        ),
                        conditions=(
                            InvariantCondition(
                                key=constraint.key,
                                condition_type=condition_type,
                                expected_value=value,
                            ),
                        ),
                        severity=severity,
                        remediation_types=(remediation,),
                    ),
                    gate=gate,
                )
                installed.append(invariant_id)
            if installed:
                self.intents.link_invariants(intent_id, installed)
            result = self.intents.compile(intent_id)
            self._log(
                "intent.activate",
                {
                    "intent_id": intent_id,
                    "status": result.status.name,
                    "invariants": installed,
                    "errors": list(result.errors),
                },
            )
            return result

    # ------------------------------------------------------------------
    # 3. TOPOLOGY + ATTACK PATH  (P6)
    # ------------------------------------------------------------------

    def add_asset(
        self,
        node_id: str,
        node_type: Any = "UNKNOWN",
        *,
        scope_id: Optional[str] = None,
        **attributes: Any,
    ) -> SecurityGraphNode:
        with self._lock:
            scope = self._scope(scope_id)
            node = SecurityGraphNode(
                node_id=node_id,
                node_type=_enum(GraphNodeType, node_type),
                scope_id=scope,
                attributes=dict(attributes),
            )
            self.graph(scope).add_node(node)
            return node

    def link_assets(
        self,
        source_id: str,
        target_id: str,
        edge_type: Any = "CONNECTS_TO",
        *,
        weight: float = 0.5,
        scope_id: Optional[str] = None,
        edge_id: Optional[str] = None,
        **attributes: Any,
    ) -> SecurityGraphEdge:
        with self._lock:
            scope = self._scope(scope_id)
            edge = SecurityGraphEdge(
                edge_id=edge_id or f"{source_id}->{target_id}",
                source_id=source_id,
                target_id=target_id,
                edge_type=_enum(GraphEdgeType, edge_type),
                scope_id=scope,
                weight=weight,
                attributes=dict(attributes),
            )
            self.graph(scope).add_edge(edge)
            return edge

    def attack_path(
        self,
        source_id: str,
        target_id: str,
        *,
        scope_id: Optional[str] = None,
    ) -> AttackPathReport:
        with self._lock:
            scope = self._scope(scope_id)
            graph = self.graph(scope)
            path = graph.reconstruct_attack_path(source_id, target_id)
            points: Tuple[InterventionPoint, ...] = ()
            if path.status != PathStatus.NOT_FOUND:
                points = graph.identify_intervention_points(path)
            self._log(
                "attack_path",
                {
                    "scope_id": scope,
                    "source": source_id,
                    "target": target_id,
                    "status": path.status.name,
                    "score": path.total_score,
                    "points": [p.node_id for p in points],
                },
            )
            return AttackPathReport(scope, path, points)

    # ------------------------------------------------------------------
    # 4. RESPONSE RECOMMENDATION  (P10 + P11 gate)
    # ------------------------------------------------------------------

    def default_candidates(
        self, report: AttackPathReport
    ) -> List[InterventionCandidate]:
        """
        Heuristic candidate generation: for every intervention point on the
        path, propose ISOLATE / RESTRICT / MONITOR on that node.

        These numbers are *defaults*, not measured values. Pass your own
        ``candidate_builder`` to ``recommend_response`` to use real data.
        """
        scope = report.scope_id
        graph = self.graph(scope)
        edges = graph.active_edges()
        total_edges = max(1, len(edges))
        steps = max(1, len(report.path.steps) - 1)
        path_risk = _clamp(report.path.total_score / steps)
        confidence = self._latest_confidence.get(
            scope, self.config.default_confidence
        )

        candidates: List[InterventionCandidate] = []
        for point in report.intervention_points:
            try:
                node = graph.get_node(point.node_id)
                node_type = node.node_type.name.lower()
            except KeyError:
                node_type = "unknown"
            touching = sum(
                1
                for e in edges
                if point.node_id in (e.source_id, e.target_id)
            )
            connectivity = touching / total_edges
            target = InterventionTarget(
                target_id=point.node_id,
                target_type=node_type,
                scope_id=scope,
            )
            blocking = _clamp(point.blocking_score)
            specs = (
                (InterventionType.ISOLATE, 0.90, 0.20 + 0.60 * connectivity,
                 0.30, 0.90),
                (InterventionType.RESTRICT, 0.60, 0.10 + 0.30 * connectivity,
                 0.20, 0.95),
                (InterventionType.MONITOR, 0.15, 0.0, 0.05, 1.0),
            )
            for itype, rr, collateral, cost, reversibility in specs:
                candidates.append(
                    InterventionCandidate(
                        candidate_id=(
                            f"{report.path.path_id}:"
                            f"{point.node_id}:{itype.name.lower()}"
                        ),
                        scope_id=scope,
                        intervention_type=itype,
                        target=target,
                        expected_risk_reduction=_clamp(
                            blocking * rr * path_risk
                        ),
                        collateral_impact=_clamp(collateral),
                        execution_cost=_clamp(cost),
                        reversibility=_clamp(reversibility),
                        confidence=_clamp(confidence),
                        rationale=point.reason,
                    )
                )
        return candidates

    def recommend_response(
        self,
        report: AttackPathReport,
        *,
        objective: Any = "BALANCED",
        constraints: Optional[InterventionConstraints] = None,
        candidate_builder: Optional[CandidateBuilder] = None,
    ) -> ResponsePlan:
        with self._lock:
            scope = report.scope_id
            builder = candidate_builder or (
                lambda rep, brain: brain.default_candidates(rep)
            )
            candidates = list(builder(report, self))
            if not candidates:
                return ResponsePlan(
                    scope, "", (), {}, (), (), {}
                )
            request_id = f"req-{uuid.uuid4().hex[:12]}"
            request_kwargs: Dict[str, Any] = {
                "request_id": request_id,
                "scope_id": scope,
                "objective": _enum(OptimizationObjective, objective),
            }
            if constraints is not None:
                request_kwargs["constraints"] = constraints
            result = self.optimizer.optimize(
                OptimizationRequest(**request_kwargs), candidates
            )
            by_id = {c.candidate_id: c for c in candidates}

            blocked: Dict[str, str] = {}
            selectable: List[str] = []
            for scored in result.ranked_candidates:
                if not scored.feasible:
                    continue
                candidate = by_id[scored.candidate_id]
                allowed, reason = self.check_gate(
                    f"{candidate.intervention_type.name.lower()}:"
                    f"{candidate.target.target_id}",
                    scope_id=scope,
                )
                if allowed:
                    selectable.append(scored.candidate_id)
                else:
                    blocked[scored.candidate_id] = reason

            self._log(
                "response.recommend",
                {
                    "scope_id": scope,
                    "request_id": request_id,
                    "recommended": list(result.recommended_candidate_ids),
                    "selectable": selectable,
                    "blocked": blocked,
                },
            )
            return ResponsePlan(
                scope_id=scope,
                request_id=request_id,
                ranked=tuple(result.ranked_candidates),
                candidates=by_id,
                recommended_ids=tuple(result.recommended_candidate_ids),
                selectable_ids=tuple(selectable),
                blocked=blocked,
            )

    # ------------------------------------------------------------------
    # 5. AUTHORITY  (P12)
    # ------------------------------------------------------------------

    def add_authority_node(
        self,
        node_id: str,
        node_type: Any,
        name: str,
        *,
        scope_id: Optional[str] = None,
    ) -> AuthorityNode:
        with self._lock:
            node = AuthorityNode(
                node_id=node_id,
                scope_id=self._scope(scope_id),
                node_type=_enum(AuthorityNodeType, node_type),
                name=name,
            )
            self.authority.add_node(node)
            return node

    def grant(
        self,
        edge_id: str,
        source_node_id: str,
        target_node_id: str,
        permissions: Iterable[str],
        *,
        edge_type: Any = "DIRECT_GRANT",
        delegation_depth: int = 0,
        scope_id: Optional[str] = None,
    ) -> AuthorityEdge:
        with self._lock:
            edge = AuthorityEdge(
                edge_id=edge_id,
                scope_id=self._scope(scope_id),
                source_node_id=source_node_id,
                target_node_id=target_node_id,
                edge_type=_enum(AuthorityEdgeType, edge_type),
                permissions=frozenset(permissions),
                delegation_depth=delegation_depth,
            )
            self.authority.add_edge(edge)
            self._log(
                "authority.grant",
                {
                    "edge_id": edge_id,
                    "from": source_node_id,
                    "to": target_node_id,
                    "permissions": sorted(edge.permissions),
                },
            )
            return edge

    def set_authority_baseline(
        self,
        baseline_id: str,
        *,
        allowed_edges: Iterable[str],
        allowed_permissions: Iterable[str],
        maximum_delegation_depth: int = 1,
        scope_id: Optional[str] = None,
    ) -> AuthorityBaseline:
        with self._lock:
            scope = self._scope(scope_id)
            baseline = AuthorityBaseline(
                baseline_id=baseline_id,
                scope_id=scope,
                allowed_edges=frozenset(allowed_edges),
                allowed_permissions=frozenset(allowed_permissions),
                maximum_delegation_depth=maximum_delegation_depth,
            )
            self.authority.add_baseline(baseline)
            self._baselines.setdefault(scope, []).append(baseline_id)
            return baseline

    def check_authority_drift(
        self, scope_id: Optional[str] = None
    ) -> Tuple[AuthorityDrift, ...]:
        scope = self._scope(scope_id)
        drifts: List[AuthorityDrift] = []
        for baseline_id in self._baselines.get(scope, ()):
            drifts.extend(self.authority.detect_drift(baseline_id))
        return tuple(drifts)

    def authorize(
        self,
        actor_id: str,
        permission: str,
        *,
        scope_id: Optional[str] = None,
    ) -> AuthorizationDecision:
        """Permission check + (optionally) no unresolved drift for actor."""
        with self._lock:
            scope = self._scope(scope_id)
            reasons: List[str] = []
            try:
                node = self.authority.get_node(actor_id)
            except KeyError:
                decision = AuthorizationDecision(
                    False, actor_id, permission, ("unknown actor",)
                )
                self._log_authz(decision)
                return decision

            state_name = getattr(
                node.authority_state, "name", str(node.authority_state)
            )
            if state_name != "ACTIVE":
                reasons.append(f"actor authority state is {state_name}")

            if permission not in self.authority.permissions_for(actor_id):
                reasons.append(f"actor lacks permission '{permission}'")

            if self.config.block_on_authority_drift:
                outgoing = {
                    e.edge_id
                    for e in self.authority.outgoing_authority(actor_id)
                }
                for drift in self.check_authority_drift(scope):
                    if drift.node_id == actor_id or (
                        drift.edge_id and drift.edge_id in outgoing
                    ):
                        reasons.append(
                            f"unresolved authority drift: "
                            f"{drift.drift_type.name}"
                        )
                        break

            decision = AuthorizationDecision(
                not reasons, actor_id, permission, tuple(reasons)
            )
            self._log_authz(decision)
            return decision

    def _log_authz(self, decision: AuthorizationDecision) -> None:
        self._log(
            "authorize",
            {
                "actor_id": decision.actor_id,
                "permission": decision.permission,
                "allowed": decision.allowed,
                "reasons": list(decision.reasons),
            },
        )

    # ------------------------------------------------------------------
    # 6. ATTRIBUTION  (P9, fed only by TRUSTED memory)
    # ------------------------------------------------------------------

    def register_adversary(
        self,
        label: str,
        *,
        techniques: Iterable[str] = (),
        infrastructure: Iterable[str] = (),
        window: Optional[Tuple[datetime, datetime]] = None,
        scope_id: Optional[str] = None,
    ) -> str:
        with self._lock:
            scope = self._scope(scope_id)
            if label in self._adversaries:
                raise ValueError(f"adversary already registered: {label}")
            now = _utc_now()
            start, end = window or (now - timedelta(days=30), now)
            ttp_map: Dict[str, str] = {}
            for technique in techniques:
                ttp_id = f"ttp:{label}:{technique}"
                self.attribution.add_ttp(
                    AdversaryTTP(
                        ttp_id=ttp_id,
                        scope_id=scope,
                        technique_id=technique,
                        observed_at=now,
                    )
                )
                ttp_map[technique] = ttp_id
            infra_map: Dict[str, str] = {}
            for identifier in infrastructure:
                infra_id = f"infra:{label}:{identifier}"
                self.attribution.add_infrastructure(
                    AdversaryInfrastructure(
                        infrastructure_id=infra_id,
                        scope_id=scope,
                        infrastructure_type="indicator",
                        identifier=identifier,
                        first_seen=start,
                        last_seen=end,
                    )
                )
                infra_map[identifier] = infra_id
            campaign_id = f"campaign:{label}"
            self.attribution.add_campaign(
                AdversaryCampaign(
                    campaign_id=campaign_id,
                    scope_id=scope,
                    name=label,
                    window=TimeWindow(start=start, end=end),
                    infrastructure_ids=frozenset(infra_map.values()),
                    ttp_ids=frozenset(ttp_map.values()),
                )
            )
            hypothesis_id = f"hyp:{label}"
            self.attribution.create_hypothesis(
                AdversaryHypothesis(
                    hypothesis_id=hypothesis_id,
                    scope_id=scope,
                    adversary_label=label,
                    campaign_ids=frozenset({campaign_id}),
                    ttp_ids=frozenset(ttp_map.values()),
                    infrastructure_ids=frozenset(infra_map.values()),
                )
            )
            self._adversaries[label] = {
                "scope": scope,
                "hypothesis_id": hypothesis_id,
                "ttps": ttp_map,
                "infra": infra_map,
            }
            self._log(
                "attribution.register",
                {"label": label, "hypothesis_id": hypothesis_id},
            )
            return hypothesis_id

    def attribute(
        self,
        label: str,
        *,
        observed_techniques: Iterable[str] = (),
        observed_infrastructure: Iterable[str] = (),
        window: Optional[Tuple[datetime, datetime]] = None,
        evidence_memory_ids: Iterable[str] = (),
    ) -> AttributionReport:
        """
        Correlate observations with a registered adversary hypothesis.

        Memories that are not TRUSTED (quarantined / degraded / revoked)
        are excluded from the evidence set and reported in
        ``excluded_evidence_memory_ids``.
        """
        with self._lock:
            if label not in self._adversaries:
                raise KeyError(f"unknown adversary: {label}")
            info = self._adversaries[label]
            hypothesis_id = info["hypothesis_id"]
            scope = info["scope"]

            matched_ttps, unmatched_ttps = [], []
            for technique in observed_techniques:
                ttp_id = info["ttps"].get(technique)
                (matched_ttps if ttp_id else unmatched_ttps).append(
                    ttp_id or technique
                )
            matched_infra, unmatched_infra = [], []
            for identifier in observed_infrastructure:
                infra_id = info["infra"].get(identifier)
                (matched_infra if infra_id else unmatched_infra).append(
                    infra_id or identifier
                )

            results: List[CorrelationResult] = []
            results.append(
                self.attribution.correlate_ttp(hypothesis_id, matched_ttps)
            )
            results.append(
                self.attribution.correlate_infrastructure(
                    hypothesis_id, matched_infra
                )
            )
            if window is not None:
                results.append(
                    self.attribution.correlate_temporal(
                        hypothesis_id,
                        TimeWindow(start=window[0], end=window[1]),
                    )
                )

            used: List[str] = []
            excluded: Dict[str, str] = {}
            for memory_id in evidence_memory_ids:
                try:
                    memory = self.memory.get_memory(memory_id)
                except KeyError:
                    excluded[memory_id] = "memory not found"
                    continue
                if not self.trust.is_usable_for_trusted_decision(memory_id):
                    excluded[memory_id] = (
                        "not trusted: "
                        + self.trust.get_state(memory_id).name
                    )
                    continue
                evidence_id = f"ev:{label}:{memory_id}"
                try:
                    self.attribution.add_evidence(
                        AttributionEvidence(
                            evidence_id=evidence_id,
                            scope_id=scope,
                            evidence_type=AttributionEvidenceType.BEHAVIORAL,
                            source_id=memory.subject,
                            observed_at=memory.created_at,
                            description=memory.statement,
                            reliability=_clamp(memory.confidence),
                            relevance=0.8,
                            direction=1.0,
                            ttp_ids=frozenset(matched_ttps),
                            infrastructure_ids=frozenset(matched_infra),
                        )
                    )
                except ValueError:
                    pass  # already registered earlier
                self.attribution.attach_evidence(hypothesis_id, evidence_id)
                used.append(memory_id)

            assessment = self.attribution.assess(hypothesis_id, results)
            self._log(
                "attribution.assess",
                {
                    "label": label,
                    "confidence": assessment.confidence_score,
                    "level": assessment.confidence_level.name,
                    "used_evidence": used,
                    "excluded_evidence": excluded,
                },
            )
            return AttributionReport(
                hypothesis_id=hypothesis_id,
                assessment=assessment,
                matched_ttps=tuple(matched_ttps),
                unmatched_ttps=tuple(unmatched_ttps),
                matched_infrastructure=tuple(matched_infra),
                unmatched_infrastructure=tuple(unmatched_infra),
                used_evidence_memory_ids=tuple(used),
                excluded_evidence_memory_ids=excluded,
            )

    # ------------------------------------------------------------------
    # 7. FULL RESPONSE LOOP  (P10/P11/P12/P16/P15/P14)
    # ------------------------------------------------------------------

    def respond(
        self,
        report: AttackPathReport,
        *,
        actor_id: str,
        objective: Any = "BALANCED",
        executor: Optional[Executor] = None,
        expected: Optional[Mapping[str, Any]] = None,
        independent_observer: Optional[IndependentObserver] = None,
        simulator: Optional[Simulator] = None,
        candidate_builder: Optional[CandidateBuilder] = None,
        constraints: Optional[InterventionConstraints] = None,
    ) -> ResponseReport:
        """
        Recommend -> gate -> authorize -> simulate -> (execute) -> verify
        -> re-plan decision.

        ``executor`` is YOUR callback that performs the action and returns
        the observed outcome as a mapping. Without it the loop stops after
        authorization (status ``PLANNED``). Nothing is ever executed by
        this library itself.

        ``simulator`` is an optional callback ``candidate -> bool`` that
        decides whether the action is viable (e.g. a digital twin). When it
        is omitted the simulation stage is SKIPPED. The built-in P16 engine
        is NOT used as a gate by default: it only rolls a seeded random
        number (see ``experiment_simulator``) and does not model the action.
        """
        with self._lock:
            scope = report.scope_id
            notes: List[str] = []

            if executor is not None and not expected:
                raise ValueError(
                    "expected outcomes are required when an executor is given"
                )

            plan = self.recommend_response(
                report,
                objective=objective,
                constraints=constraints,
                candidate_builder=candidate_builder,
            )
            if not plan.candidates:
                return self._finish(
                    ResponseReport("NO_CANDIDATE", scope, notes=tuple(notes))
                )
            if not plan.selectable_ids:
                status = (
                    "BLOCKED_BY_INVARIANT"
                    if plan.blocked
                    else "NO_FEASIBLE_CANDIDATE"
                )
                return self._finish(
                    ResponseReport(
                        status, scope, blocked=dict(plan.blocked),
                        notes=tuple(notes),
                    )
                )

            # prefer the optimizer's recommendation when it is selectable
            chosen_id = next(
                (c for c in plan.recommended_ids if c in plan.selectable_ids),
                plan.selectable_ids[0],
            )
            candidate = plan.candidates[chosen_id]
            permission = candidate.intervention_type.name.lower()
            base = dict(
                scope_id=scope,
                candidate_id=chosen_id,
                intervention=permission,
                target_id=candidate.target.target_id,
                blocked=dict(plan.blocked),
            )

            decision = self.authorize(actor_id, permission, scope_id=scope)
            if not decision.allowed:
                return self._finish(
                    ResponseReport(
                        "DENIED", authorization=decision,
                        notes=tuple(notes), **base,
                    )
                )

            if simulator is None:
                sim_status, viable = "SKIPPED", True
                notes.append("no simulator supplied: simulation skipped")
            else:
                viable = bool(simulator(candidate))
                sim_status = "VIABLE" if viable else "NOT_VIABLE"
            if not viable:
                return self._finish(
                    ResponseReport(
                        "SIMULATION_FAILED",
                        authorization=decision,
                        simulation_status=sim_status,
                        notes=tuple(notes),
                        **base,
                    )
                )

            cycle_id, plan_id = self._open_cycle(
                scope, candidate, actor_id, viable, report
            )

            if executor is None:
                notes.append("dry run: no executor supplied")
                return self._finish(
                    ResponseReport(
                        "PLANNED",
                        authorization=decision,
                        simulation_status=sim_status,
                        cycle_id=cycle_id,
                        notes=tuple(notes),
                        **base,
                    )
                )

            observed = dict(executor(candidate))
            action_id = f"act-{uuid.uuid4().hex[:12]}"
            self.replanner.add_action(
                ActionReference(
                    action_id=action_id,
                    scope_id=scope,
                    plan_id=plan_id,
                    recorded_at=_utc_now(),
                    action_type=permission,
                    execution_reference=chosen_id,
                )
            )
            self.replanner.record_action(cycle_id, action_id)

            verification = self._verify(
                scope, action_id, expected or {}, observed,
                dict(independent_observer(candidate))
                if independent_observer
                else {},
            )
            verification_id = verification.verification_id
            self.replanner.add_verification(
                VerificationReference(
                    verification_id=verification_id,
                    scope_id=scope,
                    action_id=action_id,
                    verified_at=_utc_now(),
                    status=verification.status.name,
                    confidence=_clamp(verification.confidence),
                    reason=verification.reason,
                )
            )
            self.replanner.record_verification(cycle_id, verification_id)

            if verification.status != VerificationStatus.SUCCESS:
                trigger_type = (
                    ReplanTriggerType.VERIFICATION_PARTIAL
                    if verification.status == VerificationStatus.PARTIAL
                    else ReplanTriggerType.VERIFICATION_FAILURE
                )
                trigger_id = f"trg-{uuid.uuid4().hex[:12]}"
                self.replanner.add_trigger(
                    ReplanTrigger(
                        trigger_id=trigger_id,
                        scope_id=scope,
                        trigger_type=trigger_type,
                        created_at=_utc_now(),
                        source_reference=verification_id,
                        reason=verification.reason,
                    )
                )
                self.replanner.register_trigger(cycle_id, trigger_id)

            decision_value = self.replanner.decide(cycle_id)
            status = {
                ReplanDecision.CONTINUE: "VERIFIED",
                ReplanDecision.REPLAN: "NEEDS_REPLAN",
                ReplanDecision.STOP: "STOPPED",
            }[decision_value]
            return self._finish(
                ResponseReport(
                    status,
                    authorization=decision,
                    simulation_status=sim_status,
                    verification_status=verification.status.name,
                    replan_decision=decision_value.name,
                    cycle_id=cycle_id,
                    notes=tuple(notes),
                    **base,
                )
            )

    def _finish(self, report: ResponseReport) -> ResponseReport:
        self._log(
            "response.result",
            {
                "status": report.status,
                "scope_id": report.scope_id,
                "candidate_id": report.candidate_id,
                "replan_decision": report.replan_decision,
                "verification": report.verification_status,
                "blocked": dict(report.blocked),
            },
        )
        return report

    def experiment_simulator(self, candidate: InterventionCandidate) -> bool:
        """
        Optional ``simulator`` backed by the P16 experiment engine.

        WARNING: P16 is a placeholder model. Each step is a seeded random
        roll (80% pass / 15% inconclusive / 5% fail) that does not depend
        on the action, so ~20% of calls return False for reasons unrelated
        to the action. Use it to exercise the pipeline, not to make real
        decisions; supply your own simulator for that.
        """
        return self._simulate(candidate)[1]

    def _simulate(
        self, candidate: InterventionCandidate
    ) -> Tuple[str, bool]:
        """Offline dry-run of the action on the P16 experiment engine."""
        scope = candidate.scope_id
        suffix = uuid.uuid4().hex[:8]
        target_id = f"sim-target:{candidate.target.target_id}:{suffix}"
        scenario_id = f"sim-scenario:{suffix}"
        experiment_id = f"sim-exp:{suffix}"
        self.experiments.add_target(
            ExperimentTarget(
                target_id=target_id,
                scope_id=scope,
                target_type=candidate.target.target_type,
            )
        )
        self.experiments.add_scenario(
            ExperimentScenario(
                scenario_id=scenario_id,
                scope_id=scope,
                scenario_type=ScenarioType.DEFENSIVE_RESPONSE,
                name=f"simulate {candidate.intervention_type.name.lower()}",
                description=(
                    f"offline dry run of "
                    f"{candidate.intervention_type.name.lower()} on "
                    f"{candidate.target.target_id}"
                ),
                target_ids=(target_id,),
            )
        )
        self.experiments.add_step(
            ExperimentStep(
                step_id=f"sim-step:{suffix}",
                scenario_id=scenario_id,
                sequence=1,
                operation=f"apply_{candidate.intervention_type.name.lower()}",
            )
        )
        self.experiments.create_experiment(
            experiment_id=experiment_id,
            scope_id=scope,
            experiment_type=ExperimentType.DEFENSE,
            scenario_ids=[scenario_id],
            seed=int(_short_hash(candidate.candidate_id), 16) % (2 ** 31),
        )
        self.experiments.prepare(experiment_id)
        outcome = self.experiments.run(experiment_id)
        return outcome.status.name, (
            outcome.status == ExperimentOutcomeStatus.SUCCESS
        )

    def _open_cycle(
        self,
        scope: str,
        candidate: InterventionCandidate,
        actor_id: str,
        viable: bool,
        report: AttackPathReport,
    ) -> Tuple[str, str]:
        now = _utc_now()
        suffix = uuid.uuid4().hex[:10]

        observation_id = self._latest_telemetry.get(scope)
        obs_ref_id = f"obs:{observation_id or report.path.path_id}:{suffix}"
        self.replanner.add_observation(
            ObservationReference(
                observation_id=obs_ref_id,
                scope_id=scope,
                source="hydra_brain",
                observed_at=now,
                summary=f"attack path {report.path.path_id}",
            )
        )

        state_id = self._latest_state.get(scope)
        if state_id is None:
            state = self.state.create_state(
                scope_id=scope, data={"initialised_by": "respond"}
            )
            state_id = state.state_id
            self._latest_state[scope] = state_id
        state = self.state.get_state(state_id)
        state_ref_id = f"{state_id}:{suffix}"
        self.replanner.add_state(
            StateReference(
                state_id=state_ref_id,
                scope_id=scope,
                version=int(state.sequence) + 1,
                observed_at=now,
                state_hash=state.state_hash or _short_hash(state_id),
            )
        )

        plan_id = f"plan:{candidate.candidate_id}:{suffix}"
        self.replanner.add_plan(
            PlanReference(
                plan_id=plan_id,
                scope_id=scope,
                version=1,
                created_at=now,
                plan_hash=_short_hash(plan_id, candidate.candidate_id),
                action_references=(candidate.candidate_id,),
            )
        )
        sim_id = f"sim:{suffix}"
        self.replanner.add_simulation(
            SimulationReference(
                simulation_id=sim_id,
                scope_id=scope,
                plan_id=plan_id,
                created_at=now,
                viable=viable,
                simulation_hash=_short_hash(sim_id, plan_id),
            )
        )
        auth_id = f"auth:{suffix}"
        self.replanner.add_authorization(
            AuthorizationReference(
                authorization_id=auth_id,
                scope_id=scope,
                plan_id=plan_id,
                authorized=True,
                authorized_at=now,
                authority_reference=actor_id,
                reason="authority graph permission granted",
            )
        )

        cycle = self.replanner.create_cycle(scope)
        cid = cycle.cycle_id
        self.replanner.record_observations(cid, [obs_ref_id])
        self.replanner.attach_state(cid, state_ref_id)
        self.replanner.attach_plan(cid, plan_id)
        self.replanner.attach_simulation(cid, sim_id)
        self.replanner.attach_authorization(cid, auth_id)
        return cid, plan_id

    def _verify(
        self,
        scope: str,
        action_id: str,
        expected: Mapping[str, Any],
        observed: Mapping[str, Any],
        independent: Mapping[str, Any],
    ) -> VerificationResult:
        suffix = uuid.uuid4().hex[:10]
        now = _utc_now()
        expected_ids: List[str] = []
        for key, value in expected.items():
            outcome_id = f"exp:{suffix}:{key}"
            self.verifier.add_expected(
                ExpectedOutcome(
                    outcome_id=outcome_id,
                    scope_id=scope,
                    key=str(key),
                    expected_value=value,
                )
            )
            expected_ids.append(outcome_id)

        observations = [
            ObservedOutcome(
                observation_id=f"obs:{suffix}:{key}",
                scope_id=scope,
                key=str(key),
                observed_value=value,
                observed_at=now,
                source_id="executor",
            )
            for key, value in observed.items()
        ]

        evidence_ids: List[str] = []
        for key, value in independent.items():
            evidence_id = f"evi:{suffix}:{key}"
            self.verifier.add_evidence(
                IndependentEvidence(
                    evidence_id=evidence_id,
                    scope_id=scope,
                    evidence_type=EvidenceType.INDEPENDENT_SENSOR,
                    source_id="independent_observer",
                    key=str(key),
                    value=value,
                    collected_at=now,
                    integrity=EvidenceIntegrity.VALID,
                    confidence=0.9,
                )
            )
            evidence_ids.append(evidence_id)

        return self.verifier.verify(
            scope_id=scope,
            subject_reference=action_id,
            expected_outcome_ids=expected_ids,
            observed_outcomes=observations,
            evidence_ids=evidence_ids,
        )

    # ------------------------------------------------------------------
    # 8. HEALTH
    # ------------------------------------------------------------------

    def validate_all(self) -> Dict[str, List[str]]:
        """Run every engine's self-validation + the audit chain check."""
        report: Dict[str, List[str]] = {}
        for name, engine in (
            ("causal_memory", self.memory),
            ("memory_trust", self.trust),
            ("attribution", self.attribution),
            ("optimizer", self.optimizer),
            ("invariants", self.invariants),
            ("authority", self.authority),
            ("intents", self.intents),
            ("verifier", self.verifier),
            ("replanner", self.replanner),
            ("experiments", self.experiments),
        ):
            report[name] = [str(e) for e in engine.validate()]
        for scope, graph in self._graphs.items():
            report[f"graph:{scope}"] = [str(e) for e in graph.validate()]
        report["audit"] = self.audit.verify()
        return report

    def healthy(self) -> bool:
        return all(not errors for errors in self.validate_all().values())
