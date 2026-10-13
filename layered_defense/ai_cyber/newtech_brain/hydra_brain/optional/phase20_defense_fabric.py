"""
HYDRA™ — Phase 20
Multi-Layer Defense Fabric

SCOPE
-----
Integrate existing defensive capabilities across:

1. Identity
2. Endpoint
3. Network
4. Cloud
5. Application
6. Data
7. Connector
8. Agent
9. Memory
10. Model
11. Policy
12. Execution
13. Verification
14. Recovery
15. Regeneration
16. Audit

PHASE BOUNDARY
--------------
This phase integrates and correlates already implemented capabilities.

It does NOT implement:
- Resource & Availability Resilience       (Phase 21)
- Full Autonomous Security Control Loop    (Phase 22)
- Adversarial Validation                   (Phase 23)
- Scientific Benchmarking                  (Phase 24)
- Enterprise Hardening                     (Phase 25)
- Production Validation                    (Phase 26)
- IP / Novelty / Final Validation          (Phase 27)

No destructive or offensive operations are performed.
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


def ensure_aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware")


def stable_hash(*parts: object) -> str:
    material = "|".join(str(x) for x in parts)
    return hashlib.sha256(
        material.encode("utf-8")
    ).hexdigest()


# ============================================================================
# ENUMS
# ============================================================================

class DefenseLayer(str, Enum):
    IDENTITY = "IDENTITY"
    ENDPOINT = "ENDPOINT"
    NETWORK = "NETWORK"
    CLOUD = "CLOUD"
    APPLICATION = "APPLICATION"
    DATA = "DATA"
    CONNECTOR = "CONNECTOR"
    AGENT = "AGENT"
    MEMORY = "MEMORY"
    MODEL = "MODEL"
    POLICY = "POLICY"
    EXECUTION = "EXECUTION"
    VERIFICATION = "VERIFICATION"
    RECOVERY = "RECOVERY"
    REGENERATION = "REGENERATION"
    AUDIT = "AUDIT"


class LayerStatus(str, Enum):
    UNKNOWN = "UNKNOWN"
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    AT_RISK = "AT_RISK"
    COMPROMISED = "COMPROMISED"


class SignalSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SignalType(str, Enum):
    STATE = "STATE"
    INTEGRITY = "INTEGRITY"
    GRAPH = "GRAPH"
    MEMORY = "MEMORY"
    ATTRIBUTION = "ATTRIBUTION"
    INTERVENTION = "INTERVENTION"
    INVARIANT = "INVARIANT"
    AUTHORITY = "AUTHORITY"
    INTENT = "INTENT"
    VERIFICATION = "VERIFICATION"
    REPLANNING = "REPLANNING"
    EXPERIMENT = "EXPERIMENT"
    AI_SELF_PROTECTION = "AI_SELF_PROTECTION"
    RECOVERY = "RECOVERY"
    REGENERATION = "REGENERATION"
    AUDIT = "AUDIT"


class CorrelationStatus(str, Enum):
    UNCORRELATED = "UNCORRELATED"
    CORRELATED = "CORRELATED"
    CONFLICTING = "CONFLICTING"


class FabricDecision(str, Enum):
    MONITOR = "MONITOR"
    ESCALATE = "ESCALATE"
    CONTAINMENT_REQUIRED = "CONTAINMENT_REQUIRED"
    VERIFICATION_REQUIRED = "VERIFICATION_REQUIRED"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
    REGENERATION_REQUIRED = "REGENERATION_REQUIRED"


# ============================================================================
# LAYER REGISTRATION
# ============================================================================

@dataclass(frozen=True)
class DefenseLayerRegistration:

    registration_id: str
    scope_id: str
    layer: DefenseLayer

    status: LayerStatus

    component_reference: str
    interface_reference: str

    capabilities: FrozenSet[str]

    registered_at: datetime

    registration_hash: str

    def __post_init__(self) -> None:

        ensure_aware(self.registered_at)

        if not self.registration_id.strip():
            raise ValueError(
                "registration_id required"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id required"
            )

        if not self.component_reference.strip():
            raise ValueError(
                "component_reference required"
            )

        if not self.interface_reference.strip():
            raise ValueError(
                "interface_reference required"
            )

        if not self.registration_hash.strip():
            raise ValueError(
                "registration_hash required"
            )


# ============================================================================
# DEFENSE SIGNAL
# ============================================================================

@dataclass(frozen=True)
class DefenseSignal:

    signal_id: str
    scope_id: str

    layer: DefenseLayer
    signal_type: SignalType
    severity: SignalSeverity

    source_reference: str

    finding: str
    confidence: float

    evidence_references: FrozenSet[str]

    observed_at: datetime

    signal_hash: str

    def __post_init__(self) -> None:

        ensure_aware(self.observed_at)

        if not self.signal_id.strip():
            raise ValueError(
                "signal_id required"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id required"
            )

        if not self.source_reference.strip():
            raise ValueError(
                "source_reference required"
            )

        if not self.finding.strip():
            raise ValueError(
                "finding required"
            )

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "confidence must be between 0 and 1"
            )

        if not self.signal_hash.strip():
            raise ValueError(
                "signal_hash required"
            )


# ============================================================================
# CROSS-LAYER CORRELATION
# ============================================================================

@dataclass(frozen=True)
class LayerCorrelation:

    correlation_id: str
    scope_id: str

    signal_ids: FrozenSet[str]
    layers: FrozenSet[DefenseLayer]

    status: CorrelationStatus

    confidence: float

    explanation: str

    created_at: datetime

    correlation_hash: str

    def __post_init__(self) -> None:

        ensure_aware(self.created_at)

        if not self.correlation_id.strip():
            raise ValueError(
                "correlation_id required"
            )

        if not self.signal_ids:
            raise ValueError(
                "at least one signal required"
            )

        if not self.layers:
            raise ValueError(
                "at least one layer required"
            )

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "confidence must be between 0 and 1"
            )

        if not self.explanation.strip():
            raise ValueError(
                "explanation required"
            )

        if not self.correlation_hash.strip():
            raise ValueError(
                "correlation_hash required"
            )


# ============================================================================
# FABRIC ASSESSMENT
# ============================================================================

@dataclass(frozen=True)
class FabricAssessment:

    assessment_id: str
    scope_id: str

    active_layers: FrozenSet[DefenseLayer]
    affected_layers: FrozenSet[DefenseLayer]

    highest_severity: SignalSeverity

    overall_confidence: float

    decision: FabricDecision

    signal_ids: FrozenSet[str]
    correlation_ids: FrozenSet[str]

    created_at: datetime

    assessment_hash: str

    def __post_init__(self) -> None:

        ensure_aware(self.created_at)

        if not self.assessment_id.strip():
            raise ValueError(
                "assessment_id required"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id required"
            )

        if not 0.0 <= self.overall_confidence <= 1.0:
            raise ValueError(
                "overall_confidence invalid"
            )

        if not self.assessment_hash.strip():
            raise ValueError(
                "assessment_hash required"
            )


# ============================================================================
# DEFENSE FABRIC
# ============================================================================

class MultiLayerDefenseFabric:

    def __init__(self) -> None:

        self._registrations: Dict[
            str,
            DefenseLayerRegistration,
        ] = {}

        self._signals: Dict[
            str,
            DefenseSignal,
        ] = {}

        self._correlations: Dict[
            str,
            LayerCorrelation,
        ] = {}

        self._assessments: Dict[
            str,
            FabricAssessment,
        ] = {}

        self._lock = RLock()

    # ========================================================================
    # LAYER REGISTRATION
    # ========================================================================

    def register_layer(
        self,
        registration: DefenseLayerRegistration,
    ) -> None:

        with self._lock:

            if registration.registration_id in (
                self._registrations
            ):
                raise ValueError(
                    "duplicate layer registration"
                )

            self._registrations[
                registration.registration_id
            ] = registration

    def get_layer(
        self,
        registration_id: str,
    ) -> DefenseLayerRegistration:

        registration = (
            self._registrations.get(
                registration_id
            )
        )

        if registration is None:
            raise KeyError(
                "layer registration not found"
            )

        return registration

    def layers_for_scope(
        self,
        scope_id: str,
    ) -> Tuple[
        DefenseLayerRegistration,
        ...,
    ]:

        with self._lock:

            return tuple(
                registration
                for registration
                in self._registrations.values()
                if registration.scope_id == scope_id
            )

    # ========================================================================
    # SIGNAL INGESTION
    # ========================================================================

    def add_signal(
        self,
        signal: DefenseSignal,
    ) -> None:

        with self._lock:

            if signal.signal_id in self._signals:
                raise ValueError(
                    "duplicate signal"
                )

            registered = any(
                registration.scope_id
                == signal.scope_id
                and registration.layer
                == signal.layer
                for registration
                in self._registrations.values()
            )

            if not registered:
                raise ValueError(
                    "signal layer is not registered"
                )

            self._signals[
                signal.signal_id
            ] = signal

    def signals_for_scope(
        self,
        scope_id: str,
    ) -> Tuple[DefenseSignal, ...]:

        with self._lock:

            return tuple(
                signal
                for signal
                in self._signals.values()
                if signal.scope_id == scope_id
            )

    # ========================================================================
    # CROSS-LAYER CORRELATION
    # ========================================================================

    def correlate(
        self,
        *,
        scope_id: str,
        signal_ids: Iterable[str],
    ) -> LayerCorrelation:

        with self._lock:

            ids = frozenset(signal_ids)

            if not ids:
                raise ValueError(
                    "signal_ids required"
                )

            signals: List[
                DefenseSignal
            ] = []

            for signal_id in ids:

                signal = self._signals.get(
                    signal_id
                )

                if signal is None:
                    raise KeyError(
                        f"signal not found: {signal_id}"
                    )

                if signal.scope_id != scope_id:
                    raise ValueError(
                        "signal scope mismatch"
                    )

                signals.append(signal)

            layers = frozenset(
                signal.layer
                for signal in signals
            )

            if len(layers) == 1:

                status = (
                    CorrelationStatus.UNCORRELATED
                )

                confidence = max(
                    signal.confidence
                    for signal in signals
                )

                explanation = (
                    "signals originate from one "
                    "defense layer"
                )

            else:

                status = (
                    CorrelationStatus.CORRELATED
                )

                confidence = min(
                    1.0,
                    sum(
                        signal.confidence
                        for signal in signals
                    ) / len(signals)
                    + (
                        0.10
                        * (len(layers) - 1)
                    ),
                )

                explanation = (
                    "signals from multiple defense "
                    "layers support a shared security "
                    "condition"
                )

            correlation_hash = stable_hash(
                "layer-correlation",
                scope_id,
                tuple(sorted(ids)),
                tuple(
                    sorted(
                        layer.value
                        for layer in layers
                    )
                ),
                status.value,
                confidence,
            )

            correlation = LayerCorrelation(
                correlation_id=stable_hash(
                    "correlation",
                    correlation_hash,
                ),
                scope_id=scope_id,
                signal_ids=ids,
                layers=layers,
                status=status,
                confidence=confidence,
                explanation=explanation,
                created_at=utc_now(),
                correlation_hash=correlation_hash,
            )

            self._correlations[
                correlation.correlation_id
            ] = correlation

            return correlation

    # ========================================================================
    # SEVERITY
    # ========================================================================

    @staticmethod
    def _severity_order(
        severity: SignalSeverity,
    ) -> int:

        return {
            SignalSeverity.INFO: 0,
            SignalSeverity.LOW: 1,
            SignalSeverity.MEDIUM: 2,
            SignalSeverity.HIGH: 3,
            SignalSeverity.CRITICAL: 4,
        }[severity]

    # ========================================================================
    # FABRIC DECISION
    # ========================================================================

    @staticmethod
    def _decision_for(
        severity: SignalSeverity,
        confidence: float,
        affected_layers: FrozenSet[DefenseLayer],
    ) -> FabricDecision:

        if (
            severity == SignalSeverity.CRITICAL
            and confidence >= 0.85
        ):
            if DefenseLayer.REGENERATION in (
                affected_layers
            ):
                return (
                    FabricDecision.REGENERATION_REQUIRED
                )

            if DefenseLayer.RECOVERY in (
                affected_layers
            ):
                return (
                    FabricDecision.RECOVERY_REQUIRED
                )

            return (
                FabricDecision.CONTAINMENT_REQUIRED
            )

        if (
            severity == SignalSeverity.HIGH
            and confidence >= 0.70
        ):
            return (
                FabricDecision.CONTAINMENT_REQUIRED
            )

        if (
            DefenseLayer.VERIFICATION
            in affected_layers
        ):
            return (
                FabricDecision.VERIFICATION_REQUIRED
            )

        if confidence >= 0.50:
            return FabricDecision.ESCALATE

        return FabricDecision.MONITOR

    # ========================================================================
    # ASSESSMENT
    # ========================================================================

    def assess(
        self,
        *,
        scope_id: str,
        signal_ids: Optional[
            Iterable[str]
        ] = None,
        correlation_ids: Optional[
            Iterable[str]
        ] = None,
    ) -> FabricAssessment:

        with self._lock:

            if signal_ids is None:

                selected_signals = [
                    signal
                    for signal
                    in self._signals.values()
                    if signal.scope_id
                    == scope_id
                ]

            else:

                selected_signals = []

                for signal_id in (
                    signal_ids
                ):

                    signal = self._signals.get(
                        signal_id
                    )

                    if signal is None:
                        raise KeyError(
                            f"signal not found: "
                            f"{signal_id}"
                        )

                    if signal.scope_id != scope_id:
                        raise ValueError(
                            "signal scope mismatch"
                        )

                    selected_signals.append(
                        signal
                    )

            selected_signal_ids = frozenset(
                signal.signal_id
                for signal in selected_signals
            )

            selected_correlation_ids = (
                frozenset(
                    correlation_ids or ()
                )
            )

            correlations: List[
                LayerCorrelation
            ] = []

            for correlation_id in (
                selected_correlation_ids
            ):

                correlation = (
                    self._correlations.get(
                        correlation_id
                    )
                )

                if correlation is None:
                    raise KeyError(
                        f"correlation not found: "
                        f"{correlation_id}"
                    )

                if correlation.scope_id != scope_id:
                    raise ValueError(
                        "correlation scope mismatch"
                    )

                correlations.append(
                    correlation
                )

            active_layers = frozenset(
                registration.layer
                for registration
                in self._registrations.values()
                if registration.scope_id == scope_id
                and registration.status
                != LayerStatus.UNKNOWN
            )

            affected_layers = frozenset(
                signal.layer
                for signal in selected_signals
            )

            for correlation in correlations:
                affected_layers = (
                    affected_layers
                    | correlation.layers
                )

            if selected_signals:

                highest_severity = max(
                    (
                        signal.severity
                        for signal
                        in selected_signals
                    ),
                    key=self._severity_order,
                )

                confidence_values = [
                    signal.confidence
                    for signal
                    in selected_signals
                ]

                overall_confidence = (
                    sum(confidence_values)
                    / len(confidence_values)
                )

            elif correlations:

                highest_severity = (
                    SignalSeverity.INFO
                )

                overall_confidence = max(
                    correlation.confidence
                    for correlation
                    in correlations
                )

            else:

                highest_severity = (
                    SignalSeverity.INFO
                )

                overall_confidence = 0.0

            decision = self._decision_for(
                highest_severity,
                overall_confidence,
                affected_layers,
            )

            assessment_hash = stable_hash(
                "fabric-assessment",
                scope_id,
                tuple(sorted(selected_signal_ids)),
                tuple(sorted(selected_correlation_ids)),
                tuple(
                    sorted(
                        layer.value
                        for layer
                        in active_layers
                    )
                ),
                tuple(
                    sorted(
                        layer.value
                        for layer
                        in affected_layers
                    )
                ),
                highest_severity.value,
                overall_confidence,
                decision.value,
            )

            assessment = FabricAssessment(
                assessment_id=stable_hash(
                    "assessment",
                    assessment_hash,
                ),
                scope_id=scope_id,
                active_layers=active_layers,
                affected_layers=affected_layers,
                highest_severity=highest_severity,
                overall_confidence=overall_confidence,
                decision=decision,
                signal_ids=selected_signal_ids,
                correlation_ids=selected_correlation_ids,
                created_at=utc_now(),
                assessment_hash=assessment_hash,
            )

            self._assessments[
                assessment.assessment_id
            ] = assessment

            return assessment

    # ========================================================================
    # LAYER HEALTH
    # ========================================================================

    def layer_status(
        self,
        *,
        scope_id: str,
        layer: DefenseLayer,
    ) -> LayerStatus:

        with self._lock:

            registrations = [
                registration
                for registration
                in self._registrations.values()
                if registration.scope_id == scope_id
                and registration.layer == layer
            ]

            if not registrations:
                return LayerStatus.UNKNOWN

            if any(
                registration.status
                == LayerStatus.COMPROMISED
                for registration in registrations
            ):
                return LayerStatus.COMPROMISED

            if any(
                registration.status
                == LayerStatus.AT_RISK
                for registration in registrations
            ):
                return LayerStatus.AT_RISK

            if any(
                registration.status
                == LayerStatus.DEGRADED
                for registration in registrations
            ):
                return LayerStatus.DEGRADED

            return LayerStatus.HEALTHY

    # ========================================================================
    # QUERY
    # ========================================================================

    def get_assessment(
        self,
        assessment_id: str,
    ) -> FabricAssessment:

        assessment = (
            self._assessments.get(
                assessment_id
            )
        )

        if assessment is None:
            raise KeyError(
                "assessment not found"
            )

        return assessment

    def correlations_for_scope(
        self,
        scope_id: str,
    ) -> Tuple[
        LayerCorrelation,
        ...,
    ]:

        with self._lock:

            return tuple(
                correlation
                for correlation
                in self._correlations.values()
                if correlation.scope_id == scope_id
            )

    # ========================================================================
    # VALIDATION
    # ========================================================================

    def validate(self) -> List[str]:

        errors: List[str] = []

        with self._lock:

            for registration_id, registration in (
                self._registrations.items()
            ):

                if (
                    registration_id
                    != registration.registration_id
                ):
                    errors.append(
                        "layer registration key mismatch"
                    )

            for signal_id, signal in (
                self._signals.items()
            ):

                if signal_id != signal.signal_id:
                    errors.append(
                        "signal key mismatch"
                    )

                registered = any(
                    registration.scope_id
                    == signal.scope_id
                    and registration.layer
                    == signal.layer
                    for registration
                    in self._registrations.values()
                )

                if not registered:
                    errors.append(
                        f"signal has no registered "
                        f"layer: {signal_id}"
                    )

            for correlation_id, correlation in (
                self._correlations.items()
            ):

                if (
                    correlation_id
                    != correlation.correlation_id
                ):
                    errors.append(
                        "correlation key mismatch"
                    )

                for signal_id in (
                    correlation.signal_ids
                ):

                    signal = self._signals.get(
                        signal_id
                    )

                    if signal is None:
                        errors.append(
                            f"correlation references "
                            f"unknown signal: {signal_id}"
                        )

                    elif (
                        signal.scope_id
                        != correlation.scope_id
                    ):
                        errors.append(
                            "correlation signal "
                            "scope mismatch"
                        )

            for assessment_id, assessment in (
                self._assessments.items()
            ):

                if (
                    assessment_id
                    != assessment.assessment_id
                ):
                    errors.append(
                        "assessment key mismatch"
                    )

                for signal_id in (
                    assessment.signal_ids
                ):

                    if signal_id not in self._signals:
                        errors.append(
                            f"assessment references "
                            f"unknown signal: {signal_id}"
                        )

                for correlation_id in (
                    assessment.correlation_ids
                ):

                    if (
                        correlation_id
                        not in self._correlations
                    ):
                        errors.append(
                            f"assessment references "
                            f"unknown correlation: "
                            f"{correlation_id}"
                        )

        return errors


# ============================================================================
# TESTS
# ============================================================================

class Phase20Tests(unittest.TestCase):

    def setUp(self):

        self.fabric = (
            MultiLayerDefenseFabric()
        )

        self.scope = "enterprise-a"

        self.fabric.register_layer(
            DefenseLayerRegistration(
                registration_id="identity-reg",
                scope_id=self.scope,
                layer=DefenseLayer.IDENTITY,
                status=LayerStatus.HEALTHY,
                component_reference=(
                    "phase12.dynamic-authority-graph"
                ),
                interface_reference=(
                    "authority-graph-interface"
                ),
                capabilities=frozenset(
                    {
                        "authority-analysis",
                        "privilege-drift",
                    }
                ),
                registered_at=utc_now(),
                registration_hash="identity-hash",
            )
        )

        self.fabric.register_layer(
            DefenseLayerRegistration(
                registration_id="agent-reg",
                scope_id=self.scope,
                layer=DefenseLayer.AGENT,
                status=LayerStatus.HEALTHY,
                component_reference=(
                    "phase19.ai-agent-self-protection"
                ),
                interface_reference=(
                    "ai-protection-interface"
                ),
                capabilities=frozenset(
                    {
                        "prompt-injection",
                        "goal-hijacking",
                        "tool-poisoning",
                    }
                ),
                registered_at=utc_now(),
                registration_hash="agent-hash",
            )
        )

    # ========================================================================
    # Registration
    # ========================================================================

    def test_layer_registration(self):

        layers = (
            self.fabric.layers_for_scope(
                self.scope
            )
        )

        self.assertEqual(
            len(layers),
            2,
        )

    # ========================================================================
    # Signal ingestion
    # ========================================================================

    def test_signal_ingestion(self):

        signal = DefenseSignal(
            signal_id="signal-1",
            scope_id=self.scope,
            layer=DefenseLayer.AGENT,
            signal_type=(
                SignalType.AI_SELF_PROTECTION
            ),
            severity=SignalSeverity.HIGH,
            source_reference="agent-monitor",
            finding="prompt injection suspected",
            confidence=0.85,
            evidence_references=frozenset(),
            observed_at=utc_now(),
            signal_hash="signal-hash",
        )

        self.fabric.add_signal(
            signal
        )

        signals = (
            self.fabric.signals_for_scope(
                self.scope
            )
        )

        self.assertEqual(
            len(signals),
            1,
        )

    # ========================================================================
    # Cross-layer correlation
    # ========================================================================

    def test_cross_layer_correlation(self):

        identity_signal = DefenseSignal(
            signal_id="identity-signal",
            scope_id=self.scope,
            layer=DefenseLayer.IDENTITY,
            signal_type=SignalType.AUTHORITY,
            severity=SignalSeverity.HIGH,
            source_reference="authority-graph",
            finding="unexpected privilege expansion",
            confidence=0.80,
            evidence_references=frozenset(),
            observed_at=utc_now(),
            signal_hash="identity-signal-hash",
        )

        agent_signal = DefenseSignal(
            signal_id="agent-signal",
            scope_id=self.scope,
            layer=DefenseLayer.AGENT,
            signal_type=(
                SignalType.AI_SELF_PROTECTION
            ),
            severity=SignalSeverity.HIGH,
            source_reference="agent-protection",
            finding="unexpected authority request",
            confidence=0.90,
            evidence_references=frozenset(),
            observed_at=utc_now(),
            signal_hash="agent-signal-hash",
        )

        self.fabric.add_signal(
            identity_signal
        )

        self.fabric.add_signal(
            agent_signal
        )

        correlation = (
            self.fabric.correlate(
                scope_id=self.scope,
                signal_ids={
                    "identity-signal",
                    "agent-signal",
                },
            )
        )

        self.assertEqual(
            correlation.status,
            CorrelationStatus.CORRELATED,
        )

        self.assertEqual(
            len(correlation.layers),
            2,
        )

    # ========================================================================
    # Assessment
    # ========================================================================

    def test_assessment(self):

        signal = DefenseSignal(
            signal_id="critical-signal",
            scope_id=self.scope,
            layer=DefenseLayer.AGENT,
            signal_type=(
                SignalType.AI_SELF_PROTECTION
            ),
            severity=SignalSeverity.CRITICAL,
            source_reference="agent-protection",
            finding="rogue agent detected",
            confidence=0.96,
            evidence_references=frozenset(),
            observed_at=utc_now(),
            signal_hash="critical-signal-hash",
        )

        self.fabric.add_signal(
            signal
        )

        assessment = (
            self.fabric.assess(
                scope_id=self.scope,
                signal_ids={
                    "critical-signal"
                },
            )
        )

        self.assertEqual(
            assessment.highest_severity,
            SignalSeverity.CRITICAL,
        )

        self.assertEqual(
            assessment.decision,
            FabricDecision.CONTAINMENT_REQUIRED,
        )

    # ========================================================================
    # Layer status
    # ========================================================================

    def test_layer_status(self):

        status = (
            self.fabric.layer_status(
                scope_id=self.scope,
                layer=DefenseLayer.AGENT,
            )
        )

        self.assertEqual(
            status,
            LayerStatus.HEALTHY,
        )

    # ========================================================================
    # Unknown layer
    # ========================================================================

    def test_unknown_layer(self):

        status = (
            self.fabric.layer_status(
                scope_id=self.scope,
                layer=DefenseLayer.CLOUD,
            )
        )

        self.assertEqual(
            status,
            LayerStatus.UNKNOWN,
        )

    # ========================================================================
    # Invalid signal layer
    # ========================================================================

    def test_unregistered_signal_rejected(self):

        signal = DefenseSignal(
            signal_id="invalid-signal",
            scope_id=self.scope,
            layer=DefenseLayer.NETWORK,
            signal_type=SignalType.STATE,
            severity=SignalSeverity.MEDIUM,
            source_reference="network",
            finding="network anomaly",
            confidence=0.70,
            evidence_references=frozenset(),
            observed_at=utc_now(),
            signal_hash="invalid-hash",
        )

        with self.assertRaises(
            ValueError
        ):
            self.fabric.add_signal(
                signal
            )

    # ========================================================================
    # Global validation
    # ========================================================================

    def test_validation(self):

        self.assertEqual(
            self.fabric.validate(),
            [],
        )


# ============================================================================
# TEST RUNNER
# ============================================================================

def run_phase20_tests() -> None:

    suite = (
        unittest.defaultTestLoader
        .loadTestsFromTestCase(
            Phase20Tests
        )
    )

    result = unittest.TextTestRunner(
        verbosity=2
    ).run(suite)

    if not result.wasSuccessful():
        raise AssertionError(
            "Phase 20 tests failed"
        )


if __name__ == "__main__":
    run_phase20_tests()
