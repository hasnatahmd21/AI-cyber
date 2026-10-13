"""Runtime adapter wiring the extracted HYDRA Brain into layered defence.

The engines are only imported after the caller has passed the signed integrity
gate. This integration records decisions and creates recommendations; it does
not run an OS/network isolation command, deploy controls, or restore files.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def newtech_root() -> Path:
    return Path(__file__).resolve().parent / "newtech_brain"


def verify_newtech_extraction(root: str | Path | None = None) -> list[str]:
    """Verify the extracted archive against its manifest without importing it."""
    base = Path(root).resolve() if root is not None else _repo_root()
    destination = base / "layered_defense" / "ai_cyber" / "newtech_brain"
    manifest_path = destination / "EXTRACTION_MANIFEST.json"
    errors: list[str] = []

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return [f"newtech: missing extraction manifest: {manifest_path}"]
    except (OSError, json.JSONDecodeError) as exc:
        return [f"newtech: unreadable extraction manifest: {type(exc).__name__}: {exc}"]

    archive_name = manifest.get("archive")
    if archive_name != "hydra_brain_newtech.zip":
        errors.append("newtech: unexpected archive name in extraction manifest")
    else:
        archive_path = base / archive_name
        if not archive_path.is_file():
            errors.append(f"newtech: source archive missing: {archive_name}")
        else:
            expected_archive = manifest.get("archive_sha256")
            if not isinstance(expected_archive, str) or _sha256_file(archive_path) != expected_archive:
                errors.append("newtech: source archive SHA-256 mismatch")

    declared = manifest.get("files")
    if not isinstance(declared, list):
        return errors + ["newtech: extraction manifest files field is invalid"]

    expected_paths: set[str] = set()
    expected_total = 0
    for item in declared:
        if not isinstance(item, dict):
            errors.append("newtech: invalid file record in extraction manifest")
            continue
        name = item.get("path")
        if not isinstance(name, str) or not name:
            errors.append("newtech: file record has no path")
            continue
        rel = PurePosixPath(name)
        if rel.is_absolute() or ".." in rel.parts or "\\" in name:
            errors.append(f"newtech: unsafe manifest path: {name!r}")
            continue
        normalized = rel.as_posix()
        if normalized in expected_paths:
            errors.append(f"newtech: duplicate manifest path: {normalized}")
            continue
        expected_paths.add(normalized)
        path = destination.joinpath(*rel.parts)
        try:
            path.resolve().relative_to(destination.resolve())
        except ValueError:
            errors.append(f"newtech: manifest path escapes destination: {normalized}")
            continue
        if not path.is_file():
            errors.append(f"newtech: extracted file missing: {normalized}")
            continue
        try:
            actual_size = path.stat().st_size
            actual_hash = _sha256_file(path)
        except OSError as exc:
            errors.append(f"newtech: cannot read {normalized}: {type(exc).__name__}")
            continue
        if actual_size != item.get("size_bytes"):
            errors.append(f"newtech: size mismatch: {normalized}")
        if actual_hash != item.get("sha256"):
            errors.append(f"newtech: SHA-256 mismatch: {normalized}")
        expected_total += int(item.get("size_bytes", -1))

    actual_paths: set[str] = set()
    if destination.is_dir():
        for path in destination.rglob("*"):
            if not path.is_file():
                continue
            rel = path.relative_to(destination).as_posix()
            if rel == "EXTRACTION_MANIFEST.json" or "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            actual_paths.add(rel)
    else:
        errors.append("newtech: extracted package directory missing")

    for name in sorted(expected_paths - actual_paths):
        errors.append(f"newtech: missing expected payload: {name}")
    for name in sorted(actual_paths - expected_paths):
        errors.append(f"newtech: unexpected payload file: {name}")

    if len(declared) != manifest.get("file_count"):
        errors.append("newtech: manifest file_count does not match records")
    if expected_total != manifest.get("total_uncompressed_bytes"):
        errors.append("newtech: manifest uncompressed byte total does not match records")
    return errors


@dataclass(frozen=True)
class NewTechEventResult:
    event_id: str
    scope_id: str
    accepted: bool
    blocked: bool
    reason: str
    integrity_status: str = "UNKNOWN"
    trust_state: str = "UNKNOWN"
    fabric_decision: str = "UNKNOWN"
    loop_id: str | None = None
    audit_hash: str = ""
    adaptive_control_id: str | None = None
    regeneration_id: str | None = None


class HydraBrainIntegration:
    """Wires phases 4-22 to real layered-defence runtime events.

    Runtime events pass through rate limiting, untrusted-input inspection,
    the core HydraBrain ingestion bridge, cross-layer signal correlation, and
    a typed observation/state/plan record in phase 22. No executor is called.
    """

    _LAYERS = (
        (4, "security-state", "DATA", ("state-snapshots", "state-transitions")),
        (5, "state-integrity", "VERIFICATION", ("integrity", "replay-detection")),
        (6, "security-graph", "NETWORK", ("attack-path-analysis",)),
        (7, "causal-memory", "MEMORY", ("causal-links", "evidence-lineage")),
        (8, "memory-trust", "IDENTITY", ("trust-assessment", "quarantine-model")),
        (9, "attribution", "AUDIT", ("evidence-attribution",)),
        (10, "intervention-optimizer", "EXECUTION", ("candidate-ranking",)),
        (11, "invariants", "POLICY", ("pre-action-invariants",)),
        (12, "authority-graph", "IDENTITY", ("authority-drift",)),
        (13, "intent-compiler", "POLICY", ("intent-constraints",)),
        (14, "independent-verification", "VERIFICATION", ("outcome-verification",)),
        (15, "continuous-replanning", "EXECUTION", ("replanning-records",)),
        (16, "cyber-experiment", "MODEL", ("offline-experiment-model",)),
        (17, "regeneration", "REGENERATION", ("recovery-planning",)),
        (18, "adaptive-defense", "RECOVERY", ("control-candidates",)),
        (19, "agent-self-protection", "AGENT", ("input-screening", "agent-risk")),
        (20, "defense-fabric", "AUDIT", ("cross-layer-correlation",)),
        (21, "resource-resilience", "ENDPOINT", ("rate-limiting", "safe-mode-model")),
        (22, "control-loop", "APPLICATION", ("typed-control-loop",)),
    )

    def __init__(self, *, maximum_events_per_minute: int = 120) -> None:
        if maximum_events_per_minute <= 0:
            raise ValueError("maximum_events_per_minute must be positive")
        errors = verify_newtech_extraction()
        if errors:
            raise RuntimeError("; ".join(errors))

        package_root = str(newtech_root())
        if package_root not in sys.path:
            sys.path.insert(0, package_root)

        # Imported only on first use, after the caller has passed integrity checks.
        from hydra_brain import BrainConfig, HydraBrain, PlatformBridge
        from hydra_brain.optional.phase17_regeneration import (
            CompromisedAsset, CyberRegenerationEngine,
        )
        from hydra_brain.optional.phase18_adaptive_defense import (
            AdaptiveDefenseEngine, ControlType, LessonType, SecurityLesson,
        )
        from hydra_brain.optional.phase19_agent_protection import AIAgentSelfProtectionEngine
        from hydra_brain.optional.phase20_defense_fabric import (
            DefenseLayer, DefenseLayerRegistration, DefenseSignal,
            FabricDecision, LayerStatus, MultiLayerDefenseFabric, SignalSeverity, SignalType,
        )
        from hydra_brain.optional.phase21_resilience import (
            EnforcementAction, RateLimit, ResourceAvailabilityResilienceEngine, ResourceType,
        )
        from hydra_brain.optional.phase22_control_loop import (
            AutonomousSecurityControlLoop, ComponentReference, LoopObservation, LoopPlanReference,
            LoopStateReference,
        )

        self._types = {
            "CompromisedAsset": CompromisedAsset,
            "ControlType": ControlType,
            "DefenseLayer": DefenseLayer,
            "DefenseLayerRegistration": DefenseLayerRegistration,
            "DefenseSignal": DefenseSignal,
            "FabricDecision": FabricDecision,
            "LayerStatus": LayerStatus,
            "LessonType": LessonType,
            "LoopObservation": LoopObservation,
            "LoopPlanReference": LoopPlanReference,
            "LoopStateReference": LoopStateReference,
            "RateLimit": RateLimit,
            "SecurityLesson": SecurityLesson,
            "SignalSeverity": SignalSeverity,
            "SignalType": SignalType,
            "ResourceType": ResourceType,
            "EnforcementAction": EnforcementAction,
            "ComponentReference": ComponentReference,
        }
        self.brain = HydraBrain(BrainConfig())
        self.bridge = PlatformBridge(self.brain)
        self.regeneration = CyberRegenerationEngine()
        self.adaptive_defense = AdaptiveDefenseEngine()
        self.agent_protection = AIAgentSelfProtectionEngine()
        self.defense_fabric = MultiLayerDefenseFabric()
        self.resource_resilience = ResourceAvailabilityResilienceEngine()
        self.control_loop = AutonomousSecurityControlLoop(maximum_iterations=16)
        self.maximum_events_per_minute = maximum_events_per_minute
        self._registered_scopes: set[str] = set()
        self._rate_limits: dict[str, str] = {}
        self._component_ids: set[str] = set()
        self._regeneration_cases: dict[str, Any] = {}
        self._sequence = 0
        self._ensure_components()
        self._ensure_scope("default")

    @staticmethod
    def _digest(*parts: Any) -> str:
        material = json.dumps(parts, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    @staticmethod
    def _timestamp() -> datetime:
        return datetime.now(timezone.utc)

    def _ensure_components(self) -> None:
        refs = (
            (4, "SecurityStateEngine", "phase04.state"),
            (5, "StateIntegrityEngine", "phase05.integrity"),
            (6, "TemporalSecurityGraph", "phase06.graph-per-scope"),
            (7, "CausalSecurityMemoryEngine", "phase07.memory"),
            (8, "MemoryTrustQuarantineEngine", "phase08.trust"),
            (9, "AdversaryAttributionEngine", "phase09.attribution"),
            (10, "InterventionOptimizer", "phase10.optimizer"),
            (11, "SecurityInvariantEngine", "phase11.invariants"),
            (12, "DynamicAuthorityGraph", "phase12.authority"),
            (13, "SecurityIntentCompiler", "phase13.intents"),
            (14, "IndependentVerificationEngine", "phase14.verifier"),
            (15, "ContinuousReplanningEngine", "phase15.replanner"),
            (16, "CyberExperimentEngine", "phase16.experiments"),
            (17, "CyberRegenerationEngine", "phase17.regeneration"),
            (18, "AdaptiveDefenseEngine", "phase18.adaptive-defense"),
            (19, "AIAgentSelfProtectionEngine", "phase19.agent-protection"),
            (20, "MultiLayerDefenseFabric", "phase20.fabric"),
            (21, "ResourceAvailabilityResilienceEngine", "phase21.resilience"),
            (22, "AutonomousSecurityControlLoop", "phase22.control-loop"),
        )
        ComponentReference = self._types["ComponentReference"]
        for phase, component_type, component_id in refs:
            ref_id = f"hydra-phase-{phase:02d}"
            self.control_loop.register_component(
                ComponentReference(
                    reference_id=ref_id,
                    component_type=component_type,
                    component_id=component_id,
                )
            )
            self._component_ids.add(ref_id)

    def _ensure_scope(self, scope_id: str) -> None:
        if scope_id in self._registered_scopes:
            return
        enums = self._types
        DefenseLayer = enums["DefenseLayer"]
        Registration = enums["DefenseLayerRegistration"]
        LayerStatus = enums["LayerStatus"]
        now = self._timestamp()
        scope_tag = hashlib.sha256(scope_id.encode("utf-8")).hexdigest()[:12]
        for phase, name, layer_name, capabilities in self._LAYERS:
            layer = getattr(DefenseLayer, layer_name)
            registration_id = f"{scope_tag}:phase-{phase:02d}"
            registration_hash = self._digest(
                registration_id, scope_id, layer.value, name, capabilities
            )
            self.defense_fabric.register_layer(
                Registration(
                    registration_id=registration_id,
                    scope_id=scope_id,
                    layer=layer,
                    status=LayerStatus.HEALTHY,
                    component_reference=f"hydra-phase-{phase:02d}",
                    interface_reference=f"hydra_brain.phase{phase:02d}",
                    capabilities=frozenset(capabilities),
                    registered_at=now,
                    registration_hash=registration_hash,
                )
            )

        RateLimit = enums["RateLimit"]
        ResourceType = enums["ResourceType"]
        limit_id = f"runtime:{scope_tag}"
        self.resource_resilience.add_rate_limit(
            RateLimit(
                limit_id=limit_id,
                scope_id=scope_id,
                resource_type=ResourceType.API_REQUEST,
                maximum_events=self.maximum_events_per_minute,
                window_seconds=60.0,
                created_at=now,
            )
        )
        self._rate_limits[scope_id] = limit_id
        self._registered_scopes.add(scope_id)

    @staticmethod
    def _normalize_scope(event: Mapping[str, Any]) -> str:
        scope = str(event.get("tenant_id") or "default").strip()
        if not scope or len(scope) > 256:
            raise ValueError("tenant_id must be a non-empty string of at most 256 characters")
        return scope

    def _observation(self, event_id: str, scope_id: str, summary: str) -> str:
        self._sequence += 1
        now = self._timestamp()
        loop = self.control_loop.create_loop(scope_id)
        observation = self._types["LoopObservation"](
            observation_id=f"obs:{self._sequence}:{event_id}",
            scope_id=scope_id,
            source_reference=f"runtime:{event_id}",
            observation_type="RUNTIME_SECURITY_EVENT",
            summary=summary[:512],
            evidence_references=frozenset({event_id}),
            observed_at=now,
        )
        self.control_loop.record_observation(loop.loop_id, observation)
        return loop.loop_id

    def _record_loop_state_and_plan(
        self, loop_id: str, *, scope_id: str, event_id: str, state_id: str, integrity_status: str, confidence: float
    ) -> None:
        now = self._timestamp()
        state = self._types["LoopStateReference"](
            state_reference_id=f"state-ref:{event_id}",
            scope_id=scope_id,
            state_component_reference="hydra-phase-04",
            state_snapshot_reference=state_id,
            integrity_verified=(integrity_status == "VALID"),
            confidence=max(0.0, min(1.0, float(confidence))),
            created_at=now,
        )
        self.control_loop.attach_state(loop_id, state)
        plan = self._types["LoopPlanReference"](
            plan_reference_id=f"plan-ref:{event_id}",
            scope_id=scope_id,
            intervention_reference=f"record-only:{event_id}",
            intent_reference=None,
            invariant_references=frozenset(),
            expected_outcome="telemetry is recorded and the security decision is auditable; no action is executed",
            created_at=self._timestamp(),
        )
        self.control_loop.attach_plan(loop_id, plan)

    def _record_fabric(
        self, *, event_id: str, scope_id: str, layer_a: str, layer_b: str,
        severity: str, confidence: float, finding: str,
    ) -> Any:
        enums = self._types
        DefenseSignal = enums["DefenseSignal"]
        DefenseLayer = enums["DefenseLayer"]
        SignalType = enums["SignalType"]
        SignalSeverity = enums["SignalSeverity"]
        now = self._timestamp()
        scope_tag = hashlib.sha256(scope_id.encode("utf-8")).hexdigest()[:12]
        signal_ids = []
        for suffix, layer_name, signal_type in (
            ("a", layer_a, "AI_SELF_PROTECTION" if layer_a == "AGENT" else "STATE"),
            ("b", layer_b, "AUDIT"),
        ):
            signal_id = f"signal:{event_id}:{suffix}"
            material = (signal_id, scope_id, layer_name, severity, confidence, finding)
            self.defense_fabric.add_signal(
                DefenseSignal(
                    signal_id=signal_id,
                    scope_id=scope_id,
                    layer=getattr(DefenseLayer, layer_name),
                    signal_type=getattr(SignalType, signal_type),
                    severity=getattr(SignalSeverity, severity),
                    source_reference=f"runtime:{event_id}",
                    finding=finding[:512],
                    confidence=max(0.0, min(1.0, float(confidence))),
                    evidence_references=frozenset({event_id}),
                    observed_at=now,
                    signal_hash=self._digest(material),
                )
            )
            signal_ids.append(signal_id)
        correlation = self.defense_fabric.correlate(
            scope_id=scope_id, signal_ids=signal_ids
        )
        return self.defense_fabric.assess(
            scope_id=scope_id, signal_ids=signal_ids,
            correlation_ids=[correlation.correlation_id],
        )

    def _make_adaptive_candidate(
        self, *, event_id: str, scope_id: str, confidence: float
    ) -> str:
        now = self._timestamp()
        lesson_id = f"lesson:{event_id}"
        self.adaptive_defense.add_lesson(
            self._types["SecurityLesson"](
                lesson_id=lesson_id,
                scope_id=scope_id,
                lesson_type=self._types["LessonType"].INCIDENT,
                source_reference=f"runtime:{event_id}",
                observed_problem="Untrusted runtime input matched a known prompt-injection indicator",
                desired_outcome="Reject the input before it reaches the HYDRA execution entry point",
                evidence_references=frozenset({event_id}),
                confidence=max(0.0, min(1.0, float(confidence))),
                created_at=now,
            )
        )
        adaptation_id = f"adaptation:{event_id}"
        self.adaptive_defense.create_adaptation(
            adaptation_id=adaptation_id,
            scope_id=scope_id,
            lesson_ids=(lesson_id,),
        )
        control = self.adaptive_defense.generate_control(
            adaptation_id,
            control_type=self._types["ControlType"].RESTRICT,
            target_reference="hydra-cli-input",
            objective="Candidate control: reject detected prompt-injection input before HYDRA execution",
            parameters=(("mode", "block_before_execution"),),
            expected_risk_reduction=max(0.0, min(1.0, float(confidence))),
            expected_collateral_impact=0.05,
            reversibility=1.0,
        )
        # Proposal only. Approval, deployment and live enforcement are separate stages.
        return control.control_id

    def open_regeneration_case(
        self, *, asset_id: str, scope_id: str, compromise_reference: str,
        asset_type: str = "endpoint", criticality: int = 8,
    ) -> Any:
        """Create a typed recovery/regeneration case; does not isolate or restore anything."""
        if not asset_id.strip() or not scope_id.strip() or not compromise_reference.strip():
            raise ValueError("asset_id, scope_id and compromise_reference are required")
        key = self._digest(asset_id, scope_id, compromise_reference)
        if key in self._regeneration_cases:
            return self._regeneration_cases[key]
        now = self._timestamp()
        record_asset_id = f"{asset_id}:{key[:12]}"
        self.regeneration.add_asset(
            self._types["CompromisedAsset"](
                asset_id=record_asset_id,
                scope_id=scope_id,
                asset_type=asset_type,
                compromise_reference=compromise_reference,
                detected_at=now,
                criticality=criticality,
            )
        )
        case = self.regeneration.create_regeneration(
            regeneration_id=f"regeneration:{key[:24]}",
            scope_id=scope_id,
            asset_ids=(record_asset_id,),
        )
        self._regeneration_cases[key] = case
        self.brain.audit.append(
            "regeneration.case.created",
            {"regeneration_id": case.regeneration_id, "asset_id": asset_id, "scope_id": scope_id,
             "status": case.status.value, "execution": "not_performed"},
        )
        return case

    def process_runtime_event(self, event: Mapping[str, Any]) -> NewTechEventResult:
        """Process a structured outer-defence decision. Errors must fail closed at the caller."""
        if not isinstance(event, Mapping):
            raise TypeError("runtime event must be a mapping")
        event_id = str(event.get("event_id") or "").strip()
        if not event_id or len(event_id) > 256:
            raise ValueError("runtime event_id must be non-empty and at most 256 characters")
        scope_id = self._normalize_scope(event)
        payload = event.get("payload")
        if not isinstance(payload, Mapping):
            raise ValueError("runtime event payload must be a mapping")
        untrusted_input = event.get("untrusted_input", "")
        if not isinstance(untrusted_input, str):
            untrusted_input = str(untrusted_input)
        source = str(event.get("source") or "layered-defence")
        self._ensure_scope(scope_id)

        enforcement = self.resource_resilience.check_rate_limit(self._rate_limits[scope_id])
        if enforcement is not self._types["EnforcementAction"].ALLOW:
            assessment = self._record_fabric(
                event_id=event_id, scope_id=scope_id, layer_a="ENDPOINT", layer_b="AUDIT",
                severity="HIGH", confidence=0.85, finding="Runtime event rate limit exceeded",
            )
            loop_id = self._observation(event_id, scope_id, "Rate limit reached; request denied before HYDRA execution")
            audit_entry = self.brain.audit.append(
                "runtime.rate_limited",
                {"event_id": event_id, "scope_id": scope_id, "source": source,
                 "fabric_decision": assessment.decision.value},
            )
            return NewTechEventResult(
                event_id=event_id, scope_id=scope_id, accepted=False, blocked=True,
                reason="newtech rate limit exceeded", fabric_decision=assessment.decision.value,
                loop_id=loop_id, audit_hash=audit_entry.entry_hash,
            )

        detected, confidence, detector_reason = self.agent_protection.detect_prompt_injection(untrusted_input)
        if detected:
            assessment = self._record_fabric(
                event_id=event_id, scope_id=scope_id, layer_a="AGENT", layer_b="AUDIT",
                severity="HIGH", confidence=max(0.70, float(confidence)),
                finding="Known prompt-injection indicator detected in untrusted runtime input",
            )
            loop_id = self._observation(
                event_id, scope_id,
                "Untrusted runtime input was screened and blocked before trusted telemetry ingestion",
            )
            control_id = self._make_adaptive_candidate(
                event_id=event_id, scope_id=scope_id, confidence=confidence
            )
            audit_entry = self.brain.audit.append(
                "security.prompt_injection.detected",
                {"event_id": event_id, "scope_id": scope_id, "confidence": float(confidence),
                 "indicator": detector_reason, "untrusted_input_sha256": hashlib.sha256(untrusted_input.encode("utf-8")).hexdigest(),
                 "fabric_decision": assessment.decision.value, "adaptive_control_id": control_id,
                 "execution": "blocked_before_hydra"},
            )
            return NewTechEventResult(
                event_id=event_id, scope_id=scope_id, accepted=False, blocked=True,
                reason=detector_reason, fabric_decision=assessment.decision.value,
                loop_id=loop_id, audit_hash=audit_entry.entry_hash, adaptive_control_id=control_id,
            )

        mapped_event = {
            "event_id": event_id,
            "tenant_id": scope_id,
            "source": source,
            "timestamp": event.get("timestamp") or self._timestamp().isoformat(),
            "causation_id": event.get("causation_id"),
            "payload": dict(payload),
        }
        ingest = self.bridge.handle_event(mapped_event)
        if ingest is None:
            detail = self.bridge.errors[-1] if self.bridge.errors else "platform event bridge rejected input"
            assessment = self._record_fabric(
                event_id=event_id, scope_id=scope_id, layer_a="DATA", layer_b="AUDIT",
                severity="HIGH", confidence=0.85, finding="New-tech event bridge failed; request denied",
            )
            loop_id = self._observation(event_id, scope_id, "New-tech bridge failed closed")
            audit_entry = self.brain.audit.append(
                "runtime.bridge_error",
                {"event_id": event_id, "scope_id": scope_id, "error": detail[:256],
                 "fabric_decision": assessment.decision.value},
            )
            return NewTechEventResult(
                event_id=event_id, scope_id=scope_id, accepted=False, blocked=True,
                reason=f"newtech bridge error: {detail}", fabric_decision=assessment.decision.value,
                loop_id=loop_id, audit_hash=audit_entry.entry_hash,
            )

        decision_text = str(payload.get("decision", "unknown")).lower()
        reason_text = str(payload.get("reason", "runtime event recorded"))
        if decision_text in {"block", "quarantine", "error", "deny", "denied"}:
            severity, signal_confidence = ("HIGH", 0.85)
        elif decision_text in {"escalate", "restrict"}:
            severity, signal_confidence = ("MEDIUM", 0.60)
        else:
            severity, signal_confidence = ("INFO", 0.40)
        assessment = self._record_fabric(
            event_id=event_id, scope_id=scope_id, layer_a="DATA", layer_b="AUDIT",
            severity=severity, confidence=signal_confidence,
            finding=f"Layered defence decision recorded: {decision_text}",
        )
        loop_id = self._observation(
            event_id, scope_id,
            f"Layered defence decision {decision_text} recorded; {reason_text}"[:512],
        )
        if ingest.accepted and ingest.state_id:
            self._record_loop_state_and_plan(
                loop_id, scope_id=scope_id, event_id=event_id, state_id=ingest.state_id,
                integrity_status=ingest.integrity_status, confidence=ingest.confidence,
            )
        audit_entry = self.brain.audit.append(
            "runtime.defence_decision",
            {"event_id": event_id, "scope_id": scope_id, "source": source,
             "outer_decision": decision_text, "ingest_accepted": bool(ingest.accepted),
             "integrity_status": ingest.integrity_status, "trust_state": ingest.trust_state,
             "fabric_decision": assessment.decision.value, "loop_id": loop_id},
        )
        if not ingest.accepted:
            return NewTechEventResult(
                event_id=event_id, scope_id=scope_id, accepted=False, blocked=True,
                reason="newtech core rejected or deduplicated runtime telemetry",
                integrity_status=ingest.integrity_status,
                trust_state=str(ingest.trust_state or "UNKNOWN"),
                fabric_decision=assessment.decision.value, loop_id=loop_id,
                audit_hash=audit_entry.entry_hash,
            )
        return NewTechEventResult(
            event_id=event_id, scope_id=scope_id, accepted=True, blocked=False,
            reason="structured defence telemetry accepted; no executor invoked",
            integrity_status=ingest.integrity_status,
            trust_state=str(ingest.trust_state or "UNKNOWN"),
            fabric_decision=assessment.decision.value, loop_id=loop_id,
            audit_hash=audit_entry.entry_hash,
        )

    def summary(self) -> dict[str, Any]:
        """JSON-safe health/evidence summary for the encrypted outer audit."""
        audit_errors = self.brain.audit.verify()
        phase_errors: dict[str, list[str]] = {}
        for phase, engine in (
            (17, self.regeneration), (18, self.adaptive_defense),
            (19, self.agent_protection), (20, self.defense_fabric),
            (21, self.resource_resilience), (22, self.control_loop),
        ):
            try:
                errors = engine.validate()
            except Exception as exc:
                errors = [f"{type(exc).__name__}: {exc}"]
            if errors:
                phase_errors[str(phase)] = [str(x) for x in errors]
        core_errors = []
        try:
            core_errors = [str(x) for x in self.brain.validate_all()]
        except Exception as exc:
            core_errors = [f"{type(exc).__name__}: {exc}"]
        return {
            "core_audit_valid": not audit_errors,
            "core_audit_entries": len(self.brain.audit),
            "core_audit_errors": audit_errors[:20],
            "component_references": len(self._component_ids),
            "expected_component_references": 19,
            "registered_scopes": len(self._registered_scopes),
            "bridge_errors": self.bridge.errors[-10:],
            "phase_validation_errors": phase_errors,
            "core_validation_errors": core_errors[:20],
            "healthy": not audit_errors and not phase_errors and not core_errors,
            "executor_invocations": 0,
        }
