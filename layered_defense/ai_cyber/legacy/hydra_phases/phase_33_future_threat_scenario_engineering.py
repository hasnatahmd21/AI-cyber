"""
HYDRA POST-CORE — PHASE 33: FUTURE THREAT SCENARIO ENGINEERING
=================================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * Domain — 9 scenario classes, 4 adversary capability tiers,
    5 adoption stages, 6 precursor classes, 5 defensive postures
  * Inputs:
      - CURRENT STATE      (assets, dependencies, deployed controls)
      - EMERGING TECH      (categories, adoption, maturity)
      - ADOPTION           (stage + trend per technology)
      - DEPENDENCIES       (cross-technology dependency edges)
      - ADVERSARY CAPABILITY (tier + specialties)
  * Scenario engine composes the five inputs into structured
    future threat scenarios.
  * Every scenario carries:
      - scenario_id, class, horizon_months, confidence
      - affected_asset_ids, affected_technology_ids
      - precursor_indicators  (observable, checkable)
      - control_weaknesses     (which deployed controls are missing)
      - defensive_strategies   (concrete, prioritized)
      - preparedness_requirements
      - adversary_capability_required
      - forecast_not_claim=True
  * Findings — 8 kinds
  * Machine-checkable scenario invariants
  * In-memory + SQLite stores
  * Phase-33 engine facade
  * Full test suite + manual runner

Doctrine: this is scenario engineering. Every scenario is a
structured hypothesis about a future, composed from explicit inputs,
and every scenario asserts `forecast_not_claim=True`. No scenario
claims that the future will happen.

No third-party dependencies.

Run tests:
    python hydra_phase33_future_threat_scenarios.py
    pytest hydra_phase33_future_threat_scenarios.py -q
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Mapping,
    Optional,
    Protocol,
    Sequence,
    Tuple,
)

# =============================================================================
# SECTION 1 — CONTRACTS
# =============================================================================


class Clock(Protocol):
    def now(self) -> datetime: ...


class EvidenceEmitter(Protocol):
    def emit(self, evidence: Mapping[str, Any]) -> None: ...


class ProvenanceRecorder(Protocol):
    def record(self, *, subject_id: str, action: str, at: datetime,
               details: Mapping[str, Any]) -> None: ...


# =============================================================================
# SECTION 2 — DOMAIN ENUMS
# =============================================================================


class TechCategory(str, Enum):
    AUTONOMOUS_AGENTS = "autonomous_agents"
    AI_INFRASTRUCTURE = "ai_infrastructure"
    ROBOTICS = "robotics"
    EDGE_COMPUTING = "edge_computing"
    NEW_CLOUD_ARCHITECTURE = "new_cloud_architecture"
    NEW_IDENTITY_SYSTEM = "new_identity_system"
    NEW_PROTOCOL = "new_protocol"
    NEW_HARDWARE = "new_hardware"
    NEW_SOFTWARE_ARCHITECTURE = "new_software_architecture"


ALL_TECH_CATEGORIES: Tuple[TechCategory, ...] = tuple(TechCategory)


class AdoptionStage(str, Enum):
    RESEARCH = "research"
    PILOT = "pilot"
    EARLY_ADOPTION = "early_adoption"
    MAINSTREAM = "mainstream"
    DECLINING = "declining"


_ADOPTION_MOD: Mapping[AdoptionStage, float] = {
    AdoptionStage.RESEARCH: 0.3,
    AdoptionStage.PILOT: 0.6,
    AdoptionStage.EARLY_ADOPTION: 1.0,
    AdoptionStage.MAINSTREAM: 0.85,
    AdoptionStage.DECLINING: 0.55,
}


def adoption_modifier(s: AdoptionStage) -> float:
    return _ADOPTION_MOD[s]


class MaturityLevel(str, Enum):
    NASCENT = "nascent"
    DEVELOPING = "developing"
    MATURE = "mature"
    LEGACY = "legacy"


_MATURITY_MOD: Mapping[MaturityLevel, float] = {
    MaturityLevel.NASCENT: 1.0,
    MaturityLevel.DEVELOPING: 0.85,
    MaturityLevel.MATURE: 0.65,
    MaturityLevel.LEGACY: 0.75,
}


def maturity_modifier(m: MaturityLevel) -> float:
    return _MATURITY_MOD[m]


class TrendDirection(str, Enum):
    ACCELERATING = "accelerating"
    STEADY = "steady"
    SLOWING = "slowing"
    UNCERTAIN = "uncertain"


_TREND_MOD: Mapping[TrendDirection, float] = {
    TrendDirection.ACCELERATING: 1.15,
    TrendDirection.STEADY: 1.0,
    TrendDirection.SLOWING: 0.9,
    TrendDirection.UNCERTAIN: 1.05,
}


def trend_modifier(t: TrendDirection) -> float:
    return _TREND_MOD[t]


class AdversaryCapability(str, Enum):
    SCRIPT_KIDDIE = "script_kiddie"
    ORGANIZED_CRIME = "organized_crime"
    INSIDER = "insider"
    NATION_STATE = "nation_state"
    ADVANCED_PERSISTENT = "advanced_persistent"


_ADVERSARY_RANK: Mapping[AdversaryCapability, int] = {
    AdversaryCapability.SCRIPT_KIDDIE: 0,
    AdversaryCapability.ORGANIZED_CRIME: 1,
    AdversaryCapability.INSIDER: 2,
    AdversaryCapability.NATION_STATE: 3,
    AdversaryCapability.ADVANCED_PERSISTENT: 4,
}


def adversary_rank(a: AdversaryCapability) -> int:
    return _ADVERSARY_RANK[a]


class ControlKind(str, Enum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    AUDIT = "audit"
    ISOLATION = "isolation"
    ATTESTATION = "attestation"
    INVENTORY = "inventory"
    RATE_LIMIT = "rate_limit"
    HUMAN_REVIEW = "human_review"
    CRYPTOGRAPHY = "cryptography"
    MONITORING = "monitoring"


class DefensivePosture(str, Enum):
    PREVENT = "prevent"
    DETECT = "detect"
    CONTAIN = "contain"
    RECOVER = "recover"
    ADAPT = "adapt"


class ScenarioClass(str, Enum):
    AGENT_DRIVEN_EXFILTRATION = "agent_driven_exfiltration"
    AI_SUPPLY_CHAIN_COMPROMISE = "ai_supply_chain_compromise"
    IDENTITY_FABRIC_TAKEOVER = "identity_fabric_takeover"
    PHYSICAL_SAFETY_INCIDENT = "physical_safety_incident"
    EDGE_FLEET_COMPROMISE = "edge_fleet_compromise"
    CLOUD_CONTROL_PLANE_BREAKOUT = "cloud_control_plane_breakout"
    PROTOCOL_DOWNGRADE_EXPLOITATION = "protocol_downgrade_exploitation"
    HARDWARE_TRUST_ANCHOR_COMPROMISE = "hardware_trust_anchor_compromise"
    CROSS_TECH_CASCADE = "cross_tech_cascade"


class PrecursorClass(str, Enum):
    TELEMETRY = "telemetry"
    CONFIGURATION = "configuration"
    BEHAVIORAL = "behavioral"
    DEPENDENCY = "dependency"
    ADVERSARY_ACTIVITY = "adversary_activity"
    SUPPLY_CHAIN = "supply_chain"


class FindingKind(str, Enum):
    SCENARIO_PRODUCED = "scenario_produced"
    HIGH_LIKELIHOOD_SCENARIO = "high_likelihood_scenario"
    PREPAREDNESS_GAP = "preparedness_gap"
    CONTROL_WEAKNESS = "control_weakness"
    DEPENDENCY_FRAGILITY = "dependency_fragility"
    ADVERSARY_CAPABILITY_EXCEEDED = "adversary_capability_exceeded"
    CROSS_TECH_CASCADE_RISK = "cross_tech_cascade_risk"
    UNMITIGATED_SCENARIO = "unmitigated_scenario"


@dataclass(frozen=True)
class ScenarioFinding:
    kind: FindingKind
    subject_id: str
    detail: str
    severity: int
    horizon_months: int
    forecast_not_claim: bool
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        if not 1 <= self.severity <= 5:
            raise ValueError("severity must be in [1,5]")
        if self.horizon_months < 1:
            raise ValueError("horizon_months must be >= 1")
        if self.forecast_not_claim is not True:
            raise ValueError(
                "scenario findings are forecasts, not claims"
            )


# =============================================================================
# SECTION 3 — INPUT MODELS
# =============================================================================


@dataclass(frozen=True)
class CurrentAsset:
    asset_id: str
    kind: str
    criticality: float
    data_classification: int   # 0..4
    deployed_controls: FrozenSet[ControlKind]
    tech_dependencies: FrozenSet[str] = frozenset()
    tags: FrozenSet[str] = frozenset()

    def __post_init__(self) -> None:
        if not self.asset_id:
            raise ValueError("asset_id is required")
        if not self.kind:
            raise ValueError("kind is required")
        if not 0.0 <= self.criticality <= 1.0:
            raise ValueError("criticality must be within [0,1]")
        if not 0 <= self.data_classification <= 4:
            raise ValueError("data_classification must be in [0,4]")


@dataclass(frozen=True)
class EmergingTech:
    tech_id: str
    category: TechCategory
    name: str
    adoption: AdoptionStage
    maturity: MaturityLevel
    trend: TrendDirection
    horizon_months: int
    capabilities: FrozenSet[str] = frozenset()
    deployed_controls: FrozenSet[ControlKind] = frozenset()

    def __post_init__(self) -> None:
        if not self.tech_id:
            raise ValueError("tech_id is required")
        if not self.name:
            raise ValueError("name is required")
        if self.horizon_months < 1:
            raise ValueError("horizon_months must be >= 1")


@dataclass(frozen=True)
class TechDependencyEdge:
    dependent_id: str
    dependency_id: str
    kind: str
    critical: bool = True

    def __post_init__(self) -> None:
        if not self.dependent_id or not self.dependency_id:
            raise ValueError("dependent/dependency ids are required")
        if self.dependent_id == self.dependency_id:
            raise ValueError("self-dependency is not allowed")
        if not self.kind:
            raise ValueError("kind is required")


@dataclass(frozen=True)
class AdversaryProfile:
    adversary_id: str
    tier: AdversaryCapability
    specialties: FrozenSet[TechCategory] = frozenset()
    sophistication: float = 0.5

    def __post_init__(self) -> None:
        if not self.adversary_id:
            raise ValueError("adversary_id is required")
        if not 0.0 <= self.sophistication <= 1.0:
            raise ValueError("sophistication must be within [0,1]")


@dataclass(frozen=True)
class CurrentState:
    assets: Tuple[CurrentAsset, ...]
    controls_deployed: FrozenSet[ControlKind]
    criticality_floor: float = 0.5

    def __post_init__(self) -> None:
        if not 0.0 <= self.criticality_floor <= 1.0:
            raise ValueError("criticality_floor must be within [0,1]")

    def asset(self, asset_id: str) -> CurrentAsset:
        for a in self.assets:
            if a.asset_id == asset_id:
                return a
        raise KeyError(f"unknown asset {asset_id}")

    def critical_assets(self) -> Tuple[CurrentAsset, ...]:
        return tuple(
            a for a in self.assets
            if a.criticality >= self.criticality_floor
        )


# =============================================================================
# SECTION 4 — SCENARIO MODEL
# =============================================================================


@dataclass(frozen=True)
class PrecursorIndicator:
    precursor_id: str
    precursor_class: PrecursorClass
    description: str
    observable_signal: str
    check_frequency_hours: int

    def __post_init__(self) -> None:
        if not self.precursor_id:
            raise ValueError("precursor_id is required")
        if not self.description:
            raise ValueError("description is required")
        if not self.observable_signal:
            raise ValueError("observable_signal is required")
        if self.check_frequency_hours < 1:
            raise ValueError("check_frequency_hours must be >= 1")


@dataclass(frozen=True)
class ControlWeakness:
    weakness_id: str
    missing_control: ControlKind
    affected_asset_ids: Tuple[str, ...]
    reason: str
    severity: int

    def __post_init__(self) -> None:
        if not self.weakness_id:
            raise ValueError("weakness_id is required")
        if not self.affected_asset_ids:
            raise ValueError("affected_asset_ids must be non-empty")
        if not 1 <= self.severity <= 5:
            raise ValueError("severity must be in [1,5]")


@dataclass(frozen=True)
class DefensiveStrategy:
    strategy_id: str
    posture: DefensivePosture
    description: str
    required_controls: FrozenSet[ControlKind]
    priority: int

    def __post_init__(self) -> None:
        if not self.strategy_id:
            raise ValueError("strategy_id is required")
        if not self.description:
            raise ValueError("description is required")
        if not 1 <= self.priority <= 10:
            raise ValueError("priority must be in [1,10]")


@dataclass(frozen=True)
class PreparednessRequirement:
    requirement_id: str
    description: str
    required_controls: FrozenSet[ControlKind]
    already_met_controls: FrozenSet[ControlKind]
    horizon_months: int

    def __post_init__(self) -> None:
        if not self.requirement_id:
            raise ValueError("requirement_id is required")
        if not self.description:
            raise ValueError("description is required")
        if self.horizon_months < 1:
            raise ValueError("horizon_months must be >= 1")

    @property
    def unmet_controls(self) -> FrozenSet[ControlKind]:
        return self.required_controls - self.already_met_controls

    @property
    def fully_met(self) -> bool:
        return not self.unmet_controls


@dataclass(frozen=True)
class FutureThreatScenario:
    scenario_id: str
    scenario_class: ScenarioClass
    title: str
    narrative: str
    horizon_months: int
    likelihood: float
    severity: int
    adversary_capability_required: AdversaryCapability
    affected_asset_ids: Tuple[str, ...]
    affected_technology_ids: Tuple[str, ...]
    precursor_indicators: Tuple[PrecursorIndicator, ...]
    control_weaknesses: Tuple[ControlWeakness, ...]
    defensive_strategies: Tuple[DefensiveStrategy, ...]
    preparedness_requirements: Tuple[PreparednessRequirement, ...]
    rationale: str
    forecast_not_claim: bool
    at: datetime

    def __post_init__(self) -> None:
        if not self.scenario_id:
            raise ValueError("scenario_id is required")
        if not self.title:
            raise ValueError("title is required")
        if not self.narrative:
            raise ValueError("narrative is required")
        if self.horizon_months < 1:
            raise ValueError("horizon_months must be >= 1")
        if not 0.0 <= self.likelihood <= 1.0:
            raise ValueError("likelihood must be within [0,1]")
        if not 1 <= self.severity <= 5:
            raise ValueError("severity must be in [1,5]")
        if not self.affected_asset_ids and \
                not self.affected_technology_ids:
            raise ValueError(
                "scenario must reference assets or technologies"
            )
        if self.forecast_not_claim is not True:
            raise ValueError(
                "scenarios are forecasts, not claims"
            )
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


# =============================================================================
# SECTION 5 — TEMPLATES
# =============================================================================


# Per category: (scenario_class, weight, severity, required_adversary,
#   affected capabilities, narrative template, precursor template,
#   weaknesses template, strategies template)
_SCENARIO_TEMPLATES: Mapping[
    TechCategory,
    Tuple[Tuple[
        ScenarioClass, float, int, AdversaryCapability,
        FrozenSet[str], str,
    ], ...]
] = {
    TechCategory.AUTONOMOUS_AGENTS: (
        (ScenarioClass.AGENT_DRIVEN_EXFILTRATION, 1.0, 5,
         AdversaryCapability.ORGANIZED_CRIME,
         frozenset({"autonomy", "tool_use"}),
         "Adversary leverages an autonomous agent with tool access to "
         "enumerate and exfiltrate data at machine speed."),
        (ScenarioClass.CROSS_TECH_CASCADE, 0.8, 5,
         AdversaryCapability.ADVANCED_PERSISTENT,
         frozenset({"multi_agent"}),
         "An injected agent propagates across the trust mesh, "
         "triggering cross-technology cascades."),
    ),
    TechCategory.AI_INFRASTRUCTURE: (
        (ScenarioClass.AI_SUPPLY_CHAIN_COMPROMISE, 1.0, 5,
         AdversaryCapability.NATION_STATE,
         frozenset({"training", "model_registry"}),
         "Adversary substitutes a model artifact in the training or "
         "registry pipeline, producing poisoned downstream behaviour."),
    ),
    TechCategory.ROBOTICS: (
        (ScenarioClass.PHYSICAL_SAFETY_INCIDENT, 1.0, 5,
         AdversaryCapability.ORGANIZED_CRIME,
         frozenset({"actuator"}),
         "Compromised actuation path produces a physical safety event "
         "in the operating environment."),
    ),
    TechCategory.EDGE_COMPUTING: (
        (ScenarioClass.EDGE_FLEET_COMPROMISE, 1.0, 4,
         AdversaryCapability.ORGANIZED_CRIME,
         frozenset({"ota_update"}),
         "Adversary compromises the OTA update path and propagates "
         "control across the edge fleet."),
    ),
    TechCategory.NEW_CLOUD_ARCHITECTURE: (
        (ScenarioClass.CLOUD_CONTROL_PLANE_BREAKOUT, 1.0, 5,
         AdversaryCapability.NATION_STATE,
         frozenset({"control_plane"}),
         "Adversary escapes tenant isolation through the control plane "
         "and pivots across workloads."),
    ),
    TechCategory.NEW_IDENTITY_SYSTEM: (
        (ScenarioClass.IDENTITY_FABRIC_TAKEOVER, 1.0, 5,
         AdversaryCapability.ADVANCED_PERSISTENT,
         frozenset({"did", "recovery"}),
         "Adversary abuses the identity recovery path to take over "
         "accounts without triggering normal detection."),
    ),
    TechCategory.NEW_PROTOCOL: (
        (ScenarioClass.PROTOCOL_DOWNGRADE_EXPLOITATION, 0.9, 4,
         AdversaryCapability.ORGANIZED_CRIME,
         frozenset({"downgrade_negotiation"}),
         "Adversary forces a downgrade to a weaker protocol variant "
         "and exploits the resulting exposure."),
    ),
    TechCategory.NEW_HARDWARE: (
        (ScenarioClass.HARDWARE_TRUST_ANCHOR_COMPROMISE, 1.0, 5,
         AdversaryCapability.NATION_STATE,
         frozenset({"secure_boot"}),
         "Adversary compromises a hardware trust anchor, invalidating "
         "the platform trust chain."),
    ),
    TechCategory.NEW_SOFTWARE_ARCHITECTURE: (
        (ScenarioClass.CROSS_TECH_CASCADE, 0.7, 4,
         AdversaryCapability.ORGANIZED_CRIME,
         frozenset({"plugins"}),
         "Adversary exploits a plugin trust boundary to influence "
         "downstream technologies."),
    ),
}


# Per scenario class:
#   precursor templates, weakness templates, strategy templates,
#   preparedness templates
_SCENARIO_CLASS_PLAYBOOK: Mapping[
    ScenarioClass,
    Tuple[
        Tuple[Tuple[PrecursorClass, str, str, int], ...],
        Tuple[Tuple[ControlKind, int, str], ...],
        Tuple[Tuple[DefensivePosture, str, FrozenSet[ControlKind], int], ...],
        Tuple[str, FrozenSet[ControlKind]],
    ],
] = {ScenarioClass.AGENT_DRIVEN_EXFILTRATION: (((PrecursorClass.TELEMETRY, 'abnormal tool invocation rate', 'tool_calls_per_minute > baseline_p99', 1), (PrecursorClass.BEHAVIORAL, 'agent query pattern deviates from intent', 'tool_chain_entropy_delta > threshold', 6), (PrecursorClass.ADVERSARY_ACTIVITY, 'external egress destination seen for the first time', 'new_destination_seen', 1)), ((ControlKind.AUTHORIZATION, 5, 'tool access not capability-scoped'), (ControlKind.MONITORING, 4, 'agent behaviour not continuously monitored'), (ControlKind.RATE_LIMIT, 4, 'no per-agent tool rate limit')), ((DefensivePosture.PREVENT, 'capability-scoped tool authorisation for every agent', frozenset({ControlKind.AUTHORIZATION, ControlKind.AUTHENTICATION}), 1), (DefensivePosture.DETECT, 'behaviour-based alerting on tool-chain composition', frozenset({ControlKind.MONITORING}), 2), (DefensivePosture.CONTAIN, 'real-time egress block on out-of-scope destinations', frozenset({ControlKind.ISOLATION, ControlKind.RATE_LIMIT}), 2)), ('agent-tool authorisation must be capability-scoped', frozenset({ControlKind.AUTHORIZATION, ControlKind.AUDIT, ControlKind.MONITORING}))), ScenarioClass.AI_SUPPLY_CHAIN_COMPROMISE: (((PrecursorClass.SUPPLY_CHAIN, 'unscheduled model registry publication', 'registry_publish_event_off_hours', 24), (PrecursorClass.DEPENDENCY, 'training data provenance mismatch', 'dataset_checksum_divergence', 24), (PrecursorClass.ADVERSARY_ACTIVITY, 'signer identity not in allow-list', 'unexpected_signer_id', 1)), ((ControlKind.ATTESTATION, 5, 'model artifacts not attested'), (ControlKind.INVENTORY, 4, 'model registry not inventoried'), (ControlKind.AUDIT, 4, 'artifact pipeline not fully audited')), ((DefensivePosture.PREVENT, 'signature-verified artifact ingestion only', frozenset({ControlKind.ATTESTATION, ControlKind.CRYPTOGRAPHY}), 1), (DefensivePosture.DETECT, 'continuous registry anomaly monitoring', frozenset({ControlKind.MONITORING, ControlKind.AUDIT}), 2), (DefensivePosture.RECOVER, 'trusted-baseline artifact rollback', frozenset({ControlKind.INVENTORY}), 3)), ('AI pipeline artifacts must be attested end-to-end', frozenset({ControlKind.ATTESTATION, ControlKind.INVENTORY, ControlKind.AUDIT, ControlKind.CRYPTOGRAPHY}))), ScenarioClass.IDENTITY_FABRIC_TAKEOVER: (((PrecursorClass.BEHAVIORAL, 'abnormal recovery event frequency', 'recovery_events_per_hour > baseline', 1), (PrecursorClass.CONFIGURATION, 'recovery path uses a non-standard verifier', 'recovery_verifier_not_allowlisted', 1), (PrecursorClass.TELEMETRY, 'post-recovery session origin shift', 'post_recovery_geo_shift', 1)), ((ControlKind.AUTHENTICATION, 5, 'recovery verifier not strongly authenticated'), (ControlKind.CRYPTOGRAPHY, 4, 'recovery proofs not cryptographically bound')), ((DefensivePosture.PREVENT, 'hardware-bound recovery proofs only', frozenset({ControlKind.CRYPTOGRAPHY, ControlKind.ATTESTATION}), 1), (DefensivePosture.DETECT, 'recovery-path anomaly detection', frozenset({ControlKind.MONITORING, ControlKind.AUDIT}), 2)), ('identity recovery must be cryptographically bound', frozenset({ControlKind.CRYPTOGRAPHY, ControlKind.AUTHENTICATION, ControlKind.AUDIT}))), ScenarioClass.PHYSICAL_SAFETY_INCIDENT: (((PrecursorClass.TELEMETRY, 'safety-controller heartbeat jitter', 'safety_controller_heartbeat_jitter > threshold', 1), (PrecursorClass.BEHAVIORAL, 'actuator command outside normal envelope', 'actuator_command_out_of_envelope', 1)), ((ControlKind.AUTHORIZATION, 5, 'actuation commands not gated by safety checks'), (ControlKind.ISOLATION, 4, 'physical actuation not isolated from network'), (ControlKind.HUMAN_REVIEW, 4, 'high-impact actuation not human-reviewed')), ((DefensivePosture.PREVENT, 'hardware safety interlock on actuation', frozenset({ControlKind.ISOLATION, ControlKind.AUTHORIZATION}), 1), (DefensivePosture.CONTAIN, 'physical isolation of actuation network', frozenset({ControlKind.ISOLATION}), 1)), ('physical actuation must be safety-gated', frozenset({ControlKind.AUTHORIZATION, ControlKind.ISOLATION, ControlKind.HUMAN_REVIEW}))), ScenarioClass.EDGE_FLEET_COMPROMISE: (((PrecursorClass.SUPPLY_CHAIN, 'OTA package signer not allow-listed', 'ota_signer_not_allowlisted', 1), (PrecursorClass.TELEMETRY, 'fleet node reporting anomalous attestation state', 'attestation_state_anomaly', 1)), ((ControlKind.ATTESTATION, 5, 'edge nodes not remotely attested'), (ControlKind.INVENTORY, 4, 'edge fleet not inventoried')), ((DefensivePosture.PREVENT, 'signed + attested OTA rollout', frozenset({ControlKind.ATTESTATION, ControlKind.CRYPTOGRAPHY}), 1), (DefensivePosture.DETECT, 'fleet-wide attestation drift monitoring', frozenset({ControlKind.MONITORING}), 2)), ('edge fleet must be attested end-to-end', frozenset({ControlKind.ATTESTATION, ControlKind.INVENTORY, ControlKind.AUDIT}))), ScenarioClass.CLOUD_CONTROL_PLANE_BREAKOUT: (((PrecursorClass.CONFIGURATION, 'cross-tenant IAM binding created', 'cross_tenant_iam_binding_created', 1), (PrecursorClass.ADVERSARY_ACTIVITY, 'control-plane API call from unexpected principal', 'unexpected_control_plane_principal', 1)), ((ControlKind.AUTHORIZATION, 5, 'control-plane actions not least-privilege scoped'), (ControlKind.ISOLATION, 5, 'workloads not strongly tenant-isolated'), (ControlKind.AUDIT, 4, 'control-plane audit not centralized')), ((DefensivePosture.PREVENT, 'least-privilege control-plane authorisation', frozenset({ControlKind.AUTHORIZATION, ControlKind.AUDIT}), 1), (DefensivePosture.CONTAIN, 'tenant isolation enforced at the workload boundary', frozenset({ControlKind.ISOLATION}), 1)), ('cloud control plane must be least-privilege + isolated', frozenset({ControlKind.AUTHORIZATION, ControlKind.ISOLATION, ControlKind.AUDIT}))), ScenarioClass.PROTOCOL_DOWNGRADE_EXPLOITATION: (((PrecursorClass.TELEMETRY, 'protocol version distribution shifted', 'protocol_version_mix_shift', 1), (PrecursorClass.ADVERSARY_ACTIVITY, 'negotiation replayed against a weaker peer', 'downgrade_negotiation_replay', 1)), ((ControlKind.CRYPTOGRAPHY, 4, 'no minimum crypto suite enforced'), (ControlKind.AUTHENTICATION, 4, 'peer authentication optional')), ((DefensivePosture.PREVENT, 'minimum crypto suite enforced at both ends', frozenset({ControlKind.CRYPTOGRAPHY, ControlKind.AUTHENTICATION}), 1), (DefensivePosture.DETECT, 'downgrade negotiation alerting', frozenset({ControlKind.MONITORING}), 2)), ('protocols must enforce minimum crypto suites', frozenset({ControlKind.CRYPTOGRAPHY, ControlKind.AUTHENTICATION, ControlKind.MONITORING}))), ScenarioClass.HARDWARE_TRUST_ANCHOR_COMPROMISE: (((PrecursorClass.TELEMETRY, 'boot measurement differs from baseline', 'boot_measurement_drift', 1), (PrecursorClass.SUPPLY_CHAIN, 'firmware signature chain altered', 'firmware_signer_chain_change', 24)), ((ControlKind.ATTESTATION, 5, 'boot chain not continuously attested'), (ControlKind.CRYPTOGRAPHY, 5, 'trust anchor not hardware-bound')), ((DefensivePosture.PREVENT, 'hardware-rooted boot attestation', frozenset({ControlKind.ATTESTATION, ControlKind.CRYPTOGRAPHY}), 1), (DefensivePosture.DETECT, 'boot-chain integrity monitoring', frozenset({ControlKind.MONITORING}), 1)), ('hardware trust anchor must be attested and monitored', frozenset({ControlKind.ATTESTATION, ControlKind.CRYPTOGRAPHY, ControlKind.MONITORING}))), ScenarioClass.CROSS_TECH_CASCADE: (((PrecursorClass.DEPENDENCY, 'dependency chain length increased', 'transitive_dependency_count_jump', 24), (PrecursorClass.BEHAVIORAL, 'downstream anomalies share a common origin', 'shared_origin_clustering', 1)), ((ControlKind.ISOLATION, 5, 'no cross-domain isolation between technologies'), (ControlKind.AUDIT, 4, 'cross-technology causal trail incomplete')), ((DefensivePosture.CONTAIN, 'cross-domain isolation between trust boundaries', frozenset({ControlKind.ISOLATION}), 1), (DefensivePosture.DETECT, 'cross-technology causal analysis', frozenset({ControlKind.MONITORING, ControlKind.AUDIT}), 2), (DefensivePosture.ADAPT, 'scenario-driven hardening for discovered cascade paths', frozenset({ControlKind.HUMAN_REVIEW, ControlKind.AUDIT}), 3)), ('cross-technology cascades must be bounded', frozenset({ControlKind.ISOLATION, ControlKind.AUDIT, ControlKind.MONITORING})))}


# =============================================================================
# SECTION 6 — INVARIANTS
# =============================================================================


class InvariantSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class InvariantViolation:
    invariant_id: str
    severity: InvariantSeverity
    subject_id: str
    detail: str


@dataclass(frozen=True)
class ScenarioSnapshot:
    current: CurrentState
    technologies: Mapping[str, EmergingTech]
    dependencies: Tuple[TechDependencyEdge, ...]
    adversaries: Tuple[AdversaryProfile, ...]
    scenarios: Tuple[FutureThreatScenario, ...]
    findings: Tuple[ScenarioFinding, ...]


@dataclass(frozen=True)
class ScenarioInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[ScenarioSnapshot],
                        Tuple[InvariantViolation, ...]]
    description: str


def _inv_no_scenario_claims(
    snap: ScenarioSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for s in snap.scenarios:
        if s.forecast_not_claim is not True:
            out.append(InvariantViolation(
                invariant_id="scenario.not_a_claim",
                severity=InvariantSeverity.CRITICAL,
                subject_id=s.scenario_id,
                detail="scenario claims to be a fact",
            ))
    return tuple(out)


def _inv_scenarios_have_precursors(
    snap: ScenarioSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for s in snap.scenarios:
        if not s.precursor_indicators:
            out.append(InvariantViolation(
                invariant_id="scenario.has_precursors",
                severity=InvariantSeverity.HIGH,
                subject_id=s.scenario_id,
                detail="scenario without precursor indicators",
            ))
    return tuple(out)


def _inv_scenarios_have_strategies(
    snap: ScenarioSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for s in snap.scenarios:
        if not s.defensive_strategies:
            out.append(InvariantViolation(
                invariant_id="scenario.has_strategies",
                severity=InvariantSeverity.HIGH,
                subject_id=s.scenario_id,
                detail="scenario without defensive strategies",
            ))
    return tuple(out)


def _inv_likelihood_bounded(
    snap: ScenarioSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for s in snap.scenarios:
        if not 0.0 <= s.likelihood <= 1.0:
            out.append(InvariantViolation(
                invariant_id="scenario.likelihood_bounded",
                severity=InvariantSeverity.HIGH,
                subject_id=s.scenario_id,
                detail=f"likelihood {s.likelihood}",
            ))
    return tuple(out)


def _inv_findings_not_claims(
    snap: ScenarioSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for f in snap.findings:
        if f.forecast_not_claim is not True:
            out.append(InvariantViolation(
                invariant_id="scenario.findings_not_claims",
                severity=InvariantSeverity.CRITICAL,
                subject_id=f.subject_id,
                detail="finding claims to be a fact",
            ))
    return tuple(out)


def _inv_references_registered(
    snap: ScenarioSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    asset_ids = {a.asset_id for a in snap.current.assets}
    tech_ids = set(snap.technologies.keys())
    for s in snap.scenarios:
        for aid in s.affected_asset_ids:
            if aid not in asset_ids:
                out.append(InvariantViolation(
                    invariant_id="scenario.references_registered",
                    severity=InvariantSeverity.HIGH,
                    subject_id=s.scenario_id,
                    detail=f"references unknown asset {aid}",
                ))
        for tid in s.affected_technology_ids:
            if tid not in tech_ids:
                out.append(InvariantViolation(
                    invariant_id="scenario.references_registered",
                    severity=InvariantSeverity.HIGH,
                    subject_id=s.scenario_id,
                    detail=f"references unknown technology {tid}",
                ))
    return tuple(out)


DEFAULT_INVARIANTS: Tuple[ScenarioInvariant, ...] = (
    ScenarioInvariant(
        invariant_id="scenario.not_a_claim",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_no_scenario_claims,
        description="Scenarios are forecasts, not claims.",
    ),
    ScenarioInvariant(
        invariant_id="scenario.has_precursors",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_scenarios_have_precursors,
        description="Every scenario must carry precursor indicators.",
    ),
    ScenarioInvariant(
        invariant_id="scenario.has_strategies",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_scenarios_have_strategies,
        description="Every scenario must carry defensive strategies.",
    ),
    ScenarioInvariant(
        invariant_id="scenario.likelihood_bounded",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_likelihood_bounded,
        description="Likelihood must lie within [0,1].",
    ),
    ScenarioInvariant(
        invariant_id="scenario.findings_not_claims",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_findings_not_claims,
        description="Findings are forecasts, not claims.",
    ),
    ScenarioInvariant(
        invariant_id="scenario.references_registered",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_references_registered,
        description="Scenarios must reference registered entities.",
    ),
)


def check_invariants(
    snap: ScenarioSnapshot,
    invariants: Iterable[ScenarioInvariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 7 — STORE
# =============================================================================


@dataclass(frozen=True)
class ScenarioRecord:
    scenario_id: str
    scenario_class: ScenarioClass
    likelihood: float
    severity: int
    horizon_months: int
    asset_count: int
    technology_count: int
    strategy_count: int
    updated_at: datetime


class ScenarioStore(Protocol):
    def put(self, record: ScenarioRecord) -> None: ...
    def get(self, scenario_id: str) -> Optional[ScenarioRecord]: ...
    def all(self) -> Tuple[ScenarioRecord, ...]: ...


class InMemoryScenarioStore:
    def __init__(self) -> None:
        self._data: Dict[str, ScenarioRecord] = {}

    def put(self, record: ScenarioRecord) -> None:
        existing = self._data.get(record.scenario_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._data[record.scenario_id] = record

    def get(self, scenario_id: str) -> Optional[ScenarioRecord]:
        return self._data.get(scenario_id)

    def all(self) -> Tuple[ScenarioRecord, ...]:
        return tuple(self._data.values())


class SqliteScenarioStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scenario_records (
                scenario_id TEXT PRIMARY KEY,
                scenario_class TEXT NOT NULL,
                likelihood REAL NOT NULL,
                severity INTEGER NOT NULL,
                horizon_months INTEGER NOT NULL,
                asset_count INTEGER NOT NULL,
                technology_count INTEGER NOT NULL,
                strategy_count INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scenario_findings (
                finding_id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def put(self, record: ScenarioRecord) -> None:
        existing = self.get(record.scenario_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._conn.execute(
            """
            INSERT INTO scenario_records
              (scenario_id, scenario_class, likelihood, severity,
               horizon_months, asset_count, technology_count,
               strategy_count, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scenario_id) DO UPDATE SET
              scenario_class=excluded.scenario_class,
              likelihood=excluded.likelihood,
              severity=excluded.severity,
              horizon_months=excluded.horizon_months,
              asset_count=excluded.asset_count,
              technology_count=excluded.technology_count,
              strategy_count=excluded.strategy_count,
              updated_at=excluded.updated_at
            """,
            (
                record.scenario_id, record.scenario_class.value,
                record.likelihood, record.severity,
                record.horizon_months, record.asset_count,
                record.technology_count, record.strategy_count,
                record.updated_at.isoformat(),
            ),
        )
        self._conn.commit()

    def get(self, scenario_id: str) -> Optional[ScenarioRecord]:
        row = self._conn.execute(
            "SELECT scenario_class, likelihood, severity, "
            "horizon_months, asset_count, technology_count, "
            "strategy_count, updated_at FROM scenario_records "
            "WHERE scenario_id = ?",
            (scenario_id,),
        ).fetchone()
        if row is None:
            return None
        return ScenarioRecord(
            scenario_id=scenario_id,
            scenario_class=ScenarioClass(row[0]),
            likelihood=float(row[1]), severity=int(row[2]),
            horizon_months=int(row[3]), asset_count=int(row[4]),
            technology_count=int(row[5]), strategy_count=int(row[6]),
            updated_at=datetime.fromisoformat(row[7]),
        )

    def all(self) -> Tuple[ScenarioRecord, ...]:
        rows = self._conn.execute(
            "SELECT scenario_id FROM scenario_records"
        ).fetchall()
        return tuple(
            r for r in (self.get(x[0]) for x in rows) if r is not None
        )

    def put_finding(self, finding_id: str, f: ScenarioFinding) -> None:
        payload = {
            "finding_id": finding_id,
            "kind": f.kind.value,
            "subject_id": f.subject_id,
            "detail": f.detail,
            "severity": f.severity,
            "horizon_months": f.horizon_months,
            "at": f.at.isoformat(),
        }
        self._conn.execute(
            "INSERT OR REPLACE INTO scenario_findings "
            "(finding_id, payload_json) VALUES (?, ?)",
            (finding_id, json.dumps(payload, sort_keys=True)),
        )
        self._conn.commit()


# =============================================================================
# SECTION 8 — ENGINE
# =============================================================================


@dataclass(frozen=True)
class ScenarioConfig:
    min_likelihood_to_report: float = 0.15
    min_severity_to_report: int = 3
    high_likelihood_threshold: float = 0.6
    max_scenarios: int = 2000
    max_precursors_per_scenario: int = 6
    max_strategies_per_scenario: int = 6

    def __post_init__(self) -> None:
        if not 0.0 <= self.min_likelihood_to_report <= 1.0:
            raise ValueError("min_likelihood_to_report must be within [0,1]")
        if not 1 <= self.min_severity_to_report <= 5:
            raise ValueError("min_severity_to_report must be in [1,5]")
        if not 0.0 <= self.high_likelihood_threshold <= 1.0:
            raise ValueError("high_likelihood_threshold must be within [0,1]")
        if self.max_scenarios < 1:
            raise ValueError("max_scenarios must be >= 1")
        if self.max_precursors_per_scenario < 1:
            raise ValueError("max_precursors_per_scenario must be >= 1")
        if self.max_strategies_per_scenario < 1:
            raise ValueError("max_strategies_per_scenario must be >= 1")


def _likelihood(
    base: float,
    *,
    adoption: AdoptionStage,
    maturity: MaturityLevel,
    trend: TrendDirection,
    adversary: AdversaryCapability,
    required_adversary: AdversaryCapability,
    sophistication: float,
) -> float:
    if not 0.0 <= base <= 1.0:
        raise ValueError("base must be within [0,1]")
    if not 0.0 <= sophistication <= 1.0:
        raise ValueError("sophistication must be within [0,1]")
    adv_gap = adversary_rank(adversary) - adversary_rank(required_adversary)
    if adv_gap < 0:
        adv_factor = 0.35
    elif adv_gap == 0:
        adv_factor = 1.0
    else:
        adv_factor = 1.0 + 0.05 * min(adv_gap, 4)
    raw = (
        base
        * adoption_modifier(adoption)
        * maturity_modifier(maturity)
        * trend_modifier(trend)
        * adv_factor
        * (0.75 + 0.25 * sophistication)
    )
    return max(0.0, min(1.0, raw))


class FutureThreatScenarioEngine:
    """Future threat scenario engineering engine.

    Composes five inputs — current state, emerging technology, adoption,
    dependencies, adversary capability — into structured future-threat
    scenarios with precursors, weaknesses, strategies, and preparedness
    requirements.
    """

    def __init__(
        self,
        *,
        current: CurrentState,
        store: Optional[ScenarioStore] = None,
        config: Optional[ScenarioConfig] = None,
    ) -> None:
        self._current = current
        self._store: ScenarioStore = store or InMemoryScenarioStore()
        self._config = config or ScenarioConfig()
        self._techs: Dict[str, EmergingTech] = {}
        self._deps: List[TechDependencyEdge] = []
        self._adversaries: List[AdversaryProfile] = []
        self._scenarios: Tuple[FutureThreatScenario, ...] = ()
        self._findings: List[ScenarioFinding] = []
        self._violations: Tuple[InvariantViolation, ...] = ()

    # ---- registration ----------------------------------------------------

    def register_technology(self, tech: EmergingTech) -> None:
        if tech.tech_id in self._techs:
            raise ValueError(
                f"technology {tech.tech_id} already registered"
            )
        self._techs[tech.tech_id] = tech

    def register_dependency(self, dep: TechDependencyEdge) -> None:
        if dep.dependent_id not in self._techs:
            raise KeyError(
                f"dependent {dep.dependent_id} not registered"
            )
        if dep.dependency_id not in self._techs:
            raise KeyError(
                f"dependency {dep.dependency_id} not registered"
            )
        self._deps.append(dep)

    def register_adversary(self, adv: AdversaryProfile) -> None:
        self._adversaries.append(adv)

    def current(self) -> CurrentState:
        return self._current

    def technologies(self) -> Tuple[EmergingTech, ...]:
        return tuple(self._techs.values())

    def adversaries(self) -> Tuple[AdversaryProfile, ...]:
        return tuple(self._adversaries)

    def config(self) -> ScenarioConfig:
        return self._config

    def set_config(self, config: ScenarioConfig) -> None:
        self._config = config

    # ---- recompute -------------------------------------------------------

    def recompute(
        self,
        *,
        at: datetime,
        horizon_months: Optional[int] = None,
    ) -> Tuple[FutureThreatScenario, ...]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

        cfg = self._config
        self._findings = []
        scenarios: List[FutureThreatScenario] = []

        # Aggregate adversary capability: maximum tier + best
        # sophistication.
        max_adv = AdversaryCapability.SCRIPT_KIDDIE
        max_soph = 0.0
        for adv in self._adversaries:
            if adversary_rank(adv.tier) > adversary_rank(max_adv):
                max_adv = adv.tier
            if adv.sophistication > max_soph:
                max_soph = adv.sophistication

        for tid in sorted(self._techs):
            tech = self._techs[tid]
            horizon = horizon_months or tech.horizon_months

            templates = _SCENARIO_TEMPLATES.get(tech.category, ())
            for (
                sc_class, weight, sev, req_adv, req_caps, narrative,
            ) in templates:
                # Capability gate
                if not req_caps.issubset(tech.capabilities):
                    continue
                lik = _likelihood(
                    weight, adoption=tech.adoption,
                    maturity=tech.maturity, trend=tech.trend,
                    adversary=max_adv, required_adversary=req_adv,
                    sophistication=max_soph,
                )
                if lik < cfg.min_likelihood_to_report:
                    continue
                if sev < cfg.min_severity_to_report:
                    continue

                playbook = _SCENARIO_CLASS_PLAYBOOK[sc_class]

                precursors = self._build_precursors(
                    playbook[0], limit=cfg.max_precursors_per_scenario,
                    prefix=f"{sc_class.value}:{tid}",
                )
                weaknesses = self._build_weaknesses(
                    playbook[1], tech=tech,
                    prefix=f"{sc_class.value}:{tid}",
                )
                strategies = self._build_strategies(
                    playbook[2], tech=tech,
                    limit=cfg.max_strategies_per_scenario,
                    prefix=f"{sc_class.value}:{tid}",
                )
                requirements = self._build_requirements(
                    playbook[3], tech=tech,
                    prefix=f"{sc_class.value}:{tid}",
                )

                affected_assets = self._affected_assets(tech)
                affected_technologies = (tid,) + tuple(
                    d.dependency_id for d in self._deps
                    if d.dependent_id == tid
                )
                affected_technologies = tuple(sorted(
                    set(affected_technologies)
                ))

                scenario_id = f"scenario:{sc_class.value}:{tid}"
                title = f"{sc_class.value.replace('_', ' ')} via {tech.name}"
                scenarios.append(FutureThreatScenario(
                    scenario_id=scenario_id,
                    scenario_class=sc_class,
                    title=title,
                    narrative=(
                        f"{narrative} Requires at least "
                        f"{req_adv.value} adversary capability; current "
                        f"assessed maximum is {max_adv.value}."
                    ),
                    horizon_months=horizon,
                    likelihood=lik,
                    severity=sev,
                    adversary_capability_required=req_adv,
                    affected_asset_ids=affected_assets,
                    affected_technology_ids=affected_technologies,
                    precursor_indicators=precursors,
                    control_weaknesses=weaknesses,
                    defensive_strategies=strategies,
                    preparedness_requirements=requirements,
                    rationale=(
                        f"Composed from current state + adoption "
                        f"({tech.adoption.value}) + maturity "
                        f"({tech.maturity.value}) + trend "
                        f"({tech.trend.value}) + adversary "
                        f"capability ({max_adv.value})"
                    ),
                    forecast_not_claim=True,
                    at=at,
                ))

        scenarios.sort(
            key=lambda s: (-s.likelihood, -s.severity,
                           s.scenario_id),
        )
        if len(scenarios) > cfg.max_scenarios:
            scenarios = scenarios[: cfg.max_scenarios]
        self._scenarios = tuple(scenarios)

        self._emit_findings(at=at)

        records: List[ScenarioRecord] = []
        for s in self._scenarios:
            rec = ScenarioRecord(
                scenario_id=s.scenario_id,
                scenario_class=s.scenario_class,
                likelihood=s.likelihood, severity=s.severity,
                horizon_months=s.horizon_months,
                asset_count=len(s.affected_asset_ids),
                technology_count=len(s.affected_technology_ids),
                strategy_count=len(s.defensive_strategies),
                updated_at=at,
            )
            self._store.put(rec)
            records.append(rec)

        if isinstance(self._store, SqliteScenarioStore):
            for i, f in enumerate(self._findings):
                self._store.put_finding(
                    f"f-{i:08d}-{f.kind.value}", f,
                )

        self._violations = check_invariants(self.snapshot())
        return tuple(records)

    # ---- builders --------------------------------------------------------

    def _build_precursors(
        self,
        templates: Tuple[Tuple[PrecursorClass, str, str, int], ...],
        *,
        limit: int,
        prefix: str,
    ) -> Tuple[PrecursorIndicator, ...]:
        out: List[PrecursorIndicator] = []
        for i, (pc, desc, signal, freq) in enumerate(templates):
            if i >= limit:
                break
            out.append(PrecursorIndicator(
                precursor_id=f"precursor:{prefix}:{i}",
                precursor_class=pc,
                description=desc,
                observable_signal=signal,
                check_frequency_hours=freq,
            ))
        return tuple(out)

    def _build_weaknesses(
        self,
        templates: Tuple[Tuple[ControlKind, int, str], ...],
        *,
        tech: EmergingTech,
        prefix: str,
    ) -> Tuple[ControlWeakness, ...]:
        out: List[ControlWeakness] = []
        for i, (ctrl, sev, reason) in enumerate(templates):
            if ctrl in tech.deployed_controls:
                continue
            affected = self._affected_assets(tech)
            out.append(ControlWeakness(
                weakness_id=f"weakness:{prefix}:{i}",
                missing_control=ctrl,
                affected_asset_ids=affected or ("<no-assets>",),
                reason=reason,
                severity=sev,
            ))
        return tuple(out)

    def _build_strategies(
        self,
        templates: Tuple[
            Tuple[DefensivePosture, str, FrozenSet[ControlKind], int],
            ...,
        ],
        *,
        tech: EmergingTech,
        limit: int,
        prefix: str,
    ) -> Tuple[DefensiveStrategy, ...]:
        out: List[DefensiveStrategy] = []
        for i, (posture, desc, controls, priority) in enumerate(templates):
            if i >= limit:
                break
            # Only include strategies that are not yet fully covered
            if controls.issubset(tech.deployed_controls):
                continue
            out.append(DefensiveStrategy(
                strategy_id=f"strategy:{prefix}:{i}",
                posture=posture,
                description=desc,
                required_controls=controls,
                priority=priority,
            ))
        return tuple(out)

    def _build_requirements(
        self,
        template: Tuple[str, FrozenSet[ControlKind]],
        *,
        tech: EmergingTech,
        prefix: str,
    ) -> Tuple[PreparednessRequirement, ...]:
        desc, req_controls = template
        met = req_controls & tech.deployed_controls
        return (PreparednessRequirement(
            requirement_id=f"req:{prefix}",
            description=desc,
            required_controls=req_controls,
            already_met_controls=met,
            horizon_months=tech.horizon_months,
        ),)

    def _affected_assets(self, tech: EmergingTech) -> Tuple[str, ...]:
        out: List[str] = []
        for a in self._current.assets:
            if tech.tech_id in a.tech_dependencies:
                out.append(a.asset_id)
        return tuple(sorted(out))

    # ---- findings --------------------------------------------------------

    def _emit_findings(self, *, at: datetime) -> None:
        cfg = self._config
        for s in self._scenarios:
            # Base scenario finding
            self._findings.append(ScenarioFinding(
                kind=FindingKind.SCENARIO_PRODUCED,
                subject_id=s.scenario_id,
                detail=(
                    f"{s.title} — likelihood {s.likelihood:.2f}, "
                    f"severity {s.severity}"
                ),
                severity=s.severity,
                horizon_months=s.horizon_months,
                forecast_not_claim=True, at=at,
            ))
            # High-likelihood
            if s.likelihood >= cfg.high_likelihood_threshold:
                self._findings.append(ScenarioFinding(
                    kind=FindingKind.HIGH_LIKELIHOOD_SCENARIO,
                    subject_id=s.scenario_id,
                    detail=(
                        f"likelihood {s.likelihood:.2f} >= "
                        f"{cfg.high_likelihood_threshold:.2f}"
                    ),
                    severity=s.severity,
                    horizon_months=s.horizon_months,
                    forecast_not_claim=True, at=at,
                ))
            # Control weaknesses
            for w in s.control_weaknesses:
                self._findings.append(ScenarioFinding(
                    kind=FindingKind.CONTROL_WEAKNESS,
                    subject_id=s.scenario_id,
                    detail=(
                        f"missing {w.missing_control.value}: {w.reason}"
                    ),
                    severity=w.severity,
                    horizon_months=s.horizon_months,
                    forecast_not_claim=True, at=at,
                ))
            # Preparedness gaps
            for req in s.preparedness_requirements:
                if req.fully_met:
                    continue
                self._findings.append(ScenarioFinding(
                    kind=FindingKind.PREPAREDNESS_GAP,
                    subject_id=s.scenario_id,
                    detail=(
                        f"{len(req.unmet_controls)} unmet control(s): "
                        f"{sorted(c.value for c in req.unmet_controls)}"
                    ),
                    severity=4,
                    horizon_months=s.horizon_months,
                    forecast_not_claim=True, at=at,
                ))
            # Unmitigated scenario: no strategies and no weaknesses
            if not s.defensive_strategies:
                self._findings.append(ScenarioFinding(
                    kind=FindingKind.UNMITIGATED_SCENARIO,
                    subject_id=s.scenario_id,
                    detail=(
                        "no defensive strategies available — "
                        "control gap likely"
                    ),
                    severity=5,
                    horizon_months=s.horizon_months,
                    forecast_not_claim=True, at=at,
                ))
            # Adversary capability exceeded (required > current max)
            cur_max = AdversaryCapability.SCRIPT_KIDDIE
            for adv in self._adversaries:
                if adversary_rank(adv.tier) > adversary_rank(cur_max):
                    cur_max = adv.tier
            if adversary_rank(s.adversary_capability_required) > \
               adversary_rank(cur_max):
                self._findings.append(ScenarioFinding(
                    kind=FindingKind.ADVERSARY_CAPABILITY_EXCEEDED,
                    subject_id=s.scenario_id,
                    detail=(
                        f"scenario assumes {s.adversary_capability_required.value} "
                        f"but current max is {cur_max.value}"
                    ),
                    severity=3,
                    horizon_months=s.horizon_months,
                    forecast_not_claim=True, at=at,
                ))

        # Cross-tech cascade findings
        for s in self._scenarios:
            if s.scenario_class is ScenarioClass.CROSS_TECH_CASCADE:
                self._findings.append(ScenarioFinding(
                    kind=FindingKind.CROSS_TECH_CASCADE_RISK,
                    subject_id=s.scenario_id,
                    detail=(
                        f"cascade scenario spans "
                        f"{len(s.affected_technology_ids)} tech"
                    ),
                    severity=5,
                    horizon_months=s.horizon_months,
                    forecast_not_claim=True, at=at,
                ))

        # Dependency fragility findings
        for d in self._deps:
            dep = self._techs.get(d.dependency_id)
            if dep is None:
                continue
            if dep.maturity in (
                MaturityLevel.NASCENT, MaturityLevel.DEVELOPING,
            ) and d.critical:
                self._findings.append(ScenarioFinding(
                    kind=FindingKind.DEPENDENCY_FRAGILITY,
                    subject_id=d.dependent_id,
                    detail=(
                        f"critical dependency on {d.dependency_id} "
                        f"({dep.maturity.value})"
                    ),
                    severity=4,
                    horizon_months=dep.horizon_months,
                    forecast_not_claim=True, at=at,
                ))

    # ---- queries ---------------------------------------------------------

    def scenarios(self) -> Tuple[FutureThreatScenario, ...]:
        return self._scenarios

    def scenarios_of_class(
        self, cls: ScenarioClass,
    ) -> Tuple[FutureThreatScenario, ...]:
        return tuple(
            s for s in self._scenarios if s.scenario_class is cls
        )

    def top_scenarios(
        self, *, k: int = 10,
    ) -> Tuple[FutureThreatScenario, ...]:
        if k <= 0:
            raise ValueError("k must be > 0")
        return tuple(self._scenarios[:k])

    def findings(self) -> Tuple[ScenarioFinding, ...]:
        return tuple(self._findings)

    def top_findings(
        self, *, k: int = 10,
    ) -> Tuple[ScenarioFinding, ...]:
        if k <= 0:
            raise ValueError("k must be > 0")
        ordered = sorted(
            self._findings,
            key=lambda f: (-f.severity, f.kind.value, f.subject_id),
        )
        return tuple(ordered[:k])

    def findings_by_kind(self) -> Mapping[FindingKind, int]:
        out: Dict[FindingKind, int] = {k: 0 for k in FindingKind}
        for f in self._findings:
            out[f.kind] += 1
        return out

    def scenarios_by_class(self) -> Mapping[ScenarioClass, int]:
        out: Dict[ScenarioClass, int] = {k: 0 for k in ScenarioClass}
        for s in self._scenarios:
            out[s.scenario_class] += 1
        return out

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return self._violations

    def record(self, scenario_id: str) -> Optional[ScenarioRecord]:
        return self._store.get(scenario_id)

    def snapshot(self) -> ScenarioSnapshot:
        return ScenarioSnapshot(
            current=self._current,
            technologies=dict(self._techs),
            dependencies=tuple(self._deps),
            adversaries=tuple(self._adversaries),
            scenarios=self._scenarios,
            findings=tuple(self._findings),
        )


# =============================================================================
# SECTION 9 — TESTS
# =============================================================================


def _t0() -> datetime:
    from datetime import timezone
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _asset(
    aid: str, *,
    kind: str = "service",
    criticality: float = 0.7,
    data_classification: int = 2,
    controls: Iterable[ControlKind] = (),
    deps: Iterable[str] = (),
) -> CurrentAsset:
    return CurrentAsset(
        asset_id=aid, kind=kind, criticality=criticality,
        data_classification=data_classification,
        deployed_controls=frozenset(controls),
        tech_dependencies=frozenset(deps),
    )


def _tech(
    tid: str, cat: TechCategory, *,
    name: Optional[str] = None,
    adoption: AdoptionStage = AdoptionStage.EARLY_ADOPTION,
    maturity: MaturityLevel = MaturityLevel.DEVELOPING,
    trend: TrendDirection = TrendDirection.STEADY,
    horizon: int = 24,
    caps: Iterable[str] = (),
    controls: Iterable[ControlKind] = (),
) -> EmergingTech:
    return EmergingTech(
        tech_id=tid, category=cat, name=name or tid,
        adoption=adoption, maturity=maturity, trend=trend,
        horizon_months=horizon,
        capabilities=frozenset(caps),
        deployed_controls=frozenset(controls),
    )


def _adv(
    aid: str = "adv",
    tier: AdversaryCapability = AdversaryCapability.ORGANIZED_CRIME,
    *,
    soph: float = 0.6,
) -> AdversaryProfile:
    return AdversaryProfile(
        adversary_id=aid, tier=tier, sophistication=soph,
    )


def _current(
    *assets: CurrentAsset,
    controls: Iterable[ControlKind] = (),
) -> CurrentState:
    return CurrentState(
        assets=tuple(assets),
        controls_deployed=frozenset(controls),
    )


# ---- domain ----

def test_asset_requires_id() -> None:
    try:
        CurrentAsset(
            asset_id="", kind="s", criticality=0.5,
            data_classification=1, deployed_controls=frozenset(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_asset_criticality_bounds() -> None:
    try:
        _asset("a", criticality=1.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_tech_requires_id() -> None:
    try:
        EmergingTech(
            tech_id="", category=TechCategory.AUTONOMOUS_AGENTS,
            name="x", adoption=AdoptionStage.PILOT,
            maturity=MaturityLevel.NASCENT, trend=TrendDirection.STEADY,
            horizon_months=12,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_dependency_self_rejected() -> None:
    try:
        TechDependencyEdge(
            dependent_id="a", dependency_id="a", kind="x",
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_scenario_requires_no_claim() -> None:
    try:
        FutureThreatScenario(
            scenario_id="s", scenario_class=ScenarioClass.CROSS_TECH_CASCADE,
            title="x", narrative="y", horizon_months=12,
            likelihood=0.5, severity=4,
            adversary_capability_required=AdversaryCapability.INSIDER,
            affected_asset_ids=(), affected_technology_ids=("t",),
            precursor_indicators=(), control_weaknesses=(),
            defensive_strategies=(), preparedness_requirements=(),
            rationale="x", forecast_not_claim=False, at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_scenario_requires_assets_or_techs() -> None:
    try:
        FutureThreatScenario(
            scenario_id="s", scenario_class=ScenarioClass.CROSS_TECH_CASCADE,
            title="x", narrative="y", horizon_months=12,
            likelihood=0.5, severity=4,
            adversary_capability_required=AdversaryCapability.INSIDER,
            affected_asset_ids=(), affected_technology_ids=(),
            precursor_indicators=(), control_weaknesses=(),
            defensive_strategies=(), preparedness_requirements=(),
            rationale="x", forecast_not_claim=True, at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_adoption_modifier_ordering() -> None:
    assert adoption_modifier(AdoptionStage.RESEARCH) < \
        adoption_modifier(AdoptionStage.EARLY_ADOPTION)
    assert adoption_modifier(AdoptionStage.EARLY_ADOPTION) > \
        adoption_modifier(AdoptionStage.MAINSTREAM)


def test_adversary_rank_ordering() -> None:
    assert adversary_rank(AdversaryCapability.SCRIPT_KIDDIE) < \
        adversary_rank(AdversaryCapability.ORGANIZED_CRIME)
    assert adversary_rank(AdversaryCapability.ORGANIZED_CRIME) < \
        adversary_rank(AdversaryCapability.NATION_STATE)
    assert adversary_rank(AdversaryCapability.NATION_STATE) < \
        adversary_rank(AdversaryCapability.ADVANCED_PERSISTENT)


# ---- likelihood ----

def test_likelihood_low_when_research() -> None:
    l = _likelihood(
        1.0, adoption=AdoptionStage.RESEARCH,
        maturity=MaturityLevel.NASCENT,
        trend=TrendDirection.STEADY,
        adversary=AdversaryCapability.ORGANIZED_CRIME,
        required_adversary=AdversaryCapability.ORGANIZED_CRIME,
        sophistication=0.5,
    )
    assert l < 0.4


def test_likelihood_penalized_when_adversary_below_required() -> None:
    weak = _likelihood(
        1.0, adoption=AdoptionStage.EARLY_ADOPTION,
        maturity=MaturityLevel.NASCENT,
        trend=TrendDirection.STEADY,
        adversary=AdversaryCapability.SCRIPT_KIDDIE,
        required_adversary=AdversaryCapability.NATION_STATE,
        sophistication=0.5,
    )
    strong = _likelihood(
        1.0, adoption=AdoptionStage.EARLY_ADOPTION,
        maturity=MaturityLevel.NASCENT,
        trend=TrendDirection.STEADY,
        adversary=AdversaryCapability.NATION_STATE,
        required_adversary=AdversaryCapability.NATION_STATE,
        sophistication=0.5,
    )
    assert weak < strong


def test_likelihood_bounded() -> None:
    l = _likelihood(
        1.0, adoption=AdoptionStage.EARLY_ADOPTION,
        maturity=MaturityLevel.NASCENT,
        trend=TrendDirection.ACCELERATING,
        adversary=AdversaryCapability.ADVANCED_PERSISTENT,
        required_adversary=AdversaryCapability.SCRIPT_KIDDIE,
        sophistication=1.0,
    )
    assert 0.0 <= l <= 1.0


# ---- engine basics ----

def test_engine_register_technology() -> None:
    eng = FutureThreatScenarioEngine(
        current=_current(_asset("a")),
    )
    eng.register_technology(_tech(
        "t1", TechCategory.AUTONOMOUS_AGENTS,
    ))
    assert "t1" in {t.tech_id for t in eng.technologies()}


def test_engine_rejects_duplicate_tech() -> None:
    eng = FutureThreatScenarioEngine(
        current=_current(_asset("a")),
    )
    eng.register_technology(_tech("t1", TechCategory.AUTONOMOUS_AGENTS))
    try:
        eng.register_technology(_tech("t1", TechCategory.AUTONOMOUS_AGENTS))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_dependency_requires_registered_techs() -> None:
    eng = FutureThreatScenarioEngine(
        current=_current(_asset("a")),
    )
    eng.register_technology(_tech("a", TechCategory.AUTONOMOUS_AGENTS))
    try:
        eng.register_dependency(TechDependencyEdge(
            dependent_id="a", dependency_id="missing", kind="x",
        ))
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_engine_recompute_requires_aware_time() -> None:
    from datetime import datetime as dt
    eng = FutureThreatScenarioEngine(
        current=_current(_asset("a")),
    )
    try:
        eng.recompute(at=dt(2026, 1, 1))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_recompute_empty() -> None:
    eng = FutureThreatScenarioEngine(
        current=_current(_asset("a")),
    )
    out = eng.recompute(at=_t0())
    assert out == ()


# ---- scenario production ----

def test_engine_produces_agent_exfiltration_scenario() -> None:
    eng = FutureThreatScenarioEngine(
        current=_current(_asset("a", deps=("agent-platform",))),
    )
    eng.register_technology(_tech(
        "agent-platform", TechCategory.AUTONOMOUS_AGENTS,
        caps=("autonomy", "tool_use"),
    ))
    eng.register_adversary(_adv())
    eng.recompute(at=_t0())
    classes = {s.scenario_class for s in eng.scenarios()}
    assert ScenarioClass.AGENT_DRIVEN_EXFILTRATION in classes


def test_engine_capability_gate() -> None:
    eng = FutureThreatScenarioEngine(
        current=_current(_asset("a", deps=("agent-platform",))),
    )
    # no capabilities → no scenario
    eng.register_technology(_tech(
        "agent-platform", TechCategory.AUTONOMOUS_AGENTS,
    ))
    eng.register_adversary(_adv())
    eng.recompute(at=_t0())
    assert eng.scenarios() == ()


def test_engine_scenarios_have_precursors() -> None:
    eng = FutureThreatScenarioEngine(
        current=_current(_asset("a", deps=("agent-platform",))),
    )
    eng.register_technology(_tech(
        "agent-platform", TechCategory.AUTONOMOUS_AGENTS,
        caps=("autonomy", "tool_use"),
    ))
    eng.register_adversary(_adv())
    eng.recompute(at=_t0())
    for s in eng.scenarios():
        assert s.precursor_indicators


def test_engine_scenarios_have_strategies() -> None:
    eng = FutureThreatScenarioEngine(
        current=_current(_asset("a", deps=("agent-platform",))),
    )
    eng.register_technology(_tech(
        "agent-platform", TechCategory.AUTONOMOUS_AGENTS,
        caps=("autonomy", "tool_use"),
    ))
    eng.register_adversary(_adv())
    eng.recompute(at=_t0())
    for s in eng.scenarios():
        assert s.defensive_strategies


def test_engine_scenarios_have_weaknesses_when_controls_missing() -> None:
    eng = FutureThreatScenarioEngine(
        current=_current(_asset("a", deps=("agent-platform",))),
    )
    eng.register_technology(_tech(
        "agent-platform", TechCategory.AUTONOMOUS_AGENTS,
        caps=("autonomy", "tool_use"),
    ))
    eng.register_adversary(_adv())
    eng.recompute(at=_t0())
    for s in eng.scenarios():
        assert s.control_weaknesses


def test_engine_weaknesses_skipped_when_control_deployed() -> None:
    eng = FutureThreatScenarioEngine(
        current=_current(_asset("a", deps=("agent-platform",))),
    )
    eng.register_technology(_tech(
        "agent-platform", TechCategory.AUTONOMOUS_AGENTS,
        caps=("autonomy", "tool_use"),
        controls=(
            ControlKind.AUTHORIZATION,
            ControlKind.MONITORING,
            ControlKind.RATE_LIMIT,
        ),
    ))
    eng.register_adversary(_adv())
    eng.recompute(at=_t0())
    for s in eng.scenarios():
        # AUTHORIZATION weakness should be gone
        assert not any(
            w.missing_control is ControlKind.AUTHORIZATION
            for w in s.control_weaknesses
        )


def test_engine_scenario_not_claim() -> None:
    eng = FutureThreatScenarioEngine(
        current=_current(_asset("a", deps=("agent-platform",))),
    )
    eng.register_technology(_tech(
        "agent-platform", TechCategory.AUTONOMOUS_AGENTS,
        caps=("autonomy",),
    ))
    eng.register_adversary(_adv())
    eng.recompute(at=_t0())
    for s in eng.scenarios():
        assert s.forecast_not_claim is True


def test_engine_identity_fabric_scenario() -> None:
    eng = FutureThreatScenarioEngine(
        current=_current(_asset("idn", deps=("did-fabric",))),
    )
    eng.register_technology(_tech(
        "did-fabric", TechCategory.NEW_IDENTITY_SYSTEM,
        caps=("did", "recovery"),
    ))
    eng.register_adversary(_adv(tier=AdversaryCapability.ADVANCED_PERSISTENT))
    eng.recompute(at=_t0())
    classes = {s.scenario_class for s in eng.scenarios()}
    assert ScenarioClass.IDENTITY_FABRIC_TAKEOVER in classes


def test_engine_cross_tech_cascade_scenario() -> None:
    eng = FutureThreatScenarioEngine(
        current=_current(_asset("a", deps=("agent-platform",))),
    )
    eng.register_technology(_tech(
        "agent-platform", TechCategory.AUTONOMOUS_AGENTS,
        caps=("multi_agent",),
    ))
    eng.register_adversary(_adv(tier=AdversaryCapability.ADVANCED_PERSISTENT))
    eng.recompute(at=_t0())
    classes = {s.scenario_class for s in eng.scenarios()}
    assert ScenarioClass.CROSS_TECH_CASCADE in classes


def test_engine_horizon_override() -> None:
    eng = FutureThreatScenarioEngine(
        current=_current(_asset("a", deps=("agent-platform",))),
    )
    eng.register_technology(_tech(
        "agent-platform", TechCategory.AUTONOMOUS_AGENTS,
        horizon=120, caps=("autonomy", "tool_use"),
    ))
    eng.register_adversary(_adv())
    eng.recompute(at=_t0(), horizon_months=6)
    for s in eng.scenarios():
        assert s.horizon_months == 6


# ---- findings ----

def test_engine_scenario_produced_finding() -> None:
    eng = FutureThreatScenarioEngine(
        current=_current(_asset("a", deps=("agent-platform",))),
    )
    eng.register_technology(_tech(
        "agent-platform", TechCategory.AUTONOMOUS_AGENTS,
        caps=("autonomy", "tool_use"),
    ))
    eng.register_adversary(_adv())
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.SCENARIO_PRODUCED in kinds


def test_engine_control_weakness_finding() -> None:
    eng = FutureThreatScenarioEngine(
        current=_current(_asset("a", deps=("agent-platform",))),
    )
    eng.register_technology(_tech(
        "agent-platform", TechCategory.AUTONOMOUS_AGENTS,
        caps=("autonomy", "tool_use"),
    ))
    eng.register_adversary(_adv())
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.CONTROL_WEAKNESS in kinds


def test_engine_preparedness_gap_finding() -> None:
    eng = FutureThreatScenarioEngine(
        current=_current(_asset("a", deps=("agent-platform",))),
    )
    eng.register_technology(_tech(
        "agent-platform", TechCategory.AUTONOMOUS_AGENTS,
        caps=("autonomy", "tool_use"),
    ))
    eng.register_adversary(_adv())
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.PREPAREDNESS_GAP in kinds


def test_engine_adversary_capability_exceeded_finding() -> None:
    eng = FutureThreatScenarioEngine(
        current=_current(_asset("a", deps=("agent-platform",))),
    )
    # INSIDER cannot attack nation-state-level scenarios
    eng.register_technology(_tech(
        "did-fabric", TechCategory.NEW_IDENTITY_SYSTEM,
        caps=("did", "recovery"),
    ))
    eng.register_adversary(_adv(
        tier=AdversaryCapability.ORGANIZED_CRIME,
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.ADVERSARY_CAPABILITY_EXCEEDED in kinds


def test_engine_dependency_fragility_finding() -> None:
    eng = FutureThreatScenarioEngine(
        current=_current(_asset("a", deps=("consumer",))),
    )
    eng.register_technology(_tech(
        "consumer", TechCategory.AUTONOMOUS_AGENTS,
    ))
    eng.register_technology(_tech(
        "dep", TechCategory.NEW_IDENTITY_SYSTEM,
        maturity=MaturityLevel.NASCENT,
        adoption=AdoptionStage.PILOT,
    ))
    eng.register_dependency(TechDependencyEdge(
        dependent_id="consumer", dependency_id="dep",
        kind="uses", critical=True,
    ))
    eng.register_adversary(_adv())
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.DEPENDENCY_FRAGILITY in kinds


def test_engine_high_likelihood_finding() -> None:
    eng = FutureThreatScenarioEngine(
        current=_current(_asset("a", deps=("agent-platform",))),
        config=ScenarioConfig(high_likelihood_threshold=0.3),
    )
    eng.register_technology(_tech(
        "agent-platform", TechCategory.AUTONOMOUS_AGENTS,
        caps=("autonomy", "tool_use"),
    ))
    eng.register_adversary(_adv(tier=AdversaryCapability.NATION_STATE))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.HIGH_LIKELIHOOD_SCENARIO in kinds


def test_engine_findings_by_kind() -> None:
    eng = FutureThreatScenarioEngine(
        current=_current(_asset("a", deps=("agent-platform",))),
    )
    eng.register_technology(_tech(
        "agent-platform", TechCategory.AUTONOMOUS_AGENTS,
        caps=("autonomy", "tool_use"),
    ))
    eng.register_adversary(_adv())
    eng.recompute(at=_t0())
    counts = eng.findings_by_kind()
    assert counts[FindingKind.SCENARIO_PRODUCED] >= 1


def test_engine_top_findings_sorted() -> None:
    eng = FutureThreatScenarioEngine(
        current=_current(_asset("a", deps=("agent-platform",))),
    )
    eng.register_technology(_tech(
        "agent-platform", TechCategory.AUTONOMOUS_AGENTS,
        caps=("autonomy", "tool_use"),
    ))
    eng.register_adversary(_adv())
    eng.recompute(at=_t0())
    top = eng.top_findings(k=20)
    severities = [f.severity for f in top]
    assert severities == sorted(severities, reverse=True)


def test_engine_top_findings_invalid_k() -> None:
    eng = FutureThreatScenarioEngine(
        current=_current(_asset("a")),
    )
    try:
        eng.top_findings(k=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- queries ----

def test_engine_top_scenarios_sorted() -> None:
    eng = FutureThreatScenarioEngine(
        current=_current(_asset("a", deps=("agent-platform",))),
    )
    eng.register_technology(_tech(
        "agent-platform", TechCategory.AUTONOMOUS_AGENTS,
        caps=("autonomy", "tool_use", "multi_agent"),
    ))
    eng.register_adversary(_adv(tier=AdversaryCapability.ADVANCED_PERSISTENT))
    eng.recompute(at=_t0())
    top = eng.top_scenarios(k=10)
    likes = [s.likelihood for s in top]
    assert likes == sorted(likes, reverse=True)


def test_engine_top_scenarios_invalid_k() -> None:
    eng = FutureThreatScenarioEngine(
        current=_current(_asset("a")),
    )
    try:
        eng.top_scenarios(k=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_scenarios_of_class() -> None:
    eng = FutureThreatScenarioEngine(
        current=_current(_asset("a", deps=("agent-platform",))),
    )
    eng.register_technology(_tech(
        "agent-platform", TechCategory.AUTONOMOUS_AGENTS,
        caps=("autonomy", "tool_use"),
    ))
    eng.register_adversary(_adv())
    eng.recompute(at=_t0())
    s = eng.scenarios_of_class(
        ScenarioClass.AGENT_DRIVEN_EXFILTRATION,
    )
    assert len(s) >= 1


def test_engine_scenarios_by_class() -> None:
    eng = FutureThreatScenarioEngine(
        current=_current(_asset("a", deps=("agent-platform",))),
    )
    eng.register_technology(_tech(
        "agent-platform", TechCategory.AUTONOMOUS_AGENTS,
        caps=("autonomy", "tool_use"),
    ))
    eng.register_adversary(_adv())
    eng.recompute(at=_t0())
    counts = eng.scenarios_by_class()
    assert counts[ScenarioClass.AGENT_DRIVEN_EXFILTRATION] >= 1


def test_engine_record_lookup() -> None:
    eng = FutureThreatScenarioEngine(
        current=_current(_asset("a", deps=("agent-platform",))),
    )
    eng.register_technology(_tech(
        "agent-platform", TechCategory.AUTONOMOUS_AGENTS,
        caps=("autonomy", "tool_use"),
    ))
    eng.register_adversary(_adv())
    scenarios = eng.recompute(at=_t0())
    rec = eng.record(scenarios[0].scenario_id)
    assert rec is not None
    assert rec.scenario_class is scenarios[0].scenario_class


# ---- config ----

def test_engine_config_validation() -> None:
    try:
        ScenarioConfig(min_severity_to_report=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_set_config() -> None:
    eng = FutureThreatScenarioEngine(
        current=_current(_asset("a")),
    )
    cfg = ScenarioConfig(min_likelihood_to_report=0.9)
    eng.set_config(cfg)
    assert eng.config() is cfg


def test_engine_min_likelihood_filters() -> None:
    eng = FutureThreatScenarioEngine(
        current=_current(_asset("a", deps=("t",))),
        config=ScenarioConfig(min_likelihood_to_report=0.95),
    )
    eng.register_technology(_tech(
        "t", TechCategory.AUTONOMOUS_AGENTS,
        caps=("autonomy", "tool_use"),
        adoption=AdoptionStage.RESEARCH,
    ))
    eng.register_adversary(_adv())
    eng.recompute(at=_t0())
    # RESEARCH adoption → low likelihood → all filtered
    assert eng.scenarios() == ()


# ---- invariants ----

def test_invariant_clean_snapshot() -> None:
    eng = FutureThreatScenarioEngine(
        current=_current(_asset("a", deps=("agent-platform",))),
    )
    eng.register_technology(_tech(
        "agent-platform", TechCategory.AUTONOMOUS_AGENTS,
        caps=("autonomy", "tool_use"),
        controls=(
            ControlKind.AUTHORIZATION,
            ControlKind.MONITORING,
            ControlKind.RATE_LIMIT,
            ControlKind.AUDIT,
        ),
    ))
    eng.register_adversary(_adv())
    eng.recompute(at=_t0())
    assert eng.violations() == ()


def test_invariant_scenario_not_claim() -> None:
    bad = object.__new__(FutureThreatScenario)
    object.__setattr__(bad, "scenario_id", "s")
    object.__setattr__(bad, "scenario_class",
                       ScenarioClass.CROSS_TECH_CASCADE)
    object.__setattr__(bad, "title", "x")
    object.__setattr__(bad, "narrative", "y")
    object.__setattr__(bad, "horizon_months", 12)
    object.__setattr__(bad, "likelihood", 0.5)
    object.__setattr__(bad, "severity", 4)
    object.__setattr__(bad, "adversary_capability_required",
                       AdversaryCapability.INSIDER)
    object.__setattr__(bad, "affected_asset_ids", ())
    object.__setattr__(bad, "affected_technology_ids", ("t",))
    object.__setattr__(bad, "precursor_indicators", ())
    object.__setattr__(bad, "control_weaknesses", ())
    object.__setattr__(bad, "defensive_strategies", ())
    object.__setattr__(bad, "preparedness_requirements", ())
    object.__setattr__(bad, "rationale", "x")
    object.__setattr__(bad, "forecast_not_claim", False)
    object.__setattr__(bad, "at", _t0())
    snap = ScenarioSnapshot(
        current=_current(_asset("a")),
        technologies={}, dependencies=(), adversaries=(),
        scenarios=(bad,), findings=(),
    )
    v = check_invariants(snap)
    assert any(x.invariant_id == "scenario.not_a_claim" for x in v)


# ---- store ----

def test_in_memory_store_rejects_stale() -> None:
    s = InMemoryScenarioStore()
    t = _t0()
    s.put(ScenarioRecord(
        "s", ScenarioClass.CROSS_TECH_CASCADE, 0.5, 4, 24, 1, 1, 2, t,
    ))
    earlier = t.replace(year=t.year - 1)
    try:
        s.put(ScenarioRecord(
            "s", ScenarioClass.CROSS_TECH_CASCADE, 0.5, 4, 24, 1, 1, 2,
            earlier,
        ))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "scenario.db")
    store = SqliteScenarioStore(db)
    store.put(ScenarioRecord(
        "s1", ScenarioClass.AGENT_DRIVEN_EXFILTRATION,
        0.7, 5, 24, 2, 3, 2, _t0(),
    ))
    got = store.get("s1")
    assert got is not None
    assert got.scenario_class is ScenarioClass.AGENT_DRIVEN_EXFILTRATION
    assert got.asset_count == 2


def test_sqlite_store_finding_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "scenario.db")
    store = SqliteScenarioStore(db)
    f = ScenarioFinding(
        kind=FindingKind.SCENARIO_PRODUCED,
        subject_id="s1", detail="x", severity=4,
        horizon_months=24, forecast_not_claim=True, at=_t0(),
    )
    store.put_finding("fid-1", f)
    row = store._conn.execute(
        "SELECT payload_json FROM scenario_findings "
        "WHERE finding_id = 'fid-1'"
    ).fetchone()
    assert row is not None
    payload = json.loads(row[0])
    assert payload["kind"] == "scenario_produced"


# =============================================================================
# SECTION 10 — MANUAL RUNNER
# =============================================================================


def _run_all_tests() -> Tuple[int, int]:
    import traceback
    g = globals()
    tests = sorted(
        (name, fn) for name, fn in g.items()
        if name.startswith("test_") and callable(fn)
    )
    passed = 0
    failed = 0
    for name, fn in tests:
        try:
            fn()
        except Exception:
            failed += 1
            print(f"[FAIL] {name}")
            traceback.print_exc()
        else:
            passed += 1
            print(f"[ OK ] {name}")
    return passed, failed


if __name__ == "__main__":
    passed, failed = _run_all_tests()
    print(f"\n{passed} passed, {failed} failed")
    if failed:
        raise SystemExit(1)
