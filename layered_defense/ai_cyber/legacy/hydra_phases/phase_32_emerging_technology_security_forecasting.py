"""
HYDRA POST-CORE — PHASE 32: EMERGING TECHNOLOGY SECURITY FORECASTING
======================================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * Domain — 9 emerging-technology categories, adoption stages,
    maturity levels, 9 threat categories, 10 control kinds
  * Technology inventory with capability flags, dependencies,
    current control coverage, and horizon metadata
  * Forecast rules:
      - attack-surface templates per technology category
      - threat templates (per technology × threat category)
      - control requirement templates
      - dependency readiness checks
  * Forecasts:
      - emerging attack surfaces
      - likely threats (adoption/maturity-modulated)
      - security dependencies (readiness-gated)
      - required controls (priority-ordered)
      - preparedness gaps (required vs deployed)
  * Findings — emerging surface, likely threat, dependency gap,
    required control, preparedness gap, overdue control, adoption risk
  * Every forecast item carries: horizon_months, confidence class,
    forecast_not_claim=True
  * Machine-checkable forecasting invariants
  * In-memory + SQLite stores
  * Phase-32 engine facade
  * Full test suite + manual runner

Doctrine: this is a *forecasting* layer, not a claim layer. Every
output explicitly asserts `forecast_not_claim=True`. Nothing here
states that a threat will happen — only that it is *likely* under
stated assumptions (adoption stage + maturity + capability flags).

No third-party dependencies.

Run tests:
    python hydra_phase32_emerging_tech_forecasting.py
    pytest hydra_phase32_emerging_tech_forecasting.py -q
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


class MaturityLevel(str, Enum):
    NASCENT = "nascent"
    DEVELOPING = "developing"
    MATURE = "mature"
    LEGACY = "legacy"


class TrendDirection(str, Enum):
    ACCELERATING = "accelerating"
    STEADY = "steady"
    SLOWING = "slowing"
    UNCERTAIN = "uncertain"


class ThreatCategory(str, Enum):
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SUPPLY_CHAIN = "supply_chain"
    MODEL_MANIPULATION = "model_manipulation"
    PHYSICAL_SAFETY = "physical_safety"
    SOVEREIGNTY = "sovereignty"
    DENIAL_OF_SERVICE = "denial_of_service"
    IDENTITY_ABUSE = "identity_abuse"
    PROTOCOL_DOWNGRADE = "protocol_downgrade"


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


class ControlStatus(str, Enum):
    ABSENT = "absent"
    PLANNED = "planned"
    PARTIAL = "partial"
    DEPLOYED = "deployed"


_CONTROL_STATUS_RANK: Mapping[ControlStatus, int] = {
    ControlStatus.ABSENT: 0,
    ControlStatus.PLANNED: 1,
    ControlStatus.PARTIAL: 2,
    ControlStatus.DEPLOYED: 3,
}


def control_status_rank(s: ControlStatus) -> int:
    return _CONTROL_STATUS_RANK[s]


class ConfidenceClass(str, Enum):
    SPECULATIVE = "speculative"
    INFERRED = "inferred"
    EVIDENCED = "evidenced"


class ForecastFindingKind(str, Enum):
    EMERGING_ATTACK_SURFACE = "emerging_attack_surface"
    LIKELY_THREAT = "likely_threat"
    SECURITY_DEPENDENCY_GAP = "security_dependency_gap"
    REQUIRED_CONTROL = "required_control"
    PREPAREDNESS_GAP = "preparedness_gap"
    OVERDUE_CRITICAL_CONTROL = "overdue_critical_control"
    ADOPTION_RISK = "adoption_risk"


@dataclass(frozen=True)
class ForecastFinding:
    kind: ForecastFindingKind
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
                "forecast_not_claim must be True (findings are forecasts)"
            )


# =============================================================================
# SECTION 3 — TECHNOLOGY MODEL
# =============================================================================


@dataclass(frozen=True)
class TechnologyProfile:
    tech_id: str
    category: TechCategory
    name: str
    adoption: AdoptionStage
    maturity: MaturityLevel
    trend: TrendDirection
    horizon_months: int
    capabilities: FrozenSet[str] = frozenset()
    depends_on: FrozenSet[TechCategory] = frozenset()
    deployed_controls: FrozenSet[ControlKind] = frozenset()
    control_status: Mapping[ControlKind, ControlStatus] = field(
        default_factory=dict,
    )
    tags: FrozenSet[str] = frozenset()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.tech_id:
            raise ValueError("tech_id is required")
        if not self.name:
            raise ValueError("name is required")
        if self.horizon_months < 1:
            raise ValueError("horizon_months must be >= 1")
        for kind, status in self.control_status.items():
            if kind not in self.deployed_controls \
               and status in (
                   ControlStatus.PARTIAL, ControlStatus.DEPLOYED,
               ):
                raise ValueError(
                    f"control_status[{kind.value}]={status.value} but "
                    f"deployed_controls does not include it"
                )

    def control_rank(self, kind: ControlKind) -> int:
        status = self.control_status.get(
            kind,
            ControlStatus.DEPLOYED if kind in self.deployed_controls
            else ControlStatus.ABSENT,
        )
        return control_status_rank(status)


@dataclass(frozen=True)
class TechDependency:
    dependent_tech_id: str
    dependency_tech_id: str
    kind: str
    critical: bool = True
    at: Optional[datetime] = None

    def __post_init__(self) -> None:
        if not self.dependent_tech_id or not self.dependency_tech_id:
            raise ValueError("dependent/dependency tech_id required")
        if self.dependent_tech_id == self.dependency_tech_id:
            raise ValueError("self-dependency not allowed")
        if not self.kind:
            raise ValueError("kind is required")
        if self.at is not None and self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


# =============================================================================
# SECTION 4 — FORECAST RULES
# =============================================================================


# ---- Attack-surface templates ---------------------------------------------
#
# Each entry is (surface_id, required_capabilities, severity, description).
# A surface fires when the technology has *all* required capabilities.

_SURFACE_TEMPLATES: Mapping[
    TechCategory, Tuple[Tuple[str, FrozenSet[str], int, str], ...]
] = {
    TechCategory.AUTONOMOUS_AGENTS: (
        ("agent_to_agent_trust_mesh",
         frozenset({"multi_agent"}), 4,
         "cross-agent trust mesh"),
        ("tool_chaining_surface",
         frozenset({"tool_use"}), 4,
         "tool composition / chaining"),
        ("autonomous_decision_surface",
         frozenset({"autonomy"}), 5,
         "unsupervised decision surface"),
        ("prompt_injection_surface",
         frozenset({"external_input"}), 4,
         "external input prompt-injection surface"),
    ),
    TechCategory.AI_INFRASTRUCTURE: (
        ("model_serving_endpoint_surface",
         frozenset({"model_serving"}), 4,
         "model serving endpoint"),
        ("accelerator_driver_surface",
         frozenset({"gpu"}), 4,
         "accelerator driver / firmware"),
        ("training_pipeline_surface",
         frozenset({"training"}), 4,
         "training pipeline"),
        ("model_registry_surface",
         frozenset({"model_registry"}), 3,
         "model registry / artifact store"),
    ),
    TechCategory.ROBOTICS: (
        ("physical_actuator_surface",
         frozenset({"actuator"}), 5,
         "physical actuation"),
        ("safety_controller_surface",
         frozenset({"safety_controller"}), 5,
         "safety controller path"),
        ("fleet_coordination_surface",
         frozenset({"fleet"}), 4,
         "fleet coordination"),
    ),
    TechCategory.EDGE_COMPUTING: (
        ("remote_attestation_surface",
         frozenset({"remote_attestation"}), 4,
         "remote attestation path"),
        ("edge_data_residency_surface",
         frozenset({"data_residency"}), 3,
         "edge data residency"),
        ("edge_update_surface",
         frozenset({"ota_update"}), 4,
         "edge OTA update path"),
    ),
    TechCategory.NEW_CLOUD_ARCHITECTURE: (
        ("multi_tenant_control_plane_surface",
         frozenset({"control_plane"}), 5,
         "control-plane multi-tenancy"),
        ("serverless_tenant_isolation_surface",
         frozenset({"serverless"}), 4,
         "serverless tenant isolation"),
        ("service_mesh_identity_surface",
         frozenset({"service_mesh"}), 4,
         "service mesh identity fabric"),
    ),
    TechCategory.NEW_IDENTITY_SYSTEM: (
        ("decentralized_identifier_surface",
         frozenset({"did"}), 4,
         "decentralized identifier registry"),
        ("verifiable_credential_surface",
         frozenset({"vc"}), 4,
         "verifiable credential issuance"),
        ("recovery_path_surface",
         frozenset({"recovery"}), 5,
         "identity recovery path"),
    ),
    TechCategory.NEW_PROTOCOL: (
        ("protocol_downgrade_surface",
         frozenset({"downgrade_negotiation"}), 4,
         "protocol downgrade negotiation"),
        ("unauth_transport_surface",
         frozenset({"transport"}), 3,
         "transport-layer authentication"),
    ),
    TechCategory.NEW_HARDWARE: (
        ("firmware_attestation_surface",
         frozenset({"secure_boot"}), 4,
         "firmware attestation chain"),
        ("side_channel_surface",
         frozenset({"shared_cache"}), 4,
         "shared-cache side channel"),
    ),
    TechCategory.NEW_SOFTWARE_ARCHITECTURE: (
        ("plugin_boundary_surface",
         frozenset({"plugins"}), 4,
         "plugin trust boundary"),
        ("schema_evolution_surface",
         frozenset({"schema_evolution"}), 3,
         "schema evolution surface"),
    ),
}


# ---- Threat templates ------------------------------------------------------
#
# (threat_category, base_likelihood 0..1, severity 1..5, description,
#  required_controls set)

_THREAT_TEMPLATES: Mapping[
    TechCategory,
    Tuple[Tuple[ThreatCategory, float, int, str, FrozenSet[ControlKind]], ...],
] = {
    TechCategory.AUTONOMOUS_AGENTS: (
        (ThreatCategory.PRIVILEGE_ESCALATION, 0.7, 5,
         "excessive agent agency",
         frozenset({ControlKind.AUTHORIZATION, ControlKind.AUDIT,
                    ControlKind.HUMAN_REVIEW})),
        (ThreatCategory.DATA_EXFILTRATION, 0.7, 5,
         "agent-mediated data egress",
         frozenset({ControlKind.MONITORING, ControlKind.RATE_LIMIT,
                    ControlKind.AUTHORIZATION})),
        (ThreatCategory.IDENTITY_ABUSE, 0.6, 4,
         "agent identity spoofing",
         frozenset({ControlKind.AUTHENTICATION, ControlKind.ATTESTATION})),
    ),
    TechCategory.AI_INFRASTRUCTURE: (
        (ThreatCategory.SUPPLY_CHAIN, 0.7, 5,
         "model/dataset artifact substitution",
         frozenset({ControlKind.INVENTORY, ControlKind.ATTESTATION,
                    ControlKind.AUDIT})),
        (ThreatCategory.MODEL_MANIPULATION, 0.7, 5,
         "model weights tampering",
         frozenset({ControlKind.ATTESTATION, ControlKind.CRYPTOGRAPHY,
                    ControlKind.AUDIT})),
        (ThreatCategory.DENIAL_OF_SERVICE, 0.6, 4,
         "accelerator / serving DoS",
         frozenset({ControlKind.RATE_LIMIT, ControlKind.ISOLATION,
                    ControlKind.MONITORING})),
    ),
    TechCategory.ROBOTICS: (
        (ThreatCategory.PHYSICAL_SAFETY, 0.6, 5,
         "physical actuation compromise",
         frozenset({ControlKind.AUTHORIZATION, ControlKind.ISOLATION,
                    ControlKind.HUMAN_REVIEW})),
        (ThreatCategory.PRIVILEGE_ESCALATION, 0.5, 4,
         "fleet controller takeover",
         frozenset({ControlKind.AUTHORIZATION, ControlKind.ATTESTATION})),
    ),
    TechCategory.EDGE_COMPUTING: (
        (ThreatCategory.SOVEREIGNTY, 0.6, 4,
         "cross-border edge data flow",
         frozenset({ControlKind.INVENTORY, ControlKind.AUDIT,
                    ControlKind.CRYPTOGRAPHY})),
        (ThreatCategory.SUPPLY_CHAIN, 0.6, 4,
         "edge OTA supply chain",
         frozenset({ControlKind.ATTESTATION, ControlKind.AUDIT,
                    ControlKind.INVENTORY})),
        (ThreatCategory.DENIAL_OF_SERVICE, 0.5, 3,
         "edge node flood",
         frozenset({ControlKind.RATE_LIMIT, ControlKind.MONITORING})),
    ),
    TechCategory.NEW_CLOUD_ARCHITECTURE: (
        (ThreatCategory.PRIVILEGE_ESCALATION, 0.7, 5,
         "cross-tenant control-plane abuse",
         frozenset({ControlKind.AUTHORIZATION, ControlKind.ISOLATION,
                    ControlKind.AUDIT})),
        (ThreatCategory.SOVEREIGNTY, 0.6, 4,
         "unexpected region residency",
         frozenset({ControlKind.INVENTORY, ControlKind.AUDIT})),
        (ThreatCategory.DENIAL_OF_SERVICE, 0.6, 4,
         "noisy-neighbor DoS",
         frozenset({ControlKind.ISOLATION, ControlKind.RATE_LIMIT})),
    ),
    TechCategory.NEW_IDENTITY_SYSTEM: (
        (ThreatCategory.IDENTITY_ABUSE, 0.8, 5,
         "identity takeover / recovery abuse",
         frozenset({ControlKind.AUTHENTICATION, ControlKind.AUTHORIZATION,
                    ControlKind.AUDIT, ControlKind.CRYPTOGRAPHY})),
        (ThreatCategory.PRIVILEGE_ESCALATION, 0.6, 5,
         "credential replay / delegation abuse",
         frozenset({ControlKind.AUTHORIZATION, ControlKind.CRYPTOGRAPHY,
                    ControlKind.MONITORING})),
    ),
    TechCategory.NEW_PROTOCOL: (
        (ThreatCategory.PROTOCOL_DOWNGRADE, 0.7, 4,
         "negotiated downgrade to weaker variant",
         frozenset({ControlKind.AUTHENTICATION, ControlKind.CRYPTOGRAPHY,
                    ControlKind.MONITORING})),
        (ThreatCategory.DENIAL_OF_SERVICE, 0.5, 3,
         "protocol flood",
         frozenset({ControlKind.RATE_LIMIT, ControlKind.ISOLATION})),
    ),
    TechCategory.NEW_HARDWARE: (
        (ThreatCategory.SUPPLY_CHAIN, 0.7, 5,
         "silicon / firmware supply chain",
         frozenset({ControlKind.INVENTORY, ControlKind.ATTESTATION,
                    ControlKind.CRYPTOGRAPHY})),
        (ThreatCategory.DATA_EXFILTRATION, 0.5, 4,
         "side-channel data leakage",
         frozenset({ControlKind.ISOLATION, ControlKind.MONITORING})),
    ),
    TechCategory.NEW_SOFTWARE_ARCHITECTURE: (
        (ThreatCategory.SUPPLY_CHAIN, 0.7, 4,
         "plugin / dependency supply chain",
         frozenset({ControlKind.INVENTORY, ControlKind.ATTESTATION})),
        (ThreatCategory.PRIVILEGE_ESCALATION, 0.6, 4,
         "plugin boundary violation",
         frozenset({ControlKind.ISOLATION, ControlKind.AUTHORIZATION})),
    ),
}


# ---- Adoption / maturity modulation ---------------------------------------

_ADOPTION_MODIFIER: Mapping[AdoptionStage, float] = {
    AdoptionStage.RESEARCH: 0.4,
    AdoptionStage.PILOT: 0.7,
    AdoptionStage.EARLY_ADOPTION: 1.0,
    AdoptionStage.MAINSTREAM: 0.8,
    AdoptionStage.DECLINING: 0.5,
}

_MATURITY_MODIFIER: Mapping[MaturityLevel, float] = {
    MaturityLevel.NASCENT: 1.0,
    MaturityLevel.DEVELOPING: 0.9,
    MaturityLevel.MATURE: 0.7,
    MaturityLevel.LEGACY: 0.8,
}

_TREND_MODIFIER: Mapping[TrendDirection, float] = {
    TrendDirection.ACCELERATING: 1.15,
    TrendDirection.STEADY: 1.0,
    TrendDirection.SLOWING: 0.9,
    TrendDirection.UNCERTAIN: 1.05,
}


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))


def adjusted_likelihood(
    base: float,
    *,
    adoption: AdoptionStage,
    maturity: MaturityLevel,
    trend: TrendDirection,
) -> float:
    if not 0.0 <= base <= 1.0:
        raise ValueError("base must be within [0,1]")
    mod = (
        _ADOPTION_MODIFIER[adoption]
        * _MATURITY_MODIFIER[maturity]
        * _TREND_MODIFIER[trend]
    )
    return _clamp01(base * mod)


# =============================================================================
# SECTION 5 — FORECAST OUTPUT
# =============================================================================


@dataclass(frozen=True)
class AttackSurfaceForecast:
    tech_id: str
    category: TechCategory
    surface_id: str
    description: str
    severity: int
    confidence: ConfidenceClass
    horizon_months: int
    forecast_not_claim: bool
    at: datetime

    def __post_init__(self) -> None:
        if not self.tech_id or not self.surface_id:
            raise ValueError("tech_id and surface_id required")
        if not 1 <= self.severity <= 5:
            raise ValueError("severity must be in [1,5]")
        if self.horizon_months < 1:
            raise ValueError("horizon_months must be >= 1")
        if self.forecast_not_claim is not True:
            raise ValueError("forecast_not_claim must be True")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


@dataclass(frozen=True)
class ThreatForecast:
    tech_id: str
    category: TechCategory
    threat_category: ThreatCategory
    likelihood: float
    severity: int
    required_controls: FrozenSet[ControlKind]
    description: str
    confidence: ConfidenceClass
    horizon_months: int
    forecast_not_claim: bool
    at: datetime

    def __post_init__(self) -> None:
        if not 0.0 <= self.likelihood <= 1.0:
            raise ValueError("likelihood must be within [0,1]")
        if not 1 <= self.severity <= 5:
            raise ValueError("severity must be in [1,5]")
        if self.horizon_months < 1:
            raise ValueError("horizon_months must be >= 1")
        if self.forecast_not_claim is not True:
            raise ValueError("forecast_not_claim must be True")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


@dataclass(frozen=True)
class DependencyForecast:
    tech_id: str
    depends_on_tech_id: str
    dependency_category: Optional[TechCategory]
    dependency_adoption: Optional[AdoptionStage]
    dependency_maturity: Optional[MaturityLevel]
    ready: bool
    gap_reason: Optional[str]
    critical: bool
    horizon_months: int
    confidence: ConfidenceClass
    forecast_not_claim: bool
    at: datetime

    def __post_init__(self) -> None:
        if not self.tech_id or not self.depends_on_tech_id:
            raise ValueError("tech_id and depends_on_tech_id required")
        if self.horizon_months < 1:
            raise ValueError("horizon_months must be >= 1")
        if self.forecast_not_claim is not True:
            raise ValueError("forecast_not_claim must be True")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


@dataclass(frozen=True)
class ControlRequirement:
    tech_id: str
    control: ControlKind
    priority: int                # 1 = highest
    reason: str
    current_status: ControlStatus
    covered: bool
    horizon_months: int
    forecast_not_claim: bool
    at: datetime

    def __post_init__(self) -> None:
        if not 1 <= self.priority <= 10:
            raise ValueError("priority must be in [1,10]")
        if self.horizon_months < 1:
            raise ValueError("horizon_months must be >= 1")
        if self.forecast_not_claim is not True:
            raise ValueError("forecast_not_claim must be True")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


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
class ForecastSnapshot:
    technologies: Mapping[str, TechnologyProfile]
    dependencies: Tuple[TechDependency, ...]
    surfaces: Tuple[AttackSurfaceForecast, ...]
    threats: Tuple[ThreatForecast, ...]
    dependency_forecasts: Tuple[DependencyForecast, ...]
    controls: Tuple[ControlRequirement, ...]
    findings: Tuple[ForecastFinding, ...]


@dataclass(frozen=True)
class ForecastInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[ForecastSnapshot],
                        Tuple[InvariantViolation, ...]]
    description: str


def _inv_forecasts_are_not_claims(
    snap: ForecastSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for s in snap.surfaces:
        if s.forecast_not_claim is not True:
            out.append(InvariantViolation(
                invariant_id="fc.forecasts_not_claims",
                severity=InvariantSeverity.CRITICAL,
                subject_id=s.surface_id,
                detail="surface forecast claims to be a fact",
            ))
    for t in snap.threats:
        if t.forecast_not_claim is not True:
            out.append(InvariantViolation(
                invariant_id="fc.forecasts_not_claims",
                severity=InvariantSeverity.CRITICAL,
                subject_id=f"{t.tech_id}:{t.threat_category.value}",
                detail="threat forecast claims to be a fact",
            ))
    for d in snap.dependency_forecasts:
        if d.forecast_not_claim is not True:
            out.append(InvariantViolation(
                invariant_id="fc.forecasts_not_claims",
                severity=InvariantSeverity.CRITICAL,
                subject_id=d.depends_on_tech_id,
                detail="dependency forecast claims to be a fact",
            ))
    return tuple(out)


def _inv_likelihood_bounded(
    snap: ForecastSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for t in snap.threats:
        if not 0.0 <= t.likelihood <= 1.0:
            out.append(InvariantViolation(
                invariant_id="fc.likelihood_bounded",
                severity=InvariantSeverity.HIGH,
                subject_id=t.tech_id,
                detail=f"likelihood {t.likelihood}",
            ))
    return tuple(out)


def _inv_findings_not_claims(
    snap: ForecastSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for f in snap.findings:
        if f.forecast_not_claim is not True:
            out.append(InvariantViolation(
                invariant_id="fc.findings_not_claims",
                severity=InvariantSeverity.CRITICAL,
                subject_id=f.subject_id,
                detail="finding claims to be a fact",
            ))
    return tuple(out)


def _inv_dependencies_registered(
    snap: ForecastSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for d in snap.dependencies:
        if d.dependent_tech_id not in snap.technologies:
            out.append(InvariantViolation(
                invariant_id="fc.dependencies_registered",
                severity=InvariantSeverity.HIGH,
                subject_id=d.dependent_tech_id,
                detail="dependent technology not registered",
            ))
    return tuple(out)


def _inv_controls_have_horizon(
    snap: ForecastSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for c in snap.controls:
        if c.horizon_months < 1:
            out.append(InvariantViolation(
                invariant_id="fc.controls_have_horizon",
                severity=InvariantSeverity.HIGH,
                subject_id=c.tech_id,
                detail=f"horizon {c.horizon_months}",
            ))
    return tuple(out)


DEFAULT_INVARIANTS: Tuple[ForecastInvariant, ...] = (
    ForecastInvariant(
        invariant_id="fc.forecasts_not_claims",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_forecasts_are_not_claims,
        description="Every forecast must declare forecast_not_claim.",
    ),
    ForecastInvariant(
        invariant_id="fc.likelihood_bounded",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_likelihood_bounded,
        description="Threat likelihood must lie within [0,1].",
    ),
    ForecastInvariant(
        invariant_id="fc.findings_not_claims",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_findings_not_claims,
        description="Findings must not claim to be facts.",
    ),
    ForecastInvariant(
        invariant_id="fc.dependencies_registered",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_dependencies_registered,
        description="Dependency edges must reference registered techs.",
    ),
    ForecastInvariant(
        invariant_id="fc.controls_have_horizon",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_controls_have_horizon,
        description="Control requirements must carry a horizon.",
    ),
)


def check_invariants(
    snap: ForecastSnapshot,
    invariants: Iterable[ForecastInvariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 7 — STORE
# =============================================================================


@dataclass(frozen=True)
class TechRecord:
    tech_id: str
    category: TechCategory
    adoption: AdoptionStage
    maturity: MaturityLevel
    horizon_months: int
    surface_count: int
    threat_count: int
    gap_count: int
    updated_at: datetime


class ForecastStore(Protocol):
    def put(self, record: TechRecord) -> None: ...
    def get(self, tech_id: str) -> Optional[TechRecord]: ...
    def all(self) -> Tuple[TechRecord, ...]: ...


class InMemoryForecastStore:
    def __init__(self) -> None:
        self._data: Dict[str, TechRecord] = {}

    def put(self, record: TechRecord) -> None:
        existing = self._data.get(record.tech_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._data[record.tech_id] = record

    def get(self, tech_id: str) -> Optional[TechRecord]:
        return self._data.get(tech_id)

    def all(self) -> Tuple[TechRecord, ...]:
        return tuple(self._data.values())


class SqliteForecastStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS fc_techs (
                tech_id TEXT PRIMARY KEY,
                category TEXT NOT NULL,
                adoption TEXT NOT NULL,
                maturity TEXT NOT NULL,
                horizon_months INTEGER NOT NULL,
                surface_count INTEGER NOT NULL,
                threat_count INTEGER NOT NULL,
                gap_count INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS fc_findings (
                finding_id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def put(self, record: TechRecord) -> None:
        existing = self.get(record.tech_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._conn.execute(
            """
            INSERT INTO fc_techs
              (tech_id, category, adoption, maturity, horizon_months,
               surface_count, threat_count, gap_count, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tech_id) DO UPDATE SET
              category=excluded.category,
              adoption=excluded.adoption,
              maturity=excluded.maturity,
              horizon_months=excluded.horizon_months,
              surface_count=excluded.surface_count,
              threat_count=excluded.threat_count,
              gap_count=excluded.gap_count,
              updated_at=excluded.updated_at
            """,
            (
                record.tech_id, record.category.value,
                record.adoption.value, record.maturity.value,
                record.horizon_months, record.surface_count,
                record.threat_count, record.gap_count,
                record.updated_at.isoformat(),
            ),
        )
        self._conn.commit()

    def get(self, tech_id: str) -> Optional[TechRecord]:
        row = self._conn.execute(
            "SELECT category, adoption, maturity, horizon_months, "
            "surface_count, threat_count, gap_count, updated_at "
            "FROM fc_techs WHERE tech_id = ?",
            (tech_id,),
        ).fetchone()
        if row is None:
            return None
        return TechRecord(
            tech_id=tech_id, category=TechCategory(row[0]),
            adoption=AdoptionStage(row[1]),
            maturity=MaturityLevel(row[2]),
            horizon_months=int(row[3]),
            surface_count=int(row[4]), threat_count=int(row[5]),
            gap_count=int(row[6]),
            updated_at=datetime.fromisoformat(row[7]),
        )

    def all(self) -> Tuple[TechRecord, ...]:
        rows = self._conn.execute("SELECT tech_id FROM fc_techs").fetchall()
        return tuple(
            r for r in (self.get(x[0]) for x in rows) if r is not None
        )

    def put_finding(self, finding_id: str, f: ForecastFinding) -> None:
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
            "INSERT OR REPLACE INTO fc_findings "
            "(finding_id, payload_json) VALUES (?, ?)",
            (finding_id, json.dumps(payload, sort_keys=True)),
        )
        self._conn.commit()


# =============================================================================
# SECTION 8 — ENGINE
# =============================================================================


@dataclass(frozen=True)
class ForecastConfig:
    min_likelihood_to_report: float = 0.2
    min_severity_to_report: int = 3
    critical_control_priority: int = 2
    max_findings: int = 5000

    def __post_init__(self) -> None:
        if not 0.0 <= self.min_likelihood_to_report <= 1.0:
            raise ValueError(
                "min_likelihood_to_report must be within [0,1]"
            )
        if not 1 <= self.min_severity_to_report <= 5:
            raise ValueError("min_severity_to_report must be in [1,5]")
        if not 1 <= self.critical_control_priority <= 10:
            raise ValueError("critical_control_priority must be in [1,10]")
        if self.max_findings < 1:
            raise ValueError("max_findings must be >= 1")


class EmergingTechForecastEngine:
    """Emerging-technology security forecasting engine.

    Consumes a technology inventory + dependency edges and produces:
      * emerging attack-surface forecasts
      * likely-threat forecasts
      * security-dependency forecasts
      * required-control forecasts
      * preparedness-gap findings
    """

    def __init__(
        self,
        *,
        store: Optional[ForecastStore] = None,
        config: Optional[ForecastConfig] = None,
    ) -> None:
        self._store: ForecastStore = store or InMemoryForecastStore()
        self._config = config or ForecastConfig()
        self._techs: Dict[str, TechnologyProfile] = {}
        self._deps: List[TechDependency] = []
        self._surfaces: Tuple[AttackSurfaceForecast, ...] = ()
        self._threats: Tuple[ThreatForecast, ...] = ()
        self._dep_forecasts: Tuple[DependencyForecast, ...] = ()
        self._controls: Tuple[ControlRequirement, ...] = ()
        self._findings: List[ForecastFinding] = []
        self._violations: Tuple[InvariantViolation, ...] = ()

    # ---- registration ----------------------------------------------------

    def register_technology(self, tech: TechnologyProfile) -> None:
        if tech.tech_id in self._techs:
            raise ValueError(
                f"technology {tech.tech_id} already registered"
            )
        self._techs[tech.tech_id] = tech

    def register_dependency(self, dep: TechDependency) -> None:
        if dep.dependent_tech_id not in self._techs:
            raise KeyError(
                f"dependent tech {dep.dependent_tech_id} not registered"
            )
        if dep.dependency_tech_id not in self._techs:
            raise KeyError(
                f"dependency tech {dep.dependency_tech_id} not registered"
            )
        self._deps.append(dep)

    def technology(self, tech_id: str) -> Optional[TechnologyProfile]:
        return self._techs.get(tech_id)

    def technologies(self) -> Tuple[TechnologyProfile, ...]:
        return tuple(self._techs.values())

    def config(self) -> ForecastConfig:
        return self._config

    def set_config(self, config: ForecastConfig) -> None:
        self._config = config

    # ---- forecasting -----------------------------------------------------

    def recompute(
        self, *, at: datetime, horizon_months: Optional[int] = None,
    ) -> Tuple[TechRecord, ...]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        cfg = self._config
        h_override = horizon_months

        self._findings = []
        surfaces: List[AttackSurfaceForecast] = []
        threats: List[ThreatForecast] = []
        dep_forecasts: List[DependencyForecast] = []
        controls: List[ControlRequirement] = []

        # 1. Surfaces + threats + controls per technology
        for tid in sorted(self._techs):
            tech = self._techs[tid]
            horizon = h_override or tech.horizon_months

            self._forecast_surfaces(
                tech, horizon=horizon, at=at, out=surfaces,
            )
            self._forecast_threats(
                tech, horizon=horizon, at=at, out=threats,
                controls_out=controls,
            )

        # 2. Dependency forecasts
        for d in self._deps:
            dep_forecasts.append(self._forecast_dependency(
                d, horizon=h_override, at=at,
            ))

        # 3. Sort deterministically
        surfaces.sort(
            key=lambda s: (-s.severity, s.tech_id, s.surface_id),
        )
        threats.sort(
            key=lambda t: (-t.likelihood, -t.severity,
                           t.tech_id, t.threat_category.value),
        )
        controls.sort(
            key=lambda c: (c.priority, c.tech_id, c.control.value),
        )
        dep_forecasts.sort(
            key=lambda d: (not d.critical, d.tech_id,
                           d.depends_on_tech_id),
        )

        self._surfaces = tuple(surfaces)
        self._threats = tuple(threats)
        self._dep_forecasts = tuple(dep_forecasts)
        self._controls = tuple(controls)

        # 4. Findings
        self._emit_surface_findings(at=at)
        self._emit_threat_findings(at=at)
        self._emit_dependency_findings(at=at)
        self._emit_control_findings(at=at)

        if len(self._findings) > cfg.max_findings:
            self._findings = self._findings[: cfg.max_findings]

        # 5. Persist tech records
        records: List[TechRecord] = []
        for tid in sorted(self._techs):
            tech = self._techs[tid]
            surface_count = sum(
                1 for s in self._surfaces if s.tech_id == tid
            )
            threat_count = sum(
                1 for t in self._threats if t.tech_id == tid
            )
            gap_count = sum(
                1 for c in self._controls
                if c.tech_id == tid and not c.covered
            )
            rec = TechRecord(
                tech_id=tid, category=tech.category,
                adoption=tech.adoption, maturity=tech.maturity,
                horizon_months=h_override or tech.horizon_months,
                surface_count=surface_count,
                threat_count=threat_count,
                gap_count=gap_count,
                updated_at=at,
            )
            self._store.put(rec)
            records.append(rec)

        if isinstance(self._store, SqliteForecastStore):
            for i, f in enumerate(self._findings):
                self._store.put_finding(
                    f"f-{i:08d}-{f.kind.value}", f,
                )

        self._violations = check_invariants(self.snapshot())
        return tuple(records)

    # ---- forecast primitives ---------------------------------------------

    def _forecast_surfaces(
        self,
        tech: TechnologyProfile,
        *,
        horizon: int,
        at: datetime,
        out: List[AttackSurfaceForecast],
    ) -> None:
        templates = _SURFACE_TEMPLATES.get(tech.category, ())
        for sid, req_caps, sev, desc in templates:
            if not req_caps.issubset(tech.capabilities):
                continue
            # Confidence: an EARLY_ADOPTION / PILOT technology with
            # accelerating trend → INFERRED. Research → SPECULATIVE.
            conf = _confidence_for(
                tech.adoption, tech.maturity,
            )
            out.append(AttackSurfaceForecast(
                tech_id=tech.tech_id, category=tech.category,
                surface_id=sid, description=desc,
                severity=sev, confidence=conf,
                horizon_months=horizon,
                forecast_not_claim=True,
                at=at,
            ))

    def _forecast_threats(
        self,
        tech: TechnologyProfile,
        *,
        horizon: int,
        at: datetime,
        out: List[ThreatForecast],
        controls_out: List[ControlRequirement],
    ) -> None:
        templates = _THREAT_TEMPLATES.get(tech.category, ())
        for (
            threat_cat, base_lik, base_sev, desc, req_controls,
        ) in templates:
            lik = adjusted_likelihood(
                base_lik,
                adoption=tech.adoption,
                maturity=tech.maturity,
                trend=tech.trend,
            )
            if lik < self._config.min_likelihood_to_report:
                continue
            if base_sev < self._config.min_severity_to_report:
                continue
            conf = _confidence_for(tech.adoption, tech.maturity)
            out.append(ThreatForecast(
                tech_id=tech.tech_id, category=tech.category,
                threat_category=threat_cat, likelihood=lik,
                severity=base_sev, required_controls=req_controls,
                description=desc, confidence=conf,
                horizon_months=horizon,
                forecast_not_claim=True,
                at=at,
            ))

            # Emit control requirements — priority derived from
            # threat severity.
            priority = _control_priority(base_sev)
            for c in sorted(req_controls, key=lambda x: x.value):
                current = tech.control_status.get(
                    c, ControlStatus.DEPLOYED
                    if c in tech.deployed_controls
                    else ControlStatus.ABSENT,
                )
                covered = control_status_rank(current) >= \
                    control_status_rank(ControlStatus.PARTIAL)
                controls_out.append(ControlRequirement(
                    tech_id=tech.tech_id, control=c,
                    priority=priority,
                    reason=(
                        f"required by threat {threat_cat.value} "
                        f"({desc})"
                    ),
                    current_status=current, covered=covered,
                    horizon_months=horizon,
                    forecast_not_claim=True, at=at,
                ))

    def _forecast_dependency(
        self,
        dep: TechDependency,
        *,
        horizon: Optional[int],
        at: datetime,
    ) -> DependencyForecast:
        dependency = self._techs.get(dep.dependency_tech_id)
        if dependency is None:
            return DependencyForecast(
                tech_id=dep.dependent_tech_id,
                depends_on_tech_id=dep.dependency_tech_id,
                dependency_category=None,
                dependency_adoption=None,
                dependency_maturity=None,
                ready=False,
                gap_reason="dependency technology not registered",
                critical=dep.critical,
                horizon_months=horizon or 12,
                confidence=ConfidenceClass.SPECULATIVE,
                forecast_not_claim=True, at=at,
            )
        ready = True
        gap_reason: Optional[str] = None
        if dependency.maturity in (
            MaturityLevel.NASCENT, MaturityLevel.DEVELOPING,
        ):
            ready = False
            gap_reason = (
                f"dependency is {dependency.maturity.value}; "
                f"not mature enough for critical reliance"
            )
        elif dependency.adoption is AdoptionStage.RESEARCH:
            ready = False
            gap_reason = "dependency is still in RESEARCH"
        elif dependency.adoption is AdoptionStage.DECLINING:
            ready = False
            gap_reason = "dependency is DECLINING — plan migration"
        return DependencyForecast(
            tech_id=dep.dependent_tech_id,
            depends_on_tech_id=dep.dependency_tech_id,
            dependency_category=dependency.category,
            dependency_adoption=dependency.adoption,
            dependency_maturity=dependency.maturity,
            ready=ready, gap_reason=gap_reason,
            critical=dep.critical,
            horizon_months=horizon or 12,
            confidence=(
                ConfidenceClass.INFERRED if ready
                else ConfidenceClass.EVIDENCED
            ),
            forecast_not_claim=True, at=at,
        )

    # ---- findings --------------------------------------------------------

    def _emit_surface_findings(self, *, at: datetime) -> None:
        for s in self._surfaces:
            if s.severity < self._config.min_severity_to_report:
                continue
            self._findings.append(ForecastFinding(
                kind=ForecastFindingKind.EMERGING_ATTACK_SURFACE,
                subject_id=s.tech_id,
                detail=(
                    f"emerging surface {s.surface_id} "
                    f"({s.description}) at severity {s.severity}"
                ),
                severity=s.severity, horizon_months=s.horizon_months,
                forecast_not_claim=True, at=at,
            ))

    def _emit_threat_findings(self, *, at: datetime) -> None:
        for t in self._threats:
            self._findings.append(ForecastFinding(
                kind=ForecastFindingKind.LIKELY_THREAT,
                subject_id=t.tech_id,
                detail=(
                    f"likely threat {t.threat_category.value} "
                    f"(p≈{t.likelihood:.2f}, severity {t.severity}) — "
                    f"{t.description}"
                ),
                severity=t.severity,
                horizon_months=t.horizon_months,
                forecast_not_claim=True, at=at,
            ))

    def _emit_dependency_findings(self, *, at: datetime) -> None:
        for d in self._dep_forecasts:
            if d.ready:
                continue
            sev = 4 if d.critical else 3
            self._findings.append(ForecastFinding(
                kind=ForecastFindingKind.SECURITY_DEPENDENCY_GAP,
                subject_id=d.tech_id,
                detail=(
                    f"depends on {d.depends_on_tech_id} which is "
                    f"{d.gap_reason or 'not ready'}"
                ),
                severity=sev, horizon_months=d.horizon_months,
                forecast_not_claim=True, at=at,
            ))

    def _emit_control_findings(self, *, at: datetime) -> None:
        # Required controls
        for c in self._controls:
            self._findings.append(ForecastFinding(
                kind=ForecastFindingKind.REQUIRED_CONTROL,
                subject_id=c.tech_id,
                detail=(
                    f"control {c.control.value} required "
                    f"(priority {c.priority}) — {c.reason}"
                ),
                severity=3 if c.covered else 4,
                horizon_months=c.horizon_months,
                forecast_not_claim=True, at=at,
            ))
            if not c.covered:
                # Preparedness gap
                sev = 5 if c.priority <= \
                    self._config.critical_control_priority else 4
                self._findings.append(ForecastFinding(
                    kind=ForecastFindingKind.PREPAREDNESS_GAP,
                    subject_id=c.tech_id,
                    detail=(
                        f"required control {c.control.value} "
                        f"is {c.current_status.value}"
                    ),
                    severity=sev, horizon_months=c.horizon_months,
                    forecast_not_claim=True, at=at,
                ))
                # Overdue critical control: early adoption + critical
                tech = self._techs.get(c.tech_id)
                if tech is not None \
                   and tech.adoption in (
                       AdoptionStage.EARLY_ADOPTION,
                       AdoptionStage.MAINSTREAM,
                   ) \
                   and c.priority <= \
                       self._config.critical_control_priority \
                   and c.current_status in (
                       ControlStatus.ABSENT, ControlStatus.PLANNED,
                   ):
                    self._findings.append(ForecastFinding(
                        kind=ForecastFindingKind.OVERDUE_CRITICAL_CONTROL,
                        subject_id=c.tech_id,
                        detail=(
                            f"technology in {tech.adoption.value} "
                            f"lacks critical control "
                            f"{c.control.value} "
                            f"(status {c.current_status.value})"
                        ),
                        severity=5,
                        horizon_months=c.horizon_months,
                        forecast_not_claim=True, at=at,
                    ))

    # ---- queries ---------------------------------------------------------

    def surfaces(self) -> Tuple[AttackSurfaceForecast, ...]:
        return self._surfaces

    def threat_forecasts(self) -> Tuple[ThreatForecast, ...]:
        return self._threats

    def dependency_forecasts(self) -> Tuple[DependencyForecast, ...]:
        return self._dep_forecasts

    def control_requirements(self) -> Tuple[ControlRequirement, ...]:
        return self._controls

    def gaps(self) -> Tuple[ControlRequirement, ...]:
        return tuple(c for c in self._controls if not c.covered)

    def findings(self) -> Tuple[ForecastFinding, ...]:
        return tuple(self._findings)

    def top_findings(
        self, *, k: int = 10,
    ) -> Tuple[ForecastFinding, ...]:
        if k <= 0:
            raise ValueError("k must be > 0")
        ordered = sorted(
            self._findings,
            key=lambda f: (-f.severity, f.kind.value, f.subject_id),
        )
        return tuple(ordered[:k])

    def findings_by_kind(self) -> Mapping[ForecastFindingKind, int]:
        out: Dict[ForecastFindingKind, int] = {
            k: 0 for k in ForecastFindingKind
        }
        for f in self._findings:
            out[f.kind] += 1
        return out

    def threats_by_category(self) -> Mapping[ThreatCategory, int]:
        out: Dict[ThreatCategory, int] = {k: 0 for k in ThreatCategory}
        for t in self._threats:
            out[t.threat_category] += 1
        return out

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return self._violations

    def record(self, tech_id: str) -> Optional[TechRecord]:
        return self._store.get(tech_id)

    def snapshot(self) -> ForecastSnapshot:
        return ForecastSnapshot(
            technologies=dict(self._techs),
            dependencies=tuple(self._deps),
            surfaces=self._surfaces,
            threats=self._threats,
            dependency_forecasts=self._dep_forecasts,
            controls=self._controls,
            findings=tuple(self._findings),
        )


def _confidence_for(
    adoption: AdoptionStage, maturity: MaturityLevel,
) -> ConfidenceClass:
    if adoption is AdoptionStage.RESEARCH:
        return ConfidenceClass.SPECULATIVE
    if adoption in (
        AdoptionStage.PILOT, AdoptionStage.EARLY_ADOPTION,
    ):
        return ConfidenceClass.INFERRED
    return ConfidenceClass.EVIDENCED


def _control_priority(threat_severity: int) -> int:
    # Map threat severity (1..5) to control priority (1..5).
    if not 1 <= threat_severity <= 5:
        raise ValueError("threat_severity must be in [1,5]")
    return max(1, min(5, 6 - threat_severity)) + \
        0 if False else (6 - threat_severity)


# =============================================================================
# SECTION 9 — TESTS
# =============================================================================


def _t0() -> datetime:
    from datetime import timezone
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _tech(
    tid: str, category: TechCategory, *,
    name: Optional[str] = None,
    adoption: AdoptionStage = AdoptionStage.EARLY_ADOPTION,
    maturity: MaturityLevel = MaturityLevel.DEVELOPING,
    trend: TrendDirection = TrendDirection.STEADY,
    horizon: int = 24,
    caps: Iterable[str] = (),
    depends: Iterable[TechCategory] = (),
    controls: Iterable[ControlKind] = (),
    control_status: Optional[
        Mapping[ControlKind, ControlStatus]
    ] = None,
    tags: Iterable[str] = (),
) -> TechnologyProfile:
    return TechnologyProfile(
        tech_id=tid, category=category, name=name or tid,
        adoption=adoption, maturity=maturity, trend=trend,
        horizon_months=horizon,
        capabilities=frozenset(caps),
        depends_on=frozenset(depends),
        deployed_controls=frozenset(controls),
        control_status=dict(control_status or {}),
        tags=frozenset(tags),
    )


def _dep(
    dep_id: str, to_id: str, *,
    kind: str = "depends_on", critical: bool = True,
) -> TechDependency:
    return TechDependency(
        dependent_tech_id=dep_id, dependency_tech_id=to_id,
        kind=kind, critical=critical, at=_t0(),
    )


# ---- domain ----

def test_tech_requires_id() -> None:
    try:
        TechnologyProfile(
            tech_id="", category=TechCategory.AUTONOMOUS_AGENTS,
            name="x", adoption=AdoptionStage.PILOT,
            maturity=MaturityLevel.NASCENT, trend=TrendDirection.STEADY,
            horizon_months=12,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_tech_requires_horizon() -> None:
    try:
        _tech("a", TechCategory.AUTONOMOUS_AGENTS, horizon=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_tech_control_status_consistency() -> None:
    try:
        _tech(
            "a", TechCategory.AUTONOMOUS_AGENTS,
            controls=(),
            control_status={
                ControlKind.AUTHORIZATION: ControlStatus.DEPLOYED,
            },
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_dependency_self_rejected() -> None:
    try:
        TechDependency(
            dependent_tech_id="a", dependency_tech_id="a",
            kind="x", at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_finding_requires_forecast_flag() -> None:
    try:
        ForecastFinding(
            kind=ForecastFindingKind.LIKELY_THREAT,
            subject_id="a", detail="x", severity=3,
            horizon_months=12, forecast_not_claim=False, at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_control_status_rank_ordering() -> None:
    assert control_status_rank(ControlStatus.ABSENT) < \
        control_status_rank(ControlStatus.PLANNED)
    assert control_status_rank(ControlStatus.PLANNED) < \
        control_status_rank(ControlStatus.PARTIAL)
    assert control_status_rank(ControlStatus.PARTIAL) < \
        control_status_rank(ControlStatus.DEPLOYED)


# ---- likelihood modulation ----

def test_likelihood_research_low() -> None:
    l = adjusted_likelihood(
        1.0, adoption=AdoptionStage.RESEARCH,
        maturity=MaturityLevel.NASCENT,
        trend=TrendDirection.STEADY,
    )
    assert l < 0.5


def test_likelihood_early_adoption_highest() -> None:
    early = adjusted_likelihood(
        1.0, adoption=AdoptionStage.EARLY_ADOPTION,
        maturity=MaturityLevel.NASCENT,
        trend=TrendDirection.ACCELERATING,
    )
    mature = adjusted_likelihood(
        1.0, adoption=AdoptionStage.MAINSTREAM,
        maturity=MaturityLevel.MATURE,
        trend=TrendDirection.STEADY,
    )
    assert early > mature


def test_likelihood_bounds() -> None:
    l = adjusted_likelihood(
        1.0, adoption=AdoptionStage.EARLY_ADOPTION,
        maturity=MaturityLevel.NASCENT,
        trend=TrendDirection.ACCELERATING,
    )
    assert 0.0 <= l <= 1.0


def test_likelihood_rejects_bad_base() -> None:
    try:
        adjusted_likelihood(
            -0.1, adoption=AdoptionStage.PILOT,
            maturity=MaturityLevel.NASCENT,
            trend=TrendDirection.STEADY,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- engine basics ----

def test_engine_registers_technology() -> None:
    eng = EmergingTechForecastEngine()
    eng.register_technology(_tech(
        "t1", TechCategory.AUTONOMOUS_AGENTS,
    ))
    assert eng.technology("t1") is not None


def test_engine_rejects_duplicate_technology() -> None:
    eng = EmergingTechForecastEngine()
    eng.register_technology(_tech("t1", TechCategory.AUTONOMOUS_AGENTS))
    try:
        eng.register_technology(_tech("t1", TechCategory.AUTONOMOUS_AGENTS))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_dependency_registration_requires_registered_techs() -> None:
    eng = EmergingTechForecastEngine()
    eng.register_technology(_tech("a", TechCategory.AUTONOMOUS_AGENTS))
    try:
        eng.register_dependency(_dep("a", "missing"))
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_engine_recompute_requires_aware_time() -> None:
    from datetime import datetime as dt
    eng = EmergingTechForecastEngine()
    try:
        eng.recompute(at=dt(2026, 1, 1))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_recompute_empty() -> None:
    eng = EmergingTechForecastEngine()
    out = eng.recompute(at=_t0())
    assert out == ()


# ---- surface forecast ----

def test_engine_surface_forecast_fires_for_capabilities() -> None:
    eng = EmergingTechForecastEngine()
    eng.register_technology(_tech(
        "agent-platform", TechCategory.AUTONOMOUS_AGENTS,
        caps=("multi_agent", "tool_use"),
    ))
    eng.recompute(at=_t0())
    sids = {s.surface_id for s in eng.surfaces()}
    assert "agent_to_agent_trust_mesh" in sids
    assert "tool_chaining_surface" in sids


def test_engine_surface_forecast_skips_missing_capabilities() -> None:
    eng = EmergingTechForecastEngine()
    eng.register_technology(_tech(
        "agent-platform", TechCategory.AUTONOMOUS_AGENTS,
        caps=("tool_use",),
    ))
    eng.recompute(at=_t0())
    sids = {s.surface_id for s in eng.surfaces()}
    assert "agent_to_agent_trust_mesh" not in sids
    assert "tool_chaining_surface" in sids


def test_engine_surface_forecast_not_claim() -> None:
    eng = EmergingTechForecastEngine()
    eng.register_technology(_tech(
        "agent-platform", TechCategory.AUTONOMOUS_AGENTS,
        caps=("autonomy",),
    ))
    eng.recompute(at=_t0())
    for s in eng.surfaces():
        assert s.forecast_not_claim is True


# ---- threat forecast ----

def test_engine_threat_forecast_agent_priv_esc() -> None:
    eng = EmergingTechForecastEngine()
    eng.register_technology(_tech(
        "agent-platform", TechCategory.AUTONOMOUS_AGENTS,
        adoption=AdoptionStage.EARLY_ADOPTION,
        maturity=MaturityLevel.NASCENT,
    ))
    eng.recompute(at=_t0())
    cats = {t.threat_category for t in eng.threat_forecasts()}
    assert ThreatCategory.PRIVILEGE_ESCALATION in cats


def test_engine_threat_forecast_research_low_likelihood() -> None:
    eng = EmergingTechForecastEngine(
        config=ForecastConfig(min_likelihood_to_report=0.01),
    )
    eng.register_technology(_tech(
        "r", TechCategory.AUTONOMOUS_AGENTS,
        adoption=AdoptionStage.RESEARCH,
        maturity=MaturityLevel.NASCENT,
    ))
    eng.recompute(at=_t0())
    # All threats should have low likelihood (< 0.5) because adoption is RESEARCH
    for t in eng.threat_forecasts():
        assert t.likelihood < 0.5


def test_engine_threat_forecast_filters_by_min_likelihood() -> None:
    eng = EmergingTechForecastEngine(
        config=ForecastConfig(min_likelihood_to_report=0.95),
    )
    eng.register_technology(_tech(
        "r", TechCategory.AUTONOMOUS_AGENTS,
        adoption=AdoptionStage.RESEARCH,
        maturity=MaturityLevel.NASCENT,
    ))
    eng.recompute(at=_t0())
    assert eng.threat_forecasts() == ()


def test_engine_threat_forecast_not_claim() -> None:
    eng = EmergingTechForecastEngine()
    eng.register_technology(_tech(
        "t", TechCategory.AUTONOMOUS_AGENTS,
    ))
    eng.recompute(at=_t0())
    for t in eng.threat_forecasts():
        assert t.forecast_not_claim is True


def test_engine_threats_by_category() -> None:
    eng = EmergingTechForecastEngine()
    eng.register_technology(_tech(
        "t", TechCategory.AUTONOMOUS_AGENTS,
    ))
    eng.recompute(at=_t0())
    counts = eng.threats_by_category()
    assert counts[ThreatCategory.PRIVILEGE_ESCALATION] >= 1


# ---- dependency forecast ----

def test_engine_dependency_gap_when_maturity_low() -> None:
    eng = EmergingTechForecastEngine()
    eng.register_technology(_tech(
        "consumer", TechCategory.AUTONOMOUS_AGENTS,
    ))
    eng.register_technology(_tech(
        "dependency", TechCategory.NEW_IDENTITY_SYSTEM,
        maturity=MaturityLevel.NASCENT,
    ))
    eng.register_dependency(_dep("consumer", "dependency"))
    eng.recompute(at=_t0())
    dep_fc = eng.dependency_forecasts()
    assert len(dep_fc) == 1
    assert not dep_fc[0].ready


def test_engine_dependency_ready_when_mature() -> None:
    eng = EmergingTechForecastEngine()
    eng.register_technology(_tech(
        "consumer", TechCategory.AUTONOMOUS_AGENTS,
    ))
    eng.register_technology(_tech(
        "dependency", TechCategory.NEW_IDENTITY_SYSTEM,
        maturity=MaturityLevel.MATURE,
        adoption=AdoptionStage.MAINSTREAM,
    ))
    eng.register_dependency(_dep("consumer", "dependency"))
    eng.recompute(at=_t0())
    dep_fc = eng.dependency_forecasts()
    assert dep_fc[0].ready


def test_engine_dependency_declining_gap() -> None:
    eng = EmergingTechForecastEngine()
    eng.register_technology(_tech(
        "consumer", TechCategory.AUTONOMOUS_AGENTS,
    ))
    eng.register_technology(_tech(
        "legacy", TechCategory.NEW_SOFTWARE_ARCHITECTURE,
        adoption=AdoptionStage.DECLINING,
        maturity=MaturityLevel.LEGACY,
    ))
    eng.register_dependency(_dep("consumer", "legacy"))
    eng.recompute(at=_t0())
    dep_fc = eng.dependency_forecasts()[0]
    assert not dep_fc.ready
    assert "DECLINING" in (dep_fc.gap_reason or "")


# ---- control requirement + gap ----

def test_engine_required_controls_emitted() -> None:
    eng = EmergingTechForecastEngine()
    eng.register_technology(_tech(
        "t", TechCategory.AUTONOMOUS_AGENTS,
    ))
    eng.recompute(at=_t0())
    controls = eng.control_requirements()
    assert len(controls) >= 1
    control_kinds = {c.control for c in controls}
    assert ControlKind.AUTHORIZATION in control_kinds


def test_engine_control_covered_when_deployed() -> None:
    eng = EmergingTechForecastEngine()
    eng.register_technology(_tech(
        "t", TechCategory.AUTONOMOUS_AGENTS,
        controls=(ControlKind.AUTHORIZATION,),
    ))
    eng.recompute(at=_t0())
    auth = [
        c for c in eng.control_requirements()
        if c.control is ControlKind.AUTHORIZATION
    ]
    assert all(c.covered for c in auth)


def test_engine_preparedness_gap_when_absent() -> None:
    eng = EmergingTechForecastEngine()
    eng.register_technology(_tech(
        "t", TechCategory.AUTONOMOUS_AGENTS,
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert ForecastFindingKind.PREPAREDNESS_GAP in kinds


def test_engine_gaps_only_uncovered() -> None:
    eng = EmergingTechForecastEngine()
    eng.register_technology(_tech(
        "t", TechCategory.AUTONOMOUS_AGENTS,
    ))
    eng.recompute(at=_t0())
    for c in eng.gaps():
        assert not c.covered


def test_engine_overdue_critical_control() -> None:
    eng = EmergingTechForecastEngine()
    eng.register_technology(_tech(
        "t", TechCategory.AUTONOMOUS_AGENTS,
        adoption=AdoptionStage.EARLY_ADOPTION,
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert ForecastFindingKind.OVERDUE_CRITICAL_CONTROL in kinds


def test_engine_overdue_absent_when_planned_control() -> None:
    eng = EmergingTechForecastEngine()
    eng.register_technology(_tech(
        "t", TechCategory.AUTONOMOUS_AGENTS,
        adoption=AdoptionStage.MAINSTREAM,
        control_status={
            ControlKind.AUTHORIZATION: ControlStatus.PLANNED,
        },
    ))
    # AUTHORIZATION = PLANNED → not DEPLOYED → still "not covered"
    eng.recompute(at=_t0())
    auth = [
        c for c in eng.control_requirements()
        if c.control is ControlKind.AUTHORIZATION
    ]
    assert any(not c.covered for c in auth)


# ---- findings by kind ----

def test_engine_findings_by_kind() -> None:
    eng = EmergingTechForecastEngine()
    eng.register_technology(_tech(
        "t", TechCategory.AUTONOMOUS_AGENTS,
        caps=("autonomy",),
    ))
    eng.recompute(at=_t0())
    counts = eng.findings_by_kind()
    assert counts[ForecastFindingKind.LIKELY_THREAT] >= 1
    assert counts[ForecastFindingKind.PREPAREDNESS_GAP] >= 1


def test_engine_top_findings_sorted() -> None:
    eng = EmergingTechForecastEngine()
    eng.register_technology(_tech(
        "t", TechCategory.AUTONOMOUS_AGENTS,
        caps=("autonomy",),
    ))
    eng.recompute(at=_t0())
    top = eng.top_findings(k=20)
    severities = [f.severity for f in top]
    assert severities == sorted(severities, reverse=True)


def test_engine_top_findings_invalid_k() -> None:
    eng = EmergingTechForecastEngine()
    try:
        eng.top_findings(k=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- record ----

def test_engine_record_lookup() -> None:
    eng = EmergingTechForecastEngine()
    eng.register_technology(_tech(
        "t", TechCategory.AUTONOMOUS_AGENTS,
        caps=("autonomy",),
    ))
    eng.recompute(at=_t0())
    rec = eng.record("t")
    assert rec is not None
    assert rec.category is TechCategory.AUTONOMOUS_AGENTS


# ---- config ----

def test_engine_config_validation() -> None:
    try:
        ForecastConfig(min_severity_to_report=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_set_config() -> None:
    eng = EmergingTechForecastEngine()
    cfg = ForecastConfig(min_likelihood_to_report=0.9)
    eng.set_config(cfg)
    assert eng.config() is cfg


def test_engine_horizon_override() -> None:
    eng = EmergingTechForecastEngine()
    eng.register_technology(_tech(
        "t", TechCategory.AUTONOMOUS_AGENTS,
        horizon=120,
        caps=("autonomy",),
    ))
    eng.recompute(at=_t0(), horizon_months=6)
    for s in eng.surfaces():
        assert s.horizon_months == 6


# ---- invariants ----

def test_invariant_clean_snapshot() -> None:
    eng = EmergingTechForecastEngine()
    eng.register_technology(_tech(
        "t", TechCategory.AUTONOMOUS_AGENTS,
        controls=(
            ControlKind.AUTHORIZATION, ControlKind.AUDIT,
            ControlKind.HUMAN_REVIEW, ControlKind.MONITORING,
            ControlKind.RATE_LIMIT, ControlKind.AUTHENTICATION,
            ControlKind.ATTESTATION,
        ),
    ))
    eng.recompute(at=_t0())
    assert eng.violations() == ()


def test_invariant_forecasts_not_claims() -> None:
    # Craft a snapshot with a violating forecast by direct mutation
    bad = object.__new__(AttackSurfaceForecast)
    object.__setattr__(bad, "tech_id", "t")
    object.__setattr__(bad, "category", TechCategory.AUTONOMOUS_AGENTS)
    object.__setattr__(bad, "surface_id", "s")
    object.__setattr__(bad, "description", "x")
    object.__setattr__(bad, "severity", 3)
    object.__setattr__(bad, "confidence", ConfidenceClass.INFERRED)
    object.__setattr__(bad, "horizon_months", 12)
    object.__setattr__(bad, "forecast_not_claim", False)
    object.__setattr__(bad, "at", _t0())
    snap = ForecastSnapshot(
        technologies={}, dependencies=(),
        surfaces=(bad,), threats=(), dependency_forecasts=(),
        controls=(), findings=(),
    )
    v = check_invariants(snap)
    assert any(
        x.invariant_id == "fc.forecasts_not_claims" for x in v
    )


# ---- store ----

def test_in_memory_store_rejects_stale() -> None:
    s = InMemoryForecastStore()
    t = _t0()
    s.put(TechRecord(
        "t", TechCategory.AUTONOMOUS_AGENTS,
        AdoptionStage.PILOT, MaturityLevel.NASCENT, 12, 1, 1, 1, t,
    ))
    earlier = t.replace(year=t.year - 1)
    try:
        s.put(TechRecord(
            "t", TechCategory.AUTONOMOUS_AGENTS,
            AdoptionStage.PILOT, MaturityLevel.NASCENT, 12, 1, 1, 1,
            earlier,
        ))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "fc.db")
    store = SqliteForecastStore(db)
    store.put(TechRecord(
        "t", TechCategory.EDGE_COMPUTING,
        AdoptionStage.EARLY_ADOPTION, MaturityLevel.DEVELOPING,
        24, 2, 3, 1, _t0(),
    ))
    got = store.get("t")
    assert got is not None
    assert got.category is TechCategory.EDGE_COMPUTING
    assert got.surface_count == 2


def test_sqlite_store_finding_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "fc.db")
    store = SqliteForecastStore(db)
    f = ForecastFinding(
        kind=ForecastFindingKind.LIKELY_THREAT,
        subject_id="t", detail="x", severity=4,
        horizon_months=24, forecast_not_claim=True, at=_t0(),
    )
    store.put_finding("fid-1", f)
    row = store._conn.execute(
        "SELECT payload_json FROM fc_findings WHERE finding_id = 'fid-1'"
    ).fetchone()
    assert row is not None
    payload = json.loads(row[0])
    assert payload["kind"] == "likely_threat"


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
