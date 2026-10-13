"""
HYDRA POST-CORE — PHASE 8: AI SUPPLY-CHAIN TRUST
====================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * AI chain domain (datasets, models, frameworks, packages, dependencies,
    agents, tools, applications, deployments, runtime)
  * Model security model (weights hash, family, size, licence, encryption)
  * Agent security model (tool allowlist, delegation depth, sandbox)
  * Tool security model (dangerous capabilities, network egress, filesystem)
  * AI attestations (dataset cards, model cards, SBOMs, signatures)
  * Trust propagation forward along the AI chain
  * Break detection:
      - model substitution
      - poisoned dependency
      - unauthorized model update
      - AI package compromise
      - provenance break
      - runtime trust divergence
      - tool overreach
      - agent overreach
      - trust-chain discontinuity
  * Continuity score with per-link weakness
  * Explicit trust-label transitions
  * Machine-checkable AI supply-chain invariants
  * In-memory and SQLite stores
  * Phase-8 engine facade
  * Full test suite + manual runner

This is NEW AI supply-chain trust-continuity technology. It is not an
MLOps platform, not a model registry, not a scanner — it is continuous
trust state across the entire AI lifecycle.

Run tests:
    python hydra_phase8_ai_supply_chain_trust.py
    pytest hydra_phase8_ai_supply_chain_trust.py -q
"""
from __future__ import annotations

import hashlib
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
    Tuple,
)

# =============================================================================
# SECTION 1 — CONTRACTS
# =============================================================================


class Clock(Protocol):
    def now(self) -> datetime: ...


class IdProvider(Protocol):
    def new_id(self, prefix: str = "") -> str: ...


class EvidenceEmitter(Protocol):
    def emit(self, evidence: Mapping[str, Any]) -> None: ...


class ProvenanceRecorder(Protocol):
    def record(self, *, subject_id: str, action: str, at: datetime,
               details: Mapping[str, Any]) -> None: ...


class AuditSink(Protocol):
    def append(self, record: Mapping[str, Any]) -> None: ...


# =============================================================================
# SECTION 2 — DOMAIN
# =============================================================================


class AIStage(str, Enum):
    DATASET = "dataset"
    MODEL = "model"
    FRAMEWORK = "framework"
    PACKAGE = "package"
    DEPENDENCY = "dependency"
    AGENT = "agent"
    TOOL = "tool"
    APPLICATION = "application"
    DEPLOYMENT = "deployment"
    RUNTIME = "runtime"


_AI_STAGE_ORDER: Mapping[AIStage, int] = {
    AIStage.DATASET: 0,
    AIStage.MODEL: 1,
    AIStage.FRAMEWORK: 2,
    AIStage.PACKAGE: 3,
    AIStage.DEPENDENCY: 4,
    AIStage.AGENT: 5,
    AIStage.TOOL: 6,
    AIStage.APPLICATION: 7,
    AIStage.DEPLOYMENT: 8,
    AIStage.RUNTIME: 9,
}


def ai_stage_order(stage: AIStage) -> int:
    return _AI_STAGE_ORDER[stage]


class TrustLabel(str, Enum):
    UNKNOWN = "unknown"
    OBSERVED = "observed"
    TRUSTED = "trusted"
    DEGRADED = "degraded"
    SUSPICIOUS = "suspicious"
    COMPROMISED = "compromised"
    QUARANTINED = "quarantined"


_LABEL_SEVERITY: Mapping[TrustLabel, int] = {
    TrustLabel.UNKNOWN: 0,
    TrustLabel.OBSERVED: 1,
    TrustLabel.TRUSTED: 1,
    TrustLabel.DEGRADED: 2,
    TrustLabel.SUSPICIOUS: 3,
    TrustLabel.COMPROMISED: 4,
    TrustLabel.QUARANTINED: 5,
}


def label_severity(label: TrustLabel) -> int:
    return _LABEL_SEVERITY[label]


def worse_of(a: TrustLabel, b: TrustLabel) -> TrustLabel:
    return a if label_severity(a) >= label_severity(b) else b


def is_untrusted(label: TrustLabel) -> bool:
    return label in (
        TrustLabel.SUSPICIOUS,
        TrustLabel.COMPROMISED,
        TrustLabel.QUARANTINED,
    )


class AIBreakKind(str, Enum):
    NONE = "none"
    MODEL_SUBSTITUTION = "model_substitution"
    POISONED_DEPENDENCY = "poisoned_dependency"
    UNAUTHORIZED_MODEL_UPDATE = "unauthorized_model_update"
    AI_PACKAGE_COMPROMISE = "ai_package_compromise"
    PROVENANCE_BREAK = "provenance_break"
    RUNTIME_DIVERGENCE = "runtime_divergence"
    TOOL_OVERREACH = "tool_overreach"
    AGENT_OVERREACH = "agent_overreach"
    TRUST_CHAIN_DISCONTINUITY = "trust_chain_discontinuity"


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    source: str
    confidence: float
    observed_at: datetime
    payload: Mapping[str, Any]

    def __post_init__(self) -> None:
        if not self.evidence_id:
            raise ValueError("evidence_id is required")
        if not self.source:
            raise ValueError("source is required")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be within [0,1]")
        if self.observed_at.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")


def canonical_digest(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


# =============================================================================
# SECTION 3 — AI SUB-MODELS
# =============================================================================


class ModelFamily(str, Enum):
    LLM = "llm"
    VISION = "vision"
    MULTIMODAL = "multimodal"
    EMBEDDING = "embedding"
    CLASSIFIER = "classifier"
    GENERATIVE = "generative"
    OTHER = "other"


@dataclass(frozen=True)
class ModelSecurity:
    """Security-relevant model characteristics."""
    family: ModelFamily
    parameter_count: int
    weights_digest: str
    licence: str
    weights_encrypted: bool = False
    is_fine_tune: bool = False
    base_model_digest: Optional[str] = None
    training_data_provenance_verified: bool = False
    eval_score: Optional[float] = None
    known_unsafe: bool = False

    def __post_init__(self) -> None:
        if self.parameter_count < 0:
            raise ValueError("parameter_count must be non-negative")
        if not self.weights_digest:
            raise ValueError("weights_digest is required")
        if not self.licence:
            raise ValueError("licence is required")
        if self.is_fine_tune and not self.base_model_digest:
            raise ValueError(
                "fine-tuned model must declare base_model_digest"
            )

    def risky_score(self) -> float:
        """0..1, higher = riskier model characteristics."""
        s = 0.0
        if not self.weights_encrypted:
            s += 0.10
        if self.is_fine_tune and not self.base_model_digest:
            s += 0.20
        if not self.training_data_provenance_verified:
            s += 0.20
        if self.known_unsafe:
            s += 0.40
        if self.licence.lower() in {"unknown", "proprietary-unknown", "none"}:
            s += 0.10
        return max(0.0, min(1.0, s))


class ToolCapability(str, Enum):
    NETWORK_EGRESS = "network_egress"
    FILESYSTEM_READ = "filesystem_read"
    FILESYSTEM_WRITE = "filesystem_write"
    SHELL_EXEC = "shell_exec"
    CREDENTIAL_ACCESS = "credential_access"
    DATABASE_WRITE = "database_write"
    BROWSER_AUTOMATION = "browser_automation"
    CODE_EXECUTION = "code_execution"


HIGH_RISK_TOOL_CAPS: FrozenSet[ToolCapability] = frozenset({
    ToolCapability.SHELL_EXEC,
    ToolCapability.CREDENTIAL_ACCESS,
    ToolCapability.CODE_EXECUTION,
    ToolCapability.DATABASE_WRITE,
})


@dataclass(frozen=True)
class ToolSecurity:
    tool_id: str
    capabilities: FrozenSet[ToolCapability]
    sandboxed: bool = True
    egress_allowlist: FrozenSet[str] = frozenset()
    max_calls_per_minute: Optional[int] = None
    reads_untrusted_content: bool = False

    def __post_init__(self) -> None:
        if not self.tool_id:
            raise ValueError("tool_id is required")

    def dangerous_score(self) -> float:
        s = 0.0
        if self.capabilities & HIGH_RISK_TOOL_CAPS:
            s += 0.30
        if not self.sandboxed:
            s += 0.25
        if ToolCapability.NETWORK_EGRESS in self.capabilities and not self.egress_allowlist:
            s += 0.20
        if self.reads_untrusted_content:
            s += 0.15
        if self.max_calls_per_minute is None and self.capabilities:
            s += 0.10
        return max(0.0, min(1.0, s))


@dataclass(frozen=True)
class AgentSecurity:
    agent_id: str
    allowed_tools: FrozenSet[str]
    max_delegation_depth: int
    sandboxed: bool = True
    has_network_egress: bool = False
    accepts_external_input: bool = True
    system_prompt_signed: bool = False

    def __post_init__(self) -> None:
        if not self.agent_id:
            raise ValueError("agent_id is required")
        if self.max_delegation_depth < 0:
            raise ValueError("max_delegation_depth must be non-negative")

    def dangerous_score(self) -> float:
        s = 0.0
        if not self.sandboxed:
            s += 0.25
        if self.has_network_egress:
            s += 0.15
        if self.accepts_external_input:
            s += 0.15
        if not self.system_prompt_signed:
            s += 0.20
        if self.max_delegation_depth > 3:
            s += 0.15
        return max(0.0, min(1.0, s))


# =============================================================================
# SECTION 4 — CHAIN ENTITIES
# =============================================================================


@dataclass(frozen=True)
class AIPublisher:
    publisher_id: str
    trust: float
    verified: bool = True
    known_compromised: bool = False

    def __post_init__(self) -> None:
        if not self.publisher_id:
            raise ValueError("publisher_id is required")
        if not 0.0 <= self.trust <= 1.0:
            raise ValueError("trust must be within [0,1]")


@dataclass(frozen=True)
class AIArtifact:
    artifact_id: str
    stage: AIStage
    name: str
    digest: str
    producer_id: str
    parent_artifact_id: Optional[str]
    derived_at: datetime
    model: Optional[ModelSecurity] = None
    agent: Optional[AgentSecurity] = None
    tool: Optional[ToolSecurity] = None

    def __post_init__(self) -> None:
        if not self.artifact_id:
            raise ValueError("artifact_id is required")
        if not self.name:
            raise ValueError("name is required")
        if not self.digest:
            raise ValueError("digest is required")
        if not self.producer_id:
            raise ValueError("producer_id is required")
        if self.derived_at.tzinfo is None:
            raise ValueError("derived_at must be timezone-aware")

        # Consistency check: stage must match sub-model presence
        if self.stage is AIStage.MODEL and self.model is None:
            raise ValueError(f"model artifact {self.artifact_id} requires ModelSecurity")
        if self.stage is AIStage.AGENT and self.agent is None:
            raise ValueError(f"agent artifact {self.artifact_id} requires AgentSecurity")
        if self.stage is AIStage.TOOL and self.tool is None:
            raise ValueError(f"tool artifact {self.artifact_id} requires ToolSecurity")

    def intrinsic_risk(self) -> float:
        if self.model is not None:
            return self.model.risky_score()
        if self.agent is not None:
            return self.agent.dangerous_score()
        if self.tool is not None:
            return self.tool.dangerous_score()
        return 0.0


@dataclass(frozen=True)
class AIAttestation:
    attestation_id: str
    subject_artifact_id: str
    subject_digest: str
    attestation_kind: str          # "model_card", "dataset_card", "sbom", "signature"
    signer_id: str
    signature_valid: bool
    signed_at: datetime
    payload_digest: str
    evidence: Evidence

    def __post_init__(self) -> None:
        if not self.attestation_id:
            raise ValueError("attestation_id is required")
        if not self.subject_artifact_id:
            raise ValueError("subject_artifact_id is required")
        if not self.subject_digest:
            raise ValueError("subject_digest is required")
        if not self.attestation_kind:
            raise ValueError("attestation_kind is required")
        if not self.signer_id:
            raise ValueError("signer_id is required")
        if not self.payload_digest:
            raise ValueError("payload_digest is required")
        if self.signed_at.tzinfo is None:
            raise ValueError("signed_at must be timezone-aware")


@dataclass(frozen=True)
class AIChainLink:
    parent_artifact_id: str
    child_artifact_id: str
    expected_parent_digest: str
    expected_child_digest: str

    def __post_init__(self) -> None:
        if self.parent_artifact_id == self.child_artifact_id:
            raise ValueError("self-links are not allowed")
        if not self.expected_parent_digest or not self.expected_child_digest:
            raise ValueError("expected digests are required")


# =============================================================================
# SECTION 5 — TRUST STATE
# =============================================================================


NEUTRAL_SCORE = 0.5


@dataclass(frozen=True)
class TrustSignal:
    signal_id: str
    weight: float
    polarity: float
    at: datetime
    evidence: Evidence

    def __post_init__(self) -> None:
        if not 0.0 <= self.weight <= 1.0:
            raise ValueError("weight must be within [0,1]")
        if not -1.0 <= self.polarity <= 1.0:
            raise ValueError("polarity must be within [-1,1]")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


@dataclass(frozen=True)
class TrustState:
    score: float
    confidence: float
    basis: Tuple[TrustSignal, ...]
    updated_at: datetime

    def __post_init__(self) -> None:
        if not 0.0 <= self.score <= 1.0:
            raise ValueError("score must be within [0,1]")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be within [0,1]")
        if self.updated_at.tzinfo is None:
            raise ValueError("updated_at must be timezone-aware")


def neutral_trust(at: datetime) -> TrustState:
    return TrustState(score=NEUTRAL_SCORE, confidence=0.0,
                      basis=(), updated_at=at)


def combine_trust(signals: Iterable[TrustSignal], at: datetime) -> TrustState:
    basis = tuple(sorted(signals, key=lambda s: s.at))
    if not basis:
        return neutral_trust(at)
    num = 0.0
    den = 0.0
    for s in basis:
        num += s.weight * s.polarity
        den += s.weight
    if den <= 0.0:
        return neutral_trust(at)
    raw = num / den
    score = max(0.0, min(1.0, (raw + 1.0) / 2.0))
    confidence = den / (den + 2.0)
    return TrustState(score=score, confidence=confidence,
                      basis=basis, updated_at=at)


def derive_label(trust: TrustState) -> TrustLabel:
    if trust.confidence < 0.4:
        return TrustLabel.UNKNOWN
    s = trust.score
    if s < 0.30:
        return TrustLabel.SUSPICIOUS
    if s < 0.55:
        return TrustLabel.DEGRADED
    if s < 0.85:
        return TrustLabel.OBSERVED
    return TrustLabel.TRUSTED


# =============================================================================
# SECTION 6 — AI CHAIN GRAPH
# =============================================================================


class AIChainGraph:
    def __init__(self) -> None:
        self._artifacts: Dict[str, AIArtifact] = {}
        self._out: Dict[str, List[str]] = {}
        self._in: Dict[str, List[str]] = {}
        self._links: Dict[Tuple[str, str], AIChainLink] = {}

    def add_artifact(self, artifact: AIArtifact) -> None:
        if artifact.artifact_id in self._artifacts:
            raise ValueError(f"artifact {artifact.artifact_id} already exists")
        self._artifacts[artifact.artifact_id] = artifact
        self._out.setdefault(artifact.artifact_id, [])
        self._in.setdefault(artifact.artifact_id, [])

    def artifact(self, artifact_id: str) -> AIArtifact:
        a = self._artifacts.get(artifact_id)
        if a is None:
            raise KeyError(f"unknown artifact {artifact_id}")
        return a

    def add_link(self, link: AIChainLink) -> None:
        if link.parent_artifact_id not in self._artifacts:
            raise KeyError(f"parent {link.parent_artifact_id} not registered")
        if link.child_artifact_id not in self._artifacts:
            raise KeyError(f"child {link.child_artifact_id} not registered")
        if (link.parent_artifact_id, link.child_artifact_id) in self._links:
            raise ValueError(
                f"link {link.parent_artifact_id}->{link.child_artifact_id} "
                f"already exists"
            )
        if self._would_cycle(link.parent_artifact_id, link.child_artifact_id):
            raise ValueError(
                f"link {link.parent_artifact_id}->{link.child_artifact_id} "
                f"creates a cycle"
            )
        p = self._artifacts[link.parent_artifact_id]
        c = self._artifacts[link.child_artifact_id]
        if ai_stage_order(c.stage) <= ai_stage_order(p.stage):
            raise ValueError(
                f"child stage {c.stage.value} must be after parent "
                f"stage {p.stage.value}"
            )
        self._out[link.parent_artifact_id].append(link.child_artifact_id)
        self._in[link.child_artifact_id].append(link.parent_artifact_id)
        self._links[(link.parent_artifact_id, link.child_artifact_id)] = link

    def _would_cycle(self, parent: str, child: str) -> bool:
        cur: Optional[str] = parent
        seen: set = set()
        while cur is not None and cur not in seen:
            if cur == child:
                return True
            seen.add(cur)
            parents = self._in.get(cur, [])
            cur = parents[0] if parents else None
        return False

    def parents_of(self, artifact_id: str) -> Tuple[str, ...]:
        return tuple(self._in.get(artifact_id, []))

    def children_of(self, artifact_id: str) -> Tuple[str, ...]:
        return tuple(self._out.get(artifact_id, []))

    def link(self, parent: str, child: str) -> Optional[AIChainLink]:
        return self._links.get((parent, child))

    def all_artifacts(self) -> Tuple[AIArtifact, ...]:
        return tuple(self._artifacts.values())

    def all_links(self) -> Tuple[AIChainLink, ...]:
        return tuple(self._links.values())


# =============================================================================
# SECTION 7 — BREAK DETECTION
# =============================================================================


@dataclass(frozen=True)
class AIBreakFinding:
    kind: AIBreakKind
    artifact_id: str
    parent_artifact_id: Optional[str]
    detail: str
    severity: int
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


def detect_model_substitution(
    graph: AIChainGraph,
    artifact_id: str,
    *,
    expected_weights_digest: str,
    at: datetime,
) -> Optional[AIBreakFinding]:
    art = graph.artifact(artifact_id)
    if art.model is None:
        return None
    if art.model.weights_digest != expected_weights_digest:
        return AIBreakFinding(
            kind=AIBreakKind.MODEL_SUBSTITUTION,
            artifact_id=artifact_id,
            parent_artifact_id=None,
            detail=(
                f"model {artifact_id} weights digest "
                f"{art.model.weights_digest[:12]}… != expected "
                f"{expected_weights_digest[:12]}…"
            ),
            severity=5,
            at=at,
        )
    return None


def detect_poisoned_dependency(
    declared_dependencies: Mapping[str, str],
    observed_dependencies: Mapping[str, str],
    *,
    artifact_id: str,
    poisoned_hashes: FrozenSet[str],
    at: datetime,
) -> Tuple[AIBreakFinding, ...]:
    """Compare declared vs observed AI dependency digests and flag any
    whose observed hash is on the known-poisoned list."""
    out: List[AIBreakFinding] = []
    for name, declared in declared_dependencies.items():
        observed = observed_dependencies.get(name)
        if observed is None:
            out.append(AIBreakFinding(
                kind=AIBreakKind.TRUST_CHAIN_DISCONTINUITY,
                artifact_id=artifact_id,
                parent_artifact_id=None,
                detail=f"declared AI dependency {name} missing at runtime",
                severity=3,
                at=at,
            ))
            continue
        if observed != declared:
            if observed in poisoned_hashes:
                out.append(AIBreakFinding(
                    kind=AIBreakKind.POISONED_DEPENDENCY,
                    artifact_id=artifact_id,
                    parent_artifact_id=None,
                    detail=(
                        f"AI dependency {name} replaced with known-poisoned "
                        f"hash {observed[:12]}…"
                    ),
                    severity=5,
                    at=at,
                ))
            else:
                out.append(AIBreakFinding(
                    kind=AIBreakKind.POISONED_DEPENDENCY,
                    artifact_id=artifact_id,
                    parent_artifact_id=None,
                    detail=(
                        f"AI dependency {name} digest mismatch: declared "
                        f"{declared[:12]}… observed {observed[:12]}…"
                    ),
                    severity=4,
                    at=at,
                ))
    return tuple(out)


def detect_unauthorized_model_update(
    artifact: AIArtifact,
    *,
    authorized_publishers: FrozenSet[str],
    at: datetime,
) -> Optional[AIBreakFinding]:
    if artifact.producer_id not in authorized_publishers:
        return AIBreakFinding(
            kind=AIBreakKind.UNAUTHORIZED_MODEL_UPDATE,
            artifact_id=artifact.artifact_id,
            parent_artifact_id=None,
            detail=(
                f"model artifact {artifact.artifact_id} published by "
                f"unauthorized producer {artifact.producer_id}"
            ),
            severity=4,
            at=at,
        )
    return None


def detect_ai_package_compromise(
    artifact: AIArtifact,
    *,
    producer: Optional[AIPublisher],
    at: datetime,
) -> Optional[AIBreakFinding]:
    if producer is None:
        return None
    if producer.known_compromised:
        return AIBreakFinding(
            kind=AIBreakKind.AI_PACKAGE_COMPROMISE,
            artifact_id=artifact.artifact_id,
            parent_artifact_id=None,
            detail=(
                f"producer {producer.publisher_id} is marked compromised"
            ),
            severity=5,
            at=at,
        )
    if producer.trust < 0.3:
        return AIBreakFinding(
            kind=AIBreakKind.AI_PACKAGE_COMPROMISE,
            artifact_id=artifact.artifact_id,
            parent_artifact_id=None,
            detail=(
                f"producer {producer.publisher_id} trust is very low "
                f"({producer.trust:.2f})"
            ),
            severity=4,
            at=at,
        )
    return None


def detect_ai_provenance_break(
    artifact: AIArtifact,
    attestations: Iterable[AIAttestation],
    *,
    at: datetime,
) -> Optional[AIBreakFinding]:
    applicable = [
        a for a in attestations
        if a.subject_artifact_id == artifact.artifact_id
    ]
    # Models and datasets require at least one attestation
    requires_attestation = artifact.stage in (AIStage.MODEL, AIStage.DATASET)
    if not applicable:
        if requires_attestation:
            return AIBreakFinding(
                kind=AIBreakKind.PROVENANCE_BREAK,
                artifact_id=artifact.artifact_id,
                parent_artifact_id=None,
                detail=(
                    f"no attestation present for {artifact.artifact_id} "
                    f"({artifact.stage.value})"
                ),
                severity=4,
                at=at,
            )
        return None
    for a in applicable:
        if a.subject_digest != artifact.digest:
            return AIBreakFinding(
                kind=AIBreakKind.MODEL_SUBSTITUTION,
                artifact_id=artifact.artifact_id,
                parent_artifact_id=None,
                detail=(
                    f"attestation {a.attestation_id} bound to different digest"
                ),
                severity=5,
                at=at,
            )
        if not a.signature_valid:
            return AIBreakFinding(
                kind=AIBreakKind.PROVENANCE_BREAK,
                artifact_id=artifact.artifact_id,
                parent_artifact_id=None,
                detail=(
                    f"attestation {a.attestation_id} signature invalid"
                ),
                severity=4,
                at=at,
            )
    return None


def detect_runtime_ai_divergence(
    runtime_artifact: AIArtifact,
    *,
    expected_digest: str,
    at: datetime,
) -> Optional[AIBreakFinding]:
    if runtime_artifact.digest != expected_digest:
        return AIBreakFinding(
            kind=AIBreakKind.RUNTIME_DIVERGENCE,
            artifact_id=runtime_artifact.artifact_id,
            parent_artifact_id=None,
            detail=(
                f"runtime AI artifact digest "
                f"{runtime_artifact.digest[:12]}… != expected "
                f"{expected_digest[:12]}…"
            ),
            severity=5,
            at=at,
        )
    return None


def detect_tool_overreach(
    artifact: AIArtifact,
    *,
    allowed_capabilities: FrozenSet[ToolCapability],
    at: datetime,
) -> Optional[AIBreakFinding]:
    if artifact.tool is None:
        return None
    excess = artifact.tool.capabilities - allowed_capabilities
    if excess:
        return AIBreakFinding(
            kind=AIBreakKind.TOOL_OVERREACH,
            artifact_id=artifact.artifact_id,
            parent_artifact_id=None,
            detail=(
                f"tool {artifact.artifact_id} has capabilities beyond "
                f"policy: {sorted(c.value for c in excess)}"
            ),
            severity=4,
            at=at,
        )
    return None


def detect_agent_overreach(
    artifact: AIArtifact,
    *,
    declared_allowed_tools: FrozenSet[str],
    tools_reachable: FrozenSet[str],
    max_delegation_depth: int,
    at: datetime,
) -> Optional[AIBreakFinding]:
    if artifact.agent is None:
        return None
    excess_tools = tools_reachable - declared_allowed_tools
    if excess_tools:
        return AIBreakFinding(
            kind=AIBreakKind.AGENT_OVERREACH,
            artifact_id=artifact.artifact_id,
            parent_artifact_id=None,
            detail=(
                f"agent {artifact.artifact_id} can reach tools beyond "
                f"allowlist: {sorted(excess_tools)}"
            ),
            severity=4,
            at=at,
        )
    if artifact.agent.max_delegation_depth > max_delegation_depth:
        return AIBreakFinding(
            kind=AIBreakKind.AGENT_OVERREACH,
            artifact_id=artifact.artifact_id,
            parent_artifact_id=None,
            detail=(
                f"agent {artifact.artifact_id} delegation depth "
                f"{artifact.agent.max_delegation_depth} exceeds policy "
                f"({max_delegation_depth})"
            ),
            severity=4,
            at=at,
        )
    return None


def detect_ai_discontinuity(
    graph: AIChainGraph,
    artifact_id: str,
    *,
    at: datetime,
) -> Optional[AIBreakFinding]:
    art = graph.artifact(artifact_id)
    if art.stage is AIStage.DATASET:
        return None
    parents = graph.parents_of(artifact_id)
    if not parents:
        return AIBreakFinding(
            kind=AIBreakKind.TRUST_CHAIN_DISCONTINUITY,
            artifact_id=artifact_id,
            parent_artifact_id=None,
            detail=(
                f"artifact {artifact_id} at stage {art.stage.value} has "
                f"no parent link"
            ),
            severity=4,
            at=at,
        )
    return None


# =============================================================================
# SECTION 8 — CONTINUITY ANALYSIS
# =============================================================================


@dataclass(frozen=True)
class AIContinuityResult:
    artifact_id: str
    label: TrustLabel
    trust: TrustState
    continuity: float
    findings: Tuple[AIBreakFinding, ...]
    chain: Tuple[str, ...]
    rationale: str
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        if not 0.0 <= self.continuity <= 1.0:
            raise ValueError("continuity must be within [0,1]")


def _ai_ancestors(graph: AIChainGraph, artifact_id: str) -> Tuple[str, ...]:
    chain: List[str] = [artifact_id]
    cur = artifact_id
    seen: set = set()
    while True:
        if cur in seen:
            break
        seen.add(cur)
        parents = graph.parents_of(cur)
        if not parents:
            break
        cur = parents[0]
        chain.append(cur)
    chain.reverse()
    return tuple(chain)


def effective_ai_continuity(
    *,
    root_trust: float,
    link_postures: Iterable[float],
    intrinsic_risk: float,
    findings: Iterable[AIBreakFinding],
) -> float:
    base = max(0.0, min(1.0, root_trust))
    for p in link_postures:
        if not 0.0 <= p <= 1.0:
            raise ValueError("link posture must be within [0,1]")
        base *= 0.5 + 0.5 * p
    # intrinsic risk of the final artifact
    base *= (1.0 - 0.5 * max(0.0, min(1.0, intrinsic_risk)))
    penalty = 0.0
    for f in findings:
        penalty += 0.05 * f.severity
    return max(0.0, min(1.0, base - penalty))


def analyse_ai_continuity(
    graph: AIChainGraph,
    artifact_id: str,
    *,
    publisher_trust: Mapping[str, float],
    attestations: Mapping[str, Tuple[AIAttestation, ...]],
    link_postures: Mapping[Tuple[str, str], float],
    findings_by_artifact: Mapping[str, Tuple[AIBreakFinding, ...]],
    at: datetime,
) -> AIContinuityResult:
    chain = _ai_ancestors(graph, artifact_id)
    if not chain:
        raise KeyError(f"unknown artifact {artifact_id}")

    root = graph.artifact(chain[0])
    root_trust = publisher_trust.get(root.producer_id, NEUTRAL_SCORE)

    postures: List[float] = []
    for i in range(len(chain) - 1):
        key = (chain[i], chain[i + 1])
        postures.append(link_postures.get(key, 0.5))

    chain_findings: List[AIBreakFinding] = []
    for aid in chain:
        chain_findings.extend(findings_by_artifact.get(aid, ()))

    target = graph.artifact(artifact_id)
    intrinsic = target.intrinsic_risk()

    continuity = effective_ai_continuity(
        root_trust=root_trust,
        link_postures=postures,
        intrinsic_risk=intrinsic,
        findings=chain_findings,
    )

    provisional = TrustState(
        score=continuity, confidence=0.9, basis=(), updated_at=at,
    )
    label = derive_label(provisional)
    for f in chain_findings:
        if f.severity >= 5:
            label = worse_of(label, TrustLabel.COMPROMISED)
        elif f.severity >= 4:
            label = worse_of(label, TrustLabel.SUSPICIOUS)
        elif f.severity >= 3:
            label = worse_of(label, TrustLabel.DEGRADED)

    for aid in chain:
        for a in attestations.get(aid, ()):
            if not a.signature_valid:
                label = worse_of(label, TrustLabel.SUSPICIOUS)

    rationale = (
        f"chain length {len(chain)}, root trust {root_trust:.2f}, "
        f"intrinsic risk {intrinsic:.2f}, {len(chain_findings)} finding(s)"
    )

    return AIContinuityResult(
        artifact_id=artifact_id,
        label=label,
        trust=TrustState(
            score=continuity, confidence=0.9, basis=(), updated_at=at,
        ),
        continuity=continuity,
        findings=tuple(chain_findings),
        chain=chain,
        rationale=rationale,
        at=at,
    )


# =============================================================================
# SECTION 9 — TRANSITIONS
# =============================================================================


class TransitionOutcome(str, Enum):
    ALLOWED = "allowed"
    REJECTED_INVALID = "rejected_invalid"
    REQUIRES_VERIFICATION = "requires_verification"


_ALLOWED_LABEL_EDGES: Mapping[TrustLabel, FrozenSet[TrustLabel]] = {
    TrustLabel.UNKNOWN: frozenset({
        TrustLabel.OBSERVED, TrustLabel.DEGRADED, TrustLabel.SUSPICIOUS,
        TrustLabel.TRUSTED, TrustLabel.COMPROMISED,
        TrustLabel.QUARANTINED,
    }),
    TrustLabel.OBSERVED: frozenset({
        TrustLabel.TRUSTED, TrustLabel.DEGRADED,
        TrustLabel.SUSPICIOUS, TrustLabel.COMPROMISED,
    }),
    TrustLabel.TRUSTED: frozenset({
        TrustLabel.DEGRADED, TrustLabel.SUSPICIOUS,
        TrustLabel.COMPROMISED, TrustLabel.QUARANTINED,
    }),
    TrustLabel.DEGRADED: frozenset({
        TrustLabel.OBSERVED, TrustLabel.SUSPICIOUS,
        TrustLabel.COMPROMISED, TrustLabel.QUARANTINED,
    }),
    TrustLabel.SUSPICIOUS: frozenset({
        TrustLabel.OBSERVED, TrustLabel.DEGRADED,
        TrustLabel.COMPROMISED, TrustLabel.QUARANTINED,
    }),
    TrustLabel.COMPROMISED: frozenset({TrustLabel.QUARANTINED}),
    TrustLabel.QUARANTINED: frozenset({TrustLabel.OBSERVED}),
}


@dataclass(frozen=True)
class TransitionRequest:
    entity_id: str
    from_label: TrustLabel
    to_label: TrustLabel
    reason: str
    verified: bool


@dataclass(frozen=True)
class TransitionDecision:
    outcome: TransitionOutcome
    rationale: str


def evaluate_transition(req: TransitionRequest) -> TransitionDecision:
    if not req.reason:
        return TransitionDecision(
            TransitionOutcome.REJECTED_INVALID, "reason is required"
        )
    if req.from_label is req.to_label:
        return TransitionDecision(TransitionOutcome.ALLOWED, "no-op")
    permitted = _ALLOWED_LABEL_EDGES.get(req.from_label, frozenset())
    if req.to_label not in permitted:
        return TransitionDecision(
            TransitionOutcome.REJECTED_INVALID,
            f"{req.from_label.value} -> {req.to_label.value} not permitted",
        )
    going_better = label_severity(req.to_label) < label_severity(req.from_label)
    reaching_trust_from_unknown = (
        req.from_label is TrustLabel.UNKNOWN
        and req.to_label is TrustLabel.TRUSTED
    )
    if (going_better or reaching_trust_from_unknown) and not req.verified:
        return TransitionDecision(
            TransitionOutcome.REQUIRES_VERIFICATION,
            "recovery transitions require verification",
        )
    return TransitionDecision(TransitionOutcome.ALLOWED, "permitted")


# =============================================================================
# SECTION 10 — INVARIANTS
# =============================================================================


class InvariantSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class ArtifactSnapshot:
    artifact: AIArtifact
    label: TrustLabel
    continuity: float
    findings: Tuple[AIBreakFinding, ...]


@dataclass(frozen=True)
class AISupplyChainSnapshot:
    graph: AIChainGraph
    artifacts: Mapping[str, ArtifactSnapshot]
    attestations: Mapping[str, Tuple[AIAttestation, ...]]
    publishers: Mapping[str, AIPublisher]


@dataclass(frozen=True)
class InvariantViolation:
    invariant_id: str
    severity: InvariantSeverity
    subject_id: str
    detail: str


@dataclass(frozen=True)
class AISupplyChainInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[AISupplyChainSnapshot], Tuple[InvariantViolation, ...]]
    description: str


def _inv_trusted_model_needs_attestation(
    snap: AISupplyChainSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for aid, snapsh in snap.artifacts.items():
        if snapsh.label is not TrustLabel.TRUSTED:
            continue
        if snapsh.artifact.stage not in (AIStage.MODEL, AIStage.DATASET):
            continue
        atts = snap.attestations.get(aid, ())
        if not atts or not any(a.signature_valid for a in atts):
            out.append(InvariantViolation(
                invariant_id="ai.trusted_model_needs_attestation",
                severity=InvariantSeverity.CRITICAL,
                subject_id=aid,
                detail=(
                    f"{snapsh.artifact.stage.value} {aid} is TRUSTED without "
                    f"a valid attestation"
                ),
            ))
    return tuple(out)


def _inv_trusted_with_untrusted_parent(
    snap: AISupplyChainSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for aid, snapsh in snap.artifacts.items():
        if snapsh.label is not TrustLabel.TRUSTED:
            continue
        for p in snap.graph.parents_of(aid):
            ps = snap.artifacts.get(p)
            if ps is None:
                continue
            if is_untrusted(ps.label):
                out.append(InvariantViolation(
                    invariant_id="ai.trusted_with_untrusted_parent",
                    severity=InvariantSeverity.CRITICAL,
                    subject_id=aid,
                    detail=(
                        f"{aid} TRUSTED while parent {p} is {ps.label.value}"
                    ),
                ))
    return tuple(out)


def _inv_chain_no_discontinuity(
    snap: AISupplyChainSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for aid, snapsh in snap.artifacts.items():
        if snapsh.artifact.stage is AIStage.DATASET:
            continue
        parents = snap.graph.parents_of(aid)
        if not parents:
            out.append(InvariantViolation(
                invariant_id="ai.chain_discontinuity",
                severity=InvariantSeverity.CRITICAL,
                subject_id=aid,
                detail=(
                    f"non-root artifact {aid} at stage "
                    f"{snapsh.artifact.stage.value} has no parent"
                ),
            ))
    return tuple(out)


def _inv_tool_with_high_risk_caps_must_be_sandboxed(
    snap: AISupplyChainSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for aid, snapsh in snap.artifacts.items():
        tool = snapsh.artifact.tool
        if tool is None:
            continue
        if (tool.capabilities & HIGH_RISK_TOOL_CAPS) and not tool.sandboxed:
            out.append(InvariantViolation(
                invariant_id="ai.high_risk_tool_not_sandboxed",
                severity=InvariantSeverity.CRITICAL,
                subject_id=aid,
                detail=(
                    f"tool {aid} has high-risk capabilities "
                    f"{sorted(c.value for c in tool.capabilities & HIGH_RISK_TOOL_CAPS)} "
                    f"but is not sandboxed"
                ),
            ))
    return tuple(out)


def _inv_deployed_agent_must_be_trusted(
    snap: AISupplyChainSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for aid, snapsh in snap.artifacts.items():
        if snapsh.artifact.stage not in (AIStage.DEPLOYMENT, AIStage.RUNTIME):
            continue
        if is_untrusted(snapsh.label):
            out.append(InvariantViolation(
                invariant_id="ai.untrusted_deployment_or_runtime",
                severity=InvariantSeverity.CRITICAL,
                subject_id=aid,
                detail=(
                    f"stage {snapsh.artifact.stage.value} artifact {aid} "
                    f"is {snapsh.label.value}"
                ),
            ))
    return tuple(out)


def _inv_digest_reuse_across_stages(
    snap: AISupplyChainSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    seen: Dict[str, Tuple[AIStage, str]] = {}
    for aid, snapsh in snap.artifacts.items():
        key = snapsh.artifact.digest
        if key in seen:
            prev_stage, prev_id = seen[key]
            if prev_stage is not snapsh.artifact.stage:
                out.append(InvariantViolation(
                    invariant_id="ai.digest_reuse_across_stages",
                    severity=InvariantSeverity.HIGH,
                    subject_id=aid,
                    detail=(
                        f"digest {key[:12]}… appears at both {prev_id} "
                        f"({prev_stage.value}) and {aid} "
                        f"({snapsh.artifact.stage.value})"
                    ),
                ))
        else:
            seen[key] = (snapsh.artifact.stage, aid)
    return tuple(out)


DEFAULT_INVARIANTS: Tuple[AISupplyChainInvariant, ...] = (
    AISupplyChainInvariant(
        invariant_id="ai.trusted_model_needs_attestation",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_trusted_model_needs_attestation,
        description="TRUSTED models/datasets must have a valid attestation.",
    ),
    AISupplyChainInvariant(
        invariant_id="ai.trusted_with_untrusted_parent",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_trusted_with_untrusted_parent,
        description="TRUSTED artifact cannot have an untrusted parent.",
    ),
    AISupplyChainInvariant(
        invariant_id="ai.chain_discontinuity",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_chain_no_discontinuity,
        description="Non-root AI artifacts must have a parent link.",
    ),
    AISupplyChainInvariant(
        invariant_id="ai.high_risk_tool_not_sandboxed",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_tool_with_high_risk_caps_must_be_sandboxed,
        description="High-risk tools must be sandboxed.",
    ),
    AISupplyChainInvariant(
        invariant_id="ai.untrusted_deployment_or_runtime",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_deployed_agent_must_be_trusted,
        description="Deployment/runtime artifacts must not be untrusted.",
    ),
    AISupplyChainInvariant(
        invariant_id="ai.digest_reuse_across_stages",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_digest_reuse_across_stages,
        description="Same digest must not appear at different AI stages.",
    ),
)


def check_invariants(
    snap: AISupplyChainSnapshot,
    invariants: Iterable[AISupplyChainInvariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 11 — STORES
# =============================================================================


@dataclass(frozen=True)
class AIArtifactStateRecord:
    artifact_id: str
    label: TrustLabel
    continuity: float
    findings_count: int
    updated_at: datetime


class AISupplyChainStore(Protocol):
    def get(self, artifact_id: str) -> Optional[AIArtifactStateRecord]: ...
    def put(self, record: AIArtifactStateRecord) -> None: ...
    def all(self) -> Tuple[AIArtifactStateRecord, ...]: ...


class InMemoryAISupplyChainStore:
    def __init__(self) -> None:
        self._data: Dict[str, AIArtifactStateRecord] = {}

    def get(self, artifact_id: str) -> Optional[AIArtifactStateRecord]:
        return self._data.get(artifact_id)

    def put(self, record: AIArtifactStateRecord) -> None:
        existing = self._data.get(record.artifact_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._data[record.artifact_id] = record

    def all(self) -> Tuple[AIArtifactStateRecord, ...]:
        return tuple(self._data.values())


class SqliteAISupplyChainStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ai_artifact_state (
                artifact_id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                continuity REAL NOT NULL,
                findings_count INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ai_attestations (
                attestation_id TEXT PRIMARY KEY,
                subject_artifact_id TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ai_publishers (
                publisher_id TEXT PRIMARY KEY,
                trust REAL NOT NULL,
                verified INTEGER NOT NULL,
                known_compromised INTEGER NOT NULL
            )
            """
        )
        self._conn.commit()

    def get(self, artifact_id: str) -> Optional[AIArtifactStateRecord]:
        row = self._conn.execute(
            "SELECT label, continuity, findings_count, updated_at "
            "FROM ai_artifact_state WHERE artifact_id = ?",
            (artifact_id,),
        ).fetchone()
        if row is None:
            return None
        return AIArtifactStateRecord(
            artifact_id=artifact_id,
            label=TrustLabel(row[0]),
            continuity=float(row[1]),
            findings_count=int(row[2]),
            updated_at=datetime.fromisoformat(row[3]),
        )

    def put(self, record: AIArtifactStateRecord) -> None:
        existing = self.get(record.artifact_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._conn.execute(
            """
            INSERT INTO ai_artifact_state
              (artifact_id, label, continuity, findings_count, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(artifact_id) DO UPDATE SET
              label=excluded.label,
              continuity=excluded.continuity,
              findings_count=excluded.findings_count,
              updated_at=excluded.updated_at
            """,
            (record.artifact_id, record.label.value, record.continuity,
             record.findings_count, record.updated_at.isoformat()),
        )
        self._conn.commit()

    def all(self) -> Tuple[AIArtifactStateRecord, ...]:
        rows = self._conn.execute(
            "SELECT artifact_id FROM ai_artifact_state"
        ).fetchall()
        return tuple(
            r for r in (self.get(x[0]) for x in rows) if r is not None
        )

    def put_attestation(self, att: AIAttestation) -> None:
        payload = {
            "attestation_id": att.attestation_id,
            "subject_artifact_id": att.subject_artifact_id,
            "subject_digest": att.subject_digest,
            "attestation_kind": att.attestation_kind,
            "signer_id": att.signer_id,
            "signature_valid": att.signature_valid,
            "signed_at": att.signed_at.isoformat(),
            "payload_digest": att.payload_digest,
            "evidence_id": att.evidence.evidence_id,
            "evidence_source": att.evidence.source,
            "evidence_confidence": att.evidence.confidence,
            "evidence_observed_at": att.evidence.observed_at.isoformat(),
        }
        self._conn.execute(
            "INSERT OR REPLACE INTO ai_attestations "
            "(attestation_id, subject_artifact_id, payload_json) "
            "VALUES (?, ?, ?)",
            (att.attestation_id, att.subject_artifact_id,
             json.dumps(payload, sort_keys=True)),
        )
        self._conn.commit()

    def get_attestation(self, attestation_id: str) -> Optional[AIAttestation]:
        row = self._conn.execute(
            "SELECT payload_json FROM ai_attestations "
            "WHERE attestation_id = ?",
            (attestation_id,),
        ).fetchone()
        if row is None:
            return None
        p = json.loads(row[0])
        return AIAttestation(
            attestation_id=p["attestation_id"],
            subject_artifact_id=p["subject_artifact_id"],
            subject_digest=p["subject_digest"],
            attestation_kind=p["attestation_kind"],
            signer_id=p["signer_id"],
            signature_valid=p["signature_valid"],
            signed_at=datetime.fromisoformat(p["signed_at"]),
            payload_digest=p["payload_digest"],
            evidence=Evidence(
                evidence_id=p["evidence_id"],
                source=p["evidence_source"],
                confidence=float(p["evidence_confidence"]),
                observed_at=datetime.fromisoformat(p["evidence_observed_at"]),
                payload={},
            ),
        )

    def put_publisher(self, pub: AIPublisher) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO ai_publishers "
            "(publisher_id, trust, verified, known_compromised) "
            "VALUES (?, ?, ?, ?)",
            (pub.publisher_id, pub.trust, int(pub.verified),
             int(pub.known_compromised)),
        )
        self._conn.commit()

    def get_publisher(self, publisher_id: str) -> Optional[AIPublisher]:
        row = self._conn.execute(
            "SELECT trust, verified, known_compromised FROM ai_publishers "
            "WHERE publisher_id = ?",
            (publisher_id,),
        ).fetchone()
        if row is None:
            return None
        return AIPublisher(
            publisher_id=publisher_id,
            trust=float(row[0]),
            verified=bool(row[1]),
            known_compromised=bool(row[2]),
        )


# =============================================================================
# SECTION 12 — ENGINE
# =============================================================================


class AISupplyChainTrustEngine:
    """Continuous AI supply-chain trust engine.

    Consumes AI artifacts, attestations, publishers, and runtime reports.
    Produces per-artifact trust label + continuity score + findings.
    """

    def __init__(
        self, *, store: Optional[AISupplyChainStore] = None,
    ) -> None:
        self._store: AISupplyChainStore = store or InMemoryAISupplyChainStore()
        self._graph = AIChainGraph()
        self._publishers: Dict[str, AIPublisher] = {}
        self._attestations: Dict[str, List[AIAttestation]] = {}
        self._link_postures: Dict[Tuple[str, str], float] = {}
        self._findings: Dict[str, List[AIBreakFinding]] = {}
        self._labels: Dict[str, TrustLabel] = {}
        self._continuity: Dict[str, AIContinuityResult] = {}
        self._violations: Tuple[InvariantViolation, ...] = ()

        # Policy
        self._authorized_model_publishers: set = set()
        self._poisoned_ai_dependency_hashes: set = set()
        self._allowed_tool_capabilities: set = set(ToolCapability)
        self._agent_max_delegation_depth: int = 2

    # ---- registration ---------------------------------------------------

    def register_publisher(self, publisher: AIPublisher) -> None:
        if publisher.publisher_id in self._publishers:
            raise ValueError(
                f"publisher {publisher.publisher_id} already registered"
            )
        self._publishers[publisher.publisher_id] = publisher

    def authorize_model_publisher(self, publisher_id: str) -> None:
        self._authorized_model_publishers.add(publisher_id)

    def mark_ai_dependency_poisoned(self, digest: str) -> None:
        self._poisoned_ai_dependency_hashes.add(digest)

    def set_allowed_tool_capabilities(
        self, caps: Iterable[ToolCapability],
    ) -> None:
        self._allowed_tool_capabilities = set(caps)

    def set_agent_max_delegation_depth(self, depth: int) -> None:
        if depth < 0:
            raise ValueError("depth must be non-negative")
        self._agent_max_delegation_depth = depth

    def add_artifact(self, artifact: AIArtifact) -> None:
        self._graph.add_artifact(artifact)

    def add_link(self, link: AIChainLink, *, posture: float = 0.9) -> None:
        if not 0.0 <= posture <= 1.0:
            raise ValueError("posture must be within [0,1]")
        self._graph.add_link(link)
        self._link_postures[
            (link.parent_artifact_id, link.child_artifact_id)
        ] = posture

    def add_attestation(self, attestation: AIAttestation) -> None:
        if attestation.subject_artifact_id not in {
            a.artifact_id for a in self._graph.all_artifacts()
        }:
            raise KeyError(
                f"attestation subject {attestation.subject_artifact_id} "
                f"not registered"
            )
        self._attestations.setdefault(
            attestation.subject_artifact_id, []
        ).append(attestation)

    # ---- runtime reports -------------------------------------------------

    def report_ai_dependency_digests(
        self,
        artifact_id: str,
        *,
        declared: Mapping[str, str],
        observed: Mapping[str, str],
        at: datetime,
    ) -> Tuple[AIBreakFinding, ...]:
        findings = detect_poisoned_dependency(
            declared, observed, artifact_id=artifact_id,
            poisoned_hashes=frozenset(self._poisoned_ai_dependency_hashes),
            at=at,
        )
        self._findings.setdefault(artifact_id, []).extend(findings)
        return findings

    def report_runtime_ai_digest(
        self,
        artifact_id: str,
        *,
        expected_digest: str,
        at: datetime,
    ) -> Optional[AIBreakFinding]:
        art = self._graph.artifact(artifact_id)
        f = detect_runtime_ai_divergence(
            art, expected_digest=expected_digest, at=at,
        )
        if f is not None:
            self._findings.setdefault(artifact_id, []).append(f)
        return f

    def report_agent_reachable_tools(
        self,
        artifact_id: str,
        *,
        reachable: FrozenSet[str],
        at: datetime,
    ) -> Optional[AIBreakFinding]:
        art = self._graph.artifact(artifact_id)
        if art.agent is None:
            return None
        f = detect_agent_overreach(
            art,
            declared_allowed_tools=art.agent.allowed_tools,
            tools_reachable=reachable,
            max_delegation_depth=self._agent_max_delegation_depth,
            at=at,
        )
        if f is not None:
            self._findings.setdefault(artifact_id, []).append(f)
        return f

    # ---- recompute -------------------------------------------------------

    def recompute(self, *, at: datetime) -> Tuple[AIArtifactStateRecord, ...]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

        # Augment structural findings
        for art in self._graph.all_artifacts():
            # Provenance
            prov = detect_ai_provenance_break(
                art, self._attestations.get(art.artifact_id, ()), at=at,
            )
            if prov is not None:
                self._findings.setdefault(art.artifact_id, []).append(prov)

            # AI package compromise (any stage)
            producer = self._publishers.get(art.producer_id)
            comp = detect_ai_package_compromise(
                art, producer=producer, at=at,
            )
            if comp is not None:
                self._findings.setdefault(art.artifact_id, []).append(comp)

            # Unauthorized model update
            if art.stage is AIStage.MODEL:
                unauth = detect_unauthorized_model_update(
                    art,
                    authorized_publishers=frozenset(
                        self._authorized_model_publishers
                    ),
                    at=at,
                )
                if unauth is not None:
                    self._findings.setdefault(art.artifact_id, []).append(unauth)

            # Tool overreach
            if art.stage is AIStage.TOOL:
                ov = detect_tool_overreach(
                    art,
                    allowed_capabilities=frozenset(
                        self._allowed_tool_capabilities
                    ),
                    at=at,
                )
                if ov is not None:
                    self._findings.setdefault(art.artifact_id, []).append(ov)

            # Discontinuity
            disc = detect_ai_discontinuity(self._graph, art.artifact_id, at=at)
            if disc is not None:
                self._findings.setdefault(art.artifact_id, []).append(disc)

        # Continuity per artifact
        publisher_trust = {
            pid: pub.trust for pid, pub in self._publishers.items()
        }
        attestations_map = {
            aid: tuple(lst) for aid, lst in self._attestations.items()
        }
        findings_map = {
            aid: tuple(lst) for aid, lst in self._findings.items()
        }

        records: List[AIArtifactStateRecord] = []
        for art in self._graph.all_artifacts():
            result = analyse_ai_continuity(
                self._graph, art.artifact_id,
                publisher_trust=publisher_trust,
                attestations=attestations_map,
                link_postures=self._link_postures,
                findings_by_artifact=findings_map,
                at=at,
            )
            self._continuity[art.artifact_id] = result

            previous = self._labels.get(art.artifact_id, TrustLabel.UNKNOWN)
            if previous is not result.label:
                verified = (
                    result.continuity >= 0.6
                    and not is_untrusted(result.label)
                )
                decision = evaluate_transition(TransitionRequest(
                    entity_id=art.artifact_id,
                    from_label=previous,
                    to_label=result.label,
                    reason="recompute",
                    verified=verified,
                ))
                if decision.outcome in (
                    TransitionOutcome.REJECTED_INVALID,
                    TransitionOutcome.REQUIRES_VERIFICATION,
                ):
                    result = AIContinuityResult(
                        artifact_id=result.artifact_id,
                        label=previous,
                        trust=result.trust,
                        continuity=result.continuity,
                        findings=result.findings,
                        chain=result.chain,
                        rationale=result.rationale + " | transition held",
                        at=result.at,
                    )

            self._labels[art.artifact_id] = result.label

            rec = AIArtifactStateRecord(
                artifact_id=art.artifact_id,
                label=result.label,
                continuity=result.continuity,
                findings_count=len(result.findings),
                updated_at=at,
            )
            self._store.put(rec)
            records.append(rec)

        self._violations = check_invariants(self.snapshot())
        return tuple(records)

    # ---- queries ---------------------------------------------------------

    def label(self, artifact_id: str) -> Optional[TrustLabel]:
        return self._labels.get(artifact_id)

    def continuity(self, artifact_id: str) -> Optional[AIContinuityResult]:
        return self._continuity.get(artifact_id)

    def state(self, artifact_id: str) -> Optional[AIArtifactStateRecord]:
        return self._store.get(artifact_id)

    def findings(self, artifact_id: str) -> Tuple[AIBreakFinding, ...]:
        return tuple(self._findings.get(artifact_id, ()))

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return self._violations

    def snapshot(self) -> AISupplyChainSnapshot:
        artifacts: Dict[str, ArtifactSnapshot] = {}
        for a in self._graph.all_artifacts():
            rec = self._store.get(a.artifact_id)
            if rec is None:
                continue
            artifacts[a.artifact_id] = ArtifactSnapshot(
                artifact=a,
                label=rec.label,
                continuity=rec.continuity,
                findings=tuple(self._findings.get(a.artifact_id, ())),
            )
        return AISupplyChainSnapshot(
            graph=self._graph,
            artifacts=artifacts,
            attestations={
                aid: tuple(lst) for aid, lst in self._attestations.items()
            },
            publishers=dict(self._publishers),
        )


# =============================================================================
# SECTION 13 — TESTS
# =============================================================================


def _t0() -> datetime:
    from datetime import timezone
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _ev(at: datetime, conf: float = 0.9) -> Evidence:
    return Evidence(evidence_id="e", source="test", confidence=conf,
                    observed_at=at, payload={})


def _model_sec(*, family: ModelFamily = ModelFamily.LLM,
               params: int = 7_000_000_000,
               weights_digest: str = "wD",
               licence: str = "apache-2.0",
               encrypted: bool = True,
               fine_tune: bool = False,
               base_digest: Optional[str] = None,
               provenance_verified: bool = True,
               known_unsafe: bool = False) -> ModelSecurity:
    return ModelSecurity(
        family=family, parameter_count=params, weights_digest=weights_digest,
        licence=licence, weights_encrypted=encrypted,
        is_fine_tune=fine_tune, base_model_digest=base_digest,
        training_data_provenance_verified=provenance_verified,
        known_unsafe=known_unsafe,
    )


def _tool(tid: str, caps: Iterable[ToolCapability],
          sandboxed: bool = True,
          egress_allow: Iterable[str] = (),
          max_calls: Optional[int] = 60,
          reads_untrusted: bool = False) -> ToolSecurity:
    return ToolSecurity(
        tool_id=tid, capabilities=frozenset(caps),
        sandboxed=sandboxed, egress_allowlist=frozenset(egress_allow),
        max_calls_per_minute=max_calls,
        reads_untrusted_content=reads_untrusted,
    )


def _agent(aid: str, tools: Iterable[str],
           depth: int = 1,
           sandboxed: bool = True,
           egress: bool = False,
           external_input: bool = True,
           prompt_signed: bool = True) -> AgentSecurity:
    return AgentSecurity(
        agent_id=aid, allowed_tools=frozenset(tools),
        max_delegation_depth=depth, sandboxed=sandboxed,
        has_network_egress=egress, accepts_external_input=external_input,
        system_prompt_signed=prompt_signed,
    )


def _art(aid: str, stage: AIStage, *, digest: str = "d",
         name: str = "n", producer: str = "p",
         parent: Optional[str] = None,
         at: Optional[datetime] = None,
         model: Optional[ModelSecurity] = None,
         agent: Optional[AgentSecurity] = None,
         tool: Optional[ToolSecurity] = None) -> AIArtifact:
    return AIArtifact(
        artifact_id=aid, stage=stage, name=name, digest=digest,
        producer_id=producer, parent_artifact_id=parent,
        derived_at=at or _t0(), model=model, agent=agent, tool=tool,
    )


def _link(parent: str, child: str,
          pdigest: str = "d", cdigest: str = "d") -> AIChainLink:
    return AIChainLink(
        parent_artifact_id=parent, child_artifact_id=child,
        expected_parent_digest=pdigest, expected_child_digest=cdigest,
    )


def _att(att_id: str, art_id: str, *, digest: str = "d",
         kind: str = "model_card", valid: bool = True) -> AIAttestation:
    return AIAttestation(
        attestation_id=att_id, subject_artifact_id=art_id,
        subject_digest=digest, attestation_kind=kind,
        signer_id="signer", signature_valid=valid, signed_at=_t0(),
        payload_digest="pd", evidence=_ev(_t0()),
    )


# ---- domain tests ---------------------------------------------------------

def test_stage_order_ai() -> None:
    assert ai_stage_order(AIStage.DATASET) < ai_stage_order(AIStage.MODEL)
    assert ai_stage_order(AIStage.MODEL) < ai_stage_order(AIStage.AGENT)
    assert ai_stage_order(AIStage.AGENT) < ai_stage_order(AIStage.RUNTIME)


def test_publisher_trust_bounds() -> None:
    try:
        AIPublisher(publisher_id="p", trust=1.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_model_sec_fine_tune_requires_base() -> None:
    try:
        ModelSecurity(
            family=ModelFamily.LLM, parameter_count=1, weights_digest="d",
            licence="apache-2.0", is_fine_tune=True, base_model_digest=None,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_artifact_requires_model_sec_for_model_stage() -> None:
    try:
        AIArtifact(
            artifact_id="m", stage=AIStage.MODEL, name="m", digest="d",
            producer_id="p", parent_artifact_id=None, derived_at=_t0(),
            model=None,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_artifact_requires_agent_sec_for_agent_stage() -> None:
    try:
        AIArtifact(
            artifact_id="a", stage=AIStage.AGENT, name="a", digest="d",
            producer_id="p", parent_artifact_id=None, derived_at=_t0(),
            agent=None,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_artifact_requires_tool_sec_for_tool_stage() -> None:
    try:
        AIArtifact(
            artifact_id="t", stage=AIStage.TOOL, name="t", digest="d",
            producer_id="p", parent_artifact_id=None, derived_at=_t0(),
            tool=None,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_canonical_digest_deterministic() -> None:
    assert canonical_digest({"a": 1, "b": 2}) == canonical_digest({"b": 2, "a": 1})


# ---- sub-model scores -----------------------------------------------------

def test_model_safe_low_score() -> None:
    m = _model_sec()
    assert m.risky_score() < 0.2


def test_model_known_unsafe_high() -> None:
    m = _model_sec(known_unsafe=True)
    assert m.risky_score() >= 0.4


def test_model_fine_tune_without_provenance_risk() -> None:
    m = _model_sec(fine_tune=True, base_digest="bD", provenance_verified=False)
    assert m.risky_score() >= 0.2


def test_tool_safe_low_score() -> None:
    t = _tool("t", [ToolCapability.FILESYSTEM_READ])
    assert t.dangerous_score() < 0.3


def test_tool_shell_unsandboxed_high() -> None:
    t = _tool("t", [ToolCapability.SHELL_EXEC], sandboxed=False)
    assert t.dangerous_score() >= 0.5


def test_agent_safe_low() -> None:
    a = _agent("a", tools=("read",), depth=1)
    assert a.dangerous_score() < 0.3


def test_agent_unsigned_prompt_raises_score() -> None:
    a = _agent("a", tools=(), depth=1, prompt_signed=False)
    assert a.dangerous_score() >= 0.2


# ---- graph tests ----------------------------------------------------------

def test_graph_rejects_duplicate_artifact() -> None:
    g = AIChainGraph()
    g.add_artifact(_art("s", AIStage.DATASET))
    try:
        g.add_artifact(_art("s", AIStage.DATASET))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_graph_link_stage_order_enforced() -> None:
    g = AIChainGraph()
    g.add_artifact(_art("d", AIStage.DATASET))
    g.add_artifact(_art("s2", AIStage.DATASET))
    try:
        g.add_link(_link("s2", "d"))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_graph_rejects_duplicate_link() -> None:
    g = AIChainGraph()
    g.add_artifact(_art("d", AIStage.DATASET))
    g.add_artifact(_art("m", AIStage.MODEL, model=_model_sec()))
    g.add_link(_link("d", "m"))
    try:
        g.add_link(_link("d", "m"))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_graph_parents_of() -> None:
    g = AIChainGraph()
    g.add_artifact(_art("d", AIStage.DATASET))
    g.add_artifact(_art("m", AIStage.MODEL, model=_model_sec()))
    g.add_link(_link("d", "m"))
    assert g.parents_of("m") == ("d",)


# ---- trust tests ----------------------------------------------------------

def test_combine_trust_empty_neutral() -> None:
    s = combine_trust([], _t0())
    assert s.score == NEUTRAL_SCORE and s.confidence == 0.0


def test_combine_trust_positive() -> None:
    sig = TrustSignal("s", 1.0, 1.0, _t0(), _ev(_t0()))
    assert combine_trust([sig], _t0()).score == 1.0


def test_derive_label_unknown_low_conf() -> None:
    st = TrustState(0.9, 0.1, (), _t0())
    assert derive_label(st) is TrustLabel.UNKNOWN


# ---- break detection ------------------------------------------------------

def test_model_substitution_detected() -> None:
    g = AIChainGraph()
    g.add_artifact(_art("m", AIStage.MODEL,
                        model=_model_sec(weights_digest="DREAL")))
    f = detect_model_substitution(
        g, "m", expected_weights_digest="DOTHER", at=_t0(),
    )
    assert f is not None and f.kind is AIBreakKind.MODEL_SUBSTITUTION


def test_poisoned_dependency_detected() -> None:
    findings = detect_poisoned_dependency(
        {"lib": "aaa"}, {"lib": "bbb"},
        artifact_id="x",
        poisoned_hashes=frozenset({"bbb"}),
        at=_t0(),
    )
    assert any(f.kind is AIBreakKind.POISONED_DEPENDENCY and f.severity == 5
               for f in findings)


def test_poisoned_dependency_generic_mismatch() -> None:
    findings = detect_poisoned_dependency(
        {"lib": "aaa"}, {"lib": "ccc"},
        artifact_id="x",
        poisoned_hashes=frozenset({"bbb"}),
        at=_t0(),
    )
    assert any(f.kind is AIBreakKind.POISONED_DEPENDENCY and f.severity == 4
               for f in findings)


def test_poisoned_dependency_missing() -> None:
    findings = detect_poisoned_dependency(
        {"lib": "aaa"}, {},
        artifact_id="x",
        poisoned_hashes=frozenset(),
        at=_t0(),
    )
    assert any(f.kind is AIBreakKind.TRUST_CHAIN_DISCONTINUITY
               for f in findings)


def test_unauthorized_model_update_detected() -> None:
    art = _art("m", AIStage.MODEL, producer="rogue", model=_model_sec())
    f = detect_unauthorized_model_update(
        art, authorized_publishers=frozenset({"trusted"}), at=_t0(),
    )
    assert f is not None and f.kind is AIBreakKind.UNAUTHORIZED_MODEL_UPDATE


def test_ai_package_compromise_known_compromised() -> None:
    art = _art("p", AIStage.PACKAGE)
    pub = AIPublisher("evil", 0.9, known_compromised=True)
    f = detect_ai_package_compromise(art, producer=pub, at=_t0())
    assert f is not None and f.kind is AIBreakKind.AI_PACKAGE_COMPROMISE


def test_ai_package_compromise_low_trust() -> None:
    art = _art("p", AIStage.PACKAGE)
    pub = AIPublisher("sketchy", 0.1)
    f = detect_ai_package_compromise(art, producer=pub, at=_t0())
    assert f is not None and f.kind is AIBreakKind.AI_PACKAGE_COMPROMISE


def test_provenance_break_model_no_attestation() -> None:
    art = _art("m", AIStage.MODEL, model=_model_sec())
    f = detect_ai_provenance_break(art, (), at=_t0())
    assert f is not None and f.kind is AIBreakKind.PROVENANCE_BREAK


def test_provenance_break_invalid_signature() -> None:
    art = _art("m", AIStage.MODEL, digest="d", model=_model_sec())
    att = _att("a", "m", digest="d", valid=False)
    f = detect_ai_provenance_break(art, (att,), at=_t0())
    assert f is not None and f.kind is AIBreakKind.PROVENANCE_BREAK


def test_provenance_break_digest_mismatch() -> None:
    art = _art("m", AIStage.MODEL, digest="dR", model=_model_sec())
    att = _att("a", "m", digest="dX")
    f = detect_ai_provenance_break(art, (att,), at=_t0())
    assert f is not None and f.kind is AIBreakKind.MODEL_SUBSTITUTION


def test_runtime_ai_divergence_detected() -> None:
    art = _art("r", AIStage.RUNTIME, digest="dR")
    f = detect_runtime_ai_divergence(art, expected_digest="dX", at=_t0())
    assert f is not None and f.kind is AIBreakKind.RUNTIME_DIVERGENCE


def test_tool_overreach_detected() -> None:
    art = _art("t", AIStage.TOOL,
               tool=_tool("t", [ToolCapability.SHELL_EXEC]))
    f = detect_tool_overreach(
        art, allowed_capabilities=frozenset({ToolCapability.FILESYSTEM_READ}),
        at=_t0(),
    )
    assert f is not None and f.kind is AIBreakKind.TOOL_OVERREACH


def test_agent_overreach_tools_detected() -> None:
    art = _art("a", AIStage.AGENT,
               agent=_agent("a", tools=("t1",)))
    f = detect_agent_overreach(
        art, declared_allowed_tools=frozenset({"t1"}),
        tools_reachable=frozenset({"t1", "t2"}),
        max_delegation_depth=2, at=_t0(),
    )
    assert f is not None and f.kind is AIBreakKind.AGENT_OVERREACH


def test_agent_overreach_depth_detected() -> None:
    art = _art("a", AIStage.AGENT,
               agent=_agent("a", tools=(), depth=5))
    f = detect_agent_overreach(
        art, declared_allowed_tools=frozenset(),
        tools_reachable=frozenset(),
        max_delegation_depth=2, at=_t0(),
    )
    assert f is not None and f.kind is AIBreakKind.AGENT_OVERREACH


def test_ai_discontinuity_non_root_without_parent() -> None:
    g = AIChainGraph()
    g.add_artifact(_art("m", AIStage.MODEL, model=_model_sec()))
    f = detect_ai_discontinuity(g, "m", at=_t0())
    assert f is not None and f.kind is AIBreakKind.TRUST_CHAIN_DISCONTINUITY


def test_ai_discontinuity_dataset_is_root() -> None:
    g = AIChainGraph()
    g.add_artifact(_art("d", AIStage.DATASET))
    assert detect_ai_discontinuity(g, "d", at=_t0()) is None


# ---- continuity -----------------------------------------------------------

def test_effective_ai_continuity_no_penalties() -> None:
    c = effective_ai_continuity(
        root_trust=1.0, link_postures=[1.0], intrinsic_risk=0.0, findings=[],
    )
    assert c == 1.0


def test_effective_ai_continuity_weak_link_halves() -> None:
    c = effective_ai_continuity(
        root_trust=1.0, link_postures=[0.0], intrinsic_risk=0.0, findings=[],
    )
    assert abs(c - 0.5) < 1e-9


def test_effective_ai_continuity_intrinsic_risk_penalty() -> None:
    c = effective_ai_continuity(
        root_trust=1.0, link_postures=[], intrinsic_risk=1.0, findings=[],
    )
    assert c <= 0.5 + 1e-9


def test_effective_ai_continuity_findings_penalize() -> None:
    f = AIBreakFinding(
        kind=AIBreakKind.RUNTIME_DIVERGENCE, artifact_id="x",
        parent_artifact_id=None, detail="d", severity=5, at=_t0(),
    )
    c = effective_ai_continuity(
        root_trust=1.0, link_postures=[], intrinsic_risk=0.0, findings=[f],
    )
    assert c < 1.0


def test_analyse_ai_continuity_returns_chain() -> None:
    g = AIChainGraph()
    g.add_artifact(_art("d", AIStage.DATASET, digest="dD", producer="pub"))
    g.add_artifact(_art("m", AIStage.MODEL, digest="dM", parent="d",
                        producer="pub", model=_model_sec()))
    g.add_link(_link("d", "m", pdigest="dD", cdigest="dM"))
    res = analyse_ai_continuity(
        g, "m",
        publisher_trust={"pub": 0.95},
        attestations={"m": (_att("a", "m", digest="dM"),)},
        link_postures={("d", "m"): 0.95},
        findings_by_artifact={},
        at=_t0(),
    )
    assert res.chain == ("d", "m")
    assert res.continuity > 0.3


# ---- transitions ----------------------------------------------------------

def test_transition_compromise_to_trusted_rejected() -> None:
    d = evaluate_transition(TransitionRequest(
        entity_id="a", from_label=TrustLabel.COMPROMISED,
        to_label=TrustLabel.TRUSTED, reason="x", verified=True,
    ))
    assert d.outcome is TransitionOutcome.REJECTED_INVALID


def test_transition_quarantine_recovery_requires_verification() -> None:
    d = evaluate_transition(TransitionRequest(
        entity_id="a", from_label=TrustLabel.QUARANTINED,
        to_label=TrustLabel.OBSERVED, reason="x", verified=False,
    ))
    assert d.outcome is TransitionOutcome.REQUIRES_VERIFICATION


def test_transition_reason_required() -> None:
    d = evaluate_transition(TransitionRequest(
        entity_id="a", from_label=TrustLabel.OBSERVED,
        to_label=TrustLabel.TRUSTED, reason="", verified=True,
    ))
    assert d.outcome is TransitionOutcome.REJECTED_INVALID


# ---- engine integration ---------------------------------------------------

def _build_clean_ai_chain() -> AISupplyChainTrustEngine:
    eng = AISupplyChainTrustEngine()
    eng.register_publisher(AIPublisher("data-pub", 0.95))
    eng.register_publisher(AIPublisher("model-pub", 0.95))
    eng.register_publisher(AIPublisher("app-pub", 0.95))
    eng.authorize_model_publisher("model-pub")

    eng.add_artifact(_art("ds", AIStage.DATASET, digest="dDS",
                          producer="data-pub"))
    eng.add_artifact(_art("model", AIStage.MODEL, digest="dM",
                          producer="model-pub", parent="ds",
                          model=_model_sec(weights_digest="wM")))
    eng.add_artifact(_art("app", AIStage.APPLICATION, digest="dA",
                          producer="app-pub", parent="model"))

    eng.add_link(_link("ds", "model", pdigest="dDS", cdigest="dM"),
                 posture=0.95)
    eng.add_link(_link("model", "app", pdigest="dM", cdigest="dA"),
                 posture=0.95)

    eng.add_attestation(_att("att-ds", "ds", digest="dDS",
                             kind="dataset_card"))
    eng.add_attestation(_att("att-model", "model", digest="dM",
                             kind="model_card"))
    return eng


def test_engine_clean_chain_no_violations() -> None:
    eng = _build_clean_ai_chain()
    eng.recompute(at=_t0())
    assert eng.violations() == ()


def test_engine_model_substitution_via_expected_digest() -> None:
    eng = _build_clean_ai_chain()
    # Attestation bound to different digest → MODEL_SUBSTITUTION
    eng.add_attestation(_att("bad", "model", digest="dWRONG"))
    records = eng.recompute(at=_t0())
    m = next(r for r in records if r.artifact_id == "model")
    assert label_severity(m.label) >= label_severity(TrustLabel.SUSPICIOUS)


def test_engine_unauthorized_model_publisher_flagged() -> None:
    eng = AISupplyChainTrustEngine()
    eng.register_publisher(AIPublisher("rogue", 0.9))
    # Note: do NOT authorize this publisher
    eng.add_artifact(_art("ds", AIStage.DATASET, digest="dD", producer="rogue"))
    eng.add_artifact(_art("m", AIStage.MODEL, digest="dM",
                          producer="rogue", parent="ds",
                          model=_model_sec()))
    eng.add_link(_link("ds", "m", pdigest="dD", cdigest="dM"), posture=0.9)
    eng.add_attestation(_att("a-ds", "ds", digest="dD",
                             kind="dataset_card"))
    eng.add_attestation(_att("a-m", "m", digest="dM"))
    records = eng.recompute(at=_t0())
    m = next(r for r in records if r.artifact_id == "m")
    assert label_severity(m.label) >= label_severity(TrustLabel.SUSPICIOUS)


def test_engine_poisoned_ai_dependency_flagged() -> None:
    eng = _build_clean_ai_chain()
    eng.mark_ai_dependency_poisoned("BADHASH")
    findings = eng.report_ai_dependency_digests(
        "app",
        declared={"libx": "GOODHASH"},
        observed={"libx": "BADHASH"},
        at=_t0(),
    )
    assert any(f.kind is AIBreakKind.POISONED_DEPENDENCY and f.severity == 5
               for f in findings)
    records = eng.recompute(at=_t0())
    app = next(r for r in records if r.artifact_id == "app")
    assert label_severity(app.label) >= label_severity(TrustLabel.COMPROMISED)


def test_engine_tool_not_sandboxed_invariant() -> None:
    eng = AISupplyChainTrustEngine()
    eng.register_publisher(AIPublisher("p", 0.9))
    eng.add_artifact(_art("ds", AIStage.DATASET, digest="dD", producer="p"))
    eng.add_artifact(_art(
        "t", AIStage.TOOL, digest="dT", producer="p", parent="ds",
        tool=_tool("t", [ToolCapability.SHELL_EXEC], sandboxed=False),
    ))
    eng.add_link(_link("ds", "t", pdigest="dD", cdigest="dT"), posture=0.9)
    eng.add_attestation(_att("a-ds", "ds", digest="dD",
                             kind="dataset_card"))
    eng.recompute(at=_t0())
    assert any(v.invariant_id == "ai.high_risk_tool_not_sandboxed"
               for v in eng.violations())


def test_engine_agent_overreach_via_report() -> None:
    eng = AISupplyChainTrustEngine()
    eng.register_publisher(AIPublisher("p", 0.9))
    eng.add_artifact(_art("ds", AIStage.DATASET, digest="dD", producer="p"))
    eng.add_artifact(_art(
        "a", AIStage.AGENT, digest="dA", producer="p", parent="ds",
        agent=_agent("a", tools=("t1",), depth=1),
    ))
    eng.add_link(_link("ds", "a", pdigest="dD", cdigest="dA"), posture=0.9)
    eng.add_attestation(_att("a-ds", "ds", digest="dD",
                             kind="dataset_card"))
    f = eng.report_agent_reachable_tools(
        "a", reachable=frozenset({"t1", "t2"}), at=_t0(),
    )
    assert f is not None and f.kind is AIBreakKind.AGENT_OVERREACH


def test_engine_trusted_without_attestation_violation() -> None:
    eng = AISupplyChainTrustEngine()
    eng.register_publisher(AIPublisher("p", 1.0))
    eng.add_artifact(_art("ds", AIStage.DATASET, digest="dD", producer="p"))
    # Manually mark as TRUSTED without attestations
    eng._labels["ds"] = TrustLabel.TRUSTED
    eng._store.put(AIArtifactStateRecord(
        artifact_id="ds", label=TrustLabel.TRUSTED,
        continuity=1.0, findings_count=0, updated_at=_t0(),
    ))
    violations = check_invariants(eng.snapshot())
    assert any(v.invariant_id == "ai.trusted_model_needs_attestation"
               for v in violations)


def test_engine_digest_reuse_across_stages() -> None:
    eng = AISupplyChainTrustEngine()
    eng.register_publisher(AIPublisher("p", 0.9))
    eng.add_artifact(_art("ds", AIStage.DATASET, digest="SAME",
                          producer="p"))
    eng.add_artifact(_art("m", AIStage.MODEL, digest="SAME",
                          producer="p", parent="ds",
                          model=_model_sec(weights_digest="wS")))
    eng.add_link(_link("ds", "m", pdigest="SAME", cdigest="SAME"),
                 posture=0.9)
    eng.add_attestation(_att("a-ds", "ds", digest="SAME",
                             kind="dataset_card"))
    eng.add_attestation(_att("a-m", "m", digest="SAME"))
    eng.recompute(at=_t0())
    assert any(v.invariant_id == "ai.digest_reuse_across_stages"
               for v in eng.violations())


def test_engine_chain_discontinuity_flagged() -> None:
    eng = AISupplyChainTrustEngine()
    eng.register_publisher(AIPublisher("p", 0.9))
    eng.add_artifact(_art("m", AIStage.MODEL, digest="dM",
                          producer="p", model=_model_sec()))
    eng.add_attestation(_att("a", "m", digest="dM"))
    eng.recompute(at=_t0())
    assert any(v.invariant_id == "ai.chain_discontinuity"
               for v in eng.violations())


# ---- store tests ----------------------------------------------------------

def test_in_memory_store_rejects_stale() -> None:
    s = InMemoryAISupplyChainStore()
    t = _t0()
    s.put(AIArtifactStateRecord("a", TrustLabel.TRUSTED, 0.9, 0, t))
    earlier = t.replace(year=t.year - 1)
    try:
        s.put(AIArtifactStateRecord("a", TrustLabel.UNKNOWN, 0.5, 0, earlier))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_artifact_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "ai.db")
    store = SqliteAISupplyChainStore(db)
    t = _t0()
    store.put(AIArtifactStateRecord("m", TrustLabel.TRUSTED, 0.9, 2, t))
    got = store.get("m")
    assert got is not None and got.label is TrustLabel.TRUSTED
    assert got.findings_count == 2


def test_sqlite_store_attestation_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "ai.db")
    store = SqliteAISupplyChainStore(db)
    att = _att("a1", "m", digest="dX", kind="model_card")
    store.put_attestation(att)
    got = store.get_attestation("a1")
    assert got is not None and got.subject_digest == "dX"
    assert got.attestation_kind == "model_card"


def test_sqlite_store_publisher_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "ai.db")
    store = SqliteAISupplyChainStore(db)
    pub = AIPublisher("pub", 0.85, verified=True, known_compromised=False)
    store.put_publisher(pub)
    got = store.get_publisher("pub")
    assert got is not None and got.trust == 0.85
    assert got.known_compromised is False


# =============================================================================
# SECTION 14 — MANUAL RUNNER
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
