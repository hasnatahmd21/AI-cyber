"""
HYDRA POST-CORE — PHASE 30: EMERGENT THREAT DISCOVERY
=========================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * Domain — 7 component kinds, 8 capability domains, 4 composition
    kinds, 6 dangerous-pattern classes, 3 safety verdicts
  * Capability model — each component declares capabilities with
    levels (none / read / write / execute / admin)
  * Individual safety assessment — every component is checked against
    dangerous patterns *by itself*
  * Composition model — sequential / parallel / delegated / chained
  * Emergent capability calculator — union of capabilities reachable
    via composition, with amplification for delegated / chained
  * Dangerous pattern matcher — pattern matches on capability set
  * Emergent threat detector — pattern matched by composition but NOT
    by any individual component
  * Explicit proofs on every finding:
      - individually_safe_verified=True
      - composition_required=True
      - not_a_compromise_claim=True
  * Findings roll-up by threat class, severity, capability domain
  * Machine-checkable emergent-threat invariants
  * In-memory + SQLite stores
  * Phase-30 engine facade
  * Full test suite + manual runner

Central thesis:
    SAFE agent + SAFE tool + SAFE API + SAFE identity
        =  UNSAFE combined capability

This phase identifies threats that only appear when individually
benign components are composed. It is NOT another detection engine
and it does NOT claim compromise.

No third-party dependencies.

Run tests:
    python hydra_phase30_emergent_threat_discovery.py
    pytest hydra_phase30_emergent_threat_discovery.py -q
"""
from __future__ import annotations

import itertools
import json
import sqlite3
from collections import defaultdict, deque
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
    Set,
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


class ComponentKind(str, Enum):
    AGENT = "agent"
    TOOL = "tool"
    API = "api"
    IDENTITY = "identity"
    SERVICE = "service"
    DATASET = "dataset"
    WORKFLOW = "workflow"


ALL_COMPONENT_KINDS: Tuple[ComponentKind, ...] = tuple(ComponentKind)


class CapabilityDomain(str, Enum):
    DATA_READ = "data_read"
    DATA_WRITE = "data_write"
    CODE_EXECUTE = "code_execute"
    NETWORK_EGRESS = "network_egress"
    CREDENTIAL_ACCESS = "credential_access"
    AUTHORITY_GRANT = "authority_grant"
    CONTROL_MODIFY = "control_modify"
    HUMAN_REVIEW = "human_review"


ALL_DOMAINS: Tuple[CapabilityDomain, ...] = tuple(CapabilityDomain)


class CapabilityLevel(int, Enum):
    NONE = 0
    READ = 1
    WRITE = 2
    EXECUTE = 3
    ADMIN = 4


_LEVEL_RANK: Mapping[CapabilityLevel, int] = {
    CapabilityLevel.NONE: 0,
    CapabilityLevel.READ: 1,
    CapabilityLevel.WRITE: 2,
    CapabilityLevel.EXECUTE: 3,
    CapabilityLevel.ADMIN: 4,
}


def level_rank(l: CapabilityLevel) -> int:
    return _LEVEL_RANK[l]


class CompositionKind(str, Enum):
    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"
    DELEGATED = "delegated"
    CHAINED = "chained"


# For DELEGATED / CHAINED we apply a modest amplification: capabilities
# can appear *stronger* because the composed chain effectively acts as
# a single principal. Amplification is bounded to +1 level per step.
_AMPLIFICATION: Mapping[CompositionKind, int] = {
    CompositionKind.SEQUENTIAL: 0,
    CompositionKind.PARALLEL: 0,
    CompositionKind.DELEGATED: 1,
    CompositionKind.CHAINED: 1,
}


def amplification(k: CompositionKind) -> int:
    return _AMPLIFICATION[k]


class SafetyVerdict(str, Enum):
    SAFE = "safe"
    LIMITED = "limited"
    UNSAFE = "unsafe"


class ThreatClass(str, Enum):
    EMERGENT_CAPABILITY = "emergent_capability"
    PRIVILEGE_CHAIN = "privilege_chain"
    DATA_FLOW = "data_flow"
    AUTHORITY_AMPLIFICATION = "authority_amplification"
    CONTROL_BYPASS = "control_bypass"


class ConfidenceClass(str, Enum):
    SPECULATIVE = "speculative"
    INFERRED = "inferred"
    OBSERVED = "observed"


# =============================================================================
# SECTION 3 — DANGEROUS PATTERNS
# =============================================================================


# A dangerous pattern requires *all* listed (domain → min_level) to hold.
@dataclass(frozen=True)
class DangerousPattern:
    pattern_id: str
    threat_class: ThreatClass
    required: Mapping[CapabilityDomain, CapabilityLevel]
    severity: int
    description: str

    def __post_init__(self) -> None:
        if not self.pattern_id:
            raise ValueError("pattern_id is required")
        if not self.required:
            raise ValueError("required must be non-empty")
        if not 1 <= self.severity <= 5:
            raise ValueError("severity must be in [1,5]")
        if not self.description:
            raise ValueError("description is required")

    def matches(
        self, caps: Mapping[CapabilityDomain, CapabilityLevel],
    ) -> bool:
        for domain, min_level in self.required.items():
            have = caps.get(domain, CapabilityLevel.NONE)
            if level_rank(have) < level_rank(min_level):
                return False
        return True

    def required_domains(self) -> FrozenSet[CapabilityDomain]:
        return frozenset(self.required.keys())


DEFAULT_PATTERNS: Tuple[DangerousPattern, ...] = (
    DangerousPattern(
        pattern_id="exfil_read_plus_egress",
        threat_class=ThreatClass.DATA_FLOW,
        required={
            CapabilityDomain.DATA_READ: CapabilityLevel.READ,
            CapabilityDomain.NETWORK_EGRESS: CapabilityLevel.WRITE,
        },
        severity=4,
        description="Read + outbound network access enables data exfiltration",
    ),
    DangerousPattern(
        pattern_id="cred_theft",
        threat_class=ThreatClass.EMERGENT_CAPABILITY,
        required={
            CapabilityDomain.CREDENTIAL_ACCESS: CapabilityLevel.READ,
            CapabilityDomain.NETWORK_EGRESS: CapabilityLevel.WRITE,
        },
        severity=5,
        description="Credential access + egress enables credential theft",
    ),
    DangerousPattern(
        pattern_id="rce_via_composition",
        threat_class=ThreatClass.EMERGENT_CAPABILITY,
        required={
            CapabilityDomain.CODE_EXECUTE: CapabilityLevel.EXECUTE,
            CapabilityDomain.NETWORK_EGRESS: CapabilityLevel.WRITE,
        },
        severity=5,
        description="Code execution + egress enables remote exploitation",
    ),
    DangerousPattern(
        pattern_id="persistence_write_plus_cred",
        threat_class=ThreatClass.EMERGENT_CAPABILITY,
        required={
            CapabilityDomain.DATA_WRITE: CapabilityLevel.WRITE,
            CapabilityDomain.CREDENTIAL_ACCESS: CapabilityLevel.READ,
        },
        severity=4,
        description="Data write + credential access enables durable persistence",
    ),
    DangerousPattern(
        pattern_id="priv_esc_via_grant_plus_execute",
        threat_class=ThreatClass.PRIVILEGE_CHAIN,
        required={
            CapabilityDomain.AUTHORITY_GRANT: CapabilityLevel.WRITE,
            CapabilityDomain.CODE_EXECUTE: CapabilityLevel.EXECUTE,
        },
        severity=5,
        description="Authority grant + code execution enables privilege escalation",
    ),
    DangerousPattern(
        pattern_id="audit_tampering",
        threat_class=ThreatClass.CONTROL_BYPASS,
        required={
            CapabilityDomain.CONTROL_MODIFY: CapabilityLevel.WRITE,
            CapabilityDomain.DATA_WRITE: CapabilityLevel.WRITE,
        },
        severity=4,
        description="Control modification + data write enables audit tampering",
    ),
    DangerousPattern(
        pattern_id="unsupervised_high_impact",
        threat_class=ThreatClass.EMERGENT_CAPABILITY,
        required={
            CapabilityDomain.CODE_EXECUTE: CapabilityLevel.EXECUTE,
            CapabilityDomain.NETWORK_EGRESS: CapabilityLevel.WRITE,
            CapabilityDomain.HUMAN_REVIEW: CapabilityLevel.NONE,
        },
        severity=5,
        description=(
            "High-impact execution + egress without human review "
            "enables unsupervised high-impact action"
        ),
    ),
    DangerousPattern(
        pattern_id="authority_amplification",
        threat_class=ThreatClass.AUTHORITY_AMPLIFICATION,
        required={
            CapabilityDomain.AUTHORITY_GRANT: CapabilityLevel.EXECUTE,
            CapabilityDomain.CREDENTIAL_ACCESS: CapabilityLevel.WRITE,
        },
        severity=5,
        description=(
            "Authority grant + credential write amplifies effective "
            "authority beyond declared scope"
        ),
    ),
    DangerousPattern(
        pattern_id="code_execute_plus_credential_access",
        threat_class=ThreatClass.EMERGENT_CAPABILITY,
        required={
            CapabilityDomain.CODE_EXECUTE: CapabilityLevel.EXECUTE,
            CapabilityDomain.CREDENTIAL_ACCESS: CapabilityLevel.READ,
        },
        severity=5,
        description=(
            "Code execution + credential access enables code-driven "
            "credential theft or direct credential use"
        ),
    ),
    DangerousPattern(
        pattern_id="code_execute_plus_data_write",
        threat_class=ThreatClass.EMERGENT_CAPABILITY,
        required={
            CapabilityDomain.CODE_EXECUTE: CapabilityLevel.EXECUTE,
            CapabilityDomain.DATA_WRITE: CapabilityLevel.WRITE,
        },
        severity=4,
        description=(
            "Code execution + data write enables code-driven data "
            "tampering or malware deployment"
        ),
    ),
    DangerousPattern(
        pattern_id="control_modify_plus_code_execute",
        threat_class=ThreatClass.CONTROL_BYPASS,
        required={
            CapabilityDomain.CONTROL_MODIFY: CapabilityLevel.WRITE,
            CapabilityDomain.CODE_EXECUTE: CapabilityLevel.EXECUTE,
        },
        severity=5,
        description=(
            "Control modification + code execution enables disabling "
            "defenses immediately before or during an attack"
        ),
    ),
    DangerousPattern(
        pattern_id="control_modify_plus_credential_access",
        threat_class=ThreatClass.CONTROL_BYPASS,
        required={
            CapabilityDomain.CONTROL_MODIFY: CapabilityLevel.WRITE,
            CapabilityDomain.CREDENTIAL_ACCESS: CapabilityLevel.READ,
        },
        severity=4,
        description=(
            "Control modification + credential access enables "
            "disabling monitoring while accessing credentials"
        ),
    ),
)


# =============================================================================
# SECTION 4 — COMPONENT MODEL
# =============================================================================


@dataclass(frozen=True)
class ComponentProfile:
    """An AI-system component (agent, tool, api, identity, ...).

    Capabilities are declared as a mapping of domain → level. A
    component that does not declare a domain is treated as
    CapabilityLevel.NONE for that domain.
    """
    component_id: str
    kind: ComponentKind
    name: str
    capabilities: Mapping[CapabilityDomain, CapabilityLevel]
    tenant_id: str
    tags: FrozenSet[str] = frozenset()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.component_id:
            raise ValueError("component_id is required")
        if not self.name:
            raise ValueError("name is required")
        if not self.tenant_id:
            raise ValueError("tenant_id is required")
        for d, l in self.capabilities.items():
            if not isinstance(d, CapabilityDomain):
                raise ValueError(f"invalid domain {d!r}")
            if not isinstance(l, CapabilityLevel):
                raise ValueError(f"invalid level {l!r}")

    def cap(self, d: CapabilityDomain) -> CapabilityLevel:
        return self.capabilities.get(d, CapabilityLevel.NONE)

    def normalized_capabilities(
        self,
    ) -> Mapping[CapabilityDomain, CapabilityLevel]:
        return {
            d: self.capabilities.get(d, CapabilityLevel.NONE)
            for d in ALL_DOMAINS
        }


# =============================================================================
# SECTION 5 — INDIVIDUAL SAFETY
# =============================================================================


@dataclass(frozen=True)
class IndividualSafety:
    component_id: str
    verdict: SafetyVerdict
    matched_patterns: Tuple[str, ...]
    rationale: str

    def __post_init__(self) -> None:
        if not self.component_id:
            raise ValueError("component_id is required")


def assess_individual_safety(
    component: ComponentProfile,
    *,
    patterns: Iterable[DangerousPattern],
) -> IndividualSafety:
    caps = component.normalized_capabilities()
    matched: List[str] = []
    max_severity = 0
    for p in patterns:
        if p.matches(caps):
            matched.append(p.pattern_id)
            max_severity = max(max_severity, p.severity)

    if not matched:
        return IndividualSafety(
            component_id=component.component_id,
            verdict=SafetyVerdict.SAFE,
            matched_patterns=(),
            rationale="component does not match any dangerous pattern",
        )
    if max_severity >= 4:
        return IndividualSafety(
            component_id=component.component_id,
            verdict=SafetyVerdict.UNSAFE,
            matched_patterns=tuple(matched),
            rationale=(
                f"component matches {len(matched)} dangerous pattern(s) "
                f"with max severity {max_severity}"
            ),
        )
    return IndividualSafety(
        component_id=component.component_id,
        verdict=SafetyVerdict.LIMITED,
        matched_patterns=tuple(matched),
        rationale=(
            f"component matches {len(matched)} low-severity pattern(s)"
        ),
    )


# =============================================================================
# SECTION 6 — COMPOSITION MODEL
# =============================================================================


@dataclass(frozen=True)
class Composition:
    composition_id: str
    kind: CompositionKind
    component_ids: Tuple[str, ...]
    at: Optional[datetime] = None

    def __post_init__(self) -> None:
        if not self.composition_id:
            raise ValueError("composition_id is required")
        if len(self.component_ids) < 2:
            raise ValueError(
                "composition must have at least two components"
            )
        if len(set(self.component_ids)) != len(self.component_ids):
            raise ValueError("component_ids must be unique")
        if self.at is not None and self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


def compose_capabilities(
    composition: Composition,
    *,
    profiles: Mapping[str, ComponentProfile],
) -> Mapping[CapabilityDomain, CapabilityLevel]:
    """Union of capabilities across components, with amplification
    applied for DELEGATED / CHAINED compositions.

    Amplification is applied *per composition*, on the union, capped
    at ADMIN. Amplification = (1 if delegated/chained else 0) applied
    only to domains where at least two components already declare
    non-NONE capability.
    """
    missing = [cid for cid in composition.component_ids
               if cid not in profiles]
    if missing:
        raise KeyError(
            f"unknown component(s) in composition: {missing}"
        )

    union: Dict[CapabilityDomain, CapabilityLevel] = {
        d: CapabilityLevel.NONE for d in ALL_DOMAINS
    }
    presence_count: Dict[CapabilityDomain, int] = {
        d: 0 for d in ALL_DOMAINS
    }

    for cid in composition.component_ids:
        c = profiles[cid]
        for d in ALL_DOMAINS:
            lvl = c.cap(d)
            if lvl is not CapabilityLevel.NONE:
                presence_count[d] += 1
            if level_rank(lvl) > level_rank(union[d]):
                union[d] = lvl

    amp = amplification(composition.kind)
    if amp > 0:
        for d in ALL_DOMAINS:
            if presence_count[d] >= 2 and union[d] is not CapabilityLevel.NONE:
                boosted = min(
                    level_rank(union[d]) + amp, 4,
                )
                # Map rank back to CapabilityLevel
                for level in CapabilityLevel:
                    if level_rank(level) == boosted:
                        union[d] = level
                        break

    return {d: union[d] for d in ALL_DOMAINS}


# =============================================================================
# SECTION 7 — EMERGENT CAPABILITY
# =============================================================================


@dataclass(frozen=True)
class EmergentCapability:
    """A capability that appears only in the composed set — i.e. it is
    NOT the union of what any single component already provides beyond
    its own declared level for a domain that is only 'enabled' by the
    composition."""
    domain: CapabilityDomain
    composed_level: CapabilityLevel
    max_individual_level: CapabilityLevel
    contributed_by: Tuple[str, ...]

    def __post_init__(self) -> None:
        if level_rank(self.composed_level) <= \
                level_rank(self.max_individual_level):
            raise ValueError(
                "emergent capability requires composed_level > "
                "max_individual_level"
            )


def find_emergent_capabilities(
    composition: Composition,
    *,
    profiles: Mapping[str, ComponentProfile],
) -> Tuple[EmergentCapability, ...]:
    composed = compose_capabilities(composition, profiles=profiles)
    out: List[EmergentCapability] = []
    for d in ALL_DOMAINS:
        composed_level = composed[d]
        max_individual = CapabilityLevel.NONE
        contributors: List[str] = []
        for cid in composition.component_ids:
            lvl = profiles[cid].cap(d)
            if lvl is not CapabilityLevel.NONE:
                contributors.append(cid)
            if level_rank(lvl) > level_rank(max_individual):
                max_individual = lvl
        if level_rank(composed_level) > level_rank(max_individual):
            out.append(EmergentCapability(
                domain=d,
                composed_level=composed_level,
                max_individual_level=max_individual,
                contributed_by=tuple(sorted(contributors)),
            ))
    return tuple(out)


# =============================================================================
# SECTION 8 — EMERGENT THREAT FINDING
# =============================================================================


@dataclass(frozen=True)
class EmergentThreat:
    threat_id: str
    pattern_id: str
    pattern_description: str
    threat_class: ThreatClass
    composition_id: str
    composition_kind: CompositionKind
    component_ids: Tuple[str, ...]
    emergent_capabilities: Tuple[EmergentCapability, ...]
    contributing_domains: Tuple[CapabilityDomain, ...]
    severity: int
    confidence: ConfidenceClass
    individually_safe_verified: bool
    composition_required: bool
    not_a_compromise_claim: bool
    rationale: str
    at: datetime

    def __post_init__(self) -> None:
        if not self.threat_id:
            raise ValueError("threat_id is required")
        if not self.pattern_id:
            raise ValueError("pattern_id is required")
        if not self.composition_id:
            raise ValueError("composition_id is required")
        if len(self.component_ids) < 2:
            raise ValueError(
                "threat must include at least two components"
            )
        if not 1 <= self.severity <= 5:
            raise ValueError("severity must be in [1,5]")
        if self.individually_safe_verified is not True:
            raise ValueError(
                "individually_safe_verified must be True "
                "(this is a compositional, not a local, finding)"
            )
        if self.composition_required is not True:
            raise ValueError(
                "composition_required must be True"
            )
        if self.not_a_compromise_claim is not True:
            raise ValueError(
                "emergent threats must not claim compromise"
            )
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


# =============================================================================
# SECTION 9 — DETECTOR
# =============================================================================


def _threat_id(
    pattern_id: str, composition_id: str,
) -> str:
    return f"emergent:{pattern_id}:{composition_id}"


def detect_emergent_threats(
    composition: Composition,
    *,
    profiles: Mapping[str, ComponentProfile],
    patterns: Sequence[DangerousPattern],
    individual_safety: Mapping[str, IndividualSafety],
    at: datetime,
) -> Tuple[EmergentThreat, ...]:
    """Detect threats that appear at the composition level but do NOT
    appear when any single component is inspected alone."""
    if at.tzinfo is None:
        raise ValueError("at must be timezone-aware")

    # 1. Every involved component must be registered and individually
    #    safe (SAFE verdict). Otherwise this is not an *emergent*
    #    threat — it is a local problem.
    for cid in composition.component_ids:
        if cid not in profiles:
            raise KeyError(f"unknown component {cid}")
        safety = individual_safety.get(cid)
        if safety is None:
            raise KeyError(
                f"component {cid} has no individual safety assessment"
            )
        if safety.verdict is not SafetyVerdict.SAFE:
            return ()

    # 2. Compute composed capability set
    composed = compose_capabilities(composition, profiles=profiles)

    # 3. Find patterns that match the composed set
    matched_patterns = [
        p for p in patterns if p.matches(composed)
    ]
    if not matched_patterns:
        return ()

    # 4. Compute emergent capabilities (which domain-level entries
    #    exist only at the composition level)
    emergent = find_emergent_capabilities(
        composition, profiles=profiles,
    )

    out: List[EmergentThreat] = []
    for p in matched_patterns:
        # The pattern must involve at least one domain that is either:
        #   - emergent (composition-level-only), or
        #   - amplified by delegation / chaining
        # Otherwise the pattern could match a single component alone,
        # which we have already excluded via individual safety == SAFE.
        # Also require: at least 2 distinct contributing components
        # for the required domains of this pattern.
        required_domains = p.required_domains()
        contributors_per_domain: Dict[
            CapabilityDomain, Set[str]
        ] = {d: set() for d in required_domains}
        for cid in composition.component_ids:
            for d in required_domains:
                if profiles[cid].cap(d) is not CapabilityLevel.NONE:
                    contributors_per_domain[d].add(cid)

        distinct_contributors = set()
        for d in required_domains:
            distinct_contributors |= contributors_per_domain[d]

        if len(distinct_contributors) < 2:
            # Not emergent — single component already covers it
            continue

        contributing = tuple(sorted(
            d for d in required_domains
            if contributors_per_domain[d]
        ))

        rationale = (
            f"Composition of {len(composition.component_ids)} "
            f"individually-safe components ({composition.kind.value}) "
            f"produces pattern {p.pattern_id}: {p.description}"
        )
        out.append(EmergentThreat(
            threat_id=_threat_id(p.pattern_id, composition.composition_id),
            pattern_id=p.pattern_id,
            pattern_description=p.description,
            threat_class=p.threat_class,
            composition_id=composition.composition_id,
            composition_kind=composition.kind,
            component_ids=tuple(sorted(composition.component_ids)),
            emergent_capabilities=emergent,
            contributing_domains=contributing,
            severity=p.severity,
            confidence=ConfidenceClass.INFERRED,
            individually_safe_verified=True,
            composition_required=True,
            not_a_compromise_claim=True,
            rationale=rationale,
            at=at,
        ))
    return tuple(out)


# =============================================================================
# SECTION 10 — INVARIANTS
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
class EmergentSnapshot:
    components: Mapping[str, ComponentProfile]
    safety: Mapping[str, IndividualSafety]
    compositions: Tuple[Composition, ...]
    threats: Tuple[EmergentThreat, ...]
    patterns: Mapping[str, DangerousPattern]


@dataclass(frozen=True)
class EmergentInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[EmergentSnapshot],
                        Tuple[InvariantViolation, ...]]
    description: str


def _inv_no_local_threat_reported_as_emergent(
    snap: EmergentSnapshot,
) -> Tuple[InvariantViolation, ...]:
    """Every emergent threat must reference components that are all
    individually SAFE."""
    out: List[InvariantViolation] = []
    for t in snap.threats:
        for cid in t.component_ids:
            safety = snap.safety.get(cid)
            if safety is None:
                out.append(InvariantViolation(
                    invariant_id="emergent.no_local_threat",
                    severity=InvariantSeverity.CRITICAL,
                    subject_id=t.threat_id,
                    detail=f"no safety assessment for {cid}",
                ))
                continue
            if safety.verdict is not SafetyVerdict.SAFE:
                out.append(InvariantViolation(
                    invariant_id="emergent.no_local_threat",
                    severity=InvariantSeverity.CRITICAL,
                    subject_id=t.threat_id,
                    detail=(
                        f"component {cid} is not SAFE "
                        f"({safety.verdict.value})"
                    ),
                ))
    return tuple(out)


def _inv_threat_has_at_least_two_components(
    snap: EmergentSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for t in snap.threats:
        if len(t.component_ids) < 2:
            out.append(InvariantViolation(
                invariant_id="emergent.two_components",
                severity=InvariantSeverity.HIGH,
                subject_id=t.threat_id,
                detail="fewer than two components",
            ))
    return tuple(out)


def _inv_no_compromise_claim(
    snap: EmergentSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for t in snap.threats:
        if t.not_a_compromise_claim is not True:
            out.append(InvariantViolation(
                invariant_id="emergent.no_compromise_claim",
                severity=InvariantSeverity.CRITICAL,
                subject_id=t.threat_id,
                detail="threat claims compromise",
            ))
    return tuple(out)


def _inv_individually_safe_verified(
    snap: EmergentSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for t in snap.threats:
        if t.individually_safe_verified is not True:
            out.append(InvariantViolation(
                invariant_id="emergent.safe_verified",
                severity=InvariantSeverity.HIGH,
                subject_id=t.threat_id,
                detail="individually_safe_verified is not True",
            ))
    return tuple(out)


def _inv_composition_required(
    snap: EmergentSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for t in snap.threats:
        if t.composition_required is not True:
            out.append(InvariantViolation(
                invariant_id="emergent.composition_required",
                severity=InvariantSeverity.HIGH,
                subject_id=t.threat_id,
                detail="composition_required is not True",
            ))
    return tuple(out)


def _inv_severity_bounded(
    snap: EmergentSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for t in snap.threats:
        if not 1 <= t.severity <= 5:
            out.append(InvariantViolation(
                invariant_id="emergent.severity_bounded",
                severity=InvariantSeverity.HIGH,
                subject_id=t.threat_id,
                detail=f"severity {t.severity}",
            ))
    return tuple(out)


def _inv_pattern_registered(
    snap: EmergentSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for t in snap.threats:
        if t.pattern_id not in snap.patterns:
            out.append(InvariantViolation(
                invariant_id="emergent.pattern_registered",
                severity=InvariantSeverity.HIGH,
                subject_id=t.threat_id,
                detail=f"pattern {t.pattern_id} not registered",
            ))
    return tuple(out)


DEFAULT_INVARIANTS: Tuple[EmergentInvariant, ...] = (
    EmergentInvariant(
        invariant_id="emergent.no_local_threat",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_no_local_threat_reported_as_emergent,
        description="Emergent threats must not reference unsafe components.",
    ),
    EmergentInvariant(
        invariant_id="emergent.two_components",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_threat_has_at_least_two_components,
        description="Emergent threats must involve at least two components.",
    ),
    EmergentInvariant(
        invariant_id="emergent.no_compromise_claim",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_no_compromise_claim,
        description="Emergent threats must not claim compromise.",
    ),
    EmergentInvariant(
        invariant_id="emergent.safe_verified",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_individually_safe_verified,
        description="Every threat must prove individual safety.",
    ),
    EmergentInvariant(
        invariant_id="emergent.composition_required",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_composition_required,
        description="Every threat must prove composition requirement.",
    ),
    EmergentInvariant(
        invariant_id="emergent.severity_bounded",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_severity_bounded,
        description="Severity must lie within [1,5].",
    ),
    EmergentInvariant(
        invariant_id="emergent.pattern_registered",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_pattern_registered,
        description="Referenced patterns must be registered.",
    ),
)


def check_invariants(
    snap: EmergentSnapshot,
    invariants: Iterable[EmergentInvariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 11 — STORE
# =============================================================================


@dataclass(frozen=True)
class ThreatRecord:
    threat_id: str
    pattern_id: str
    threat_class: ThreatClass
    composition_id: str
    component_count: int
    severity: int
    confidence: ConfidenceClass
    updated_at: datetime


@dataclass(frozen=True)
class ComponentRecord:
    component_id: str
    kind: ComponentKind
    verdict: SafetyVerdict
    tenant_id: str
    matched_pattern_count: int
    updated_at: datetime


class EmergentStore(Protocol):
    def put_threat(self, record: ThreatRecord) -> None: ...
    def get_threat(self, threat_id: str) -> Optional[ThreatRecord]: ...
    def all_threats(self) -> Tuple[ThreatRecord, ...]: ...
    def put_component(self, record: ComponentRecord) -> None: ...
    def get_component(
        self, component_id: str,
    ) -> Optional[ComponentRecord]: ...
    def all_components(self) -> Tuple[ComponentRecord, ...]: ...


class InMemoryEmergentStore:
    def __init__(self) -> None:
        self._threats: Dict[str, ThreatRecord] = {}
        self._components: Dict[str, ComponentRecord] = {}

    def put_threat(self, record: ThreatRecord) -> None:
        existing = self._threats.get(record.threat_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._threats[record.threat_id] = record

    def get_threat(self, threat_id: str) -> Optional[ThreatRecord]:
        return self._threats.get(threat_id)

    def all_threats(self) -> Tuple[ThreatRecord, ...]:
        return tuple(self._threats.values())

    def put_component(self, record: ComponentRecord) -> None:
        existing = self._components.get(record.component_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._components[record.component_id] = record

    def get_component(
        self, component_id: str,
    ) -> Optional[ComponentRecord]:
        return self._components.get(component_id)

    def all_components(self) -> Tuple[ComponentRecord, ...]:
        return tuple(self._components.values())


class SqliteEmergentStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS emergent_threats (
                threat_id TEXT PRIMARY KEY,
                pattern_id TEXT NOT NULL,
                threat_class TEXT NOT NULL,
                composition_id TEXT NOT NULL,
                component_count INTEGER NOT NULL,
                severity INTEGER NOT NULL,
                confidence TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS emergent_components (
                component_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                verdict TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                matched_pattern_count INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def put_threat(self, record: ThreatRecord) -> None:
        existing = self.get_threat(record.threat_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._conn.execute(
            """
            INSERT INTO emergent_threats
              (threat_id, pattern_id, threat_class, composition_id,
               component_count, severity, confidence, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(threat_id) DO UPDATE SET
              pattern_id=excluded.pattern_id,
              threat_class=excluded.threat_class,
              composition_id=excluded.composition_id,
              component_count=excluded.component_count,
              severity=excluded.severity,
              confidence=excluded.confidence,
              updated_at=excluded.updated_at
            """,
            (
                record.threat_id, record.pattern_id,
                record.threat_class.value, record.composition_id,
                record.component_count, record.severity,
                record.confidence.value,
                record.updated_at.isoformat(),
            ),
        )
        self._conn.commit()

    def get_threat(self, threat_id: str) -> Optional[ThreatRecord]:
        row = self._conn.execute(
            "SELECT pattern_id, threat_class, composition_id, "
            "component_count, severity, confidence, updated_at "
            "FROM emergent_threats WHERE threat_id = ?",
            (threat_id,),
        ).fetchone()
        if row is None:
            return None
        return ThreatRecord(
            threat_id=threat_id, pattern_id=row[0],
            threat_class=ThreatClass(row[1]),
            composition_id=row[2],
            component_count=int(row[3]), severity=int(row[4]),
            confidence=ConfidenceClass(row[5]),
            updated_at=datetime.fromisoformat(row[6]),
        )

    def all_threats(self) -> Tuple[ThreatRecord, ...]:
        rows = self._conn.execute(
            "SELECT threat_id FROM emergent_threats"
        ).fetchall()
        return tuple(
            r for r in (self.get_threat(x[0]) for x in rows)
            if r is not None
        )

    def put_component(self, record: ComponentRecord) -> None:
        existing = self.get_component(record.component_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._conn.execute(
            """
            INSERT INTO emergent_components
              (component_id, kind, verdict, tenant_id,
               matched_pattern_count, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(component_id) DO UPDATE SET
              kind=excluded.kind,
              verdict=excluded.verdict,
              tenant_id=excluded.tenant_id,
              matched_pattern_count=excluded.matched_pattern_count,
              updated_at=excluded.updated_at
            """,
            (
                record.component_id, record.kind.value,
                record.verdict.value, record.tenant_id,
                record.matched_pattern_count,
                record.updated_at.isoformat(),
            ),
        )
        self._conn.commit()

    def get_component(
        self, component_id: str,
    ) -> Optional[ComponentRecord]:
        row = self._conn.execute(
            "SELECT kind, verdict, tenant_id, matched_pattern_count, "
            "updated_at FROM emergent_components WHERE component_id = ?",
            (component_id,),
        ).fetchone()
        if row is None:
            return None
        return ComponentRecord(
            component_id=component_id, kind=ComponentKind(row[0]),
            verdict=SafetyVerdict(row[1]), tenant_id=row[2],
            matched_pattern_count=int(row[3]),
            updated_at=datetime.fromisoformat(row[4]),
        )

    def all_components(self) -> Tuple[ComponentRecord, ...]:
        rows = self._conn.execute(
            "SELECT component_id FROM emergent_components"
        ).fetchall()
        return tuple(
            r for r in (self.get_component(x[0]) for x in rows)
            if r is not None
        )


# =============================================================================
# SECTION 12 — ENGINE
# =============================================================================


@dataclass(frozen=True)
class EmergentConfig:
    max_composition_size: int = 6
    max_threats: int = 2000
    include_low_severity: bool = True

    def __post_init__(self) -> None:
        if self.max_composition_size < 2:
            raise ValueError("max_composition_size must be >= 2")
        if self.max_threats < 1:
            raise ValueError("max_threats must be >= 1")


class EmergentThreatEngine:
    """Emergent threat discovery engine.

    Ingests components + explicit compositions, verifies individual
    safety, computes compositional emergence, and reports emergent
    threats with full provenance and safe-individually proofs.
    """

    def __init__(
        self,
        *,
        store: Optional[EmergentStore] = None,
        patterns: Optional[Sequence[DangerousPattern]] = None,
        config: Optional[EmergentConfig] = None,
    ) -> None:
        self._store: EmergentStore = store or InMemoryEmergentStore()
        self._patterns: List[DangerousPattern] = list(
            patterns if patterns is not None else DEFAULT_PATTERNS
        )
        self._config = config or EmergentConfig()
        self._components: Dict[str, ComponentProfile] = {}
        self._compositions: Dict[str, Composition] = {}
        self._safety: Dict[str, IndividualSafety] = {}
        self._threats: List[EmergentThreat] = []
        self._violations: Tuple[InvariantViolation, ...] = ()

    # ---- registration ----------------------------------------------------

    def register_pattern(self, pattern: DangerousPattern) -> None:
        if any(p.pattern_id == pattern.pattern_id
               for p in self._patterns):
            raise ValueError(
                f"pattern {pattern.pattern_id} already registered"
            )
        self._patterns.append(pattern)

    def register_component(self, component: ComponentProfile) -> None:
        if component.component_id in self._components:
            raise ValueError(
                f"component {component.component_id} already registered"
            )
        self._components[component.component_id] = component

    def register_composition(self, composition: Composition) -> None:
        if composition.composition_id in self._compositions:
            raise ValueError(
                f"composition {composition.composition_id} already "
                f"registered"
            )
        missing = [
            cid for cid in composition.component_ids
            if cid not in self._components
        ]
        if missing:
            raise KeyError(
                f"composition references unknown component(s): {missing}"
            )
        if len(composition.component_ids) > \
           self._config.max_composition_size:
            raise ValueError(
                f"composition size {len(composition.component_ids)} "
                f"exceeds max {self._config.max_composition_size}"
            )
        self._compositions[composition.composition_id] = composition

    def pattern(self, pattern_id: str) -> Optional[DangerousPattern]:
        for p in self._patterns:
            if p.pattern_id == pattern_id:
                return p
        return None

    def component(self, cid: str) -> Optional[ComponentProfile]:
        return self._components.get(cid)

    def composition(self, cid: str) -> Optional[Composition]:
        return self._compositions.get(cid)

    def patterns(self) -> Tuple[DangerousPattern, ...]:
        return tuple(self._patterns)

    def safety(self, cid: str) -> Optional[IndividualSafety]:
        return self._safety.get(cid)

    # ---- recompute -------------------------------------------------------

    def recompute(self, *, at: datetime) -> Tuple[EmergentThreat, ...]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

        # 1. Per-component safety
        self._safety = {}
        for cid, c in self._components.items():
            self._safety[cid] = assess_individual_safety(
                c, patterns=self._patterns,
            )

        # 2. Per-composition emergent threat detection
        threats: List[EmergentThreat] = []
        for comp in self._compositions.values():
            detected = detect_emergent_threats(
                comp,
                profiles=self._components,
                patterns=self._patterns,
                individual_safety=self._safety,
                at=at,
            )
            for t in detected:
                if not self._config.include_low_severity \
                   and t.severity < 3:
                    continue
                threats.append(t)

        # 3. Deterministic ordering & truncation
        threats.sort(
            key=lambda t: (-t.severity, t.threat_class.value,
                           t.threat_id),
        )
        if len(threats) > self._config.max_threats:
            threats = threats[: self._config.max_threats]
        self._threats = threats

        # 4. Persist
        for t in self._threats:
            self._store.put_threat(ThreatRecord(
                threat_id=t.threat_id, pattern_id=t.pattern_id,
                threat_class=t.threat_class,
                composition_id=t.composition_id,
                component_count=len(t.component_ids),
                severity=t.severity, confidence=t.confidence,
                updated_at=at,
            ))
        for cid, safety in self._safety.items():
            c = self._components[cid]
            self._store.put_component(ComponentRecord(
                component_id=cid, kind=c.kind,
                verdict=safety.verdict, tenant_id=c.tenant_id,
                matched_pattern_count=len(safety.matched_patterns),
                updated_at=at,
            ))

        self._violations = check_invariants(self.snapshot())
        return tuple(self._threats)

    # ---- queries ---------------------------------------------------------

    def threats(self) -> Tuple[EmergentThreat, ...]:
        return tuple(self._threats)

    def threats_of_class(
        self, cls: ThreatClass,
    ) -> Tuple[EmergentThreat, ...]:
        return tuple(
            t for t in self._threats if t.threat_class is cls
        )

    def threats_of_severity(
        self, min_severity: int,
    ) -> Tuple[EmergentThreat, ...]:
        if not 1 <= min_severity <= 5:
            raise ValueError("min_severity must be in [1,5]")
        return tuple(
            t for t in self._threats if t.severity >= min_severity
        )

    def threats_for_component(
        self, cid: str,
    ) -> Tuple[EmergentThreat, ...]:
        return tuple(
            t for t in self._threats if cid in t.component_ids
        )

    def top_threats(
        self, *, k: int = 10,
    ) -> Tuple[EmergentThreat, ...]:
        if k <= 0:
            raise ValueError("k must be > 0")
        return tuple(self._threats[:k])

    def threats_by_class(self) -> Mapping[ThreatClass, int]:
        out: Dict[ThreatClass, int] = {k: 0 for k in ThreatClass}
        for t in self._threats:
            out[t.threat_class] += 1
        return out

    def threats_by_domain(self) -> Mapping[CapabilityDomain, int]:
        out: Dict[CapabilityDomain, int] = {d: 0 for d in ALL_DOMAINS}
        for t in self._threats:
            for d in t.contributing_domains:
                out[d] += 1
        return out

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return self._violations

    def record(self, threat_id: str) -> Optional[ThreatRecord]:
        return self._store.get_threat(threat_id)

    def snapshot(self) -> EmergentSnapshot:
        return EmergentSnapshot(
            components=dict(self._components),
            safety=dict(self._safety),
            compositions=tuple(self._compositions.values()),
            threats=tuple(self._threats),
            patterns={p.pattern_id: p for p in self._patterns},
        )


# =============================================================================
# SECTION 13 — TESTS
# =============================================================================


def _t0() -> datetime:
    from datetime import timezone
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _comp(
    cid: str,
    kind: ComponentKind = ComponentKind.AGENT,
    *,
    name: Optional[str] = None,
    caps: Optional[
        Mapping[CapabilityDomain, CapabilityLevel]
    ] = None,
    tenant: str = "t1",
    tags: Iterable[str] = (),
) -> ComponentProfile:
    return ComponentProfile(
        component_id=cid, kind=kind, name=name or cid,
        capabilities=dict(caps or {}),
        tenant_id=tenant, tags=frozenset(tags),
    )


def _composition(
    cid: str, *components: str,
    kind: CompositionKind = CompositionKind.SEQUENTIAL,
) -> Composition:
    return Composition(
        composition_id=cid, kind=kind,
        component_ids=tuple(components), at=_t0(),
    )


# ---- domain ----

def test_component_requires_id() -> None:
    try:
        ComponentProfile(
            component_id="", kind=ComponentKind.AGENT, name="n",
            capabilities={}, tenant_id="t",
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_component_cap_lookup_defaults_none() -> None:
    c = _comp("a", caps={
        CapabilityDomain.DATA_READ: CapabilityLevel.READ,
    })
    assert c.cap(CapabilityDomain.DATA_READ) is CapabilityLevel.READ
    assert c.cap(CapabilityDomain.NETWORK_EGRESS) is \
        CapabilityLevel.NONE


def test_component_normalized_capabilities_complete() -> None:
    c = _comp("a")
    norm = c.normalized_capabilities()
    for d in ALL_DOMAINS:
        assert d in norm


def test_level_rank_monotonic() -> None:
    assert level_rank(CapabilityLevel.NONE) < level_rank(CapabilityLevel.READ)
    assert level_rank(CapabilityLevel.READ) < level_rank(CapabilityLevel.WRITE)
    assert level_rank(CapabilityLevel.WRITE) < level_rank(CapabilityLevel.EXECUTE)
    assert level_rank(CapabilityLevel.EXECUTE) < level_rank(CapabilityLevel.ADMIN)


def test_amplification_only_for_delegated_chained() -> None:
    assert amplification(CompositionKind.SEQUENTIAL) == 0
    assert amplification(CompositionKind.PARALLEL) == 0
    assert amplification(CompositionKind.DELEGATED) == 1
    assert amplification(CompositionKind.CHAINED) == 1


def test_composition_requires_id() -> None:
    try:
        Composition(
            composition_id="", kind=CompositionKind.SEQUENTIAL,
            component_ids=("a", "b"), at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_composition_requires_two_components() -> None:
    try:
        Composition(
            composition_id="c", kind=CompositionKind.SEQUENTIAL,
            component_ids=("a",), at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_composition_rejects_duplicates() -> None:
    try:
        Composition(
            composition_id="c", kind=CompositionKind.SEQUENTIAL,
            component_ids=("a", "a"), at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_composition_requires_aware_time() -> None:
    from datetime import datetime as dt
    try:
        Composition(
            composition_id="c", kind=CompositionKind.SEQUENTIAL,
            component_ids=("a", "b"), at=dt(2026, 1, 1),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- pattern matching ----

def test_pattern_matches() -> None:
    p = DangerousPattern(
        pattern_id="t", threat_class=ThreatClass.DATA_FLOW,
        required={
            CapabilityDomain.DATA_READ: CapabilityLevel.READ,
            CapabilityDomain.NETWORK_EGRESS: CapabilityLevel.WRITE,
        },
        severity=4, description="x",
    )
    caps = {
        CapabilityDomain.DATA_READ: CapabilityLevel.READ,
        CapabilityDomain.NETWORK_EGRESS: CapabilityLevel.WRITE,
    }
    assert p.matches(caps)


def test_pattern_matches_at_higher_level() -> None:
    p = DangerousPattern(
        pattern_id="t", threat_class=ThreatClass.DATA_FLOW,
        required={
            CapabilityDomain.DATA_READ: CapabilityLevel.READ,
        },
        severity=3, description="x",
    )
    caps = {
        CapabilityDomain.DATA_READ: CapabilityLevel.ADMIN,
    }
    assert p.matches(caps)


def test_pattern_rejects_missing_domain() -> None:
    p = DangerousPattern(
        pattern_id="t", threat_class=ThreatClass.DATA_FLOW,
        required={
            CapabilityDomain.DATA_READ: CapabilityLevel.READ,
            CapabilityDomain.NETWORK_EGRESS: CapabilityLevel.WRITE,
        },
        severity=4, description="x",
    )
    caps = {
        CapabilityDomain.DATA_READ: CapabilityLevel.READ,
    }
    assert not p.matches(caps)


def test_pattern_rejects_below_level() -> None:
    p = DangerousPattern(
        pattern_id="t", threat_class=ThreatClass.DATA_FLOW,
        required={
            CapabilityDomain.NETWORK_EGRESS: CapabilityLevel.WRITE,
        },
        severity=4, description="x",
    )
    caps = {
        CapabilityDomain.NETWORK_EGRESS: CapabilityLevel.READ,
    }
    assert not p.matches(caps)


def test_pattern_requires_id() -> None:
    try:
        DangerousPattern(
            pattern_id="", threat_class=ThreatClass.DATA_FLOW,
            required={
                CapabilityDomain.DATA_READ: CapabilityLevel.READ,
            },
            severity=3, description="x",
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_pattern_requires_requirements() -> None:
    try:
        DangerousPattern(
            pattern_id="p", threat_class=ThreatClass.DATA_FLOW,
            required={}, severity=3, description="x",
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- individual safety ----

def test_safety_safe_when_no_pattern_matches() -> None:
    c = _comp("a", caps={
        CapabilityDomain.DATA_READ: CapabilityLevel.READ,
    })
    s = assess_individual_safety(c, patterns=DEFAULT_PATTERNS)
    assert s.verdict is SafetyVerdict.SAFE


def test_safety_unsafe_when_high_severity_pattern() -> None:
    c = _comp("a", caps={
        CapabilityDomain.CREDENTIAL_ACCESS: CapabilityLevel.READ,
        CapabilityDomain.NETWORK_EGRESS: CapabilityLevel.WRITE,
    })
    s = assess_individual_safety(c, patterns=DEFAULT_PATTERNS)
    assert s.verdict is SafetyVerdict.UNSAFE
    assert "cred_theft" in s.matched_patterns


def test_safety_limited_when_only_low_severity() -> None:
    low = DangerousPattern(
        pattern_id="low", threat_class=ThreatClass.DATA_FLOW,
        required={
            CapabilityDomain.DATA_READ: CapabilityLevel.READ,
        },
        severity=2, description="low severity",
    )
    c = _comp("a", caps={
        CapabilityDomain.DATA_READ: CapabilityLevel.READ,
    })
    s = assess_individual_safety(c, patterns=(low,))
    assert s.verdict is SafetyVerdict.LIMITED


# ---- composition ----

def test_compose_union_of_capabilities() -> None:
    a = _comp("a", caps={
        CapabilityDomain.DATA_READ: CapabilityLevel.READ,
    })
    b = _comp("b", caps={
        CapabilityDomain.NETWORK_EGRESS: CapabilityLevel.WRITE,
    })
    profiles = {"a": a, "b": b}
    comp = _composition("c", "a", "b")
    union = compose_capabilities(comp, profiles=profiles)
    assert union[CapabilityDomain.DATA_READ] is CapabilityLevel.READ
    assert union[CapabilityDomain.NETWORK_EGRESS] is CapabilityLevel.WRITE


def test_compose_sequential_no_amplification() -> None:
    a = _comp("a", caps={
        CapabilityDomain.CODE_EXECUTE: CapabilityLevel.EXECUTE,
    })
    b = _comp("b", caps={
        CapabilityDomain.CODE_EXECUTE: CapabilityLevel.EXECUTE,
    })
    profiles = {"a": a, "b": b}
    comp = _composition(
        "c", "a", "b", kind=CompositionKind.SEQUENTIAL,
    )
    union = compose_capabilities(comp, profiles=profiles)
    assert union[CapabilityDomain.CODE_EXECUTE] is CapabilityLevel.EXECUTE


def test_compose_delegated_amplifies_shared_domain() -> None:
    a = _comp("a", caps={
        CapabilityDomain.CODE_EXECUTE: CapabilityLevel.EXECUTE,
    })
    b = _comp("b", caps={
        CapabilityDomain.CODE_EXECUTE: CapabilityLevel.EXECUTE,
    })
    profiles = {"a": a, "b": b}
    comp = _composition(
        "c", "a", "b", kind=CompositionKind.DELEGATED,
    )
    union = compose_capabilities(comp, profiles=profiles)
    assert union[CapabilityDomain.CODE_EXECUTE] is CapabilityLevel.ADMIN


def test_compose_amplification_not_applied_when_domain_single_contributor() -> None:
    a = _comp("a", caps={
        CapabilityDomain.CODE_EXECUTE: CapabilityLevel.EXECUTE,
    })
    b = _comp("b")
    profiles = {"a": a, "b": b}
    comp = _composition(
        "c", "a", "b", kind=CompositionKind.DELEGATED,
    )
    union = compose_capabilities(comp, profiles=profiles)
    assert union[CapabilityDomain.CODE_EXECUTE] is CapabilityLevel.EXECUTE


def test_compose_unknown_component_rejected() -> None:
    comp = _composition("c", "a", "b")
    try:
        compose_capabilities(comp, profiles={})
    except KeyError:
        return
    raise AssertionError("expected KeyError")


# ---- emergent capability ----

def test_emergent_capability_detected_for_amplified_domain() -> None:
    a = _comp("a", caps={
        CapabilityDomain.CODE_EXECUTE: CapabilityLevel.EXECUTE,
    })
    b = _comp("b", caps={
        CapabilityDomain.CODE_EXECUTE: CapabilityLevel.EXECUTE,
    })
    profiles = {"a": a, "b": b}
    comp = _composition(
        "c", "a", "b", kind=CompositionKind.DELEGATED,
    )
    emergents = find_emergent_capabilities(
        comp, profiles=profiles,
    )
    assert len(emergents) == 1
    assert emergents[0].domain is CapabilityDomain.CODE_EXECUTE
    assert emergents[0].composed_level is CapabilityLevel.ADMIN


def test_no_emergent_capability_when_no_amplification() -> None:
    a = _comp("a", caps={
        CapabilityDomain.CODE_EXECUTE: CapabilityLevel.EXECUTE,
    })
    b = _comp("b", caps={
        CapabilityDomain.NETWORK_EGRESS: CapabilityLevel.WRITE,
    })
    profiles = {"a": a, "b": b}
    comp = _composition("c", "a", "b")
    emergents = find_emergent_capabilities(
        comp, profiles=profiles,
    )
    assert emergents == ()


# ---- detect emergent threats ----

def _four_safe_components() -> Dict[str, ComponentProfile]:
    """agent (read) + tool (network) + api (execute) + identity (grant).

    Individually, none of these match any dangerous pattern alone.
    Composed, they combine into RCE + credential access + authority
    grant + network egress.
    """
    return {
        "agent": _comp("agent", ComponentKind.AGENT, caps={
            CapabilityDomain.DATA_READ: CapabilityLevel.READ,
        }),
        "tool": _comp("tool", ComponentKind.TOOL, caps={
            CapabilityDomain.NETWORK_EGRESS: CapabilityLevel.WRITE,
        }),
        "api": _comp("api", ComponentKind.API, caps={
            CapabilityDomain.CODE_EXECUTE: CapabilityLevel.EXECUTE,
        }),
        "identity": _comp("identity", ComponentKind.IDENTITY, caps={
            CapabilityDomain.CREDENTIAL_ACCESS: CapabilityLevel.READ,
        }),
    }


def test_detect_emergent_threats_requires_all_individual_safe() -> None:
    profiles = _four_safe_components()
    safety = {
        cid: assess_individual_safety(c, patterns=DEFAULT_PATTERNS)
        for cid, c in profiles.items()
    }
    # Sanity: all individually safe
    for s in safety.values():
        assert s.verdict is SafetyVerdict.SAFE

    comp = _composition(
        "c1", "agent", "tool", "api", "identity",
    )
    threats = detect_emergent_threats(
        comp, profiles=profiles, patterns=DEFAULT_PATTERNS,
        individual_safety=safety, at=_t0(),
    )
    assert len(threats) >= 2
    for t in threats:
        assert t.individually_safe_verified is True
        assert t.composition_required is True
        assert t.not_a_compromise_claim is True


def test_detect_returns_empty_if_component_is_unsafe() -> None:
    profiles = {
        "a": _comp("a", caps={
            CapabilityDomain.CREDENTIAL_ACCESS: CapabilityLevel.READ,
            CapabilityDomain.NETWORK_EGRESS: CapabilityLevel.WRITE,
        }),
        "b": _comp("b", caps={
            CapabilityDomain.DATA_READ: CapabilityLevel.READ,
        }),
    }
    safety = {
        cid: assess_individual_safety(c, patterns=DEFAULT_PATTERNS)
        for cid, c in profiles.items()
    }
    comp = _composition("c", "a", "b")
    threats = detect_emergent_threats(
        comp, profiles=profiles, patterns=DEFAULT_PATTERNS,
        individual_safety=safety, at=_t0(),
    )
    assert threats == ()


def test_detect_requires_aware_time() -> None:
    from datetime import datetime as dt
    profiles = _four_safe_components()
    safety = {
        cid: assess_individual_safety(c, patterns=DEFAULT_PATTERNS)
        for cid, c in profiles.items()
    }
    comp = _composition("c", "agent", "tool", "api", "identity")
    try:
        detect_emergent_threats(
            comp, profiles=profiles, patterns=DEFAULT_PATTERNS,
            individual_safety=safety, at=dt(2026, 1, 1),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_detect_missing_safety_rejected() -> None:
    profiles = _four_safe_components()
    comp = _composition("c", "agent", "tool", "api", "identity")
    try:
        detect_emergent_threats(
            comp, profiles=profiles, patterns=DEFAULT_PATTERNS,
            individual_safety={}, at=_t0(),
        )
    except KeyError:
        return
    raise AssertionError("expected KeyError")


# ---- emergent threat dataclass ----

def test_emergent_threat_requires_safe_verified() -> None:
    try:
        EmergentThreat(
            threat_id="t", pattern_id="p", pattern_description="d",
            threat_class=ThreatClass.DATA_FLOW,
            composition_id="c",
            composition_kind=CompositionKind.SEQUENTIAL,
            component_ids=("a", "b"),
            emergent_capabilities=(),
            contributing_domains=(),
            severity=3, confidence=ConfidenceClass.INFERRED,
            individually_safe_verified=False,
            composition_required=True, not_a_compromise_claim=True,
            rationale="x", at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_emergent_threat_requires_composition_required() -> None:
    try:
        EmergentThreat(
            threat_id="t", pattern_id="p", pattern_description="d",
            threat_class=ThreatClass.DATA_FLOW,
            composition_id="c",
            composition_kind=CompositionKind.SEQUENTIAL,
            component_ids=("a", "b"),
            emergent_capabilities=(),
            contributing_domains=(),
            severity=3, confidence=ConfidenceClass.INFERRED,
            individually_safe_verified=True,
            composition_required=False, not_a_compromise_claim=True,
            rationale="x", at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_emergent_threat_requires_no_compromise_claim() -> None:
    try:
        EmergentThreat(
            threat_id="t", pattern_id="p", pattern_description="d",
            threat_class=ThreatClass.DATA_FLOW,
            composition_id="c",
            composition_kind=CompositionKind.SEQUENTIAL,
            component_ids=("a", "b"),
            emergent_capabilities=(),
            contributing_domains=(),
            severity=3, confidence=ConfidenceClass.INFERRED,
            individually_safe_verified=True,
            composition_required=True, not_a_compromise_claim=False,
            rationale="x", at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_emergent_capability_requires_higher_level() -> None:
    try:
        EmergentCapability(
            domain=CapabilityDomain.DATA_READ,
            composed_level=CapabilityLevel.READ,
            max_individual_level=CapabilityLevel.READ,
            contributed_by=("a",),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- engine ----

def test_engine_register_component() -> None:
    eng = EmergentThreatEngine()
    eng.register_component(_comp("a"))
    assert eng.component("a") is not None


def test_engine_rejects_duplicate_component() -> None:
    eng = EmergentThreatEngine()
    eng.register_component(_comp("a"))
    try:
        eng.register_component(_comp("a"))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_register_composition_unknown_component_rejected() -> None:
    eng = EmergentThreatEngine()
    eng.register_component(_comp("a"))
    try:
        eng.register_composition(_composition("c", "a", "missing"))
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_engine_max_composition_size_enforced() -> None:
    eng = EmergentThreatEngine(
        config=EmergentConfig(max_composition_size=3),
    )
    for cid in ("a", "b", "c", "d"):
        eng.register_component(_comp(cid))
    try:
        eng.register_composition(_composition("c", "a", "b", "c", "d"))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_rejects_duplicate_composition() -> None:
    eng = EmergentThreatEngine()
    eng.register_component(_comp("a"))
    eng.register_component(_comp("b"))
    eng.register_composition(_composition("c", "a", "b"))
    try:
        eng.register_composition(_composition("c", "a", "b"))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_registers_custom_pattern() -> None:
    eng = EmergentThreatEngine()
    eng.register_pattern(DangerousPattern(
        pattern_id="custom", threat_class=ThreatClass.DATA_FLOW,
        required={CapabilityDomain.DATA_READ: CapabilityLevel.READ},
        severity=2, description="x",
    ))
    assert eng.pattern("custom") is not None


def test_engine_pattern_registered_defaults() -> None:
    eng = EmergentThreatEngine()
    for p in DEFAULT_PATTERNS:
        assert eng.pattern(p.pattern_id) is not None


def test_engine_recompute_requires_aware_time() -> None:
    from datetime import datetime as dt
    eng = EmergentThreatEngine()
    try:
        eng.recompute(at=dt(2026, 1, 1))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_recompute_empty() -> None:
    eng = EmergentThreatEngine()
    out = eng.recompute(at=_t0())
    assert out == ()


def test_engine_recompute_four_safe_yields_emergent_threats() -> None:
    eng = EmergentThreatEngine()
    profiles = _four_safe_components()
    for c in profiles.values():
        eng.register_component(c)
    eng.register_composition(_composition(
        "c1", "agent", "tool", "api", "identity",
    ))
    threats = eng.recompute(at=_t0())
    assert len(threats) >= 1
    for t in threats:
        assert t.individually_safe_verified is True
        assert t.composition_required is True
        assert t.not_a_compromise_claim is True


def test_engine_recompute_individual_unsafe_no_emergent() -> None:
    eng = EmergentThreatEngine()
    eng.register_component(_comp("bad", caps={
        CapabilityDomain.CREDENTIAL_ACCESS: CapabilityLevel.READ,
        CapabilityDomain.NETWORK_EGRESS: CapabilityLevel.WRITE,
    }))
    eng.register_component(_comp("a"))
    eng.register_composition(_composition("c", "bad", "a"))
    threats = eng.recompute(at=_t0())
    # Bad is individually UNSAFE → no emergent threat
    assert threats == ()
    s = eng.safety("bad")
    assert s is not None
    assert s.verdict is SafetyVerdict.UNSAFE


def test_engine_threats_of_class() -> None:
    eng = EmergentThreatEngine()
    profiles = _four_safe_components()
    for c in profiles.values():
        eng.register_component(c)
    eng.register_composition(_composition(
        "c1", "agent", "tool", "api", "identity",
    ))
    eng.recompute(at=_t0())
    df = eng.threats_of_class(ThreatClass.DATA_FLOW)
    assert len(df) >= 1


def test_engine_threats_of_severity() -> None:
    eng = EmergentThreatEngine()
    profiles = _four_safe_components()
    for c in profiles.values():
        eng.register_component(c)
    eng.register_composition(_composition(
        "c1", "agent", "tool", "api", "identity",
    ))
    eng.recompute(at=_t0())
    high = eng.threats_of_severity(4)
    for t in high:
        assert t.severity >= 4


def test_engine_threats_of_severity_invalid() -> None:
    eng = EmergentThreatEngine()
    try:
        eng.threats_of_severity(0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_threats_for_component() -> None:
    eng = EmergentThreatEngine()
    profiles = _four_safe_components()
    for c in profiles.values():
        eng.register_component(c)
    eng.register_composition(_composition(
        "c1", "agent", "tool", "api", "identity",
    ))
    eng.recompute(at=_t0())
    t_for_agent = eng.threats_for_component("agent")
    assert len(t_for_agent) >= 1


def test_engine_top_threats_sorted() -> None:
    eng = EmergentThreatEngine()
    profiles = _four_safe_components()
    for c in profiles.values():
        eng.register_component(c)
    eng.register_composition(_composition(
        "c1", "agent", "tool", "api", "identity",
    ))
    eng.recompute(at=_t0())
    top = eng.top_threats(k=10)
    severities = [t.severity for t in top]
    assert severities == sorted(severities, reverse=True)


def test_engine_top_threats_invalid_k() -> None:
    eng = EmergentThreatEngine()
    try:
        eng.top_threats(k=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_threats_by_class() -> None:
    eng = EmergentThreatEngine()
    profiles = _four_safe_components()
    for c in profiles.values():
        eng.register_component(c)
    eng.register_composition(_composition(
        "c1", "agent", "tool", "api", "identity",
    ))
    eng.recompute(at=_t0())
    by_class = eng.threats_by_class()
    total = sum(by_class.values())
    assert total >= 1


def test_engine_threats_by_domain() -> None:
    eng = EmergentThreatEngine()
    profiles = _four_safe_components()
    for c in profiles.values():
        eng.register_component(c)
    eng.register_composition(_composition(
        "c1", "agent", "tool", "api", "identity",
    ))
    eng.recompute(at=_t0())
    by_domain = eng.threats_by_domain()
    assert by_domain[CapabilityDomain.NETWORK_EGRESS] >= 1


def test_engine_record_lookup() -> None:
    eng = EmergentThreatEngine()
    profiles = _four_safe_components()
    for c in profiles.values():
        eng.register_component(c)
    eng.register_composition(_composition(
        "c1", "agent", "tool", "api", "identity",
    ))
    threats = eng.recompute(at=_t0())
    rec = eng.record(threats[0].threat_id)
    assert rec is not None
    assert rec.severity == threats[0].severity


def test_engine_max_threats_truncation() -> None:
    eng = EmergentThreatEngine(
        config=EmergentConfig(max_threats=1),
    )
    profiles = _four_safe_components()
    for c in profiles.values():
        eng.register_component(c)
    eng.register_composition(_composition(
        "c1", "agent", "tool", "api", "identity",
    ))
    threats = eng.recompute(at=_t0())
    assert len(threats) <= 1


def test_engine_exclude_low_severity() -> None:
    eng = EmergentThreatEngine(
        config=EmergentConfig(include_low_severity=False),
    )
    profiles = _four_safe_components()
    for c in profiles.values():
        eng.register_component(c)
    eng.register_composition(_composition(
        "c1", "agent", "tool", "api", "identity",
    ))
    threats = eng.recompute(at=_t0())
    for t in threats:
        assert t.severity >= 3


def test_engine_delegated_amplification_produces_emergent() -> None:
    eng = EmergentThreatEngine()
    # Two components each with execute — delegated composition
    # amplifies to admin, matching the priv_esc / authority pattern
    # via amplification.
    eng.register_component(_comp("a", caps={
        CapabilityDomain.AUTHORITY_GRANT: CapabilityLevel.WRITE,
        CapabilityDomain.CREDENTIAL_ACCESS: CapabilityLevel.WRITE,
    }))
    eng.register_component(_comp("b", caps={
        CapabilityDomain.AUTHORITY_GRANT: CapabilityLevel.WRITE,
        CapabilityDomain.CREDENTIAL_ACCESS: CapabilityLevel.WRITE,
    }))
    eng.register_composition(_composition(
        "c1", "a", "b", kind=CompositionKind.DELEGATED,
    ))
    threats = eng.recompute(at=_t0())
    # Expect the authority_amplification pattern to appear
    pattern_ids = {t.pattern_id for t in threats}
    assert "authority_amplification" in pattern_ids


def test_engine_sequential_composition_no_amplification_benefit() -> None:
    eng = EmergentThreatEngine()
    eng.register_component(_comp("a", caps={
        CapabilityDomain.AUTHORITY_GRANT: CapabilityLevel.WRITE,
        CapabilityDomain.CREDENTIAL_ACCESS: CapabilityLevel.WRITE,
    }))
    eng.register_component(_comp("b", caps={
        CapabilityDomain.AUTHORITY_GRANT: CapabilityLevel.WRITE,
        CapabilityDomain.CREDENTIAL_ACCESS: CapabilityLevel.WRITE,
    }))
    # SEQUENTIAL — should NOT amplify; pattern authority_amplification
    # requires EXECUTE-level AUTHORITY_GRANT, which is not reached.
    eng.register_composition(_composition(
        "c1", "a", "b", kind=CompositionKind.SEQUENTIAL,
    ))
    threats = eng.recompute(at=_t0())
    # No threat should have pattern authority_amplification
    for t in threats:
        assert t.pattern_id != "authority_amplification"


def test_engine_deterministic_ordering() -> None:
    def build():
        eng = EmergentThreatEngine()
        profiles = _four_safe_components()
        for c in profiles.values():
            eng.register_component(c)
        eng.register_composition(_composition(
            "c1", "agent", "tool", "api", "identity",
        ))
        return eng.recompute(at=_t0())

    a = build()
    b = build()
    assert [t.threat_id for t in a] == [t.threat_id for t in b]


# ---- invariants ----

def test_invariant_clean_snapshot() -> None:
    eng = EmergentThreatEngine()
    profiles = _four_safe_components()
    for c in profiles.values():
        eng.register_component(c)
    eng.register_composition(_composition(
        "c1", "agent", "tool", "api", "identity",
    ))
    eng.recompute(at=_t0())
    assert eng.violations() == ()


def test_invariant_no_local_threat() -> None:
    # Craft a snapshot where an emergent threat references a component
    # whose verdict is UNSAFE
    bad_safety = IndividualSafety(
        component_id="x", verdict=SafetyVerdict.UNSAFE,
        matched_patterns=("p",), rationale="x",
    )
    t = EmergentThreat(
        threat_id="t", pattern_id="p", pattern_description="d",
        threat_class=ThreatClass.DATA_FLOW, composition_id="c",
        composition_kind=CompositionKind.SEQUENTIAL,
        component_ids=("x", "y"),
        emergent_capabilities=(), contributing_domains=(),
        severity=4, confidence=ConfidenceClass.INFERRED,
        individually_safe_verified=True,
        composition_required=True, not_a_compromise_claim=True,
        rationale="x", at=_t0(),
    )
    snap = EmergentSnapshot(
        components={}, safety={"x": bad_safety}, compositions=(),
        threats=(t,), patterns={"p": DangerousPattern(
            pattern_id="p", threat_class=ThreatClass.DATA_FLOW,
            required={CapabilityDomain.DATA_READ: CapabilityLevel.READ},
            severity=4, description="x",
        )},
    )
    v = check_invariants(snap)
    assert any(
        x.invariant_id == "emergent.no_local_threat" for x in v
    )


def test_invariant_pattern_registered() -> None:
    t = EmergentThreat(
        threat_id="t", pattern_id="missing", pattern_description="d",
        threat_class=ThreatClass.DATA_FLOW, composition_id="c",
        composition_kind=CompositionKind.SEQUENTIAL,
        component_ids=("a", "b"),
        emergent_capabilities=(), contributing_domains=(),
        severity=4, confidence=ConfidenceClass.INFERRED,
        individually_safe_verified=True,
        composition_required=True, not_a_compromise_claim=True,
        rationale="x", at=_t0(),
    )
    snap = EmergentSnapshot(
        components={}, safety={}, compositions=(),
        threats=(t,), patterns={},
    )
    v = check_invariants(snap)
    assert any(
        x.invariant_id == "emergent.pattern_registered" for x in v
    )


# ---- store ----

def test_in_memory_store_rejects_stale_threat() -> None:
    s = InMemoryEmergentStore()
    t = _t0()
    s.put_threat(ThreatRecord(
        "t", "p", ThreatClass.DATA_FLOW, "c", 2, 4,
        ConfidenceClass.INFERRED, t,
    ))
    earlier = t.replace(year=t.year - 1)
    try:
        s.put_threat(ThreatRecord(
            "t", "p", ThreatClass.DATA_FLOW, "c", 2, 4,
            ConfidenceClass.INFERRED, earlier,
        ))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_threat_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "emergent.db")
    store = SqliteEmergentStore(db)
    store.put_threat(ThreatRecord(
        "t1", "exfil_read_plus_egress", ThreatClass.DATA_FLOW,
        "c1", 4, 4, ConfidenceClass.INFERRED, _t0(),
    ))
    got = store.get_threat("t1")
    assert got is not None
    assert got.threat_class is ThreatClass.DATA_FLOW
    assert got.component_count == 4


def test_sqlite_store_component_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "emergent.db")
    store = SqliteEmergentStore(db)
    store.put_component(ComponentRecord(
        "agent", ComponentKind.AGENT, SafetyVerdict.SAFE, "t1",
        0, _t0(),
    ))
    got = store.get_component("agent")
    assert got is not None
    assert got.verdict is SafetyVerdict.SAFE
    assert got.kind is ComponentKind.AGENT


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
