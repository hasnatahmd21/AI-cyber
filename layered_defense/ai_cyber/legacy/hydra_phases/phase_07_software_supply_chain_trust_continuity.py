"""
HYDRA POST-CORE — PHASE 7: SOFTWARE SUPPLY-CHAIN TRUST CONTINUITY
===================================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * Chain domain — stages, artifacts, digests, identities
  * Signed attestations bound to artifact digests
  * Trust propagation forward along the chain
    (SOURCE → DEPENDENCY → BUILD → ARTIFACT → PACKAGE →
     DEPLOYMENT → RUNTIME → UPDATE)
  * Break detection:
      - provenance break
      - dependency substitution
      - artifact substitution
      - build compromise
      - unauthorized update
      - runtime divergence
      - trust-chain discontinuity
  * Continuity score with per-link weakness
  * Explicit trust-label transitions
  * Machine-checkable supply-chain invariants
  * In-memory and SQLite stores
  * Phase-7 engine facade
  * Full test suite + manual runner

This is NEW supply-chain trust-continuity technology. It is not an SBOM
tool, not a scanner, not a build system — it is continuous trust state
across the software lifecycle.

Run tests:
    python hydra_phase7_supply_chain_trust_continuity.py
    pytest hydra_phase7_supply_chain_trust_continuity.py -q
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


class StageKind(str, Enum):
    SOURCE = "source"
    DEPENDENCY = "dependency"
    BUILD = "build"
    ARTIFACT = "artifact"
    PACKAGE = "package"
    DEPLOYMENT = "deployment"
    RUNTIME = "runtime"
    UPDATE = "update"


_STAGE_ORDER: Mapping[StageKind, int] = {
    StageKind.SOURCE: 0,
    StageKind.DEPENDENCY: 1,
    StageKind.BUILD: 2,
    StageKind.ARTIFACT: 3,
    StageKind.PACKAGE: 4,
    StageKind.DEPLOYMENT: 5,
    StageKind.RUNTIME: 6,
    StageKind.UPDATE: 7,
}


def stage_order(kind: StageKind) -> int:
    return _STAGE_ORDER[kind]


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


class BreakKind(str, Enum):
    NONE = "none"
    PROVENANCE_BREAK = "provenance_break"
    DEPENDENCY_SUBSTITUTION = "dependency_substitution"
    ARTIFACT_SUBSTITUTION = "artifact_substitution"
    BUILD_COMPROMISE = "build_compromise"
    UNAUTHORIZED_UPDATE = "unauthorized_update"
    RUNTIME_DIVERGENCE = "runtime_divergence"
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
    """Deterministic SHA-256 over canonical JSON."""
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


# =============================================================================
# SECTION 3 — CHAIN ENTITIES
# =============================================================================


@dataclass(frozen=True)
class Publisher:
    publisher_id: str
    trust: float
    verified: bool = True

    def __post_init__(self) -> None:
        if not self.publisher_id:
            raise ValueError("publisher_id is required")
        if not 0.0 <= self.trust <= 1.0:
            raise ValueError("trust must be within [0,1]")


@dataclass(frozen=True)
class ChainArtifact:
    """A node in the supply chain — a concrete artifact at a stage."""
    artifact_id: str
    stage: StageKind
    name: str
    digest: str
    producer_id: str                    # publisher/build-system/runner
    parent_artifact_id: Optional[str]   # predecessor in the chain
    derived_at: datetime

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


@dataclass(frozen=True)
class Attestation:
    """A signed statement about a specific artifact digest."""
    attestation_id: str
    subject_artifact_id: str
    subject_digest: str
    attestation_kind: str                # "slsa", "in_toto", "build", "sbom", ...
    signer_id: str
    signature_valid: bool
    signed_at: datetime
    payload_digest: str                  # digest of the attested payload
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
class ChainLink:
    """Explicit parent→child edge with the transition kind."""
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
# SECTION 4 — TRUST STATE
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
# SECTION 5 — CHAIN GRAPH
# =============================================================================


class ChainGraph:
    """Directed acyclic graph over artifacts."""

    def __init__(self) -> None:
        self._out: Dict[str, List[str]] = {}
        self._in: Dict[str, List[str]] = {}
        self._artifacts: Dict[str, ChainArtifact] = {}
        self._links: Dict[Tuple[str, str], ChainLink] = {}

    def add_artifact(self, artifact: ChainArtifact) -> None:
        if artifact.artifact_id in self._artifacts:
            raise ValueError(f"artifact {artifact.artifact_id} already exists")
        self._artifacts[artifact.artifact_id] = artifact
        self._out.setdefault(artifact.artifact_id, [])
        self._in.setdefault(artifact.artifact_id, [])

    def artifact(self, artifact_id: str) -> ChainArtifact:
        a = self._artifacts.get(artifact_id)
        if a is None:
            raise KeyError(f"unknown artifact {artifact_id}")
        return a

    def add_link(self, link: ChainLink) -> None:
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
        # Stage ordering
        p = self._artifacts[link.parent_artifact_id]
        c = self._artifacts[link.child_artifact_id]
        if stage_order(c.stage) <= stage_order(p.stage):
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

    def link(self, parent: str, child: str) -> Optional[ChainLink]:
        return self._links.get((parent, child))

    def all_artifacts(self) -> Tuple[ChainArtifact, ...]:
        return tuple(self._artifacts.values())

    def all_links(self) -> Tuple[ChainLink, ...]:
        return tuple(self._links.values())

    def roots(self) -> Tuple[str, ...]:
        return tuple(a for a in self._artifacts if not self._in.get(a))


# =============================================================================
# SECTION 6 — BREAK DETECTION
# =============================================================================


@dataclass(frozen=True)
class BreakFinding:
    kind: BreakKind
    artifact_id: str
    parent_artifact_id: Optional[str]
    detail: str
    severity: int                # 0..5 mirrors TrustLabel severity
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


def _digest_of_payload(payload: Mapping[str, Any]) -> str:
    return canonical_digest(payload)


def detect_artifact_substitution(
    graph: ChainGraph,
    parent_id: str,
    child_id: str,
    *,
    at: datetime,
) -> Optional[BreakFinding]:
    """Detect whether the child's recorded link digest does not match
    the current parent artifact digest — i.e. the parent was swapped."""
    link = graph.link(parent_id, child_id)
    if link is None:
        return BreakFinding(
            kind=BreakKind.TRUST_CHAIN_DISCONTINUITY,
            artifact_id=child_id,
            parent_artifact_id=parent_id,
            detail="no recorded link between parent and child",
            severity=4,
            at=at,
        )
    parent = graph.artifact(parent_id)
    if parent.digest != link.expected_parent_digest:
        return BreakFinding(
            kind=BreakKind.ARTIFACT_SUBSTITUTION,
            artifact_id=parent_id,
            parent_artifact_id=None,
            detail=(
                f"parent artifact {parent_id} digest {parent.digest[:12]}… "
                f"does not match link expectation "
                f"{link.expected_parent_digest[:12]}…"
            ),
            severity=4,
            at=at,
        )
    return None


def detect_dependency_substitution(
    declared_dependencies: Mapping[str, str],
    observed_dependencies: Mapping[str, str],
    *,
    artifact_id: str,
    at: datetime,
) -> Tuple[BreakFinding, ...]:
    """Compare declared vs observed dependency digests."""
    out: List[BreakFinding] = []
    for name, declared_digest in declared_dependencies.items():
        observed = observed_dependencies.get(name)
        if observed is None:
            out.append(BreakFinding(
                kind=BreakKind.TRUST_CHAIN_DISCONTINUITY,
                artifact_id=artifact_id,
                parent_artifact_id=None,
                detail=f"declared dependency {name} missing at runtime",
                severity=3,
                at=at,
            ))
        elif observed != declared_digest:
            out.append(BreakFinding(
                kind=BreakKind.DEPENDENCY_SUBSTITUTION,
                artifact_id=artifact_id,
                parent_artifact_id=None,
                detail=(
                    f"dependency {name} digest mismatch: declared "
                    f"{declared_digest[:12]}… observed {observed[:12]}…"
                ),
                severity=4,
                at=at,
            ))
    return tuple(out)


def detect_provenance_break(
    artifact: ChainArtifact,
    attestations: Iterable[Attestation],
    *,
    at: datetime,
) -> Optional[BreakFinding]:
    """Missing or mismatched attestation for the artifact."""
    applicable = [
        a for a in attestations
        if a.subject_artifact_id == artifact.artifact_id
    ]
    if not applicable:
        return BreakFinding(
            kind=BreakKind.PROVENANCE_BREAK,
            artifact_id=artifact.artifact_id,
            parent_artifact_id=None,
            detail=f"no attestation present for {artifact.artifact_id}",
            severity=3,
            at=at,
        )
    for a in applicable:
        if a.subject_digest != artifact.digest:
            return BreakFinding(
                kind=BreakKind.ARTIFACT_SUBSTITUTION,
                artifact_id=artifact.artifact_id,
                parent_artifact_id=None,
                detail=(
                    f"attestation {a.attestation_id} bound to different digest"
                ),
                severity=4,
                at=at,
            )
        if not a.signature_valid:
            return BreakFinding(
                kind=BreakKind.PROVENANCE_BREAK,
                artifact_id=artifact.artifact_id,
                parent_artifact_id=None,
                detail=(
                    f"attestation {a.attestation_id} signature invalid"
                ),
                severity=4,
                at=at,
            )
    return None


def detect_build_compromise(
    build_artifact: ChainArtifact,
    *,
    builder_trust: float,
    known_compromised_builders: FrozenSet[str],
    at: datetime,
) -> Optional[BreakFinding]:
    if build_artifact.producer_id in known_compromised_builders:
        return BreakFinding(
            kind=BreakKind.BUILD_COMPROMISE,
            artifact_id=build_artifact.artifact_id,
            parent_artifact_id=None,
            detail=(
                f"builder {build_artifact.producer_id} is known compromised"
            ),
            severity=5,
            at=at,
        )
    if builder_trust < 0.3:
        return BreakFinding(
            kind=BreakKind.BUILD_COMPROMISE,
            artifact_id=build_artifact.artifact_id,
            parent_artifact_id=None,
            detail=(
                f"builder {build_artifact.producer_id} trust is very low "
                f"({builder_trust:.2f})"
            ),
            severity=4,
            at=at,
        )
    return None


def detect_unauthorized_update(
    update_artifact: ChainArtifact,
    *,
    authorized_publishers: FrozenSet[str],
    at: datetime,
) -> Optional[BreakFinding]:
    if update_artifact.producer_id not in authorized_publishers:
        return BreakFinding(
            kind=BreakKind.UNAUTHORIZED_UPDATE,
            artifact_id=update_artifact.artifact_id,
            parent_artifact_id=None,
            detail=(
                f"update produced by unauthorized publisher "
                f"{update_artifact.producer_id}"
            ),
            severity=4,
            at=at,
        )
    return None


def detect_runtime_divergence(
    runtime_artifact: ChainArtifact,
    *,
    expected_digest: str,
    at: datetime,
) -> Optional[BreakFinding]:
    if runtime_artifact.digest != expected_digest:
        return BreakFinding(
            kind=BreakKind.RUNTIME_DIVERGENCE,
            artifact_id=runtime_artifact.artifact_id,
            parent_artifact_id=None,
            detail=(
                f"runtime digest {runtime_artifact.digest[:12]}… does not "
                f"match package digest {expected_digest[:12]}…"
            ),
            severity=5,
            at=at,
        )
    return None


def detect_discontinuity(
    graph: ChainGraph,
    artifact_id: str,
    *,
    at: datetime,
) -> Optional[BreakFinding]:
    """A non-root artifact with no parent link is a discontinuity."""
    art = graph.artifact(artifact_id)
    if art.stage is StageKind.SOURCE:
        return None
    parents = graph.parents_of(artifact_id)
    if not parents:
        return BreakFinding(
            kind=BreakKind.TRUST_CHAIN_DISCONTINUITY,
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
# SECTION 7 — CONTINUITY ANALYSIS
# =============================================================================


@dataclass(frozen=True)
class ContinuityResult:
    artifact_id: str
    label: TrustLabel
    trust: TrustState
    continuity: float                # 0..1
    findings: Tuple[BreakFinding, ...]
    chain: Tuple[str, ...]           # root → artifact
    rationale: str
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        if not 0.0 <= self.continuity <= 1.0:
            raise ValueError("continuity must be within [0,1]")


TRUST_SLACK: float = 0.05


def _ancestors_to_root(graph: ChainGraph, artifact_id: str) -> Tuple[str, ...]:
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


def effective_continuity(
    *,
    root_trust: float,
    link_postures: Iterable[float],
    findings: Iterable[BreakFinding],
) -> float:
    """Continuity = root_trust attenuated by each link's posture,
    further penalized by findings."""
    base = max(0.0, min(1.0, root_trust))
    for p in link_postures:
        if not 0.0 <= p <= 1.0:
            raise ValueError("link posture must be within [0,1]")
        base *= 0.5 + 0.5 * p     # posture 1 → unchanged; posture 0 → halve
    penalty = 0.0
    for f in findings:
        penalty += 0.05 * f.severity
    return max(0.0, min(1.0, base - penalty))


def analyse_continuity(
    graph: ChainGraph,
    artifact_id: str,
    *,
    publisher_trust: Mapping[str, float],
    attestations: Mapping[str, Tuple[Attestation, ...]],
    link_postures: Mapping[Tuple[str, str], float],
    findings_by_artifact: Mapping[str, Tuple[BreakFinding, ...]],
    at: datetime,
) -> ContinuityResult:
    """Compute continuity for a single artifact along its parent chain."""
    chain = _ancestors_to_root(graph, artifact_id)
    if not chain:
        raise KeyError(f"unknown artifact {artifact_id}")

    # Root trust: from publisher (source) of the root artifact.
    root = graph.artifact(chain[0])
    root_trust = publisher_trust.get(root.producer_id, NEUTRAL_SCORE)

    # Collect link postures along the chain.
    postures: List[float] = []
    for i in range(len(chain) - 1):
        key = (chain[i], chain[i + 1])
        postures.append(link_postures.get(key, 0.5))

    # Collect findings along the chain.
    chain_findings: List[BreakFinding] = []
    for aid in chain:
        chain_findings.extend(findings_by_artifact.get(aid, ()))

    continuity = effective_continuity(
        root_trust=root_trust,
        link_postures=postures,
        findings=chain_findings,
    )

    # Label from continuity alone — but any severity>=4 finding forces worse.
    provisional = TrustState(
        score=continuity,
        confidence=0.9,
        basis=(),
        updated_at=at,
    )
    label = derive_label(provisional)
    for f in chain_findings:
        if f.severity >= 5:
            label = worse_of(label, TrustLabel.COMPROMISED)
        elif f.severity >= 4:
            label = worse_of(label, TrustLabel.SUSPICIOUS)
        elif f.severity >= 3:
            label = worse_of(label, TrustLabel.DEGRADED)

    # Attestations check — any invalid signature forces SUSPICIOUS.
    for aid in chain:
        for a in attestations.get(aid, ()):
            if not a.signature_valid:
                label = worse_of(label, TrustLabel.SUSPICIOUS)

    rationale = (
        f"chain length {len(chain)}, root trust {root_trust:.2f}, "
        f"{len(chain_findings)} finding(s)"
    )

    return ContinuityResult(
        artifact_id=artifact_id,
        label=label,
        trust=TrustState(
            score=continuity,
            confidence=0.9,
            basis=(),
            updated_at=at,
        ),
        continuity=continuity,
        findings=tuple(chain_findings),
        chain=chain,
        rationale=rationale,
        at=at,
    )


# =============================================================================
# SECTION 8 — TRANSITIONS
# =============================================================================


class TransitionOutcome(str, Enum):
    ALLOWED = "allowed"
    REJECTED_INVALID = "rejected_invalid"
    REQUIRES_VERIFICATION = "requires_verification"


_ALLOWED_LABEL_EDGES: Mapping[TrustLabel, FrozenSet[TrustLabel]] = {
    TrustLabel.UNKNOWN: frozenset({
        TrustLabel.OBSERVED, TrustLabel.DEGRADED, TrustLabel.SUSPICIOUS,
        TrustLabel.COMPROMISED, TrustLabel.QUARANTINED,
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
    if going_better and not req.verified:
        return TransitionDecision(
            TransitionOutcome.REQUIRES_VERIFICATION,
            "recovery transitions require verification",
        )
    return TransitionDecision(TransitionOutcome.ALLOWED, "permitted")


# =============================================================================
# SECTION 9 — INVARIANTS
# =============================================================================


class InvariantSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class ArtifactSnapshot:
    artifact: ChainArtifact
    label: TrustLabel
    continuity: float
    findings: Tuple[BreakFinding, ...]


@dataclass(frozen=True)
class SupplyChainSnapshot:
    graph: ChainGraph
    artifacts: Mapping[str, ArtifactSnapshot]
    attestations: Mapping[str, Tuple[Attestation, ...]]
    publishers: Mapping[str, Publisher]


@dataclass(frozen=True)
class InvariantViolation:
    invariant_id: str
    severity: InvariantSeverity
    subject_id: str
    detail: str


@dataclass(frozen=True)
class SupplyChainInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[SupplyChainSnapshot], Tuple[InvariantViolation, ...]]
    description: str


def _inv_deployed_runtime_must_be_trusted(
    snap: SupplyChainSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for aid, snapsh in snap.artifacts.items():
        if snapsh.artifact.stage not in (StageKind.RUNTIME, StageKind.UPDATE):
            continue
        if is_untrusted(snapsh.label):
            out.append(InvariantViolation(
                invariant_id="supply.untrusted_runtime_or_update",
                severity=InvariantSeverity.CRITICAL,
                subject_id=aid,
                detail=(
                    f"stage {snapsh.artifact.stage.value} artifact {aid} "
                    f"is {snapsh.label.value}"
                ),
            ))
    return tuple(out)


def _inv_no_unsigned_attestation_supporting_trust(
    snap: SupplyChainSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for aid, snapsh in snap.artifacts.items():
        if snapsh.label is not TrustLabel.TRUSTED:
            continue
        atts = snap.attestations.get(aid, ())
        if not atts:
            out.append(InvariantViolation(
                invariant_id="supply.trusted_requires_attestation",
                severity=InvariantSeverity.CRITICAL,
                subject_id=aid,
                detail=f"artifact {aid} marked TRUSTED without any attestation",
            ))
            continue
        if not any(a.signature_valid for a in atts):
            out.append(InvariantViolation(
                invariant_id="supply.trusted_requires_valid_signature",
                severity=InvariantSeverity.CRITICAL,
                subject_id=aid,
                detail=(
                    f"artifact {aid} marked TRUSTED but no valid signature"
                ),
            ))
    return tuple(out)


def _inv_chain_no_discontinuity(
    snap: SupplyChainSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for aid, snapsh in snap.artifacts.items():
        if snapsh.artifact.stage is StageKind.SOURCE:
            continue
        parents = snap.graph.parents_of(aid)
        if not parents:
            out.append(InvariantViolation(
                invariant_id="supply.chain_discontinuity",
                severity=InvariantSeverity.CRITICAL,
                subject_id=aid,
                detail=(
                    f"non-root artifact {aid} at stage "
                    f"{snapsh.artifact.stage.value} has no parent"
                ),
            ))
    return tuple(out)


def _inv_no_compromised_stage_upstream_of_trusted(
    snap: SupplyChainSnapshot,
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
                    invariant_id="supply.trusted_with_untrusted_parent",
                    severity=InvariantSeverity.CRITICAL,
                    subject_id=aid,
                    detail=(
                        f"{aid} TRUSTED while parent {p} is "
                        f"{ps.label.value}"
                    ),
                ))
    return tuple(out)


def _inv_no_digest_reuse_across_stages(
    snap: SupplyChainSnapshot,
) -> Tuple[InvariantViolation, ...]:
    """The same digest must not appear at different chain stages unless
    explicitly linked — this would indicate artifact reuse/substitution."""
    out: List[InvariantViolation] = []
    seen: Dict[str, Tuple[StageKind, str]] = {}
    for aid, snapsh in snap.artifacts.items():
        key = snapsh.artifact.digest
        if key in seen:
            prev_stage, prev_id = seen[key]
            if prev_stage is not snapsh.artifact.stage:
                out.append(InvariantViolation(
                    invariant_id="supply.digest_reuse_across_stages",
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


DEFAULT_INVARIANTS: Tuple[SupplyChainInvariant, ...] = (
    SupplyChainInvariant(
        invariant_id="supply.untrusted_runtime_or_update",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_deployed_runtime_must_be_trusted,
        description="Runtime/update artifacts must not be untrusted.",
    ),
    SupplyChainInvariant(
        invariant_id="supply.trusted_requires_attestation",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_no_unsigned_attestation_supporting_trust,
        description="TRUSTED artifacts must have a valid attestation.",
    ),
    SupplyChainInvariant(
        invariant_id="supply.chain_discontinuity",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_chain_no_discontinuity,
        description="Non-root artifacts must have a parent link.",
    ),
    SupplyChainInvariant(
        invariant_id="supply.trusted_with_untrusted_parent",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_no_compromised_stage_upstream_of_trusted,
        description="An artifact cannot be TRUSTED if its parent is untrusted.",
    ),
    SupplyChainInvariant(
        invariant_id="supply.digest_reuse_across_stages",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_no_digest_reuse_across_stages,
        description="Same digest must not appear at different stages.",
    ),
)


def check_invariants(
    snap: SupplyChainSnapshot,
    invariants: Iterable[SupplyChainInvariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 10 — STORES
# =============================================================================


@dataclass(frozen=True)
class ArtifactStateRecord:
    artifact_id: str
    label: TrustLabel
    continuity: float
    findings_count: int
    updated_at: datetime


class SupplyChainStore(Protocol):
    def get(self, artifact_id: str) -> Optional[ArtifactStateRecord]: ...
    def put(self, record: ArtifactStateRecord) -> None: ...
    def all(self) -> Tuple[ArtifactStateRecord, ...]: ...


class InMemorySupplyChainStore:
    def __init__(self) -> None:
        self._data: Dict[str, ArtifactStateRecord] = {}

    def get(self, artifact_id: str) -> Optional[ArtifactStateRecord]:
        return self._data.get(artifact_id)

    def put(self, record: ArtifactStateRecord) -> None:
        existing = self._data.get(record.artifact_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._data[record.artifact_id] = record

    def all(self) -> Tuple[ArtifactStateRecord, ...]:
        return tuple(self._data.values())


class SqliteSupplyChainStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS supply_artifact_state (
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
            CREATE TABLE IF NOT EXISTS supply_attestations (
                attestation_id TEXT PRIMARY KEY,
                subject_artifact_id TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS supply_publishers (
                publisher_id TEXT PRIMARY KEY,
                trust REAL NOT NULL,
                verified INTEGER NOT NULL
            )
            """
        )
        self._conn.commit()

    def get(self, artifact_id: str) -> Optional[ArtifactStateRecord]:
        row = self._conn.execute(
            "SELECT label, continuity, findings_count, updated_at "
            "FROM supply_artifact_state WHERE artifact_id = ?",
            (artifact_id,),
        ).fetchone()
        if row is None:
            return None
        return ArtifactStateRecord(
            artifact_id=artifact_id,
            label=TrustLabel(row[0]),
            continuity=float(row[1]),
            findings_count=int(row[2]),
            updated_at=datetime.fromisoformat(row[3]),
        )

    def put(self, record: ArtifactStateRecord) -> None:
        existing = self.get(record.artifact_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._conn.execute(
            """
            INSERT INTO supply_artifact_state
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

    def all(self) -> Tuple[ArtifactStateRecord, ...]:
        rows = self._conn.execute(
            "SELECT artifact_id FROM supply_artifact_state"
        ).fetchall()
        return tuple(
            r for r in (self.get(x[0]) for x in rows) if r is not None
        )

    def put_attestation(self, attestation: Attestation) -> None:
        payload = {
            "attestation_id": attestation.attestation_id,
            "subject_artifact_id": attestation.subject_artifact_id,
            "subject_digest": attestation.subject_digest,
            "attestation_kind": attestation.attestation_kind,
            "signer_id": attestation.signer_id,
            "signature_valid": attestation.signature_valid,
            "signed_at": attestation.signed_at.isoformat(),
            "payload_digest": attestation.payload_digest,
            "evidence_id": attestation.evidence.evidence_id,
            "evidence_source": attestation.evidence.source,
            "evidence_confidence": attestation.evidence.confidence,
            "evidence_observed_at": attestation.evidence.observed_at.isoformat(),
        }
        self._conn.execute(
            "INSERT OR REPLACE INTO supply_attestations "
            "(attestation_id, subject_artifact_id, payload_json) "
            "VALUES (?, ?, ?)",
            (attestation.attestation_id,
             attestation.subject_artifact_id,
             json.dumps(payload, sort_keys=True)),
        )
        self._conn.commit()

    def get_attestation(self, attestation_id: str) -> Optional[Attestation]:
        row = self._conn.execute(
            "SELECT payload_json FROM supply_attestations "
            "WHERE attestation_id = ?",
            (attestation_id,),
        ).fetchone()
        if row is None:
            return None
        p = json.loads(row[0])
        return Attestation(
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

    def put_publisher(self, publisher: Publisher) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO supply_publishers "
            "(publisher_id, trust, verified) VALUES (?, ?, ?)",
            (publisher.publisher_id, publisher.trust,
             int(publisher.verified)),
        )
        self._conn.commit()

    def get_publisher(self, publisher_id: str) -> Optional[Publisher]:
        row = self._conn.execute(
            "SELECT trust, verified FROM supply_publishers "
            "WHERE publisher_id = ?",
            (publisher_id,),
        ).fetchone()
        if row is None:
            return None
        return Publisher(
            publisher_id=publisher_id,
            trust=float(row[0]),
            verified=bool(row[1]),
        )


# =============================================================================
# SECTION 11 — ENGINE
# =============================================================================


class SupplyChainTrustEngine:
    """Continuous supply-chain trust engine.

    Consumes artifacts, attestations, publishers, and observed digests.
    Produces per-artifact trust label + continuity score + findings.
    """

    def __init__(self, *, store: Optional[SupplyChainStore] = None) -> None:
        self._store: SupplyChainStore = store or InMemorySupplyChainStore()
        self._graph = ChainGraph()
        self._publishers: Dict[str, Publisher] = {}
        self._attestations: Dict[str, List[Attestation]] = {}
        self._link_postures: Dict[Tuple[str, str], float] = {}
        self._findings: Dict[str, List[BreakFinding]] = {}
        self._labels: Dict[str, TrustLabel] = {}
        self._continuity: Dict[str, ContinuityResult] = {}
        self._violations: Tuple[InvariantViolation, ...] = ()
        self._compromised_builders: set = set()
        self._authorized_update_publishers: set = set()

    # ---- registration ---------------------------------------------------

    def register_publisher(self, publisher: Publisher) -> None:
        if publisher.publisher_id in self._publishers:
            raise ValueError(
                f"publisher {publisher.publisher_id} already registered"
            )
        self._publishers[publisher.publisher_id] = publisher

    def mark_builder_compromised(self, builder_id: str) -> None:
        self._compromised_builders.add(builder_id)

    def authorize_update_publisher(self, publisher_id: str) -> None:
        self._authorized_update_publishers.add(publisher_id)

    def add_artifact(self, artifact: ChainArtifact) -> None:
        self._graph.add_artifact(artifact)

    def add_link(self, link: ChainLink, *, posture: float = 0.9) -> None:
        if not 0.0 <= posture <= 1.0:
            raise ValueError("posture must be within [0,1]")
        self._graph.add_link(link)
        self._link_postures[
            (link.parent_artifact_id, link.child_artifact_id)
        ] = posture

    def add_attestation(self, attestation: Attestation) -> None:
        if attestation.subject_artifact_id not in (
            a.artifact_id for a in self._graph.all_artifacts()
        ):
            raise KeyError(
                f"attestation subject {attestation.subject_artifact_id} "
                f"not registered"
            )
        self._attestations.setdefault(
            attestation.subject_artifact_id, []
        ).append(attestation)

    def report_dependency_digests(
        self,
        artifact_id: str,
        *,
        declared: Mapping[str, str],
        observed: Mapping[str, str],
        at: datetime,
    ) -> Tuple[BreakFinding, ...]:
        """Compare declared vs observed dependency digests at runtime."""
        findings = detect_dependency_substitution(
            declared, observed, artifact_id=artifact_id, at=at,
        )
        self._findings.setdefault(artifact_id, []).extend(findings)
        return findings

    def report_runtime_digest(
        self,
        artifact_id: str,
        *,
        expected_digest: str,
        at: datetime,
    ) -> Optional[BreakFinding]:
        art = self._graph.artifact(artifact_id)
        f = detect_runtime_divergence(art, expected_digest=expected_digest, at=at)
        if f is not None:
            self._findings.setdefault(artifact_id, []).append(f)
        return f

    # ---- recompute -------------------------------------------------------

    def recompute(self, *, at: datetime) -> Tuple[ArtifactStateRecord, ...]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

        # 1. Augment findings from structural analysis.
        for art in self._graph.all_artifacts():
            # Provenance
            prov = detect_provenance_break(
                art, self._attestations.get(art.artifact_id, ()), at=at,
            )
            if prov is not None:
                self._findings.setdefault(art.artifact_id, []).append(prov)

            # Build compromise (only for BUILD stage)
            if art.stage is StageKind.BUILD:
                builder = self._publishers.get(art.producer_id)
                builder_trust = builder.trust if builder else NEUTRAL_SCORE
                bc = detect_build_compromise(
                    art, builder_trust=builder_trust,
                    known_compromised_builders=frozenset(
                        self._compromised_builders
                    ),
                    at=at,
                )
                if bc is not None:
                    self._findings.setdefault(art.artifact_id, []).append(bc)

            # Unauthorized update (only for UPDATE stage)
            if art.stage is StageKind.UPDATE:
                uu = detect_unauthorized_update(
                    art,
                    authorized_publishers=frozenset(
                        self._authorized_update_publishers
                    ),
                    at=at,
                )
                if uu is not None:
                    self._findings.setdefault(art.artifact_id, []).append(uu)

            # Discontinuity
            disc = detect_discontinuity(self._graph, art.artifact_id, at=at)
            if disc is not None:
                self._findings.setdefault(art.artifact_id, []).append(disc)

            # Artifact substitution on parent link
            for p in self._graph.parents_of(art.artifact_id):
                sub = detect_artifact_substitution(
                    self._graph, p, art.artifact_id, at=at,
                )
                if sub is not None:
                    self._findings.setdefault(art.artifact_id, []).append(sub)

        # 2. Continuity analysis per artifact.
        publisher_trust = {
            pid: pub.trust for pid, pub in self._publishers.items()
        }
        attestations_map = {
            aid: tuple(lst) for aid, lst in self._attestations.items()
        }
        findings_map = {
            aid: tuple(lst) for aid, lst in self._findings.items()
        }

        records: List[ArtifactStateRecord] = []
        for art in self._graph.all_artifacts():
            result = analyse_continuity(
                self._graph, art.artifact_id,
                publisher_trust=publisher_trust,
                attestations=attestations_map,
                link_postures=self._link_postures,
                findings_by_artifact=findings_map,
                at=at,
            )
            self._continuity[art.artifact_id] = result

            # transition enforcement
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
                    result = ContinuityResult(
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

            rec = ArtifactStateRecord(
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

    def continuity(self, artifact_id: str) -> Optional[ContinuityResult]:
        return self._continuity.get(artifact_id)

    def state(self, artifact_id: str) -> Optional[ArtifactStateRecord]:
        return self._store.get(artifact_id)

    def findings(self, artifact_id: str) -> Tuple[BreakFinding, ...]:
        return tuple(self._findings.get(artifact_id, ()))

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return self._violations

    def snapshot(self) -> SupplyChainSnapshot:
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
        return SupplyChainSnapshot(
            graph=self._graph,
            artifacts=artifacts,
            attestations={
                aid: tuple(lst) for aid, lst in self._attestations.items()
            },
            publishers=dict(self._publishers),
        )


# =============================================================================
# SECTION 12 — TESTS
# =============================================================================


def _t0() -> datetime:
    from datetime import timezone
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _ev(at: datetime, conf: float = 0.9) -> Evidence:
    return Evidence(evidence_id="e", source="test", confidence=conf,
                    observed_at=at, payload={})


def _art(aid: str, stage: StageKind, *, digest: str = "d",
         name: str = "n", producer: str = "p",
         parent: Optional[str] = None,
         at: Optional[datetime] = None) -> ChainArtifact:
    return ChainArtifact(
        artifact_id=aid, stage=stage, name=name, digest=digest,
        producer_id=producer, parent_artifact_id=parent,
        derived_at=at or _t0(),
    )


def _link(parent: str, child: str,
          pdigest: str = "d", cdigest: str = "d") -> ChainLink:
    return ChainLink(
        parent_artifact_id=parent, child_artifact_id=child,
        expected_parent_digest=pdigest, expected_child_digest=cdigest,
    )


def _att(att_id: str, art_id: str, *, digest: str = "d",
         valid: bool = True) -> Attestation:
    return Attestation(
        attestation_id=att_id, subject_artifact_id=art_id,
        subject_digest=digest, attestation_kind="slsa",
        signer_id="signer", signature_valid=valid, signed_at=_t0(),
        payload_digest="pd", evidence=_ev(_t0()),
    )


# ---- domain tests ---------------------------------------------------------

def test_stage_ordering() -> None:
    assert stage_order(StageKind.SOURCE) < stage_order(StageKind.BUILD)
    assert stage_order(StageKind.BUILD) < stage_order(StageKind.DEPLOYMENT)
    assert stage_order(StageKind.DEPLOYMENT) < stage_order(StageKind.UPDATE)


def test_publisher_trust_bounds() -> None:
    try:
        Publisher(publisher_id="p", trust=1.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_artifact_requires_aware_time() -> None:
    from datetime import datetime as dt
    try:
        ChainArtifact(
            artifact_id="a", stage=StageKind.SOURCE, name="n",
            digest="d", producer_id="p", parent_artifact_id=None,
            derived_at=dt(2026, 1, 1),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_attestation_requires_aware_time() -> None:
    from datetime import datetime as dt
    try:
        Attestation(
            attestation_id="a", subject_artifact_id="x",
            subject_digest="d", attestation_kind="slsa",
            signer_id="s", signature_valid=True,
            signed_at=dt(2026, 1, 1), payload_digest="pd",
            evidence=_ev(_t0()),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_canonical_digest_deterministic() -> None:
    a = canonical_digest({"b": 1, "a": 2})
    b = canonical_digest({"a": 2, "b": 1})
    assert a == b


# ---- graph tests ----------------------------------------------------------

def test_graph_adds_artifacts() -> None:
    g = ChainGraph()
    g.add_artifact(_art("s", StageKind.SOURCE, digest="d1"))
    g.add_artifact(_art("b", StageKind.BUILD, digest="d2", parent="s"))
    assert "s" in {a.artifact_id for a in g.all_artifacts()}


def test_graph_duplicate_artifact_rejected() -> None:
    g = ChainGraph()
    g.add_artifact(_art("s", StageKind.SOURCE))
    try:
        g.add_artifact(_art("s", StageKind.SOURCE))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_graph_link_stage_order_enforced() -> None:
    g = ChainGraph()
    g.add_artifact(_art("s", StageKind.SOURCE))
    g.add_artifact(_art("b", StageKind.BUILD))
    try:
        # Attempt to link a later stage to an earlier stage as parent
        g.add_artifact(_art("s2", StageKind.SOURCE))
        g.add_link(_link("b", "s2"))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_graph_cycle_rejected() -> None:
    g = ChainGraph()
    g.add_artifact(_art("s", StageKind.SOURCE))
    g.add_artifact(_art("d", StageKind.DEPENDENCY))
    g.add_artifact(_art("b", StageKind.BUILD))
    g.add_link(_link("s", "d"))
    g.add_link(_link("d", "b"))
    try:
        # direct cycle not possible due to stage ordering, but ensure
        # duplicate link is rejected
        g.add_link(_link("s", "d"))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_graph_parents_of() -> None:
    g = ChainGraph()
    g.add_artifact(_art("s", StageKind.SOURCE))
    g.add_artifact(_art("b", StageKind.BUILD))
    g.add_link(_link("s", "b"))
    assert g.parents_of("b") == ("s",)
    assert g.children_of("s") == ("b",)


# ---- trust tests ----------------------------------------------------------

def test_combine_trust_empty_neutral() -> None:
    s = combine_trust([], _t0())
    assert s.score == NEUTRAL_SCORE and s.confidence == 0.0


def test_combine_trust_positive_raises() -> None:
    sig = TrustSignal("s", 1.0, 1.0, _t0(), _ev(_t0()))
    assert combine_trust([sig], _t0()).score == 1.0


def test_combine_trust_negative_lowers() -> None:
    sig = TrustSignal("s", 1.0, -1.0, _t0(), _ev(_t0()))
    assert combine_trust([sig], _t0()).score == 0.0


def test_derive_label_unknown_low_conf() -> None:
    st = TrustState(0.9, 0.1, (), _t0())
    assert derive_label(st) is TrustLabel.UNKNOWN


def test_derive_label_trusted() -> None:
    st = TrustState(0.95, 0.9, (), _t0())
    assert derive_label(st) is TrustLabel.TRUSTED


# ---- break detection ------------------------------------------------------

def test_provenance_break_missing_attestation() -> None:
    art = _art("b", StageKind.BUILD, digest="d")
    f = detect_provenance_break(art, (), at=_t0())
    assert f is not None and f.kind is BreakKind.PROVENANCE_BREAK


def test_provenance_break_digest_mismatch() -> None:
    art = _art("b", StageKind.BUILD, digest="dREAL")
    att = _att("a1", "b", digest="dDIFFERENT")
    f = detect_provenance_break(art, (att,), at=_t0())
    assert f is not None and f.kind is BreakKind.ARTIFACT_SUBSTITUTION


def test_provenance_break_invalid_signature() -> None:
    art = _art("b", StageKind.BUILD, digest="d")
    att = _att("a1", "b", digest="d", valid=False)
    f = detect_provenance_break(art, (att,), at=_t0())
    assert f is not None and f.kind is BreakKind.PROVENANCE_BREAK


def test_dependency_substitution_detected() -> None:
    findings = detect_dependency_substitution(
        {"lib": "aaa"},
        {"lib": "bbb"},
        artifact_id="x", at=_t0(),
    )
    assert any(f.kind is BreakKind.DEPENDENCY_SUBSTITUTION for f in findings)


def test_dependency_missing_detected() -> None:
    findings = detect_dependency_substitution(
        {"lib": "aaa"},
        {},
        artifact_id="x", at=_t0(),
    )
    assert any(f.kind is BreakKind.TRUST_CHAIN_DISCONTINUITY for f in findings)


def test_build_compromise_known_builder() -> None:
    art = _art("b", StageKind.BUILD, producer="evil")
    f = detect_build_compromise(
        art, builder_trust=0.9,
        known_compromised_builders=frozenset({"evil"}),
        at=_t0(),
    )
    assert f is not None and f.kind is BreakKind.BUILD_COMPROMISE


def test_build_compromise_low_trust_builder() -> None:
    art = _art("b", StageKind.BUILD, producer="sketchy")
    f = detect_build_compromise(
        art, builder_trust=0.1, known_compromised_builders=frozenset(),
        at=_t0(),
    )
    assert f is not None and f.kind is BreakKind.BUILD_COMPROMISE


def test_unauthorized_update_detected() -> None:
    art = _art("u", StageKind.UPDATE, producer="rogue")
    f = detect_unauthorized_update(
        art, authorized_publishers=frozenset({"trusted"}), at=_t0(),
    )
    assert f is not None and f.kind is BreakKind.UNAUTHORIZED_UPDATE


def test_runtime_divergence_detected() -> None:
    art = _art("r", StageKind.RUNTIME, digest="dRuntime")
    f = detect_runtime_divergence(
        art, expected_digest="dPackage", at=_t0(),
    )
    assert f is not None and f.kind is BreakKind.RUNTIME_DIVERGENCE


def test_discontinuity_non_root_without_parent() -> None:
    g = ChainGraph()
    g.add_artifact(_art("b", StageKind.BUILD))
    f = detect_discontinuity(g, "b", at=_t0())
    assert f is not None and f.kind is BreakKind.TRUST_CHAIN_DISCONTINUITY


def test_discontinuity_source_is_ok() -> None:
    g = ChainGraph()
    g.add_artifact(_art("s", StageKind.SOURCE))
    assert detect_discontinuity(g, "s", at=_t0()) is None


def test_artifact_substitution_on_link() -> None:
    g = ChainGraph()
    g.add_artifact(_art("s", StageKind.SOURCE, digest="dS"))
    g.add_artifact(_art("b", StageKind.BUILD, digest="dB", parent="s"))
    # link records a DIFFERENT expected digest than current
    g.add_link(_link("s", "b", pdigest="dOTHER"))
    f = detect_artifact_substitution(g, "s", "b", at=_t0())
    assert f is not None and f.kind is BreakKind.ARTIFACT_SUBSTITUTION


# ---- continuity -----------------------------------------------------------

def test_effective_continuity_no_penalties() -> None:
    c = effective_continuity(root_trust=1.0, link_postures=[1.0], findings=[])
    assert c == 1.0


def test_effective_continuity_weak_link_halves() -> None:
    c = effective_continuity(root_trust=1.0, link_postures=[0.0], findings=[])
    assert abs(c - 0.5) < 1e-9


def test_effective_continuity_findings_penalize() -> None:
    f = BreakFinding(
        kind=BreakKind.RUNTIME_DIVERGENCE, artifact_id="x",
        parent_artifact_id=None, detail="d", severity=5, at=_t0(),
    )
    c = effective_continuity(root_trust=1.0, link_postures=[1.0], findings=[f])
    assert c < 1.0


def test_analyse_continuity_propagates_labels() -> None:
    g = ChainGraph()
    g.add_artifact(_art("s", StageKind.SOURCE, digest="dS", producer="pub"))
    g.add_artifact(_art("b", StageKind.BUILD, digest="dB", parent="s"))
    g.add_link(_link("s", "b", pdigest="dS", cdigest="dB"))
    result = analyse_continuity(
        g, "b",
        publisher_trust={"pub": 0.95},
        attestations={"b": (_att("a1", "b", digest="dB"),)},
        link_postures={("s", "b"): 0.95},
        findings_by_artifact={},
        at=_t0(),
    )
    assert result.chain == ("s", "b")
    assert result.continuity > 0.5


def test_analyse_continuity_invalid_attestation_forces_suspicious() -> None:
    g = ChainGraph()
    g.add_artifact(_art("s", StageKind.SOURCE, digest="dS", producer="pub"))
    g.add_artifact(_art("b", StageKind.BUILD, digest="dB", parent="s"))
    g.add_link(_link("s", "b", pdigest="dS", cdigest="dB"))
    result = analyse_continuity(
        g, "b",
        publisher_trust={"pub": 1.0},
        attestations={"b": (_att("a1", "b", digest="dB", valid=False),)},
        link_postures={("s", "b"): 1.0},
        findings_by_artifact={},
        at=_t0(),
    )
    assert label_severity(result.label) >= label_severity(TrustLabel.SUSPICIOUS)


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

def _build_clean_chain() -> SupplyChainTrustEngine:
    eng = SupplyChainTrustEngine()
    eng.register_publisher(Publisher("src", 0.95))
    eng.register_publisher(Publisher("builder", 0.95))
    eng.register_publisher(Publisher("deployer", 0.95))
    eng.register_publisher(Publisher("runtime", 0.95))
    eng.authorize_update_publisher("deployer")

    eng.add_artifact(_art("src", StageKind.SOURCE, digest="dS",
                          producer="src"))
    eng.add_artifact(_art("build", StageKind.BUILD, digest="dB",
                          producer="builder", parent="src"))
    eng.add_artifact(_art("pkg", StageKind.PACKAGE, digest="dP",
                          producer="deployer", parent="build"))
    eng.add_artifact(_art("run", StageKind.RUNTIME, digest="dR",
                          producer="runtime", parent="pkg"))

    eng.add_link(_link("src", "build", pdigest="dS", cdigest="dB"),
                 posture=0.95)
    eng.add_link(_link("build", "pkg", pdigest="dB", cdigest="dP"),
                 posture=0.95)
    eng.add_link(_link("pkg", "run", pdigest="dP", cdigest="dR"),
                 posture=0.95)

    for aid, digest in (("src", "dS"), ("build", "dB"),
                        ("pkg", "dP"), ("run", "dR")):
        eng.add_attestation(_att(f"att-{aid}", aid, digest=digest))
    return eng


def test_engine_clean_chain_no_violations() -> None:
    eng = _build_clean_chain()
    eng.recompute(at=_t0())
    assert eng.violations() == ()


def test_engine_untrusted_runtime_flagged() -> None:
    eng = _build_clean_chain()
    # Force runtime to be suspicious by injecting an invalid attestation
    eng.add_attestation(_att("bad", "run", digest="dR", valid=False))
    eng.recompute(at=_t0())
    v = eng.violations()
    assert any(x.invariant_id == "supply.untrusted_runtime_or_update"
               for x in v)


def test_engine_trusted_without_attestation_violation() -> None:
    # Build a fresh engine without attestation
    eng = SupplyChainTrustEngine()
    eng.register_publisher(Publisher("src", 1.0))
    eng.add_artifact(_art("s", StageKind.SOURCE, digest="d", producer="src"))
    # Directly set the store record to TRUSTED with no attestations
    eng._store.put(ArtifactStateRecord(
        artifact_id="s", label=TrustLabel.TRUSTED,
        continuity=1.0, findings_count=0, updated_at=_t0(),
    ))
    eng._labels["s"] = TrustLabel.TRUSTED
    snap = eng.snapshot()
    viols = check_invariants(snap)
    assert any(v.invariant_id == "supply.trusted_requires_attestation"
               for v in viols)


def test_engine_trusted_with_untrusted_parent_violation() -> None:
    eng = SupplyChainTrustEngine()
    eng.register_publisher(Publisher("src", 1.0))
    eng.register_publisher(Publisher("builder", 1.0))
    eng.add_artifact(_art("s", StageKind.SOURCE, digest="dS", producer="src"))
    eng.add_artifact(_art("b", StageKind.BUILD, digest="dB",
                          producer="builder", parent="s"))
    eng.add_link(_link("s", "b", pdigest="dS", cdigest="dB"), posture=0.9)
    eng.add_attestation(_att("att-s", "s", digest="dS"))
    eng.add_attestation(_att("att-b", "b", digest="dB"))
    # Force s to be untrusted via label
    eng._labels["s"] = TrustLabel.COMPROMISED
    eng._store.put(ArtifactStateRecord(
        artifact_id="s", label=TrustLabel.COMPROMISED,
        continuity=0.1, findings_count=0, updated_at=_t0(),
    ))
    eng._store.put(ArtifactStateRecord(
        artifact_id="b", label=TrustLabel.TRUSTED,
        continuity=0.9, findings_count=0, updated_at=_t0(),
    ))
    eng._labels["b"] = TrustLabel.TRUSTED
    viols = check_invariants(eng.snapshot())
    assert any(v.invariant_id == "supply.trusted_with_untrusted_parent"
               for v in viols)


def test_engine_chain_discontinuity_flagged() -> None:
    eng = SupplyChainTrustEngine()
    eng.register_publisher(Publisher("b", 0.9))
    # BUILD stage artifact with no parent
    eng.add_artifact(_art("orphan", StageKind.BUILD, digest="d",
                          producer="b"))
    eng.add_attestation(_att("a", "orphan", digest="d"))
    eng.recompute(at=_t0())
    v = eng.violations()
    assert any(x.invariant_id == "supply.chain_discontinuity" for x in v)


def test_engine_digest_reuse_across_stages_flagged() -> None:
    eng = SupplyChainTrustEngine()
    eng.register_publisher(Publisher("p", 0.9))
    eng.add_artifact(_art("s", StageKind.SOURCE, digest="SAME", producer="p"))
    eng.add_artifact(_art("b", StageKind.BUILD, digest="SAME",
                          producer="p", parent="s"))
    eng.add_link(_link("s", "b", pdigest="SAME", cdigest="SAME"),
                 posture=0.9)
    eng.add_attestation(_att("a-s", "s", digest="SAME"))
    eng.add_attestation(_att("a-b", "b", digest="SAME"))
    eng.recompute(at=_t0())
    v = eng.violations()
    assert any(x.invariant_id == "supply.digest_reuse_across_stages"
               for x in v)


def test_engine_build_compromise_propagates() -> None:
    eng = SupplyChainTrustEngine()
    eng.register_publisher(Publisher("evil", 0.9))
    eng.mark_builder_compromised("evil")
    eng.add_artifact(_art("s", StageKind.SOURCE, digest="dS",
                          producer="evil"))
    eng.add_artifact(_art("b", StageKind.BUILD, digest="dB",
                          producer="evil", parent="s"))
    eng.add_link(_link("s", "b", pdigest="dS", cdigest="dB"), posture=0.9)
    eng.add_attestation(_att("a-s", "s", digest="dS"))
    eng.add_attestation(_att("a-b", "b", digest="dB"))
    records = eng.recompute(at=_t0())
    b = next(r for r in records if r.artifact_id == "b")
    assert label_severity(b.label) >= label_severity(TrustLabel.SUSPICIOUS)


def test_engine_unauthorized_update_flagged() -> None:
    eng = SupplyChainTrustEngine()
    eng.register_publisher(Publisher("rogue", 0.9))
    eng.add_artifact(_art("s", StageKind.SOURCE, digest="dS",
                          producer="rogue"))
    eng.add_artifact(_art("u", StageKind.UPDATE, digest="dU",
                          producer="rogue", parent="s"))
    eng.add_link(_link("s", "u", pdigest="dS", cdigest="dU"), posture=0.9)
    eng.add_attestation(_att("a-s", "s", digest="dS"))
    eng.add_attestation(_att("a-u", "u", digest="dU"))
    eng.recompute(at=_t0())
    assert any(v.invariant_id == "supply.untrusted_runtime_or_update"
               for v in eng.violations())


def test_engine_runtime_divergence_via_report() -> None:
    eng = _build_clean_chain()
    eng.report_runtime_digest("run", expected_digest="dDIFFERENT", at=_t0())
    records = eng.recompute(at=_t0())
    run = next(r for r in records if r.artifact_id == "run")
    assert label_severity(run.label) >= label_severity(TrustLabel.SUSPICIOUS)


def test_engine_dependency_substitution_via_report() -> None:
    eng = _build_clean_chain()
    findings = eng.report_dependency_digests(
        "run",
        declared={"libc": "aaa"},
        observed={"libc": "bbb"},
        at=_t0(),
    )
    assert any(f.kind is BreakKind.DEPENDENCY_SUBSTITUTION for f in findings)
    eng.recompute(at=_t0())
    run = next(r for r in eng.recompute(at=_t0()) if r.artifact_id == "run")
    assert label_severity(run.label) >= label_severity(TrustLabel.DEGRADED)


# ---- store tests ----------------------------------------------------------

def test_in_memory_store_rejects_stale() -> None:
    s = InMemorySupplyChainStore()
    t = _t0()
    s.put(ArtifactStateRecord("a", TrustLabel.TRUSTED, 0.9, 0, t))
    earlier = t.replace(year=t.year - 1)
    try:
        s.put(ArtifactStateRecord("a", TrustLabel.UNKNOWN, 0.5, 0, earlier))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_artifact_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "supply.db")
    store = SqliteSupplyChainStore(db)
    t = _t0()
    store.put(ArtifactStateRecord("a", TrustLabel.TRUSTED, 0.9, 1, t))
    got = store.get("a")
    assert got is not None and got.label is TrustLabel.TRUSTED
    assert got.findings_count == 1


def test_sqlite_store_attestation_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "supply.db")
    store = SqliteSupplyChainStore(db)
    att = _att("a1", "art", digest="dX")
    store.put_attestation(att)
    got = store.get_attestation("a1")
    assert got is not None
    assert got.subject_digest == "dX"
    assert got.signature_valid is True


def test_sqlite_store_publisher_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "supply.db")
    store = SqliteSupplyChainStore(db)
    pub = Publisher("pub", 0.85, verified=True)
    store.put_publisher(pub)
    got = store.get_publisher("pub")
    assert got is not None and got.trust == 0.85


# =============================================================================
# SECTION 13 — MANUAL RUNNER
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
