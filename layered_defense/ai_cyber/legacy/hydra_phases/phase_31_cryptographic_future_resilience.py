"""
HYDRA POST-CORE — PHASE 31: CRYPTOGRAPHIC FUTURE RESILIENCE
===============================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * Domain — 7 algorithm families, 6 quantum vulnerability classes,
    4 crypto asset kinds, 6 migration states, 5 trust states
  * Algorithm registry — security level + quantum vulnerability +
    PQC status + acceptable key-size band
  * Cryptographic asset inventory (keys, certificates, protocols,
    hashes, signatures, KEMs)
  * Dependency mapping — crypto asset → algorithm → protocol →
    service → application
  * Cryptographic trust state (verified / degraded / deprecated /
    broken / rotated) with transition rules
  * Exposure analysis — quantum-vulnerable / weak-strength /
    deprecated-algorithm surfaces
  * Migration readiness scoring per application and ecosystem-wide
  * Future cryptographic failure scenarios (algorithm break, key
    compromise, cert expiry, PQC migration gap, hybrid failure)
  * Findings — quantum-vulnerable, weak-strength, deprecated,
    harvest-now-decrypt-later, migration gap, cert expiring,
    dependency on broken algorithm
  * Machine-checkable crypto invariants
  * In-memory + SQLite stores
  * Phase-31 engine facade
  * Full test suite + manual runner

Doctrine: this is NOT a generic crypto library. It is security-state
awareness and controlled transition of cryptographic trust.

No third-party dependencies.

Run tests:
    python hydra_phase31_cryptographic_future_resilience.py
    pytest hydra_phase31_cryptographic_future_resilience.py -q
"""
from __future__ import annotations

import json
import sqlite3
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
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


class AlgorithmFamily(str, Enum):
    SYMMETRIC = "symmetric"
    HASH = "hash"
    SIGNATURE_CLASSICAL = "signature_classical"
    SIGNATURE_PQC = "signature_pqc"
    KEM_CLASSICAL = "kem_classical"
    KEM_PQC = "kem_pqc"
    HYBRID = "hybrid"


ALL_FAMILIES: Tuple[AlgorithmFamily, ...] = tuple(AlgorithmFamily)


class QuantumVulnerability(str, Enum):
    NONE = "none"                   # e.g. AES-256, hash, PQC
    GROVER_REDUCED = "grover_reduced"   # symmetric with reduced margin
    SHOR_BROKEN = "shor_broken"     # RSA, ECDSA, ECDH — fully broken
    UNKNOWN = "unknown"


_QV_RANK: Mapping[QuantumVulnerability, int] = {
    QuantumVulnerability.NONE: 0,
    QuantumVulnerability.GROVER_REDUCED: 1,
    QuantumVulnerability.UNKNOWN: 2,
    QuantumVulnerability.SHOR_BROKEN: 3,
}


def qv_rank(q: QuantumVulnerability) -> int:
    return _QV_RANK[q]


class PqcStatus(str, Enum):
    NOT_APPLICABLE = "not_applicable"   # symmetric / hash
    NOT_QUANTUM_SAFE = "not_quantum_safe"
    PQC_STANDARDIZED = "pqc_standardized"
    PQC_TRANSITION = "pqc_transition"
    HYBRID_DEPLOYED = "hybrid_deployed"


class CryptoAssetKind(str, Enum):
    KEY = "key"
    CERTIFICATE = "certificate"
    PROTOCOL = "protocol"
    HASH = "hash"
    SIGNATURE = "signature"
    KEM = "kem"


class MigrationState(str, Enum):
    NOT_STARTED = "not_started"
    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    BLOCKED = "blocked"


class TrustState(str, Enum):
    VERIFIED = "verified"
    DEGRADED = "degraded"
    DEPRECATED = "deprecated"
    BROKEN = "broken"
    ROTATED = "rotated"


_TRUST_RANK: Mapping[TrustState, int] = {
    TrustState.BROKEN: 0,
    TrustState.DEPRECATED: 1,
    TrustState.DEGRADED: 2,
    TrustState.ROTATED: 3,
    TrustState.VERIFIED: 4,
}


def trust_rank(t: TrustState) -> int:
    return _TRUST_RANK[t]


_ALLOWED_TRUST_EDGES: Mapping[
    TrustState, FrozenSet[TrustState]
] = {
    TrustState.VERIFIED: frozenset({
        TrustState.DEGRADED, TrustState.DEPRECATED,
        TrustState.BROKEN, TrustState.ROTATED,
    }),
    TrustState.DEGRADED: frozenset({
        TrustState.VERIFIED, TrustState.DEPRECATED,
        TrustState.BROKEN, TrustState.ROTATED,
    }),
    TrustState.DEPRECATED: frozenset({
        TrustState.VERIFIED, TrustState.DEGRADED,
        TrustState.BROKEN, TrustState.ROTATED,
    }),
    TrustState.BROKEN: frozenset({
        # broken can only recover through explicit rotation
        TrustState.ROTATED,
    }),
    TrustState.ROTATED: frozenset({
        TrustState.VERIFIED, TrustState.DEGRADED,
        TrustState.BROKEN,
    }),
}


class CryptoFindingKind(str, Enum):
    QUANTUM_VULNERABLE_DEPLOYED = "quantum_vulnerable_deployed"
    WEAK_STRENGTH = "weak_strength"
    DEPRECATED_ALGORITHM = "deprecated_algorithm"
    HARVEST_NOW_DECRYPT_LATER = "harvest_now_decrypt_later"
    MIGRATION_GAP = "migration_gap"
    MIGRATION_BLOCKED = "migration_blocked"
    CERT_EXPIRING = "cert_expiring"
    CERT_EXPIRED = "cert_expired"
    BROKEN_ALGORITHM_DEPENDENCY = "broken_algorithm_dependency"
    INVALID_TRUST_TRANSITION = "invalid_trust_transition"
    PQC_READINESS_GAP = "pqc_readiness_gap"
    HYBRID_INCOMPLETE = "hybrid_incomplete"


@dataclass(frozen=True)
class CryptoFinding:
    kind: CryptoFindingKind
    subject_id: str
    detail: str
    severity: int
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        if not 1 <= self.severity <= 5:
            raise ValueError("severity must be in [1,5]")


# =============================================================================
# SECTION 3 — ALGORITHM REGISTRY
# =============================================================================


@dataclass(frozen=True)
class AlgorithmProfile:
    algorithm_id: str
    family: AlgorithmFamily
    name: str
    security_level_bits: int
    quantum_vulnerability: QuantumVulnerability
    pqc_status: PqcStatus
    min_acceptable_key_bits: int
    recommended_key_bits: int
    deprecated: bool = False
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.algorithm_id:
            raise ValueError("algorithm_id is required")
        if not self.name:
            raise ValueError("name is required")
        if self.security_level_bits < 0:
            raise ValueError("security_level_bits must be >= 0")
        if self.min_acceptable_key_bits < 0:
            raise ValueError("min_acceptable_key_bits must be >= 0")
        if self.recommended_key_bits < self.min_acceptable_key_bits:
            raise ValueError(
                "recommended_key_bits must be >= min_acceptable_key_bits"
            )

    def is_pqc_capable(self) -> bool:
        return self.pqc_status in (
            PqcStatus.PQC_STANDARDIZED,
            PqcStatus.PQC_TRANSITION,
            PqcStatus.HYBRID_DEPLOYED,
        )


# A small, security-relevant reference registry. Applications can
# register additional algorithms.
DEFAULT_ALGORITHMS: Tuple[AlgorithmProfile, ...] = (
    # Symmetric
    AlgorithmProfile(
        algorithm_id="aes-256-gcm", family=AlgorithmFamily.SYMMETRIC,
        name="AES-256-GCM", security_level_bits=256,
        quantum_vulnerability=QuantumVulnerability.NONE,
        pqc_status=PqcStatus.NOT_APPLICABLE,
        min_acceptable_key_bits=256, recommended_key_bits=256,
    ),
    AlgorithmProfile(
        algorithm_id="aes-128-gcm", family=AlgorithmFamily.SYMMETRIC,
        name="AES-128-GCM", security_level_bits=128,
        quantum_vulnerability=QuantumVulnerability.GROVER_REDUCED,
        pqc_status=PqcStatus.NOT_APPLICABLE,
        min_acceptable_key_bits=256, recommended_key_bits=256,
        notes="Grover halves effective security",
    ),
    AlgorithmProfile(
        algorithm_id="3des", family=AlgorithmFamily.SYMMETRIC,
        name="3DES", security_level_bits=112,
        quantum_vulnerability=QuantumVulnerability.GROVER_REDUCED,
        pqc_status=PqcStatus.NOT_APPLICABLE,
        min_acceptable_key_bits=256, recommended_key_bits=256,
        deprecated=True,
    ),
    # Hash
    AlgorithmProfile(
        algorithm_id="sha3-256", family=AlgorithmFamily.HASH,
        name="SHA3-256", security_level_bits=256,
        quantum_vulnerability=QuantumVulnerability.NONE,
        pqc_status=PqcStatus.NOT_APPLICABLE,
        min_acceptable_key_bits=256, recommended_key_bits=256,
    ),
    AlgorithmProfile(
        algorithm_id="sha-256", family=AlgorithmFamily.HASH,
        name="SHA-256", security_level_bits=256,
        quantum_vulnerability=QuantumVulnerability.NONE,
        pqc_status=PqcStatus.NOT_APPLICABLE,
        min_acceptable_key_bits=256, recommended_key_bits=256,
    ),
    AlgorithmProfile(
        algorithm_id="sha-1", family=AlgorithmFamily.HASH,
        name="SHA-1", security_level_bits=80,
        quantum_vulnerability=QuantumVulnerability.GROVER_REDUCED,
        pqc_status=PqcStatus.NOT_APPLICABLE,
        min_acceptable_key_bits=256, recommended_key_bits=256,
        deprecated=True,
    ),
    # Classical signatures (Shor-broken)
    AlgorithmProfile(
        algorithm_id="rsa-2048", family=AlgorithmFamily.SIGNATURE_CLASSICAL,
        name="RSA-2048", security_level_bits=112,
        quantum_vulnerability=QuantumVulnerability.SHOR_BROKEN,
        pqc_status=PqcStatus.NOT_QUANTUM_SAFE,
        min_acceptable_key_bits=3072, recommended_key_bits=4096,
        notes="Broken by Shor; also below classical 128-bit target",
    ),
    AlgorithmProfile(
        algorithm_id="rsa-4096", family=AlgorithmFamily.SIGNATURE_CLASSICAL,
        name="RSA-4096", security_level_bits=140,
        quantum_vulnerability=QuantumVulnerability.SHOR_BROKEN,
        pqc_status=PqcStatus.NOT_QUANTUM_SAFE,
        min_acceptable_key_bits=3072, recommended_key_bits=4096,
    ),
    AlgorithmProfile(
        algorithm_id="ecdsa-p256", family=AlgorithmFamily.SIGNATURE_CLASSICAL,
        name="ECDSA-P256", security_level_bits=128,
        quantum_vulnerability=QuantumVulnerability.SHOR_BROKEN,
        pqc_status=PqcStatus.NOT_QUANTUM_SAFE,
        min_acceptable_key_bits=256, recommended_key_bits=384,
    ),
    AlgorithmProfile(
        algorithm_id="ed25519", family=AlgorithmFamily.SIGNATURE_CLASSICAL,
        name="Ed25519", security_level_bits=128,
        quantum_vulnerability=QuantumVulnerability.SHOR_BROKEN,
        pqc_status=PqcStatus.NOT_QUANTUM_SAFE,
        min_acceptable_key_bits=256, recommended_key_bits=256,
    ),
    # PQC signatures
    AlgorithmProfile(
        algorithm_id="ml-dsa-65", family=AlgorithmFamily.SIGNATURE_PQC,
        name="ML-DSA-65 (Dilithium3)", security_level_bits=192,
        quantum_vulnerability=QuantumVulnerability.NONE,
        pqc_status=PqcStatus.PQC_STANDARDIZED,
        min_acceptable_key_bits=0, recommended_key_bits=0,
    ),
    AlgorithmProfile(
        algorithm_id="slh-dsa-128s", family=AlgorithmFamily.SIGNATURE_PQC,
        name="SLH-DSA-128s (SPHINCS+)", security_level_bits=128,
        quantum_vulnerability=QuantumVulnerability.NONE,
        pqc_status=PqcStatus.PQC_STANDARDIZED,
        min_acceptable_key_bits=0, recommended_key_bits=0,
    ),
    # KEM classical (Shor-broken)
    AlgorithmProfile(
        algorithm_id="rsa-kem-2048", family=AlgorithmFamily.KEM_CLASSICAL,
        name="RSA-KEM-2048", security_level_bits=112,
        quantum_vulnerability=QuantumVulnerability.SHOR_BROKEN,
        pqc_status=PqcStatus.NOT_QUANTUM_SAFE,
        min_acceptable_key_bits=3072, recommended_key_bits=4096,
    ),
    AlgorithmProfile(
        algorithm_id="ecdh-p256", family=AlgorithmFamily.KEM_CLASSICAL,
        name="ECDH-P256", security_level_bits=128,
        quantum_vulnerability=QuantumVulnerability.SHOR_BROKEN,
        pqc_status=PqcStatus.NOT_QUANTUM_SAFE,
        min_acceptable_key_bits=256, recommended_key_bits=384,
    ),
    # PQC KEM
    AlgorithmProfile(
        algorithm_id="ml-kem-768", family=AlgorithmFamily.KEM_PQC,
        name="ML-KEM-768 (Kyber768)", security_level_bits=192,
        quantum_vulnerability=QuantumVulnerability.NONE,
        pqc_status=PqcStatus.PQC_STANDARDIZED,
        min_acceptable_key_bits=0, recommended_key_bits=0,
    ),
    # Hybrid
    AlgorithmProfile(
        algorithm_id="x25519-ml-kem-768",
        family=AlgorithmFamily.HYBRID,
        name="X25519 + ML-KEM-768 hybrid KEM",
        security_level_bits=192,
        quantum_vulnerability=QuantumVulnerability.NONE,
        pqc_status=PqcStatus.HYBRID_DEPLOYED,
        min_acceptable_key_bits=0, recommended_key_bits=0,
    ),
    AlgorithmProfile(
        algorithm_id="ecdsa-p256-ml-dsa-65",
        family=AlgorithmFamily.HYBRID,
        name="ECDSA-P256 + ML-DSA-65 hybrid signature",
        security_level_bits=192,
        quantum_vulnerability=QuantumVulnerability.NONE,
        pqc_status=PqcStatus.HYBRID_DEPLOYED,
        min_acceptable_key_bits=0, recommended_key_bits=0,
    ),
)


# =============================================================================
# SECTION 4 — CRYPTO ASSETS
# =============================================================================


@dataclass(frozen=True)
class CryptoAsset:
    asset_id: str
    kind: CryptoAssetKind
    name: str
    algorithm_id: str
    key_bits: int
    trust_state: TrustState
    migration_state: MigrationState
    data_classification_ceiling: int   # 0..4
    long_lived: bool = False           # secrets that must remain secret for years
    exposed_to_adversary: bool = False # bytes that adversary can capture now
    expires_at: Optional[datetime] = None
    tenant_id: str = "default"
    tags: FrozenSet[str] = frozenset()

    def __post_init__(self) -> None:
        if not self.asset_id:
            raise ValueError("asset_id is required")
        if not self.name:
            raise ValueError("name is required")
        if not self.algorithm_id:
            raise ValueError("algorithm_id is required")
        if self.key_bits < 0:
            raise ValueError("key_bits must be >= 0")
        if not 0 <= self.data_classification_ceiling <= 4:
            raise ValueError(
                "data_classification_ceiling must be in [0,4]"
            )
        if self.expires_at is not None and self.expires_at.tzinfo is None:
            raise ValueError("expires_at must be timezone-aware")


@dataclass(frozen=True)
class CryptoDependencyEdge:
    edge_id: str
    dependent_id: str
    dependency_id: str
    kind: str
    at: Optional[datetime] = None

    def __post_init__(self) -> None:
        if not self.edge_id:
            raise ValueError("edge_id is required")
        if not self.dependent_id or not self.dependency_id:
            raise ValueError("dependent_id and dependency_id required")
        if self.dependent_id == self.dependency_id:
            raise ValueError("self-edges are not allowed")
        if not self.kind:
            raise ValueError("kind is required")
        if self.at is not None and self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


class CryptoDependencyGraph:
    def __init__(self) -> None:
        self._assets: Dict[str, CryptoAsset] = {}
        self._out: Dict[str, List[str]] = defaultdict(list)
        self._in: Dict[str, List[str]] = defaultdict(list)
        self._edges: Dict[str, CryptoDependencyEdge] = {}

    def add_asset(self, asset: CryptoAsset) -> None:
        if asset.asset_id in self._assets:
            raise ValueError(f"asset {asset.asset_id} already exists")
        self._assets[asset.asset_id] = asset

    def asset(self, asset_id: str) -> CryptoAsset:
        a = self._assets.get(asset_id)
        if a is None:
            raise KeyError(f"unknown asset {asset_id}")
        return a

    def assets(self) -> Tuple[CryptoAsset, ...]:
        return tuple(self._assets.values())

    def has_asset(self, asset_id: str) -> bool:
        return asset_id in self._assets

    def add_edge(self, edge: CryptoDependencyEdge) -> None:
        if edge.edge_id in self._edges:
            raise ValueError(f"edge {edge.edge_id} already exists")
        if edge.dependent_id not in self._assets:
            raise KeyError(f"dependent {edge.dependent_id} not registered")
        if edge.dependency_id not in self._assets:
            raise KeyError(
                f"dependency {edge.dependency_id} not registered"
            )
        if self._would_create_cycle(edge.dependent_id, edge.dependency_id):
            raise ValueError(
                f"edge {edge.dependent_id}->{edge.dependency_id} "
                f"creates a cycle"
            )
        self._edges[edge.edge_id] = edge
        self._out[edge.dependent_id].append(edge.edge_id)
        self._in[edge.dependency_id].append(edge.edge_id)

    def _would_create_cycle(self, src: str, dst: str) -> bool:
        stack = [dst]
        seen: set = set()
        while stack:
            cur = stack.pop()
            if cur == src:
                return True
            if cur in seen:
                continue
            seen.add(cur)
            for eid in self._out.get(cur, ()):
                stack.append(self._edges[eid].dependency_id)
        return False

    def edges(self) -> Tuple[CryptoDependencyEdge, ...]:
        return tuple(self._edges.values())

    def children(self, asset_id: str) -> Tuple[str, ...]:
        return tuple(
            self._edges[eid].dependency_id
            for eid in self._out.get(asset_id, ())
        )

    def parents(self, asset_id: str) -> Tuple[str, ...]:
        return tuple(
            self._edges[eid].dependent_id
            for eid in self._in.get(asset_id, ())
        )

    def reachable(self, asset_id: str) -> FrozenSet[str]:
        out: set = set()
        stack = [asset_id]
        while stack:
            cur = stack.pop()
            for c in self.children(cur):
                if c in out:
                    continue
                out.add(c)
                stack.append(c)
        return frozenset(out)

    def dependents_of(self, asset_id: str) -> FrozenSet[str]:
        out: set = set()
        stack = [asset_id]
        while stack:
            cur = stack.pop()
            for p in self.parents(cur):
                if p in out:
                    continue
                out.add(p)
                stack.append(p)
        return frozenset(out)


# =============================================================================
# SECTION 5 — TRUST TRANSITION
# =============================================================================


@dataclass(frozen=True)
class TrustTransitionProposal:
    proposal_id: str
    asset_id: str
    from_state: TrustState
    to_state: TrustState
    reason: str
    verified: bool = False
    rotated: bool = False
    at: Optional[datetime] = None

    def __post_init__(self) -> None:
        if not self.proposal_id:
            raise ValueError("proposal_id is required")
        if not self.asset_id:
            raise ValueError("asset_id is required")
        if not self.reason:
            raise ValueError("reason is required")
        if self.at is not None and self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


@dataclass(frozen=True)
class TrustTransitionDecision:
    allowed: bool
    rationale: str


def evaluate_trust_transition(
    proposal: TrustTransitionProposal,
) -> TrustTransitionDecision:
    if proposal.from_state is proposal.to_state:
        return TrustTransitionDecision(
            allowed=True, rationale="no-op",
        )
    permitted = _ALLOWED_TRUST_EDGES.get(
        proposal.from_state, frozenset(),
    )
    if proposal.to_state not in permitted:
        return TrustTransitionDecision(
            allowed=False,
            rationale=(
                f"forbidden transition {proposal.from_state.value} → "
                f"{proposal.to_state.value}"
            ),
        )
    going_better = trust_rank(proposal.to_state) > \
        trust_rank(proposal.from_state)
    if going_better:
        if proposal.from_state is TrustState.BROKEN \
           and not proposal.rotated:
            return TrustTransitionDecision(
                allowed=False,
                rationale="BROKEN can only recover via ROTATED",
            )
        if not proposal.verified:
            return TrustTransitionDecision(
                allowed=False,
                rationale="recovery transitions require verification",
            )
    return TrustTransitionDecision(allowed=True, rationale="permitted")


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
class CryptoSnapshot:
    graph: CryptoDependencyGraph
    algorithms: Mapping[str, AlgorithmProfile]
    findings: Tuple[CryptoFinding, ...]


@dataclass(frozen=True)
class CryptoInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[CryptoSnapshot],
                        Tuple[InvariantViolation, ...]]
    description: str


def _inv_assets_reference_known_algorithm(
    snap: CryptoSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for a in snap.graph.assets():
        if a.algorithm_id not in snap.algorithms:
            out.append(InvariantViolation(
                invariant_id="crypto.asset_algorithm_registered",
                severity=InvariantSeverity.CRITICAL,
                subject_id=a.asset_id,
                detail=(
                    f"references unknown algorithm {a.algorithm_id}"
                ),
            ))
    return tuple(out)


def _inv_key_bits_non_negative(
    snap: CryptoSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for a in snap.graph.assets():
        if a.key_bits < 0:
            out.append(InvariantViolation(
                invariant_id="crypto.key_bits_non_negative",
                severity=InvariantSeverity.HIGH,
                subject_id=a.asset_id,
                detail=f"key_bits {a.key_bits}",
            ))
    return tuple(out)


def _inv_broken_assets_are_migration_visible(
    snap: CryptoSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for a in snap.graph.assets():
        if a.trust_state is TrustState.BROKEN \
           and a.migration_state is MigrationState.NOT_STARTED:
            out.append(InvariantViolation(
                invariant_id="crypto.broken_requires_migration",
                severity=InvariantSeverity.CRITICAL,
                subject_id=a.asset_id,
                detail="BROKEN asset with migration NOT_STARTED",
            ))
    return tuple(out)


def _inv_findings_severity_bounded(
    snap: CryptoSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for f in snap.findings:
        if not 1 <= f.severity <= 5:
            out.append(InvariantViolation(
                invariant_id="crypto.findings_severity_bounded",
                severity=InvariantSeverity.LOW,
                subject_id=f.subject_id,
                detail=f"severity {f.severity}",
            ))
    return tuple(out)


def _inv_deprecated_asset_not_verified(
    snap: CryptoSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for a in snap.graph.assets():
        alg = snap.algorithms.get(a.algorithm_id)
        if alg is None:
            continue
        if alg.deprecated and a.trust_state is TrustState.VERIFIED:
            out.append(InvariantViolation(
                invariant_id="crypto.deprecated_not_verified",
                severity=InvariantSeverity.HIGH,
                subject_id=a.asset_id,
                detail=(
                    f"asset using deprecated algorithm "
                    f"{alg.algorithm_id} is marked VERIFIED"
                ),
            ))
    return tuple(out)


DEFAULT_INVARIANTS: Tuple[CryptoInvariant, ...] = (
    CryptoInvariant(
        invariant_id="crypto.asset_algorithm_registered",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_assets_reference_known_algorithm,
        description="Assets must reference registered algorithms.",
    ),
    CryptoInvariant(
        invariant_id="crypto.key_bits_non_negative",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_key_bits_non_negative,
        description="Key bits must be non-negative.",
    ),
    CryptoInvariant(
        invariant_id="crypto.broken_requires_migration",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_broken_assets_are_migration_visible,
        description="BROKEN assets must have migration underway.",
    ),
    CryptoInvariant(
        invariant_id="crypto.findings_severity_bounded",
        severity=InvariantSeverity.LOW,
        predicate=_inv_findings_severity_bounded,
        description="Findings must carry valid severity.",
    ),
    CryptoInvariant(
        invariant_id="crypto.deprecated_not_verified",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_deprecated_asset_not_verified,
        description="Deprecated algorithms cannot be VERIFIED.",
    ),
)


def check_invariants(
    snap: CryptoSnapshot,
    invariants: Iterable[CryptoInvariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 7 — EXPOSURE + READINESS
# =============================================================================


@dataclass(frozen=True)
class CryptoExposure:
    asset_id: str
    quantum_vulnerable: bool
    weak_strength: bool
    deprecated: bool
    harvest_now_decrypt_later: bool
    exposure_score: float

    def __post_init__(self) -> None:
        if not 0.0 <= self.exposure_score <= 1.0:
            raise ValueError("exposure_score must be within [0,1]")


def compute_exposure(
    asset: CryptoAsset,
    *,
    algorithms: Mapping[str, AlgorithmProfile],
) -> CryptoExposure:
    alg = algorithms.get(asset.algorithm_id)
    if alg is None:
        return CryptoExposure(
            asset_id=asset.asset_id, quantum_vulnerable=False,
            weak_strength=False, deprecated=False,
            harvest_now_decrypt_later=False, exposure_score=0.0,
        )
    quantum = alg.quantum_vulnerability in (
        QuantumVulnerability.SHOR_BROKEN,
        QuantumVulnerability.GROVER_REDUCED,
    )
    weak = asset.key_bits < alg.min_acceptable_key_bits
    dep = alg.deprecated

    # Harvest-now-decrypt-later: long-lived, adversary-exposed, and
    # quantum-vulnerable.
    hndl = (
        alg.quantum_vulnerability is QuantumVulnerability.SHOR_BROKEN
        and asset.long_lived
        and asset.exposed_to_adversary
    )

    score = 0.0
    if quantum:
        score += 0.25
    if weak:
        score += 0.20
    if dep:
        score += 0.15
    if hndl:
        score += 0.30
    if asset.trust_state is TrustState.BROKEN:
        score += 0.10
    elif asset.trust_state is TrustState.DEPRECATED:
        score += 0.05
    if asset.data_classification_ceiling >= 3:
        score += 0.05
    return CryptoExposure(
        asset_id=asset.asset_id,
        quantum_vulnerable=quantum, weak_strength=weak,
        deprecated=dep, harvest_now_decrypt_later=hndl,
        exposure_score=max(0.0, min(1.0, score)),
    )


@dataclass(frozen=True)
class MigrationReadiness:
    application_id: str
    total_assets: int
    pqc_capable_assets: int
    migration_in_progress_or_done: int
    blocked_assets: int
    readiness: float

    def __post_init__(self) -> None:
        if self.total_assets < 0:
            raise ValueError("total_assets must be >= 0")
        if not 0.0 <= self.readiness <= 1.0:
            raise ValueError("readiness must be within [0,1]")


def _pqc_capable(asset: CryptoAsset, alg: Optional[AlgorithmProfile]) -> bool:
    if alg is None:
        return False
    if alg.is_pqc_capable():
        return True
    # Symmetric/hash algorithms are PQC-resistant by construction if
    # their security level is sufficient.
    if alg.family in (AlgorithmFamily.SYMMETRIC, AlgorithmFamily.HASH):
        return alg.quantum_vulnerability is QuantumVulnerability.NONE
    return False


def compute_migration_readiness(
    graph: CryptoDependencyGraph,
    *,
    application_id: str,
    algorithms: Mapping[str, AlgorithmProfile],
) -> MigrationReadiness:
    reachable = graph.reachable(application_id)
    if not reachable:
        return MigrationReadiness(
            application_id=application_id, total_assets=0,
            pqc_capable_assets=0, migration_in_progress_or_done=0,
            blocked_assets=0, readiness=1.0,
        )
    ids = sorted(reachable)
    total = len(ids)
    pqc = 0
    progressed = 0
    blocked = 0
    for aid in ids:
        a = graph.asset(aid)
        alg = algorithms.get(a.algorithm_id)
        if _pqc_capable(a, alg):
            pqc += 1
        if a.migration_state in (
            MigrationState.IN_PROGRESS, MigrationState.COMPLETED,
            MigrationState.PLANNED,
        ):
            progressed += 1
        if a.migration_state is MigrationState.BLOCKED:
            blocked += 1
    # Readiness combines: fraction PQC-capable + migration progress,
    # minus penalty for blocked assets.
    f_pqc = pqc / total
    f_prog = progressed / total
    penalty = 0.2 * (blocked / total)
    readiness = max(0.0, min(1.0, 0.5 * f_pqc + 0.5 * f_prog - penalty))
    return MigrationReadiness(
        application_id=application_id,
        total_assets=total, pqc_capable_assets=pqc,
        migration_in_progress_or_done=progressed,
        blocked_assets=blocked, readiness=readiness,
    )


# =============================================================================
# SECTION 8 — FAILURE SCENARIOS
# =============================================================================


@dataclass(frozen=True)
class FailureScenario:
    scenario_id: str
    kind: str
    description: str
    impacted_asset_ids: Tuple[str, ...]
    impacted_application_ids: Tuple[str, ...]
    severity: int
    plausible: bool
    at: datetime

    def __post_init__(self) -> None:
        if not self.scenario_id:
            raise ValueError("scenario_id is required")
        if not self.kind:
            raise ValueError("kind is required")
        if not 1 <= self.severity <= 5:
            raise ValueError("severity must be in [1,5]")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


def generate_failure_scenarios(
    graph: CryptoDependencyGraph,
    *,
    algorithms: Mapping[str, AlgorithmProfile],
    applications: Sequence[str],
    at: datetime,
    cert_expiry_window: timedelta = timedelta(days=60),
) -> Tuple[FailureScenario, ...]:
    if at.tzinfo is None:
        raise ValueError("at must be timezone-aware")
    out: List[FailureScenario] = []

    # 1. Quantum algorithm break: every SHOR_BROKEN asset in scope.
    quantum_assets: List[str] = []
    quantum_apps: set = set()
    for a in graph.assets():
        alg = algorithms.get(a.algorithm_id)
        if alg is not None and alg.quantum_vulnerability is \
                QuantumVulnerability.SHOR_BROKEN:
            quantum_assets.append(a.asset_id)
            for app in applications:
                if a.asset_id in graph.reachable(app):
                    quantum_apps.add(app)
    if quantum_assets:
        out.append(FailureScenario(
            scenario_id="scenario:quantum_break",
            kind="quantum_algorithm_break",
            description=(
                "A cryptographically relevant quantum computer is "
                "available: all Shor-broken assets are effectively "
                "broken instantly."
            ),
            impacted_asset_ids=tuple(sorted(quantum_assets)),
            impacted_application_ids=tuple(sorted(quantum_apps)),
            severity=5, plausible=True, at=at,
        ))

    # 2. Broken algorithm dependency
    broken: List[str] = [
        a.asset_id for a in graph.assets()
        if a.trust_state is TrustState.BROKEN
    ]
    if broken:
        apps_affected: set = set()
        for aid in broken:
            for app in applications:
                if aid in graph.reachable(app):
                    apps_affected.add(app)
        out.append(FailureScenario(
            scenario_id="scenario:broken_algorithm",
            kind="algorithm_broken_deployed",
            description=(
                "One or more deployed crypto assets are BROKEN."
            ),
            impacted_asset_ids=tuple(sorted(broken)),
            impacted_application_ids=tuple(sorted(apps_affected)),
            severity=5, plausible=True, at=at,
        ))

    # 3. Certificate expiry within window
    expiring: List[str] = []
    expired: List[str] = []
    for a in graph.assets():
        if a.kind is not CryptoAssetKind.CERTIFICATE:
            continue
        if a.expires_at is None:
            continue
        if a.expires_at <= at:
            expired.append(a.asset_id)
        elif a.expires_at <= at + cert_expiry_window:
            expiring.append(a.asset_id)
    if expiring or expired:
        all_certs = sorted(set(expiring + expired))
        apps_affected2: set = set()
        for cid in all_certs:
            for app in applications:
                if cid in graph.reachable(app):
                    apps_affected2.add(app)
        out.append(FailureScenario(
            scenario_id="scenario:cert_expiry",
            kind="certificate_expiry",
            description=(
                f"{len(expired)} expired and {len(expiring)} expiring "
                f"certificates within window."
            ),
            impacted_asset_ids=tuple(all_certs),
            impacted_application_ids=tuple(sorted(apps_affected2)),
            severity=4 if not expired else 5,
            plausible=True, at=at,
        ))

    # 4. PQC migration gap: applications with low readiness
    for app in applications:
        r = compute_migration_readiness(
            graph, application_id=app, algorithms=algorithms,
        )
        if r.total_assets == 0:
            continue
        if r.readiness < 0.5:
            out.append(FailureScenario(
                scenario_id=f"scenario:pqc_gap:{app}",
                kind="pqc_migration_gap",
                description=(
                    f"Application {app} has readiness "
                    f"{r.readiness:.2f} < 0.5."
                ),
                impacted_asset_ids=tuple(sorted(
                    graph.reachable(app)
                )),
                impacted_application_ids=(app,),
                severity=4, plausible=True, at=at,
            ))

    # 5. Hybrid incomplete: an asset is HYBRID family but its PQC
    # status is not HYBRID_DEPLOYED (shouldn't happen in default
    # registry, but applications may register malformed profiles).
    hybrid_incomplete: List[str] = []
    for a in graph.assets():
        alg = algorithms.get(a.algorithm_id)
        if alg is None:
            continue
        if alg.family is AlgorithmFamily.HYBRID \
           and alg.pqc_status is not PqcStatus.HYBRID_DEPLOYED:
            hybrid_incomplete.append(a.asset_id)
    if hybrid_incomplete:
        apps_affected3: set = set()
        for aid in hybrid_incomplete:
            for app in applications:
                if aid in graph.reachable(app):
                    apps_affected3.add(app)
        out.append(FailureScenario(
            scenario_id="scenario:hybrid_incomplete",
            kind="hybrid_incomplete",
            description=(
                "Assets declare HYBRID family but are not fully "
                "hybrid-deployed."
            ),
            impacted_asset_ids=tuple(sorted(hybrid_incomplete)),
            impacted_application_ids=tuple(sorted(apps_affected3)),
            severity=4, plausible=True, at=at,
        ))

    out.sort(key=lambda s: (-s.severity, s.scenario_id))
    return tuple(out)


# =============================================================================
# SECTION 9 — STORE
# =============================================================================


@dataclass(frozen=True)
class CryptoAssetRecord:
    asset_id: str
    kind: CryptoAssetKind
    algorithm_id: str
    trust_state: TrustState
    migration_state: MigrationState
    exposure_score: float
    updated_at: datetime


class CryptoStore(Protocol):
    def put(self, record: CryptoAssetRecord) -> None: ...
    def get(self, asset_id: str) -> Optional[CryptoAssetRecord]: ...
    def all(self) -> Tuple[CryptoAssetRecord, ...]: ...


class InMemoryCryptoStore:
    def __init__(self) -> None:
        self._data: Dict[str, CryptoAssetRecord] = {}

    def put(self, record: CryptoAssetRecord) -> None:
        existing = self._data.get(record.asset_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._data[record.asset_id] = record

    def get(self, asset_id: str) -> Optional[CryptoAssetRecord]:
        return self._data.get(asset_id)

    def all(self) -> Tuple[CryptoAssetRecord, ...]:
        return tuple(self._data.values())


class SqliteCryptoStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS crypto_assets (
                asset_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                algorithm_id TEXT NOT NULL,
                trust_state TEXT NOT NULL,
                migration_state TEXT NOT NULL,
                exposure_score REAL NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS crypto_findings (
                finding_id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def put(self, record: CryptoAssetRecord) -> None:
        existing = self.get(record.asset_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._conn.execute(
            """
            INSERT INTO crypto_assets
              (asset_id, kind, algorithm_id, trust_state,
               migration_state, exposure_score, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(asset_id) DO UPDATE SET
              kind=excluded.kind,
              algorithm_id=excluded.algorithm_id,
              trust_state=excluded.trust_state,
              migration_state=excluded.migration_state,
              exposure_score=excluded.exposure_score,
              updated_at=excluded.updated_at
            """,
            (
                record.asset_id, record.kind.value,
                record.algorithm_id, record.trust_state.value,
                record.migration_state.value,
                record.exposure_score,
                record.updated_at.isoformat(),
            ),
        )
        self._conn.commit()

    def get(self, asset_id: str) -> Optional[CryptoAssetRecord]:
        row = self._conn.execute(
            "SELECT kind, algorithm_id, trust_state, migration_state, "
            "exposure_score, updated_at FROM crypto_assets "
            "WHERE asset_id = ?",
            (asset_id,),
        ).fetchone()
        if row is None:
            return None
        return CryptoAssetRecord(
            asset_id=asset_id, kind=CryptoAssetKind(row[0]),
            algorithm_id=row[1], trust_state=TrustState(row[2]),
            migration_state=MigrationState(row[3]),
            exposure_score=float(row[4]),
            updated_at=datetime.fromisoformat(row[5]),
        )

    def all(self) -> Tuple[CryptoAssetRecord, ...]:
        rows = self._conn.execute(
            "SELECT asset_id FROM crypto_assets"
        ).fetchall()
        return tuple(
            r for r in (self.get(x[0]) for x in rows) if r is not None
        )

    def put_finding(self, finding_id: str, f: CryptoFinding) -> None:
        payload = {
            "finding_id": finding_id,
            "kind": f.kind.value,
            "subject_id": f.subject_id,
            "detail": f.detail,
            "severity": f.severity,
            "at": f.at.isoformat(),
        }
        self._conn.execute(
            "INSERT OR REPLACE INTO crypto_findings "
            "(finding_id, payload_json) VALUES (?, ?)",
            (finding_id, json.dumps(payload, sort_keys=True)),
        )
        self._conn.commit()


# =============================================================================
# SECTION 10 — ENGINE
# =============================================================================


@dataclass(frozen=True)
class CryptoConfig:
    cert_expiry_window_days: int = 60
    weak_exposure_threshold: float = 0.4
    min_readiness: float = 0.5

    def __post_init__(self) -> None:
        if self.cert_expiry_window_days < 1:
            raise ValueError("cert_expiry_window_days must be >= 1")
        if not 0.0 <= self.weak_exposure_threshold <= 1.0:
            raise ValueError("weak_exposure_threshold must be within [0,1]")
        if not 0.0 <= self.min_readiness <= 1.0:
            raise ValueError("min_readiness must be within [0,1]")


class CryptoResilienceEngine:
    """Cryptographic future-resilience engine.

    Ingests crypto assets + dependency graph + algorithm registry, and
    produces trust-state, exposure, migration-readiness, and
    failure-scenario analysis.
    """

    def __init__(
        self,
        *,
        store: Optional[CryptoStore] = None,
        algorithms: Optional[Sequence[AlgorithmProfile]] = None,
        config: Optional[CryptoConfig] = None,
    ) -> None:
        self._store: CryptoStore = store or InMemoryCryptoStore()
        self._algorithms: Dict[str, AlgorithmProfile] = {
            a.algorithm_id: a
            for a in (algorithms if algorithms is not None
                      else DEFAULT_ALGORITHMS)
        }
        self._config = config or CryptoConfig()
        self._graph = CryptoDependencyGraph()
        self._findings: List[CryptoFinding] = []
        self._exposures: Dict[str, CryptoExposure] = {}
        self._readiness: Dict[str, MigrationReadiness] = {}
        self._scenarios: Tuple[FailureScenario, ...] = ()
        self._violations: Tuple[InvariantViolation, ...] = ()

    # ---- registration ----------------------------------------------------

    def register_algorithm(self, alg: AlgorithmProfile) -> None:
        if alg.algorithm_id in self._algorithms:
            raise ValueError(
                f"algorithm {alg.algorithm_id} already registered"
            )
        self._algorithms[alg.algorithm_id] = alg

    def register_asset(self, asset: CryptoAsset) -> None:
        self._graph.add_asset(asset)

    def register_dependency(self, edge: CryptoDependencyEdge) -> None:
        self._graph.add_edge(edge)

    def graph(self) -> CryptoDependencyGraph:
        return self._graph

    def algorithm(self, algorithm_id: str) -> Optional[AlgorithmProfile]:
        return self._algorithms.get(algorithm_id)

    def algorithms(self) -> Tuple[AlgorithmProfile, ...]:
        return tuple(self._algorithms.values())

    def config(self) -> CryptoConfig:
        return self._config

    def set_config(self, config: CryptoConfig) -> None:
        self._config = config

    # ---- trust transition ------------------------------------------------

    def propose_trust_transition(
        self,
        proposal: TrustTransitionProposal,
    ) -> TrustTransitionDecision:
        # The asset must exist
        if not self._graph.has_asset(proposal.asset_id):
            raise KeyError(f"unknown asset {proposal.asset_id}")
        asset = self._graph.asset(proposal.asset_id)
        if asset.trust_state is not proposal.from_state:
            return TrustTransitionDecision(
                allowed=False,
                rationale=(
                    f"from_state {proposal.from_state.value} does not "
                    f"match asset current {asset.trust_state.value}"
                ),
            )
        decision = evaluate_trust_transition(proposal)
        if not decision.allowed:
            at = proposal.at or datetime.now().astimezone()
            self._findings.append(CryptoFinding(
                kind=CryptoFindingKind.INVALID_TRUST_TRANSITION,
                subject_id=proposal.asset_id,
                detail=decision.rationale,
                severity=4, at=at,
            ))
        return decision

    # ---- analysis --------------------------------------------------------

    def recompute(
        self, *,
        at: datetime,
        applications: Sequence[str] = (),
    ) -> Tuple[CryptoAssetRecord, ...]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

        self._findings = []
        cfg = self._config

        records: List[CryptoAssetRecord] = []
        # Per-asset exposure and findings
        for a in self._graph.assets():
            exp = compute_exposure(a, algorithms=self._algorithms)
            self._exposures[a.asset_id] = exp

            alg = self._algorithms.get(a.algorithm_id)

            if exp.quantum_vulnerable:
                self._findings.append(CryptoFinding(
                    kind=CryptoFindingKind.QUANTUM_VULNERABLE_DEPLOYED,
                    subject_id=a.asset_id,
                    detail=(
                        f"asset uses {a.algorithm_id} "
                        f"({alg.quantum_vulnerability.value if alg else '?'})"
                    ),
                    severity=4, at=at,
                ))
            if exp.weak_strength:
                self._findings.append(CryptoFinding(
                    kind=CryptoFindingKind.WEAK_STRENGTH,
                    subject_id=a.asset_id,
                    detail=(
                        f"key_bits {a.key_bits} < "
                        f"min_acceptable "
                        f"{alg.min_acceptable_key_bits if alg else '?'}"
                    ),
                    severity=4, at=at,
                ))
            if exp.deprecated:
                self._findings.append(CryptoFinding(
                    kind=CryptoFindingKind.DEPRECATED_ALGORITHM,
                    subject_id=a.asset_id,
                    detail=(
                        f"algorithm {a.algorithm_id} is deprecated"
                    ),
                    severity=3, at=at,
                ))
            if exp.harvest_now_decrypt_later:
                self._findings.append(CryptoFinding(
                    kind=CryptoFindingKind.HARVEST_NOW_DECRYPT_LATER,
                    subject_id=a.asset_id,
                    detail=(
                        "long-lived, adversary-exposed, quantum-"
                        "vulnerable asset"
                    ),
                    severity=5, at=at,
                ))
            if a.trust_state is TrustState.BROKEN:
                self._findings.append(CryptoFinding(
                    kind=CryptoFindingKind.BROKEN_ALGORITHM_DEPENDENCY,
                    subject_id=a.asset_id,
                    detail="asset is BROKEN",
                    severity=5, at=at,
                ))
            if a.migration_state is MigrationState.BLOCKED:
                self._findings.append(CryptoFinding(
                    kind=CryptoFindingKind.MIGRATION_BLOCKED,
                    subject_id=a.asset_id,
                    detail="migration is BLOCKED",
                    severity=4, at=at,
                ))
            if a.kind is CryptoAssetKind.CERTIFICATE \
               and a.expires_at is not None:
                if a.expires_at <= at:
                    self._findings.append(CryptoFinding(
                        kind=CryptoFindingKind.CERT_EXPIRED,
                        subject_id=a.asset_id,
                        detail=f"expired at {a.expires_at.isoformat()}",
                        severity=5, at=at,
                    ))
                elif a.expires_at <= at + timedelta(
                    days=cfg.cert_expiry_window_days,
                ):
                    self._findings.append(CryptoFinding(
                        kind=CryptoFindingKind.CERT_EXPIRING,
                        subject_id=a.asset_id,
                        detail=(
                            f"expires at {a.expires_at.isoformat()}"
                        ),
                        severity=3, at=at,
                    ))
            # Hybrid incomplete
            if alg is not None \
               and alg.family is AlgorithmFamily.HYBRID \
               and alg.pqc_status is not PqcStatus.HYBRID_DEPLOYED:
                self._findings.append(CryptoFinding(
                    kind=CryptoFindingKind.HYBRID_INCOMPLETE,
                    subject_id=a.asset_id,
                    detail=(
                        "HYBRID family but status is "
                        f"{alg.pqc_status.value}"
                    ),
                    severity=4, at=at,
                ))

            rec = CryptoAssetRecord(
                asset_id=a.asset_id, kind=a.kind,
                algorithm_id=a.algorithm_id,
                trust_state=a.trust_state,
                migration_state=a.migration_state,
                exposure_score=exp.exposure_score,
                updated_at=at,
            )
            self._store.put(rec)
            records.append(rec)

        # Migration readiness per application
        for app in applications:
            if not self._graph.has_asset(app):
                # Applications may reference a service/application
                # pseudo-asset. We still compute readiness using the
                # reachable subgraph if it exists; otherwise skip.
                continue
            r = compute_migration_readiness(
                self._graph, application_id=app,
                algorithms=self._algorithms,
            )
            self._readiness[app] = r
            if r.total_assets == 0:
                continue
            if r.readiness < cfg.min_readiness:
                self._findings.append(CryptoFinding(
                    kind=CryptoFindingKind.PQC_READINESS_GAP,
                    subject_id=app,
                    detail=(
                        f"readiness {r.readiness:.2f} < "
                        f"min {cfg.min_readiness:.2f} "
                        f"({r.total_assets} assets, "
                        f"{r.pqc_capable_assets} PQC-capable, "
                        f"{r.blocked_assets} blocked)"
                    ),
                    severity=4, at=at,
                ))
            if r.blocked_assets > 0:
                self._findings.append(CryptoFinding(
                    kind=CryptoFindingKind.MIGRATION_GAP,
                    subject_id=app,
                    detail=(
                        f"{r.blocked_assets} blocked asset(s) in scope"
                    ),
                    severity=4, at=at,
                ))

        # Failure scenarios
        self._scenarios = generate_failure_scenarios(
            self._graph, algorithms=self._algorithms,
            applications=tuple(
                a for a in applications
                if self._graph.has_asset(a)
            ),
            at=at,
            cert_expiry_window=timedelta(
                days=cfg.cert_expiry_window_days,
            ),
        )

        if isinstance(self._store, SqliteCryptoStore):
            for i, f in enumerate(self._findings):
                self._store.put_finding(
                    f"f-{i:08d}-{f.kind.value}", f,
                )

        self._violations = check_invariants(self.snapshot())
        return tuple(records)

    # ---- queries ---------------------------------------------------------

    def exposure(self, asset_id: str) -> Optional[CryptoExposure]:
        return self._exposures.get(asset_id)

    def migration_readiness(
        self, application_id: str,
    ) -> Optional[MigrationReadiness]:
        return self._readiness.get(application_id)

    def scenarios(self) -> Tuple[FailureScenario, ...]:
        return self._scenarios

    def findings(self) -> Tuple[CryptoFinding, ...]:
        return tuple(self._findings)

    def findings_by_kind(self) -> Mapping[CryptoFindingKind, int]:
        out: Dict[CryptoFindingKind, int] = {
            k: 0 for k in CryptoFindingKind
        }
        for f in self._findings:
            out[f.kind] += 1
        return out

    def top_findings(
        self, *, k: int = 10,
    ) -> Tuple[CryptoFinding, ...]:
        if k <= 0:
            raise ValueError("k must be > 0")
        ordered = sorted(
            self._findings,
            key=lambda f: (-f.severity, f.kind.value, f.subject_id),
        )
        return tuple(ordered[:k])

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return self._violations

    def record(self, asset_id: str) -> Optional[CryptoAssetRecord]:
        return self._store.get(asset_id)

    def snapshot(self) -> CryptoSnapshot:
        return CryptoSnapshot(
            graph=self._graph,
            algorithms=dict(self._algorithms),
            findings=tuple(self._findings),
        )


# =============================================================================
# SECTION 11 — TESTS
# =============================================================================


def _t0() -> datetime:
    from datetime import timezone
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _t(seconds: int) -> datetime:
    return _t0() + timedelta(seconds=seconds)


def _alg(
    aid: str, family: AlgorithmFamily = AlgorithmFamily.SYMMETRIC, *,
    name: Optional[str] = None,
    level: int = 256,
    qv: QuantumVulnerability = QuantumVulnerability.NONE,
    pqc: PqcStatus = PqcStatus.NOT_APPLICABLE,
    min_key: int = 256,
    rec_key: int = 256,
    deprecated: bool = False,
) -> AlgorithmProfile:
    return AlgorithmProfile(
        algorithm_id=aid, family=family, name=name or aid,
        security_level_bits=level,
        quantum_vulnerability=qv, pqc_status=pqc,
        min_acceptable_key_bits=min_key,
        recommended_key_bits=rec_key,
        deprecated=deprecated,
    )


def _asset(
    aid: str, *, kind: CryptoAssetKind = CryptoAssetKind.KEY,
    name: Optional[str] = None,
    algorithm_id: str = "aes-256-gcm",
    key_bits: int = 256,
    trust: TrustState = TrustState.VERIFIED,
    migration: MigrationState = MigrationState.NOT_STARTED,
    data_class: int = 1,
    long_lived: bool = False,
    exposed: bool = False,
    expires_at: Optional[datetime] = None,
) -> CryptoAsset:
    return CryptoAsset(
        asset_id=aid, kind=kind, name=name or aid,
        algorithm_id=algorithm_id, key_bits=key_bits,
        trust_state=trust, migration_state=migration,
        data_classification_ceiling=data_class,
        long_lived=long_lived, exposed_to_adversary=exposed,
        expires_at=expires_at,
    )


def _edge(
    eid: str, dep: str, depn: str, *, kind: str = "uses",
) -> CryptoDependencyEdge:
    return CryptoDependencyEdge(
        edge_id=eid, dependent_id=dep, dependency_id=depn,
        kind=kind, at=_t0(),
    )


# ---- domain ----

def test_algorithm_requires_id() -> None:
    try:
        AlgorithmProfile(
            algorithm_id="", family=AlgorithmFamily.SYMMETRIC,
            name="x", security_level_bits=0,
            quantum_vulnerability=QuantumVulnerability.NONE,
            pqc_status=PqcStatus.NOT_APPLICABLE,
            min_acceptable_key_bits=0, recommended_key_bits=0,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_algorithm_recommended_ge_min() -> None:
    try:
        AlgorithmProfile(
            algorithm_id="a", family=AlgorithmFamily.SYMMETRIC,
            name="x", security_level_bits=0,
            quantum_vulnerability=QuantumVulnerability.NONE,
            pqc_status=PqcStatus.NOT_APPLICABLE,
            min_acceptable_key_bits=256, recommended_key_bits=128,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_asset_rejects_bad_classification() -> None:
    try:
        _asset("a", data_class=5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_asset_rejects_naive_expiry() -> None:
    from datetime import datetime as dt
    try:
        _asset("a", expires_at=dt(2026, 1, 1))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_edge_self_rejected() -> None:
    try:
        _edge("e", "a", "a")
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_qv_rank_ordering() -> None:
    assert qv_rank(QuantumVulnerability.NONE) < \
        qv_rank(QuantumVulnerability.GROVER_REDUCED)
    assert qv_rank(QuantumVulnerability.GROVER_REDUCED) < \
        qv_rank(QuantumVulnerability.SHOR_BROKEN)


def test_trust_rank_ordering() -> None:
    assert trust_rank(TrustState.BROKEN) < \
        trust_rank(TrustState.DEPRECATED)
    assert trust_rank(TrustState.DEPRECATED) < \
        trust_rank(TrustState.DEGRADED)
    assert trust_rank(TrustState.DEGRADED) < \
        trust_rank(TrustState.ROTATED)
    assert trust_rank(TrustState.ROTATED) < \
        trust_rank(TrustState.VERIFIED)


def test_algorithm_is_pqc_capable() -> None:
    assert _alg(
        "x", qv=QuantumVulnerability.NONE,
        pqc=PqcStatus.PQC_STANDARDIZED,
    ).is_pqc_capable()
    assert not _alg(
        "x", qv=QuantumVulnerability.SHOR_BROKEN,
        pqc=PqcStatus.NOT_QUANTUM_SAFE,
    ).is_pqc_capable()


# ---- graph ----

def test_graph_duplicate_asset_rejected() -> None:
    g = CryptoDependencyGraph()
    g.add_asset(_asset("a"))
    try:
        g.add_asset(_asset("a"))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_graph_duplicate_edge_rejected() -> None:
    g = CryptoDependencyGraph()
    g.add_asset(_asset("a"))
    g.add_asset(_asset("b"))
    g.add_edge(_edge("e", "a", "b"))
    try:
        g.add_edge(_edge("e", "a", "b"))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_graph_cycle_rejected() -> None:
    g = CryptoDependencyGraph()
    g.add_asset(_asset("a"))
    g.add_asset(_asset("b"))
    g.add_asset(_asset("c"))
    g.add_edge(_edge("e1", "a", "b"))
    g.add_edge(_edge("e2", "b", "c"))
    try:
        g.add_edge(_edge("e3", "c", "a"))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_graph_reachable() -> None:
    g = CryptoDependencyGraph()
    g.add_asset(_asset("a"))
    g.add_asset(_asset("b"))
    g.add_asset(_asset("c"))
    g.add_edge(_edge("e1", "a", "b"))
    g.add_edge(_edge("e2", "b", "c"))
    assert g.reachable("a") == frozenset({"b", "c"})


def test_graph_dependents_of() -> None:
    g = CryptoDependencyGraph()
    g.add_asset(_asset("a"))
    g.add_asset(_asset("b"))
    g.add_asset(_asset("c"))
    g.add_edge(_edge("e1", "a", "b"))
    g.add_edge(_edge("e2", "b", "c"))
    assert g.dependents_of("c") == frozenset({"a", "b"})


# ---- exposure ----

def test_exposure_quantum_vulnerable_high() -> None:
    algorithms = {a.algorithm_id: a for a in DEFAULT_ALGORITHMS}
    a = _asset("k", algorithm_id="rsa-2048", key_bits=2048)
    exp = compute_exposure(a, algorithms=algorithms)
    assert exp.quantum_vulnerable
    assert exp.exposure_score > 0.2


def test_exposure_weak_strength() -> None:
    algorithms = {a.algorithm_id: a for a in DEFAULT_ALGORITHMS}
    a = _asset("k", algorithm_id="aes-128-gcm", key_bits=128)
    exp = compute_exposure(a, algorithms=algorithms)
    assert exp.weak_strength


def test_exposure_deprecated() -> None:
    algorithms = {a.algorithm_id: a for a in DEFAULT_ALGORITHMS}
    a = _asset("k", algorithm_id="sha-1", key_bits=160)
    exp = compute_exposure(a, algorithms=algorithms)
    assert exp.deprecated


def test_exposure_harvest_now_decrypt_later() -> None:
    algorithms = {a.algorithm_id: a for a in DEFAULT_ALGORITHMS}
    a = _asset(
        "k", algorithm_id="rsa-kem-2048", key_bits=2048,
        long_lived=True, exposed=True,
    )
    exp = compute_exposure(a, algorithms=algorithms)
    assert exp.harvest_now_decrypt_later


def test_exposure_no_hndl_when_not_long_lived() -> None:
    algorithms = {a.algorithm_id: a for a in DEFAULT_ALGORITHMS}
    a = _asset(
        "k", algorithm_id="rsa-kem-2048", key_bits=2048,
        long_lived=False, exposed=True,
    )
    exp = compute_exposure(a, algorithms=algorithms)
    assert not exp.harvest_now_decrypt_later


def test_exposure_pqc_clean() -> None:
    algorithms = {a.algorithm_id: a for a in DEFAULT_ALGORITHMS}
    a = _asset("k", algorithm_id="ml-kem-768", key_bits=0)
    exp = compute_exposure(a, algorithms=algorithms)
    assert not exp.quantum_vulnerable
    assert not exp.weak_strength
    assert exp.exposure_score < 0.3


# ---- trust transitions ----

def test_trust_transition_broken_to_rotated_requires_rotation_flag() -> None:
    p = TrustTransitionProposal(
        proposal_id="p", asset_id="a",
        from_state=TrustState.BROKEN, to_state=TrustState.ROTATED,
        reason="rotate", rotated=False,
    )
    d = evaluate_trust_transition(p)
    assert not d.allowed


def test_trust_transition_broken_to_rotated_allowed() -> None:
    p = TrustTransitionProposal(
        proposal_id="p", asset_id="a",
        from_state=TrustState.BROKEN, to_state=TrustState.ROTATED,
        reason="rotate", rotated=True, verified=True,
    )
    d = evaluate_trust_transition(p)
    assert d.allowed


def test_trust_transition_broken_to_verified_forbidden() -> None:
    p = TrustTransitionProposal(
        proposal_id="p", asset_id="a",
        from_state=TrustState.BROKEN, to_state=TrustState.VERIFIED,
        reason="try", verified=True, rotated=True,
    )
    d = evaluate_trust_transition(p)
    assert not d.allowed


def test_trust_transition_recovery_requires_verification() -> None:
    p = TrustTransitionProposal(
        proposal_id="p", asset_id="a",
        from_state=TrustState.ROTATED, to_state=TrustState.VERIFIED,
        reason="verify", verified=False,
    )
    d = evaluate_trust_transition(p)
    assert not d.allowed


def test_trust_transition_noop() -> None:
    p = TrustTransitionProposal(
        proposal_id="p", asset_id="a",
        from_state=TrustState.VERIFIED, to_state=TrustState.VERIFIED,
        reason="x",
    )
    d = evaluate_trust_transition(p)
    assert d.allowed


# ---- migration readiness ----

def test_readiness_no_assets_returns_one() -> None:
    g = CryptoDependencyGraph()
    g.add_asset(_asset("a"))
    r = compute_migration_readiness(
        g, application_id="a",
        algorithms={a.algorithm_id: a for a in DEFAULT_ALGORITHMS},
    )
    assert r.readiness == 1.0


def test_readiness_low_when_all_classical() -> None:
    g = CryptoDependencyGraph()
    g.add_asset(_asset("app", kind=CryptoAssetKind.PROTOCOL))
    g.add_asset(_asset("k1", algorithm_id="rsa-2048", key_bits=2048))
    g.add_edge(_edge("e1", "app", "k1"))
    r = compute_migration_readiness(
        g, application_id="app",
        algorithms={a.algorithm_id: a for a in DEFAULT_ALGORITHMS},
    )
    assert r.readiness < 0.5


def test_readiness_high_when_pqc_and_progressed() -> None:
    g = CryptoDependencyGraph()
    g.add_asset(_asset("app", kind=CryptoAssetKind.PROTOCOL))
    g.add_asset(_asset(
        "k1", algorithm_id="ml-kem-768", key_bits=0,
        migration=MigrationState.COMPLETED,
    ))
    g.add_edge(_edge("e1", "app", "k1"))
    r = compute_migration_readiness(
        g, application_id="app",
        algorithms={a.algorithm_id: a for a in DEFAULT_ALGORITHMS},
    )
    assert r.readiness >= 0.5


def test_readiness_penalizes_blocked() -> None:
    g = CryptoDependencyGraph()
    g.add_asset(_asset("app", kind=CryptoAssetKind.PROTOCOL))
    g.add_asset(_asset(
        "k1", algorithm_id="ml-kem-768", key_bits=0,
        migration=MigrationState.BLOCKED,
    ))
    g.add_edge(_edge("e1", "app", "k1"))
    r = compute_migration_readiness(
        g, application_id="app",
        algorithms={a.algorithm_id: a for a in DEFAULT_ALGORITHMS},
    )
    assert r.blocked_assets == 1
    assert r.readiness < 0.6


# ---- failure scenarios ----

def test_failure_scenario_quantum_break() -> None:
    g = CryptoDependencyGraph()
    g.add_asset(_asset("app", kind=CryptoAssetKind.PROTOCOL))
    g.add_asset(_asset("k1", algorithm_id="rsa-2048", key_bits=2048))
    g.add_edge(_edge("e1", "app", "k1"))
    scenarios = generate_failure_scenarios(
        g,
        algorithms={a.algorithm_id: a for a in DEFAULT_ALGORITHMS},
        applications=("app",), at=_t0(),
    )
    assert any(
        s.kind == "quantum_algorithm_break" for s in scenarios
    )


def test_failure_scenario_cert_expiry() -> None:
    g = CryptoDependencyGraph()
    g.add_asset(_asset("app", kind=CryptoAssetKind.PROTOCOL))
    g.add_asset(_asset(
        "cert", kind=CryptoAssetKind.CERTIFICATE,
        expires_at=_t(86400 * 10),  # 10 days
    ))
    g.add_edge(_edge("e1", "app", "cert"))
    scenarios = generate_failure_scenarios(
        g,
        algorithms={a.algorithm_id: a for a in DEFAULT_ALGORITHMS},
        applications=("app",), at=_t0(),
    )
    assert any(
        s.kind == "certificate_expiry" for s in scenarios
    )


def test_failure_scenario_pqc_gap() -> None:
    g = CryptoDependencyGraph()
    g.add_asset(_asset("app", kind=CryptoAssetKind.PROTOCOL))
    g.add_asset(_asset("k1", algorithm_id="rsa-2048", key_bits=2048))
    g.add_edge(_edge("e1", "app", "k1"))
    scenarios = generate_failure_scenarios(
        g,
        algorithms={a.algorithm_id: a for a in DEFAULT_ALGORITHMS},
        applications=("app",), at=_t0(),
    )
    assert any(s.kind == "pqc_migration_gap" for s in scenarios)


def test_failure_scenario_broken_algorithm() -> None:
    g = CryptoDependencyGraph()
    g.add_asset(_asset("app", kind=CryptoAssetKind.PROTOCOL))
    g.add_asset(_asset(
        "k1", algorithm_id="rsa-2048", key_bits=2048,
        trust=TrustState.BROKEN,
    ))
    g.add_edge(_edge("e1", "app", "k1"))
    scenarios = generate_failure_scenarios(
        g,
        algorithms={a.algorithm_id: a for a in DEFAULT_ALGORITHMS},
        applications=("app",), at=_t0(),
    )
    assert any(
        s.kind == "algorithm_broken_deployed" for s in scenarios
    )


def test_failure_scenario_requires_aware_time() -> None:
    from datetime import datetime as dt
    g = CryptoDependencyGraph()
    try:
        generate_failure_scenarios(
            g, algorithms={}, applications=(), at=dt(2026, 1, 1),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- engine ----

def test_engine_registers_asset() -> None:
    eng = CryptoResilienceEngine()
    eng.register_asset(_asset("a"))
    assert eng.graph().asset("a") is not None


def test_engine_rejects_duplicate_algorithm() -> None:
    eng = CryptoResilienceEngine()
    try:
        eng.register_algorithm(DEFAULT_ALGORITHMS[0])
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_recompute_requires_aware_time() -> None:
    from datetime import datetime as dt
    eng = CryptoResilienceEngine()
    try:
        eng.recompute(at=dt(2026, 1, 1))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_quantum_vulnerable_finding() -> None:
    eng = CryptoResilienceEngine()
    eng.register_asset(_asset("k", algorithm_id="rsa-2048", key_bits=2048))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert CryptoFindingKind.QUANTUM_VULNERABLE_DEPLOYED in kinds


def test_engine_weak_strength_finding() -> None:
    eng = CryptoResilienceEngine()
    eng.register_asset(_asset(
        "k", algorithm_id="rsa-2048", key_bits=2048,
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert CryptoFindingKind.WEAK_STRENGTH in kinds


def test_engine_deprecated_algorithm_finding() -> None:
    eng = CryptoResilienceEngine()
    eng.register_asset(_asset("k", algorithm_id="sha-1", key_bits=160))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert CryptoFindingKind.DEPRECATED_ALGORITHM in kinds


def test_engine_hndl_finding() -> None:
    eng = CryptoResilienceEngine()
    eng.register_asset(_asset(
        "k", algorithm_id="rsa-kem-2048", key_bits=2048,
        long_lived=True, exposed=True,
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert CryptoFindingKind.HARVEST_NOW_DECRYPT_LATER in kinds


def test_engine_broken_algorithm_finding() -> None:
    eng = CryptoResilienceEngine()
    eng.register_asset(_asset(
        "k", algorithm_id="aes-256-gcm", key_bits=256,
        trust=TrustState.BROKEN,
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert CryptoFindingKind.BROKEN_ALGORITHM_DEPENDENCY in kinds


def test_engine_cert_expiring_finding() -> None:
    eng = CryptoResilienceEngine()
    eng.register_asset(_asset(
        "c", kind=CryptoAssetKind.CERTIFICATE,
        expires_at=_t(86400 * 30),  # 30 days
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert CryptoFindingKind.CERT_EXPIRING in kinds


def test_engine_cert_expired_finding() -> None:
    eng = CryptoResilienceEngine()
    eng.register_asset(_asset(
        "c", kind=CryptoAssetKind.CERTIFICATE,
        expires_at=_t(-86400),  # yesterday
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert CryptoFindingKind.CERT_EXPIRED in kinds


def test_engine_pqc_readiness_gap_finding() -> None:
    eng = CryptoResilienceEngine()
    eng.register_asset(_asset("app", kind=CryptoAssetKind.PROTOCOL))
    eng.register_asset(_asset("k1", algorithm_id="rsa-2048", key_bits=2048))
    eng.register_dependency(_edge("e1", "app", "k1"))
    eng.recompute(at=_t0(), applications=("app",))
    kinds = {f.kind for f in eng.findings()}
    assert CryptoFindingKind.PQC_READINESS_GAP in kinds


def test_engine_trust_transition_invalid_records_finding() -> None:
    eng = CryptoResilienceEngine()
    eng.register_asset(_asset(
        "k", trust=TrustState.VERIFIED,
    ))
    d = eng.propose_trust_transition(TrustTransitionProposal(
        proposal_id="p", asset_id="k",
        from_state=TrustState.VERIFIED, to_state=TrustState.BROKEN,
        reason="x", at=_t0(),
    ))
    assert d.allowed
    # Now try to go from BROKEN to VERIFIED without rotation
    eng._graph = CryptoDependencyGraph()
    eng._graph.add_asset(_asset("k2", trust=TrustState.BROKEN))
    d2 = eng.propose_trust_transition(TrustTransitionProposal(
        proposal_id="p2", asset_id="k2",
        from_state=TrustState.BROKEN, to_state=TrustState.VERIFIED,
        reason="x", verified=True, at=_t0(),
    ))
    assert not d2.allowed


def test_engine_trust_transition_wrong_from_state() -> None:
    eng = CryptoResilienceEngine()
    eng.register_asset(_asset("k", trust=TrustState.VERIFIED))
    d = eng.propose_trust_transition(TrustTransitionProposal(
        proposal_id="p", asset_id="k",
        from_state=TrustState.BROKEN, to_state=TrustState.ROTATED,
        reason="x", rotated=True, at=_t0(),
    ))
    assert not d.allowed


def test_engine_migration_readiness_lookup() -> None:
    eng = CryptoResilienceEngine()
    eng.register_asset(_asset("app", kind=CryptoAssetKind.PROTOCOL))
    eng.register_asset(_asset("k1", algorithm_id="ml-kem-768", key_bits=0,
                              migration=MigrationState.COMPLETED))
    eng.register_dependency(_edge("e1", "app", "k1"))
    eng.recompute(at=_t0(), applications=("app",))
    r = eng.migration_readiness("app")
    assert r is not None
    assert r.readiness >= 0.5


def test_engine_scenarios_produced() -> None:
    eng = CryptoResilienceEngine()
    eng.register_asset(_asset("app", kind=CryptoAssetKind.PROTOCOL))
    eng.register_asset(_asset("k1", algorithm_id="rsa-2048", key_bits=2048))
    eng.register_dependency(_edge("e1", "app", "k1"))
    eng.recompute(at=_t0(), applications=("app",))
    scenarios = eng.scenarios()
    assert len(scenarios) >= 1


def test_engine_top_findings_sorted() -> None:
    eng = CryptoResilienceEngine()
    eng.register_asset(_asset("k1", algorithm_id="rsa-2048", key_bits=2048,
                              long_lived=True, exposed=True))
    eng.register_asset(_asset("k2", algorithm_id="sha-1", key_bits=160))
    eng.recompute(at=_t0())
    top = eng.top_findings(k=10)
    severities = [f.severity for f in top]
    assert severities == sorted(severities, reverse=True)


def test_engine_top_findings_invalid_k() -> None:
    eng = CryptoResilienceEngine()
    try:
        eng.top_findings(k=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_findings_by_kind() -> None:
    eng = CryptoResilienceEngine()
    eng.register_asset(_asset("k", algorithm_id="rsa-2048", key_bits=2048))
    eng.recompute(at=_t0())
    by_kind = eng.findings_by_kind()
    assert by_kind[CryptoFindingKind.QUANTUM_VULNERABLE_DEPLOYED] >= 1


def test_engine_record_lookup() -> None:
    eng = CryptoResilienceEngine()
    eng.register_asset(_asset("k", algorithm_id="aes-256-gcm", key_bits=256))
    eng.recompute(at=_t0())
    rec = eng.record("k")
    assert rec is not None
    assert rec.algorithm_id == "aes-256-gcm"


def test_engine_config_validation() -> None:
    try:
        CryptoConfig(cert_expiry_window_days=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_set_config() -> None:
    eng = CryptoResilienceEngine()
    cfg = CryptoConfig(cert_expiry_window_days=180)
    eng.set_config(cfg)
    assert eng.config() is cfg


def test_engine_hybrid_incomplete_finding() -> None:
    eng = CryptoResilienceEngine()
    # register a hybrid algorithm that is not HYBRID_DEPLOYED
    eng.register_algorithm(AlgorithmProfile(
        algorithm_id="hybrid-bad", family=AlgorithmFamily.HYBRID,
        name="Hybrid bad", security_level_bits=128,
        quantum_vulnerability=QuantumVulnerability.NONE,
        pqc_status=PqcStatus.PQC_TRANSITION,
        min_acceptable_key_bits=0, recommended_key_bits=0,
    ))
    eng.register_asset(_asset("h", algorithm_id="hybrid-bad", key_bits=0))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert CryptoFindingKind.HYBRID_INCOMPLETE in kinds


# ---- invariants ----

def test_invariant_clean_snapshot() -> None:
    eng = CryptoResilienceEngine()
    eng.register_asset(_asset("k", algorithm_id="ml-kem-768", key_bits=0,
                              migration=MigrationState.COMPLETED))
    eng.recompute(at=_t0())
    assert eng.violations() == ()


def test_invariant_broken_requires_migration() -> None:
    eng = CryptoResilienceEngine()
    eng.register_asset(_asset(
        "k", algorithm_id="rsa-2048", key_bits=2048,
        trust=TrustState.BROKEN,
        migration=MigrationState.NOT_STARTED,
    ))
    eng.recompute(at=_t0())
    v = eng.violations()
    assert any(
        x.invariant_id == "crypto.broken_requires_migration" for x in v
    )


def test_invariant_deprecated_not_verified() -> None:
    eng = CryptoResilienceEngine()
    eng.register_asset(_asset(
        "k", algorithm_id="sha-1", key_bits=256,
        trust=TrustState.VERIFIED,
    ))
    eng.recompute(at=_t0())
    v = eng.violations()
    assert any(
        x.invariant_id == "crypto.deprecated_not_verified" for x in v
    )


def test_invariant_asset_algorithm_registered() -> None:
    eng = CryptoResilienceEngine()
    # register asset referencing unknown algorithm
    eng.register_asset(_asset("k", algorithm_id="not-real", key_bits=0))
    eng.recompute(at=_t0())
    v = eng.violations()
    assert any(
        x.invariant_id == "crypto.asset_algorithm_registered" for x in v
    )


# ---- store ----

def test_in_memory_store_rejects_stale() -> None:
    s = InMemoryCryptoStore()
    t = _t0()
    s.put(CryptoAssetRecord(
        "k", CryptoAssetKind.KEY, "aes-256-gcm",
        TrustState.VERIFIED, MigrationState.NOT_STARTED, 0.1, t,
    ))
    earlier = t.replace(year=t.year - 1)
    try:
        s.put(CryptoAssetRecord(
            "k", CryptoAssetKind.KEY, "aes-256-gcm",
            TrustState.VERIFIED, MigrationState.NOT_STARTED, 0.1,
            earlier,
        ))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "crypto.db")
    store = SqliteCryptoStore(db)
    store.put(CryptoAssetRecord(
        "k", CryptoAssetKind.KEY, "ml-kem-768",
        TrustState.VERIFIED, MigrationState.COMPLETED,
        0.05, _t0(),
    ))
    got = store.get("k")
    assert got is not None
    assert got.algorithm_id == "ml-kem-768"
    assert got.migration_state is MigrationState.COMPLETED


def test_sqlite_store_finding_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "crypto.db")
    store = SqliteCryptoStore(db)
    f = CryptoFinding(
        kind=CryptoFindingKind.QUANTUM_VULNERABLE_DEPLOYED,
        subject_id="k", detail="x", severity=4, at=_t0(),
    )
    store.put_finding("fid-1", f)
    row = store._conn.execute(
        "SELECT payload_json FROM crypto_findings "
        "WHERE finding_id = 'fid-1'"
    ).fetchone()
    assert row is not None
    payload = json.loads(row[0])
    assert payload["kind"] == "quantum_vulnerable_deployed"


# =============================================================================
# SECTION 12 — MANUAL RUNNER
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
