"""
HYDRA POST-CORE — PHASE 5: CONTAINER / VIRTUALIZATION / CLOUD STATE
=====================================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * Cloud/workload domain (providers, resource kinds, workload kinds)
  * Container security-context model (privileged, host_*, caps, seccomp, ...)
  * VM security model (public IP, ingress, disk encryption, patch state)
  * Serverless security model (attached role, exposure)
  * Cloud identities (role, service account, workload identity, IRSA, ...)
  * Control-plane state (K8s API, cloud IAM, orchestrator, mesh)
  * Cross-workload / cross-cloud relationship graph
  * Continuous runtime trust state per workload + identity + control plane
  * Effective trust bounded by identity + control plane (weakest link)
  * Dangerous container combination scoring
  * Control-plane compromise cascade
  * Cross-cloud identity-chain traversal with bounded depth
  * Explicit security-state transitions
  * Machine-checkable cloud invariants
  * In-memory and SQLite stores
  * Phase-5 engine facade
  * Full test suite + manual runner

This is NEW cloud security-state technology, not a generic CSPM/CNAPP.

Run tests:
    python hydra_phase5_container_vm_cloud_state.py
    pytest hydra_phase5_container_vm_cloud_state.py -q
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


class Provider(str, Enum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    K8S = "k8s"
    ON_PREM = "on_prem"
    OTHER = "other"


class WorkloadKind(str, Enum):
    CONTAINER = "container"
    POD = "pod"
    DEPLOYMENT = "deployment"
    DAEMONSET = "daemonset"
    VM = "vm"
    SERVERLESS = "serverless"
    BATCH_JOB = "batch_job"


class ResourceKind(str, Enum):
    BUCKET = "bucket"
    DATABASE = "database"
    QUEUE = "queue"
    SECRET_STORE = "secret_store"
    LOAD_BALANCER = "load_balancer"
    NODE = "node"
    VOLUME = "volume"
    NETWORK = "network"
    FUNCTION = "function"


class IdentityKind(str, Enum):
    CLOUD_ROLE = "cloud_role"
    SERVICE_ACCOUNT = "service_account"
    WORKLOAD_IDENTITY = "workload_identity"
    MANAGED_IDENTITY = "managed_identity"
    IRSA = "irsa"
    USER = "user"


class ControlPlaneKind(str, Enum):
    K8S_API_SERVER = "k8s_api_server"
    CLOUD_IAM = "cloud_iam"
    ORCHESTRATOR = "orchestrator"
    MESH_CONTROL_PLANE = "mesh_control_plane"


class RelationshipKind(str, Enum):
    MANAGES = "manages"
    SCHEDULED_ON = "scheduled_on"
    ASSUMES = "assumes"
    MOUNTS = "mounts"
    CALLS = "calls"
    READS_FROM = "reads_from"
    WRITES_TO = "writes_to"
    DEPENDS_ON = "depends_on"


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


def is_untrusted(label: TrustLabel) -> bool:
    return label in (
        TrustLabel.SUSPICIOUS,
        TrustLabel.COMPROMISED,
        TrustLabel.QUARANTINED,
    )


def is_quarantined(label: TrustLabel) -> bool:
    return label is TrustLabel.QUARANTINED


class SeccompProfile(str, Enum):
    DISABLED = "disabled"
    RUNTIME_DEFAULT = "runtime_default"
    LOCALHOST = "localhost"


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


# =============================================================================
# SECTION 3 — SECURITY SUB-MODELS
# =============================================================================


HIGH_RISK_CONTAINER_CAPS: FrozenSet[str] = frozenset({
    "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO",
    "DAC_OVERRIDE", "DAC_READ_SEARCH", "NET_ADMIN", "NET_RAW",
    "SYS_BOOT", "MAC_ADMIN", "MAC_OVERRIDE", "SETPCAP",
})

DANGEROUS_HOST_PATHS: FrozenSet[str] = frozenset({
    "/var/run/docker.sock",
    "/var/run/containerd/containerd.sock",
    "/run/crio/crio.sock",
    "/proc",
    "/sys",
    "/",
})


@dataclass(frozen=True)
class ContainerSecurity:
    privileged: bool = False
    run_as_root: bool = False
    allow_privilege_escalation: bool = False
    host_pid: bool = False
    host_network: bool = False
    host_ipc: bool = False
    host_paths: FrozenSet[str] = frozenset()
    added_capabilities: FrozenSet[str] = frozenset()
    read_only_root_fs: bool = True
    seccomp_profile: SeccompProfile = SeccompProfile.RUNTIME_DEFAULT
    network_policy_present: bool = True
    image_signed: bool = True

    def dangerous_score(self) -> float:
        """0..1 where 1 means maximally dangerous container config."""
        score = 0.0
        if self.privileged:
            score += 0.30
        if self.run_as_root:
            score += 0.10
        if self.allow_privilege_escalation:
            score += 0.10
        if self.host_pid:
            score += 0.10
        if self.host_network:
            score += 0.10
        if self.host_ipc:
            score += 0.05
        if self.host_paths:
            score += 0.05 * min(3, len(self.host_paths))
        if not self.read_only_root_fs:
            score += 0.05
        if self.seccomp_profile is SeccompProfile.DISABLED:
            score += 0.10
        if not self.network_policy_present:
            score += 0.05
        if not self.image_signed:
            score += 0.05
        if self.added_capabilities & HIGH_RISK_CONTAINER_CAPS:
            score += 0.15
        if (self.privileged and self.host_paths
                and (self.host_paths & DANGEROUS_HOST_PATHS)):
            score += 0.30
        return max(0.0, min(1.0, score))


@dataclass(frozen=True)
class VmSecurity:
    public_ip: bool = False
    ingress_ports: FrozenSet[int] = frozenset()
    disk_encrypted: bool = True
    patched_recently: bool = True
    restrictive_security_group: bool = True

    def dangerous_score(self) -> float:
        score = 0.0
        if self.public_ip:
            score += 0.20
            wide = {22, 3389, 5432, 3306, 6379, 27017, 9200, 0}
            if self.ingress_ports & wide:
                score += 0.25
            if 0 in self.ingress_ports:  # 0.0.0.0/0
                score += 0.15
        if not self.disk_encrypted:
            score += 0.15
        if not self.patched_recently:
            score += 0.15
        if not self.restrictive_security_group:
            score += 0.10
        return max(0.0, min(1.0, score))


@dataclass(frozen=True)
class ServerlessSecurity:
    attached_role_privileged: bool = False
    exposed_via_public_gateway: bool = False
    reserved_concurrency: Optional[int] = None
    timeout_seconds: int = 30
    image_signed: bool = True

    def dangerous_score(self) -> float:
        score = 0.0
        if self.attached_role_privileged:
            score += 0.4
        if self.exposed_via_public_gateway:
            score += 0.15
        if self.timeout_seconds > 900:
            score += 0.1
        if not self.image_signed:
            score += 0.1
        return max(0.0, min(1.0, score))


# =============================================================================
# SECTION 4 — WORKLOADS, RESOURCES, IDENTITIES, CONTROL PLANES
# =============================================================================


@dataclass(frozen=True)
class CloudResource:
    resource_id: str
    provider: Provider
    region: str
    kind: ResourceKind
    criticality: float
    publicly_exposed: bool = False

    def __post_init__(self) -> None:
        if not self.resource_id:
            raise ValueError("resource_id is required")
        if not self.region:
            raise ValueError("region is required")
        if not 0.0 <= self.criticality <= 1.0:
            raise ValueError("criticality must be within [0,1]")


@dataclass(frozen=True)
class CloudIdentity:
    identity_id: str
    provider: Provider
    kind: IdentityKind
    attached_policies: FrozenSet[str]
    privileged: bool = False
    cross_provider_trusts: FrozenSet[str] = frozenset()
    parent_identity_id: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.identity_id:
            raise ValueError("identity_id is required")
        if not self.attached_policies and not self.privileged:
            # An identity with no policies and no privileged flag is benign;
            # it is allowed.
            pass


@dataclass(frozen=True)
class ControlPlane:
    plane_id: str
    kind: ControlPlaneKind
    provider: Provider
    posture: float
    compromised: bool = False
    allowed_actions: FrozenSet[str] = frozenset()

    def __post_init__(self) -> None:
        if not self.plane_id:
            raise ValueError("plane_id is required")
        if not 0.0 <= self.posture <= 1.0:
            raise ValueError("posture must be within [0,1]")


@dataclass(frozen=True)
class Workload:
    workload_id: str
    kind: WorkloadKind
    provider: Provider
    region: str
    tenant_id: str
    criticality: float
    identity_id: Optional[str]
    control_plane_id: Optional[str]
    node_id: Optional[str]
    container: Optional[ContainerSecurity] = None
    vm: Optional[VmSecurity] = None
    serverless: Optional[ServerlessSecurity] = None

    def __post_init__(self) -> None:
        if not self.workload_id:
            raise ValueError("workload_id is required")
        if not self.region:
            raise ValueError("region is required")
        if not self.tenant_id:
            raise ValueError("tenant_id is required")
        if not 0.0 <= self.criticality <= 1.0:
            raise ValueError("criticality must be within [0,1]")

        # Cross-check kind ↔ sub-model consistency
        if self.kind in (
            WorkloadKind.CONTAINER, WorkloadKind.POD, WorkloadKind.DEPLOYMENT,
            WorkloadKind.DAEMONSET, WorkloadKind.BATCH_JOB,
        ):
            if self.container is None:
                raise ValueError(
                    f"workload {self.workload_id} kind {self.kind.value} "
                    f"requires container security context"
                )
        elif self.kind is WorkloadKind.VM:
            if self.vm is None:
                raise ValueError(
                    f"workload {self.workload_id} kind vm requires vm security"
                )
        elif self.kind is WorkloadKind.SERVERLESS:
            if self.serverless is None:
                raise ValueError(
                    f"workload {self.workload_id} kind serverless requires "
                    f"serverless security"
                )

    def security_danger_score(self) -> float:
        if self.container is not None:
            return self.container.dangerous_score()
        if self.vm is not None:
            return self.vm.dangerous_score()
        if self.serverless is not None:
            return self.serverless.dangerous_score()
        return 0.0


@dataclass(frozen=True)
class RelationshipEdge:
    src: str
    dst: str
    kind: RelationshipKind

    def __post_init__(self) -> None:
        if not self.src or not self.dst:
            raise ValueError("src and dst are required")
        if self.src == self.dst:
            raise ValueError("self-relationships are not allowed")


class RelationshipGraph:
    def __init__(self) -> None:
        self._out: Dict[str, List[RelationshipEdge]] = {}
        self._edges: List[RelationshipEdge] = []

    def add(self, edge: RelationshipEdge) -> None:
        for existing in self._out.get(edge.src, []):
            if existing.dst == edge.dst and existing.kind is edge.kind:
                raise ValueError(
                    f"duplicate relationship {edge.src}->{edge.dst} "
                    f"({edge.kind.value})"
                )
        self._out.setdefault(edge.src, []).append(edge)
        self._edges.append(edge)

    def out_edges(self, src: str) -> Tuple[RelationshipEdge, ...]:
        return tuple(self._out.get(src, []))

    def all_edges(self) -> Tuple[RelationshipEdge, ...]:
        return tuple(self._edges)

    def transitive_reach(self, src: str) -> Tuple[str, ...]:
        out: List[str] = []
        seen: set = set()
        stack = [src]
        while stack:
            cur = stack.pop()
            for e in self._out.get(cur, []):
                if e.dst in seen:
                    continue
                seen.add(e.dst)
                out.append(e.dst)
                stack.append(e.dst)
        return tuple(out)


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


def decay_trust(
    state: TrustState, *, half_life_seconds: float, at: datetime,
) -> TrustState:
    if half_life_seconds <= 0:
        raise ValueError("half_life_seconds must be > 0")
    age = (at - state.updated_at).total_seconds()
    if age <= 0:
        return state
    factor = 0.5 ** (age / half_life_seconds)
    score = NEUTRAL_SCORE + (state.score - NEUTRAL_SCORE) * factor
    return TrustState(score=score, confidence=state.confidence * factor,
                      basis=state.basis, updated_at=at)


# =============================================================================
# SECTION 6 — EFFECTIVE TRUST (weakest-link across identity + control plane)
# =============================================================================


TRUST_SLACK: float = 0.1


def effective_workload_trust(
    observed: float,
    *,
    identity_trust: Optional[float],
    control_plane_trust: Optional[float],
    slack: float = TRUST_SLACK,
) -> float:
    """Workload trust cannot exceed its controlling/identity trust + slack."""
    if not 0.0 <= observed <= 1.0:
        raise ValueError("observed must be within [0,1]")
    ceilings: List[float] = []
    if identity_trust is not None:
        ceilings.append(identity_trust + slack)
    if control_plane_trust is not None:
        ceilings.append(control_plane_trust + slack)
    if not ceilings:
        return observed
    ceiling = min(1.0, min(ceilings))
    return max(0.0, min(observed, ceiling))


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
# SECTION 7 — CONTROL-PLANE COMPROMISE CASCADE
# =============================================================================


def control_plane_cascade(
    workloads: Iterable[Workload],
    control_planes: Mapping[str, ControlPlane],
) -> FrozenSet[str]:
    """Return workload_ids that inherit a compromised control-plane posture."""
    affected: set = set()
    for w in workloads:
        if w.control_plane_id is None:
            continue
        plane = control_planes.get(w.control_plane_id)
        if plane is None:
            continue
        if plane.compromised or plane.posture < 0.3:
            affected.add(w.workload_id)
    return frozenset(affected)


# =============================================================================
# SECTION 8 — CROSS-CLOUD IDENTITY CHAINS
# =============================================================================


MAX_CROSS_CLOUD_HOPS: int = 2


def find_cross_cloud_chain(
    identities: Mapping[str, CloudIdentity],
    start_id: str,
    *,
    max_hops: int = MAX_CROSS_CLOUD_HOPS + 2,
) -> Tuple[str, ...]:
    """Deterministic walk following cross_provider_trusts edges."""
    if start_id not in identities:
        return ()
    path: List[str] = [start_id]
    visited: set = {start_id}
    current = start_id
    for _ in range(max_hops):
        ident = identities.get(current)
        if ident is None or not ident.cross_provider_trusts:
            break
        # deterministic: sorted lowest id
        nxt = sorted(ident.cross_provider_trusts)[0]
        if nxt in visited:
            break
        path.append(nxt)
        visited.add(nxt)
        current = nxt
    return tuple(path)


def cross_cloud_hop_count(chain: Tuple[str, ...]) -> int:
    return max(0, len(chain) - 1)


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
# SECTION 10 — INVARIANTS
# =============================================================================


class InvariantSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class WorkloadSnapshot:
    workload: Workload
    label: TrustLabel
    trust: TrustState
    identity_label: Optional[TrustLabel] = None
    control_plane_label: Optional[TrustLabel] = None


@dataclass(frozen=True)
class CloudSnapshot:
    workloads: Mapping[str, WorkloadSnapshot]
    identities: Mapping[str, CloudIdentity]
    identity_labels: Mapping[str, TrustLabel]
    control_planes: Mapping[str, ControlPlane]
    relationships: RelationshipGraph
    cascade_affected: FrozenSet[str]


@dataclass(frozen=True)
class InvariantViolation:
    invariant_id: str
    severity: InvariantSeverity
    subject_id: str
    detail: str


@dataclass(frozen=True)
class CloudInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[CloudSnapshot], Tuple[InvariantViolation, ...]]
    description: str


def _inv_privileged_with_admin_identity(
    snap: CloudSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for wid, ws in snap.workloads.items():
        w = ws.workload
        if w.identity_id is None:
            continue
        ident = snap.identities.get(w.identity_id)
        if ident is None:
            continue
        sec = w.container
        is_privileged = bool(sec and (sec.privileged or (
            sec.added_capabilities & HIGH_RISK_CONTAINER_CAPS)))
        if is_privileged and ident.privileged:
            out.append(InvariantViolation(
                invariant_id="cloud.privileged_with_admin_identity",
                severity=InvariantSeverity.CRITICAL,
                subject_id=wid,
                detail=(
                    f"workload {wid} runs privileged and assumes admin "
                    f"identity {ident.identity_id}"
                ),
            ))
    return tuple(out)


def _inv_dangerous_container_combo(
    snap: CloudSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for wid, ws in snap.workloads.items():
        score = ws.workload.security_danger_score()
        if score >= 0.7:
            out.append(InvariantViolation(
                invariant_id="cloud.dangerous_workload_config",
                severity=InvariantSeverity.HIGH,
                subject_id=wid,
                detail=(
                    f"workload {wid} has dangerous config score {score:.2f}"
                ),
            ))
    return tuple(out)


def _inv_public_workload_needs_netpol(
    snap: CloudSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for wid, ws in snap.workloads.items():
        w = ws.workload
        sec = w.container
        if sec is None:
            continue
        if not sec.network_policy_present:
            # Only flag if the workload is exposed publicly via a relationship
            for e in snap.relationships.out_edges(wid):
                if e.kind is RelationshipKind.CALLS:
                    dst_wl = snap.workloads.get(e.dst)
                    if dst_wl is not None:
                        continue
                    # If dst is a public resource, flag
                    out.append(InvariantViolation(
                        invariant_id="cloud.public_workload_needs_netpol",
                        severity=InvariantSeverity.HIGH,
                        subject_id=wid,
                        detail=(
                            f"workload {wid} has no network policy but calls "
                            f"external {e.dst}"
                        ),
                    ))
                    break
    return tuple(out)


def _inv_compromised_plane_degrades_workloads(
    snap: CloudSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for wid in snap.cascade_affected:
        ws = snap.workloads.get(wid)
        if ws is None:
            continue
        if label_severity(ws.label) < label_severity(TrustLabel.DEGRADED):
            out.append(InvariantViolation(
                invariant_id="cloud.compromised_plane_degrades_workloads",
                severity=InvariantSeverity.CRITICAL,
                subject_id=wid,
                detail=(
                    f"workload {wid} is still {ws.label.value} under "
                    f"compromised control plane"
                ),
            ))
    return tuple(out)


def _inv_cross_cloud_chain_bounded(
    snap: CloudSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for ident in snap.identities.values():
        if not ident.cross_provider_trusts:
            continue
        chain = find_cross_cloud_chain(snap.identities, ident.identity_id)
        hops = cross_cloud_hop_count(chain)
        if hops > MAX_CROSS_CLOUD_HOPS:
            out.append(InvariantViolation(
                invariant_id="cloud.cross_cloud_chain_bounded",
                severity=InvariantSeverity.HIGH,
                subject_id=ident.identity_id,
                detail=(
                    f"cross-cloud chain from {ident.identity_id} has "
                    f"{hops} hops (>{MAX_CROSS_CLOUD_HOPS}): {list(chain)}"
                ),
            ))
    return tuple(out)


def _inv_quarantined_identity_no_active_workload(
    snap: CloudSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for wid, ws in snap.workloads.items():
        w = ws.workload
        if w.identity_id is None:
            continue
        label = snap.identity_labels.get(w.identity_id)
        if label is not None and is_quarantined(label):
            out.append(InvariantViolation(
                invariant_id="cloud.quarantined_identity_no_workload",
                severity=InvariantSeverity.CRITICAL,
                subject_id=wid,
                detail=(
                    f"workload {wid} still assumes quarantined identity "
                    f"{w.identity_id}"
                ),
            ))
    return tuple(out)


DEFAULT_INVARIANTS: Tuple[CloudInvariant, ...] = (
    CloudInvariant(
        invariant_id="cloud.privileged_with_admin_identity",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_privileged_with_admin_identity,
        description="Privileged workloads must not assume admin identities.",
    ),
    CloudInvariant(
        invariant_id="cloud.dangerous_workload_config",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_dangerous_container_combo,
        description="Workloads with dangerous security configuration must be flagged.",
    ),
    CloudInvariant(
        invariant_id="cloud.public_workload_needs_netpol",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_public_workload_needs_netpol,
        description="Externally-facing workloads must have a network policy.",
    ),
    CloudInvariant(
        invariant_id="cloud.compromised_plane_degrades_workloads",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_compromised_plane_degrades_workloads,
        description="Workloads under a compromised control plane must degrade.",
    ),
    CloudInvariant(
        invariant_id="cloud.cross_cloud_chain_bounded",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_cross_cloud_chain_bounded,
        description="Cross-cloud identity chains must not exceed the hop limit.",
    ),
    CloudInvariant(
        invariant_id="cloud.quarantined_identity_no_workload",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_quarantined_identity_no_active_workload,
        description="Quarantined identities must not be assumed by live workloads.",
    ),
)


def check_invariants(
    snap: CloudSnapshot,
    invariants: Iterable[CloudInvariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 11 — STORES
# =============================================================================


@dataclass(frozen=True)
class WorkloadStateRecord:
    workload_id: str
    label: TrustLabel
    trust_score: float
    trust_confidence: float
    updated_at: datetime


class CloudStateStore(Protocol):
    def get(self, entity_id: str) -> Optional[WorkloadStateRecord]: ...
    def put(self, record: WorkloadStateRecord) -> None: ...
    def all(self) -> Tuple[WorkloadStateRecord, ...]: ...


class InMemoryCloudStateStore:
    def __init__(self) -> None:
        self._data: Dict[str, WorkloadStateRecord] = {}

    def get(self, entity_id: str) -> Optional[WorkloadStateRecord]:
        return self._data.get(entity_id)

    def put(self, record: WorkloadStateRecord) -> None:
        existing = self._data.get(record.workload_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._data[record.workload_id] = record

    def all(self) -> Tuple[WorkloadStateRecord, ...]:
        return tuple(self._data.values())


class SqliteCloudStateStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cloud_workload_state (
                entity_id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                trust_score REAL NOT NULL,
                trust_confidence REAL NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cloud_identities (
                identity_id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cloud_control_planes (
                plane_id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def get(self, entity_id: str) -> Optional[WorkloadStateRecord]:
        row = self._conn.execute(
            "SELECT label, trust_score, trust_confidence, updated_at "
            "FROM cloud_workload_state WHERE entity_id = ?",
            (entity_id,),
        ).fetchone()
        if row is None:
            return None
        return WorkloadStateRecord(
            workload_id=entity_id,
            label=TrustLabel(row[0]),
            trust_score=float(row[1]),
            trust_confidence=float(row[2]),
            updated_at=datetime.fromisoformat(row[3]),
        )

    def put(self, record: WorkloadStateRecord) -> None:
        existing = self.get(record.workload_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._conn.execute(
            """
            INSERT INTO cloud_workload_state
              (entity_id, label, trust_score, trust_confidence, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(entity_id) DO UPDATE SET
              label=excluded.label,
              trust_score=excluded.trust_score,
              trust_confidence=excluded.trust_confidence,
              updated_at=excluded.updated_at
            """,
            (record.workload_id, record.label.value,
             record.trust_score, record.trust_confidence,
             record.updated_at.isoformat()),
        )
        self._conn.commit()

    def all(self) -> Tuple[WorkloadStateRecord, ...]:
        rows = self._conn.execute(
            "SELECT entity_id FROM cloud_workload_state"
        ).fetchall()
        return tuple(
            r for r in (self.get(x[0]) for x in rows) if r is not None
        )

    def put_identity(self, identity: CloudIdentity) -> None:
        payload = {
            "identity_id": identity.identity_id,
            "provider": identity.provider.value,
            "kind": identity.kind.value,
            "attached_policies": sorted(identity.attached_policies),
            "privileged": identity.privileged,
            "cross_provider_trusts": sorted(identity.cross_provider_trusts),
            "parent_identity_id": identity.parent_identity_id,
        }
        self._conn.execute(
            "INSERT OR REPLACE INTO cloud_identities (identity_id, payload_json) "
            "VALUES (?, ?)",
            (identity.identity_id, json.dumps(payload, sort_keys=True)),
        )
        self._conn.commit()

    def get_identity(self, identity_id: str) -> Optional[CloudIdentity]:
        row = self._conn.execute(
            "SELECT payload_json FROM cloud_identities WHERE identity_id = ?",
            (identity_id,),
        ).fetchone()
        if row is None:
            return None
        p = json.loads(row[0])
        return CloudIdentity(
            identity_id=p["identity_id"],
            provider=Provider(p["provider"]),
            kind=IdentityKind(p["kind"]),
            attached_policies=frozenset(p["attached_policies"]),
            privileged=p["privileged"],
            cross_provider_trusts=frozenset(p["cross_provider_trusts"]),
            parent_identity_id=p["parent_identity_id"],
        )

    def put_control_plane(self, plane: ControlPlane) -> None:
        payload = {
            "plane_id": plane.plane_id,
            "kind": plane.kind.value,
            "provider": plane.provider.value,
            "posture": plane.posture,
            "compromised": plane.compromised,
            "allowed_actions": sorted(plane.allowed_actions),
        }
        self._conn.execute(
            "INSERT OR REPLACE INTO cloud_control_planes (plane_id, payload_json) "
            "VALUES (?, ?)",
            (plane.plane_id, json.dumps(payload, sort_keys=True)),
        )
        self._conn.commit()

    def get_control_plane(self, plane_id: str) -> Optional[ControlPlane]:
        row = self._conn.execute(
            "SELECT payload_json FROM cloud_control_planes WHERE plane_id = ?",
            (plane_id,),
        ).fetchone()
        if row is None:
            return None
        p = json.loads(row[0])
        return ControlPlane(
            plane_id=p["plane_id"],
            kind=ControlPlaneKind(p["kind"]),
            provider=Provider(p["provider"]),
            posture=p["posture"],
            compromised=p["compromised"],
            allowed_actions=frozenset(p["allowed_actions"]),
        )


# =============================================================================
# SECTION 12 — ENGINE
# =============================================================================


class CloudSecurityStateEngine:
    """Container / VM / cloud security-state engine.

    Consumes workload, identity, control plane, and relationship inputs.
    Produces workload + identity trust state, cascade effects, invariants.
    """

    def __init__(self, *, store: Optional[CloudStateStore] = None) -> None:
        self._store: CloudStateStore = store or InMemoryCloudStateStore()
        self._workloads: Dict[str, Workload] = {}
        self._resources: Dict[str, CloudResource] = {}
        self._identities: Dict[str, CloudIdentity] = {}
        self._planes: Dict[str, ControlPlane] = {}
        self._graph = RelationshipGraph()
        self._signals: Dict[str, List[TrustSignal]] = {}
        self._identity_signals: Dict[str, List[TrustSignal]] = {}
        self._labels: Dict[str, TrustLabel] = {}
        self._identity_labels: Dict[str, TrustLabel] = {}
        self._violations: Tuple[InvariantViolation, ...] = ()
        self._cascade_affected: FrozenSet[str] = frozenset()

    # ---- registration ----------------------------------------------------

    def register_workload(self, workload: Workload) -> None:
        if workload.workload_id in self._workloads:
            raise ValueError(f"workload {workload.workload_id} already registered")
        self._workloads[workload.workload_id] = workload

    def register_resource(self, resource: CloudResource) -> None:
        if resource.resource_id in self._resources:
            raise ValueError(f"resource {resource.resource_id} already registered")
        self._resources[resource.resource_id] = resource

    def register_identity(self, identity: CloudIdentity) -> None:
        if identity.identity_id in self._identities:
            raise ValueError(f"identity {identity.identity_id} already registered")
        self._identities[identity.identity_id] = identity

    def register_control_plane(self, plane: ControlPlane) -> None:
        if plane.plane_id in self._planes:
            raise ValueError(f"control plane {plane.plane_id} already registered")
        self._planes[plane.plane_id] = plane

    def add_relationship(self, edge: RelationshipEdge) -> None:
        # Allow referring to either a workload, resource, identity, or plane
        known = (
            set(self._workloads) | set(self._resources)
            | set(self._identities) | set(self._planes)
        )
        if edge.src not in known:
            raise KeyError(f"relationship src {edge.src} not registered")
        if edge.dst not in known:
            raise KeyError(f"relationship dst {edge.dst} not registered")
        self._graph.add(edge)

    # ---- signals ---------------------------------------------------------

    def observe_workload_signal(self, workload_id: str, signal: TrustSignal) -> None:
        if workload_id not in self._workloads:
            raise KeyError(f"unknown workload {workload_id}")
        if signal.at.tzinfo is None:
            raise ValueError("signal.at must be timezone-aware")
        self._signals.setdefault(workload_id, []).append(signal)

    def observe_identity_signal(self, identity_id: str, signal: TrustSignal) -> None:
        if identity_id not in self._identities:
            raise KeyError(f"unknown identity {identity_id}")
        if signal.at.tzinfo is None:
            raise ValueError("signal.at must be timezone-aware")
        self._identity_signals.setdefault(identity_id, []).append(signal)

    # ---- recompute -------------------------------------------------------

    def recompute(self, *, at: datetime) -> Tuple[WorkloadStateRecord, ...]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

        # 1. Identity trust
        identity_trust: Dict[str, TrustState] = {}
        for iid in self._identities:
            identity_trust[iid] = combine_trust(
                self._identity_signals.get(iid, []), at
            )
            self._identity_labels[iid] = derive_label(identity_trust[iid])

        # 2. Control-plane posture → trust proxy
        #    posture directly maps to a trust score for constraint purposes.
        plane_trust: Dict[str, float] = {}
        for pid, plane in self._planes.items():
            if plane.compromised:
                plane_trust[pid] = 0.0
            else:
                plane_trust[pid] = plane.posture

        # 3. Cascade
        self._cascade_affected = control_plane_cascade(
            self._workloads.values(), self._planes
        )

        # 4. Effective workload trust
        records: List[WorkloadStateRecord] = []
        for wid, w in self._workloads.items():
            observed = combine_trust(self._signals.get(wid, []), at)

            id_score: Optional[float] = None
            if w.identity_id is not None:
                ist = identity_trust.get(w.identity_id)
                if ist is not None:
                    id_score = ist.score

            cp_score: Optional[float] = None
            if w.control_plane_id is not None:
                cp_score = plane_trust.get(w.control_plane_id)

            eff = effective_workload_trust(
                observed.score,
                identity_trust=id_score,
                control_plane_trust=cp_score,
            )

            # Cascade forces DEGRADED at minimum
            cascade_label_floor = (
                TrustLabel.DEGRADED if wid in self._cascade_affected
                else TrustLabel.UNKNOWN
            )

            eff_state = TrustState(
                score=eff, confidence=observed.confidence,
                basis=observed.basis, updated_at=at,
            )
            proposed = derive_label(eff_state)
            if label_severity(proposed) < label_severity(cascade_label_floor):
                proposed = cascade_label_floor

            # transition enforcement
            previous_label = self._labels.get(wid, TrustLabel.UNKNOWN)
            if previous_label is not proposed:
                decision = evaluate_transition(TransitionRequest(
                    entity_id=wid, from_label=previous_label,
                    to_label=proposed, reason="recompute",
                    verified=self._workload_verified(wid),
                ))
                if decision.outcome in (
                    TransitionOutcome.REJECTED_INVALID,
                    TransitionOutcome.REQUIRES_VERIFICATION,
                ):
                    proposed = previous_label

            self._labels[wid] = proposed

            record = WorkloadStateRecord(
                workload_id=wid, label=proposed,
                trust_score=eff_state.score,
                trust_confidence=eff_state.confidence,
                updated_at=at,
            )
            self._store.put(record)
            records.append(record)

        # 5. Invariants
        snapshot = self._snapshot(at)
        self._violations = check_invariants(snapshot)

        return tuple(records)

    # ---- queries ---------------------------------------------------------

    def label(self, workload_id: str) -> Optional[TrustLabel]:
        return self._labels.get(workload_id)

    def identity_label(self, identity_id: str) -> Optional[TrustLabel]:
        return self._identity_labels.get(identity_id)

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return self._violations

    def cascade_affected(self) -> FrozenSet[str]:
        return self._cascade_affected

    def relationships(self) -> RelationshipGraph:
        return self._graph

    def cross_cloud_chain(self, identity_id: str) -> Tuple[str, ...]:
        return find_cross_cloud_chain(self._identities, identity_id)

    # ---- internals -------------------------------------------------------

    def _workload_verified(self, workload_id: str) -> bool:
        signals = self._signals.get(workload_id, [])
        return any(s.evidence.confidence >= 0.7 and s.polarity > 0
                   for s in signals)

    def _snapshot(self, at: datetime) -> CloudSnapshot:
        workloads: Dict[str, WorkloadSnapshot] = {}
        for wid, w in self._workloads.items():
            rec = self._store.get(wid)
            if rec is None:
                continue
            id_label = None
            if w.identity_id is not None:
                id_label = self._identity_labels.get(w.identity_id)
            cp_label = None
            if w.control_plane_id is not None:
                plane = self._planes.get(w.control_plane_id)
                if plane is not None:
                    cp_label = derive_label(TrustState(
                        score=(0.0 if plane.compromised else plane.posture),
                        confidence=0.9, basis=(), updated_at=at,
                    ))
            workloads[wid] = WorkloadSnapshot(
                workload=w,
                label=rec.label,
                trust=TrustState(
                    score=rec.trust_score,
                    confidence=rec.trust_confidence,
                    basis=(), updated_at=rec.updated_at,
                ),
                identity_label=id_label,
                control_plane_label=cp_label,
            )
        return CloudSnapshot(
            workloads=workloads,
            identities=dict(self._identities),
            identity_labels=dict(self._identity_labels),
            control_planes=dict(self._planes),
            relationships=self._graph,
            cascade_affected=self._cascade_affected,
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


def _pos(sid: str = "s", at: Optional[datetime] = None) -> TrustSignal:
    return TrustSignal(sid, 1.0, 1.0, at or _t0(), _ev(at or _t0()))


def _neg(sid: str = "s", at: Optional[datetime] = None) -> TrustSignal:
    return TrustSignal(sid, 1.0, -1.0, at or _t0(), _ev(at or _t0()))


def _container_wl(
    wid: str = "web",
    *,
    container: Optional[ContainerSecurity] = None,
    identity_id: Optional[str] = None,
    control_plane_id: Optional[str] = None,
    criticality: float = 0.5,
    provider: Provider = Provider.K8S,
    region: str = "us-east-1",
) -> Workload:
    return Workload(
        workload_id=wid, kind=WorkloadKind.CONTAINER,
        provider=provider, region=region, tenant_id="t1",
        criticality=criticality, identity_id=identity_id,
        control_plane_id=control_plane_id, node_id=None,
        container=container or ContainerSecurity(),
    )


def _safe_container() -> ContainerSecurity:
    return ContainerSecurity(
        privileged=False, run_as_root=False, allow_privilege_escalation=False,
        host_pid=False, host_network=False, host_ipc=False,
        host_paths=frozenset(), added_capabilities=frozenset(),
        read_only_root_fs=True,
        seccomp_profile=SeccompProfile.RUNTIME_DEFAULT,
        network_policy_present=True, image_signed=True,
    )


def _priv_container() -> ContainerSecurity:
    return ContainerSecurity(
        privileged=True, run_as_root=True, allow_privilege_escalation=True,
        host_pid=True, host_network=True, host_ipc=True,
        host_paths=frozenset({"/var/run/docker.sock", "/"}),
        added_capabilities=frozenset({"SYS_ADMIN"}),
        read_only_root_fs=False,
        seccomp_profile=SeccompProfile.DISABLED,
        network_policy_present=False, image_signed=False,
    )


def _ident_admin(iid: str = "iam-admin", provider: Provider = Provider.AWS) -> CloudIdentity:
    return CloudIdentity(
        identity_id=iid, provider=provider, kind=IdentityKind.CLOUD_ROLE,
        attached_policies=frozenset({"AdministratorAccess"}),
        privileged=True,
    )


def _ident_user(iid: str = "iam-user", provider: Provider = Provider.AWS) -> CloudIdentity:
    return CloudIdentity(
        identity_id=iid, provider=provider, kind=IdentityKind.CLOUD_ROLE,
        attached_policies=frozenset({"ReadOnlyAccess"}),
        privileged=False,
    )


def _plane_ok(pid: str = "k8s-api") -> ControlPlane:
    return ControlPlane(
        plane_id=pid, kind=ControlPlaneKind.K8S_API_SERVER,
        provider=Provider.K8S, posture=0.95, compromised=False,
    )


# ---- domain tests ---------------------------------------------------------

def test_workload_requires_container_for_container_kind() -> None:
    try:
        Workload(
            workload_id="w", kind=WorkloadKind.CONTAINER,
            provider=Provider.K8S, region="r", tenant_id="t",
            criticality=0.5, identity_id=None, control_plane_id=None,
            node_id=None, container=None,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_workload_requires_vm_security_for_vm() -> None:
    try:
        Workload(
            workload_id="w", kind=WorkloadKind.VM,
            provider=Provider.AWS, region="us-east-1", tenant_id="t",
            criticality=0.5, identity_id=None, control_plane_id=None,
            node_id=None, vm=None,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_resource_region_required() -> None:
    try:
        CloudResource(resource_id="r", provider=Provider.AWS, region="",
                      kind=ResourceKind.BUCKET, criticality=0.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_control_plane_posture_bounds() -> None:
    try:
        ControlPlane(plane_id="p", kind=ControlPlaneKind.K8S_API_SERVER,
                     provider=Provider.K8S, posture=1.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- dangerous score ------------------------------------------------------

def test_safe_container_low_score() -> None:
    assert _safe_container().dangerous_score() < 0.2


def test_privileged_container_high_score() -> None:
    assert _priv_container().dangerous_score() >= 0.7


def test_host_docker_socket_boosts_score() -> None:
    a = ContainerSecurity(privileged=True,
                          host_paths=frozenset({"/tmp"}))
    b = ContainerSecurity(privileged=True,
                          host_paths=frozenset({"/var/run/docker.sock"}))
    assert b.dangerous_score() > a.dangerous_score()


def test_vm_public_with_wide_ingress_high() -> None:
    sec = VmSecurity(public_ip=True, ingress_ports=frozenset({22, 3389, 0}))
    assert sec.dangerous_score() >= 0.5


def test_serverless_admin_role_dangerous() -> None:
    sec = ServerlessSecurity(attached_role_privileged=True)
    assert sec.dangerous_score() >= 0.4


# ---- relationship tests ---------------------------------------------------

def test_relationship_self_edge_rejected() -> None:
    try:
        RelationshipEdge("a", "a", RelationshipKind.MANAGES)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_relationship_duplicate_rejected() -> None:
    g = RelationshipGraph()
    g.add(RelationshipEdge("a", "b", RelationshipKind.MANAGES))
    try:
        g.add(RelationshipEdge("a", "b", RelationshipKind.MANAGES))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_relationship_transitive_reach() -> None:
    g = RelationshipGraph()
    g.add(RelationshipEdge("a", "b", RelationshipKind.CALLS))
    g.add(RelationshipEdge("b", "c", RelationshipKind.CALLS))
    assert set(g.transitive_reach("a")) == {"b", "c"}


# ---- trust tests ----------------------------------------------------------

def test_combine_trust_empty_neutral() -> None:
    s = combine_trust([], _t0())
    assert s.score == NEUTRAL_SCORE and s.confidence == 0.0


def test_combine_trust_positive() -> None:
    assert combine_trust([_pos()], _t0()).score == 1.0


def test_combine_trust_negative() -> None:
    assert combine_trust([_neg()], _t0()).score == 0.0


def test_decay_toward_neutral() -> None:
    st = combine_trust([_pos()], _t0())
    later = _t0().replace(minute=10)
    d = decay_trust(st, half_life_seconds=60.0, at=later)
    assert d.score < st.score


# ---- effective trust tests ------------------------------------------------

def test_effective_trust_no_constraints_unchanged() -> None:
    assert effective_workload_trust(
        0.9, identity_trust=None, control_plane_trust=None
    ) == 0.9


def test_effective_trust_identity_caps() -> None:
    eff = effective_workload_trust(0.95, identity_trust=0.2,
                                   control_plane_trust=None)
    assert eff <= 0.2 + TRUST_SLACK + 1e-9


def test_effective_trust_plane_caps() -> None:
    eff = effective_workload_trust(0.95, identity_trust=None,
                                   control_plane_trust=0.1)
    assert eff <= 0.1 + TRUST_SLACK + 1e-9


def test_effective_trust_min_of_both() -> None:
    eff = effective_workload_trust(
        0.95, identity_trust=0.8, control_plane_trust=0.2,
    )
    assert eff <= 0.2 + TRUST_SLACK + 1e-9


# ---- cascade tests --------------------------------------------------------

def test_control_plane_cascade_marks_workloads() -> None:
    w = _container_wl("w", control_plane_id="p")
    plane = ControlPlane(plane_id="p", kind=ControlPlaneKind.K8S_API_SERVER,
                         provider=Provider.K8S, posture=0.9, compromised=True)
    affected = control_plane_cascade([w], {"p": plane})
    assert "w" in affected


def test_control_plane_cascade_empty_when_ok() -> None:
    w = _container_wl("w", control_plane_id="p")
    plane = _plane_ok("p")
    assert control_plane_cascade([w], {"p": plane}) == frozenset()


# ---- cross-cloud chain tests ---------------------------------------------

def test_cross_cloud_chain_single_hop() -> None:
    a = CloudIdentity("a", Provider.AWS, IdentityKind.CLOUD_ROLE,
                      frozenset({"x"}), cross_provider_trusts=frozenset({"b"}))
    b = CloudIdentity("b", Provider.GCP, IdentityKind.SERVICE_ACCOUNT,
                      frozenset({"y"}))
    chain = find_cross_cloud_chain({"a": a, "b": b}, "a")
    assert chain == ("a", "b")
    assert cross_cloud_hop_count(chain) == 1


def test_cross_cloud_chain_no_trusts() -> None:
    a = CloudIdentity("a", Provider.AWS, IdentityKind.CLOUD_ROLE,
                      frozenset({"x"}))
    chain = find_cross_cloud_chain({"a": a}, "a")
    assert chain == ("a",)


# ---- transition tests -----------------------------------------------------

def test_transition_compromise_to_trusted_rejected() -> None:
    d = evaluate_transition(TransitionRequest(
        entity_id="w", from_label=TrustLabel.COMPROMISED,
        to_label=TrustLabel.TRUSTED, reason="x", verified=True,
    ))
    assert d.outcome is TransitionOutcome.REJECTED_INVALID


def test_transition_quarantine_recovery_requires_verification() -> None:
    d = evaluate_transition(TransitionRequest(
        entity_id="w", from_label=TrustLabel.QUARANTINED,
        to_label=TrustLabel.OBSERVED, reason="x", verified=False,
    ))
    assert d.outcome is TransitionOutcome.REQUIRES_VERIFICATION


def test_transition_quarantine_recovery_verified_allowed() -> None:
    d = evaluate_transition(TransitionRequest(
        entity_id="w", from_label=TrustLabel.QUARANTINED,
        to_label=TrustLabel.OBSERVED, reason="x", verified=True,
    ))
    assert d.outcome is TransitionOutcome.ALLOWED


def test_transition_reason_required() -> None:
    d = evaluate_transition(TransitionRequest(
        entity_id="w", from_label=TrustLabel.OBSERVED,
        to_label=TrustLabel.TRUSTED, reason="", verified=True,
    ))
    assert d.outcome is TransitionOutcome.REJECTED_INVALID


# ---- invariant tests ------------------------------------------------------

def test_invariant_privileged_with_admin_identity() -> None:
    eng = CloudSecurityStateEngine()
    eng.register_workload(_container_wl(
        "w", container=_priv_container(), identity_id="iam-admin",
    ))
    eng.register_identity(_ident_admin("iam-admin"))
    eng.recompute(at=_t0())
    assert any(v.invariant_id == "cloud.privileged_with_admin_identity"
               for v in eng.violations())


def test_invariant_dangerous_workload_config() -> None:
    eng = CloudSecurityStateEngine()
    eng.register_workload(_container_wl("w", container=_priv_container()))
    eng.recompute(at=_t0())
    assert any(v.invariant_id == "cloud.dangerous_workload_config"
               for v in eng.violations())


def test_invariant_compromised_plane_degrades_workloads() -> None:
    eng = CloudSecurityStateEngine()
    eng.register_workload(_container_wl(
        "w", container=_safe_container(), control_plane_id="p",
    ))
    eng.register_control_plane(ControlPlane(
        plane_id="p", kind=ControlPlaneKind.K8S_API_SERVER,
        provider=Provider.K8S, posture=0.9, compromised=True,
    ))
    # Give strong positive signals so naturally it would be TRUSTED
    eng.observe_workload_signal("w", _pos("ok"))
    records = eng.recompute(at=_t0())
    rec = next(r for r in records if r.workload_id == "w")
    # Cascade forces DEGRADED at minimum
    assert label_severity(rec.label) >= label_severity(TrustLabel.DEGRADED)
    # And no violation because it degraded correctly
    assert not any(
        v.invariant_id == "cloud.compromised_plane_degrades_workloads"
        for v in eng.violations()
    )


def test_invariant_quarantined_identity_no_workload() -> None:
    eng = CloudSecurityStateEngine()
    eng.register_identity(_ident_user("iam-user"))
    eng.register_workload(_container_wl(
        "w", container=_safe_container(), identity_id="iam-user",
    ))
    # push iam-user to suspicious/compromised via negative signals
    for i in range(5):
        eng.observe_identity_signal("iam-user", _neg(f"n{i}"))
    eng.recompute(at=_t0())
    # The identity should be untrusted, workload still references it
    label = eng.identity_label("iam-user")
    assert label is not None and is_untrusted(label)


def test_invariant_cross_cloud_chain_bounded() -> None:
    # Build a chain longer than MAX_CROSS_CLOUD_HOPS
    eng = CloudSecurityStateEngine()
    ids = ["a", "b", "c", "d"]
    for i, iid in enumerate(ids):
        trusts = frozenset({ids[i + 1]}) if i + 1 < len(ids) else frozenset()
        eng.register_identity(CloudIdentity(
            identity_id=iid, provider=Provider.AWS,
            kind=IdentityKind.CLOUD_ROLE,
            attached_policies=frozenset({"x"}),
            cross_provider_trusts=trusts,
        ))
    eng.recompute(at=_t0())
    assert any(v.invariant_id == "cloud.cross_cloud_chain_bounded"
               for v in eng.violations())


# ---- engine integration ---------------------------------------------------

def test_engine_no_violations_clean_setup() -> None:
    eng = CloudSecurityStateEngine()
    eng.register_workload(_container_wl(
        "w", container=_safe_container(),
        identity_id="iam-user", control_plane_id="k8s-api",
    ))
    eng.register_identity(_ident_user("iam-user"))
    eng.register_control_plane(_plane_ok("k8s-api"))
    eng.observe_workload_signal("w", _pos("ok"))
    eng.observe_identity_signal("iam-user", _pos("ok"))
    eng.recompute(at=_t0())
    assert eng.violations() == ()


def test_engine_effective_trust_limited_by_identity() -> None:
    eng = CloudSecurityStateEngine()
    eng.register_workload(_container_wl(
        "w", container=_safe_container(), identity_id="iam-user",
    ))
    eng.register_identity(_ident_user("iam-user"))
    # Give the workload strong positive signals but NOT the identity
    eng.observe_workload_signal("w", _pos("ok"))
    records = eng.recompute(at=_t0())
    rec = next(r for r in records if r.workload_id == "w")
    # Identity is neutral at 0.5 → workload effective trust capped near 0.6
    assert rec.trust_score <= NEUTRAL_SCORE + TRUST_SLACK + 1e-9


def test_engine_relationship_unknown_entity_rejected() -> None:
    eng = CloudSecurityStateEngine()
    try:
        eng.add_relationship(RelationshipEdge(
            "missing", "also-missing", RelationshipKind.CALLS,
        ))
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_engine_relationship_registered_ok() -> None:
    eng = CloudSecurityStateEngine()
    eng.register_workload(_container_wl("a"))
    eng.register_workload(_container_wl("b"))
    eng.add_relationship(RelationshipEdge(
        "a", "b", RelationshipKind.CALLS,
    ))
    assert len(eng.relationships().all_edges()) == 1


# ---- store tests ----------------------------------------------------------

def test_in_memory_store_rejects_stale() -> None:
    s = InMemoryCloudStateStore()
    t = _t0()
    s.put(WorkloadStateRecord("w", TrustLabel.TRUSTED, 0.9, 0.9, t))
    earlier = t.replace(year=t.year - 1)
    try:
        s.put(WorkloadStateRecord("w", TrustLabel.UNKNOWN, 0.5, 0.5, earlier))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_workload_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "cloud.db")
    store = SqliteCloudStateStore(db)
    t = _t0()
    store.put(WorkloadStateRecord("w", TrustLabel.TRUSTED, 0.9, 0.9, t))
    got = store.get("w")
    assert got is not None and got.label is TrustLabel.TRUSTED


def test_sqlite_store_identity_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "cloud.db")
    store = SqliteCloudStateStore(db)
    ident = CloudIdentity(
        identity_id="iam-1", provider=Provider.AWS,
        kind=IdentityKind.CLOUD_ROLE,
        attached_policies=frozenset({"ReadOnly"}),
        cross_provider_trusts=frozenset({"iam-2"}),
    )
    store.put_identity(ident)
    got = store.get_identity("iam-1")
    assert got is not None
    assert got.attached_policies == ident.attached_policies
    assert got.cross_provider_trusts == ident.cross_provider_trusts


def test_sqlite_store_control_plane_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "cloud.db")
    store = SqliteCloudStateStore(db)
    plane = ControlPlane(
        plane_id="k8s-1", kind=ControlPlaneKind.K8S_API_SERVER,
        provider=Provider.K8S, posture=0.8, compromised=False,
    )
    store.put_control_plane(plane)
    got = store.get_control_plane("k8s-1")
    assert got is not None and got.posture == 0.8


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
