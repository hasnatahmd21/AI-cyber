"""
HYDRA POST-CORE — PHASE 1: OPERATING SYSTEM SECURITY DEPTH
============================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only, no implementation)
  * Domain value objects
  * Continuous trust state
  * Privilege state model
  * Process lineage + trust propagation
  * Security-configuration state + degradation detection
  * Explicit security-state transition rules
  * State derivation from observations
  * Exposure-path analysis
  * Machine-checkable OS security invariants
  * In-memory and SQLite stores
  * Phase-1 engine facade
  * Full test suite (pytest-detectable)

Run tests:
    pytest hydra_phase1_os_security_state.py -q

This module does NOT reimplement any locked HYDRA core engine.
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
# SECTION 1 — CONTRACTS (consumed from locked HYDRA baseline)
# =============================================================================


class Clock(Protocol):
    def now(self) -> datetime: ...


class IdProvider(Protocol):
    def new_id(self, prefix: str = "") -> str: ...


class EvidenceEmitter(Protocol):
    def emit(self, evidence: Mapping[str, Any]) -> None: ...


class ProvenanceRecorder(Protocol):
    def record(
        self,
        *,
        subject_id: str,
        action: str,
        at: datetime,
        details: Mapping[str, Any],
    ) -> None: ...


class AuditSink(Protocol):
    def append(self, record: Mapping[str, Any]) -> None: ...


# =============================================================================
# SECTION 2 — DOMAIN
# =============================================================================


class EntityKind(str, Enum):
    PROCESS = "process"
    FILE = "file"
    SOCKET = "socket"
    SERVICE = "service"
    USER = "user"
    KERNEL_MODULE = "kernel_module"
    NAMESPACE = "namespace"
    DEVICE = "device"


class SecurityLabel(str, Enum):
    UNKNOWN = "unknown"
    OBSERVED = "observed"
    TRUSTED = "trusted"
    DEGRADED = "degraded"
    SUSPICIOUS = "suspicious"
    COMPROMISED = "compromised"
    QUARANTINED = "quarantined"


_SEVERITY: Mapping[SecurityLabel, int] = {
    SecurityLabel.UNKNOWN: 0,
    SecurityLabel.OBSERVED: 1,
    SecurityLabel.TRUSTED: 1,
    SecurityLabel.DEGRADED: 2,
    SecurityLabel.SUSPICIOUS: 3,
    SecurityLabel.COMPROMISED: 4,
    SecurityLabel.QUARANTINED: 5,
}


def severity(label: SecurityLabel) -> int:
    return _SEVERITY[label]


class ObservationKind(str, Enum):
    PROCESS_START = "process.start"
    PROCESS_EXEC = "process.exec"
    PROCESS_EXIT = "process.exit"
    PROCESS_PTRACE = "process.ptrace"
    PRIVILEGE_CHANGE = "privilege.change"
    FILE_OPEN = "file.open"
    SOCKET_BIND = "socket.bind"
    SOCKET_CONNECT = "socket.connect"
    KERNEL_MODULE_LOAD = "kernel_module.load"
    CONTROL_STATE = "control.state"


@dataclass(frozen=True)
class EntityRef:
    entity_id: str
    kind: EntityKind
    tenant_id: str

    def __post_init__(self) -> None:
        if not self.entity_id:
            raise ValueError("entity_id is required")
        if not self.tenant_id:
            raise ValueError("tenant_id is required")


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


@dataclass(frozen=True)
class Observation:
    observation_id: str
    kind: ObservationKind
    subject: EntityRef
    observed_at: datetime
    payload: Mapping[str, Any]
    evidence: Evidence

    def __post_init__(self) -> None:
        if not self.observation_id:
            raise ValueError("observation_id is required")
        if self.observed_at.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")


# =============================================================================
# SECTION 3 — TRUST
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
    return TrustState(score=NEUTRAL_SCORE, confidence=0.0, basis=(), updated_at=at)


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
    return TrustState(score=score, confidence=confidence, basis=basis, updated_at=at)


def decay_trust(state: TrustState, *, half_life_seconds: float, at: datetime) -> TrustState:
    if half_life_seconds <= 0:
        raise ValueError("half_life_seconds must be > 0")
    age = (at - state.updated_at).total_seconds()
    if age <= 0:
        return state
    factor = 0.5 ** (age / half_life_seconds)
    score = NEUTRAL_SCORE + (state.score - NEUTRAL_SCORE) * factor
    return TrustState(
        score=score,
        confidence=state.confidence * factor,
        basis=state.basis,
        updated_at=at,
    )


# =============================================================================
# SECTION 4 — PRIVILEGE
# =============================================================================


class SeccompMode(str, Enum):
    DISABLED = "disabled"
    STRICT = "strict"
    FILTER = "filter"


class LsmEnforcement(str, Enum):
    DISABLED = "disabled"
    COMPLAINING = "complaining"
    ENFORCING = "enforcing"


KNOWN_CAPABILITIES: FrozenSet[str] = frozenset({
    "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER",
    "CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE", "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_IPC_LOCK", "CAP_IPC_OWNER",
    "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD",
    "CAP_LEASE", "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN", "CAP_SYSLOG", "CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
})

_HIGH_RISK_CAPS: FrozenSet[str] = frozenset({
    "CAP_SYS_ADMIN", "CAP_SYS_MODULE", "CAP_SYS_PTRACE", "CAP_SYS_RAWIO",
    "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_MAC_ADMIN",
    "CAP_MAC_OVERRIDE", "CAP_SETPCAP", "CAP_SYS_BOOT", "CAP_BPF",
    "CAP_PERFMON", "CAP_AUDIT_CONTROL",
})


def high_risk_caps() -> FrozenSet[str]:
    return _HIGH_RISK_CAPS


@dataclass(frozen=True)
class PrivilegeState:
    uid: int
    gid: int
    euid: int
    egid: int
    capabilities: FrozenSet[str]
    ambient_capabilities: FrozenSet[str] = frozenset()
    no_new_privs: bool = False
    seccomp: SeccompMode = SeccompMode.DISABLED
    selinux: LsmEnforcement = LsmEnforcement.DISABLED
    apparmor: LsmEnforcement = LsmEnforcement.DISABLED

    def __post_init__(self) -> None:
        unknown = self.capabilities - KNOWN_CAPABILITIES
        if unknown:
            raise ValueError(f"unknown capabilities: {sorted(unknown)}")
        unknown_amb = self.ambient_capabilities - KNOWN_CAPABILITIES
        if unknown_amb:
            raise ValueError(f"unknown ambient capabilities: {sorted(unknown_amb)}")
        if not self.ambient_capabilities.issubset(self.capabilities):
            raise ValueError("ambient capabilities must be a subset of effective capabilities")
        for name, value in (("uid", self.uid), ("gid", self.gid),
                            ("euid", self.euid), ("egid", self.egid)):
            if value < 0:
                raise ValueError(f"{name} must be non-negative")

    @property
    def has_high_risk_cap(self) -> bool:
        return bool(self.capabilities & _HIGH_RISK_CAPS)

    @property
    def is_credential_escalated(self) -> bool:
        return self.euid == 0 or self.egid == 0

    def control_posture_score(self) -> float:
        score = 1.0
        if self.seccomp is SeccompMode.DISABLED:
            score -= 0.3
        elif self.seccomp is SeccompMode.STRICT:
            score = min(score, 0.9)
        if self.selinux is LsmEnforcement.DISABLED:
            score -= 0.15
        elif self.selinux is LsmEnforcement.COMPLAINING:
            score -= 0.05
        if self.apparmor is LsmEnforcement.DISABLED:
            score -= 0.15
        elif self.apparmor is LsmEnforcement.COMPLAINING:
            score -= 0.05
        if self.no_new_privs:
            score += 0.05
        return max(0.0, min(1.0, score))

    def authority_weight(self) -> float:
        score = 0.0
        if self.is_credential_escalated:
            score += 0.4
        score += min(0.4, 0.05 * len(self.capabilities))
        if self.has_high_risk_cap:
            score += 0.2
        if self.ambient_capabilities:
            score += 0.05 * len(self.ambient_capabilities)
        return max(0.0, min(1.0, score))


def privilege_change_risk(prev: PrivilegeState, nxt: PrivilegeState) -> float:
    risk = 0.0
    gained_caps = nxt.capabilities - prev.capabilities
    if gained_caps:
        risk += 0.1 * len(gained_caps)
        if gained_caps & _HIGH_RISK_CAPS:
            risk += 0.3
    if not prev.is_credential_escalated and nxt.is_credential_escalated:
        risk += 0.4
    if prev.selinux is LsmEnforcement.ENFORCING and nxt.selinux is not LsmEnforcement.ENFORCING:
        risk += 0.2
    if prev.apparmor is LsmEnforcement.ENFORCING and nxt.apparmor is not LsmEnforcement.ENFORCING:
        risk += 0.2
    if prev.seccomp is SeccompMode.FILTER and nxt.seccomp is SeccompMode.DISABLED:
        risk += 0.2
    if prev.no_new_privs and not nxt.no_new_privs:
        risk += 0.1
    return max(0.0, min(1.0, risk))


# =============================================================================
# SECTION 5 — LINEAGE
# =============================================================================


class LineageKind(str, Enum):
    FORK = "fork"
    EXEC = "exec"
    CLONE = "clone"
    PTRACE_ATTACH = "ptrace_attach"


@dataclass(frozen=True)
class LineageEdge:
    parent_id: str
    child_id: str
    kind: LineageKind
    at: datetime

    def __post_init__(self) -> None:
        if not self.parent_id or not self.child_id:
            raise ValueError("parent_id and child_id are required")
        if self.parent_id == self.child_id:
            raise ValueError("self-edges are not allowed in lineage")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


class LineageGraph:
    def __init__(self) -> None:
        self._parents: Dict[str, str] = {}
        self._children: Dict[str, List[str]] = {}
        self._edges: List[LineageEdge] = []

    def add(self, edge: LineageEdge) -> None:
        if edge.child_id in self._parents and self._parents[edge.child_id] != edge.parent_id:
            raise ValueError(
                f"process {edge.child_id} already has parent {self._parents[edge.child_id]}"
            )
        if self._would_create_cycle(edge.parent_id, edge.child_id):
            raise ValueError(
                f"lineage edge {edge.parent_id}->{edge.child_id} creates a cycle"
            )
        self._parents[edge.child_id] = edge.parent_id
        self._children.setdefault(edge.parent_id, []).append(edge.child_id)
        self._edges.append(edge)

    def _would_create_cycle(self, parent: str, child: str) -> bool:
        cur: Optional[str] = parent
        seen: set = set()
        while cur is not None and cur not in seen:
            if cur == child:
                return True
            seen.add(cur)
            cur = self._parents.get(cur)
        return False

    def parent_of(self, process_id: str) -> Optional[str]:
        return self._parents.get(process_id)

    def ancestors(self, process_id: str) -> Tuple[str, ...]:
        out: List[str] = []
        cur = self._parents.get(process_id)
        seen: set = set()
        while cur is not None and cur not in seen:
            out.append(cur)
            seen.add(cur)
            cur = self._parents.get(cur)
        return tuple(out)

    def depth(self, process_id: str) -> int:
        return len(self.ancestors(process_id))

    def children_of(self, process_id: str) -> Tuple[str, ...]:
        return tuple(self._children.get(process_id, []))

    def edges(self) -> Tuple[LineageEdge, ...]:
        return tuple(self._edges)


@dataclass(frozen=True)
class LineageTrustInputs:
    direct_scores: Mapping[str, float]
    integrity_scores: Mapping[str, float]

    def __post_init__(self) -> None:
        for k, v in self.direct_scores.items():
            if not 0.0 <= v <= 1.0:
                raise ValueError(f"direct score for {k} out of range")
        for k, v in self.integrity_scores.items():
            if not 0.0 <= v <= 1.0:
                raise ValueError(f"integrity score for {k} out of range")


def propagate_lineage_trust(
    graph: LineageGraph,
    root_id: str,
    inputs: LineageTrustInputs,
    *,
    parent_weight: float = 0.6,
) -> Dict[str, float]:
    if not 0.0 <= parent_weight <= 1.0:
        raise ValueError("parent_weight must be within [0,1]")
    w_direct = (1.0 - parent_weight) / 2.0
    w_int = 1.0 - parent_weight - w_direct

    def score_for(node: str, parent: Optional[float]) -> float:
        d = inputs.direct_scores.get(node, 0.5)
        i = inputs.integrity_scores.get(node, 0.5)
        p = parent if parent is not None else 0.5
        raw = w_direct * d + w_int * i + parent_weight * p
        return max(0.0, min(1.0, raw))

    out: Dict[str, float] = {root_id: score_for(root_id, None)}
    stack = [root_id]
    seen: set = set()
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        for child in graph.children_of(cur):
            out[child] = score_for(child, out[cur])
            stack.append(child)
    return out


# =============================================================================
# SECTION 6 — CONFIGURATION
# =============================================================================


@dataclass(frozen=True)
class ControlState:
    control_id: str
    posture: float
    floor: float
    observed_at_source: str

    def __post_init__(self) -> None:
        if not self.control_id:
            raise ValueError("control_id is required")
        if not 0.0 <= self.posture <= 1.0:
            raise ValueError("posture must be within [0,1]")
        if not 0.0 <= self.floor <= 1.0:
            raise ValueError("floor must be within [0,1]")
        if not self.observed_at_source:
            raise ValueError("observed_at_source is required")

    @property
    def degraded(self) -> bool:
        return self.posture < self.floor


@dataclass(frozen=True)
class ConfigurationState:
    controls: Mapping[str, ControlState]

    def __post_init__(self) -> None:
        for k, v in self.controls.items():
            if k != v.control_id:
                raise ValueError(f"control key {k} != control_id {v.control_id}")

    def degraded_controls(self) -> Tuple[ControlState, ...]:
        return tuple(c for c in self.controls.values() if c.degraded)

    def posture(self) -> float:
        if not self.controls:
            return 1.0
        return sum(c.posture for c in self.controls.values()) / len(self.controls)

    def with_control(self, state: ControlState) -> "ConfigurationState":
        updated: Dict[str, ControlState] = dict(self.controls)
        updated[state.control_id] = state
        return ConfigurationState(controls=updated)


# =============================================================================
# SECTION 7 — TRANSITIONS
# =============================================================================


class TransitionOutcome(str, Enum):
    ALLOWED = "allowed"
    REJECTED_INVALID = "rejected_invalid"
    REJECTED_INVARIANT = "rejected_invariant"
    REQUIRES_VERIFICATION = "requires_verification"


_ALLOWED_ESCALATIONS: Mapping[SecurityLabel, FrozenSet[SecurityLabel]] = {
    SecurityLabel.UNKNOWN: frozenset(
        {SecurityLabel.OBSERVED, SecurityLabel.SUSPICIOUS, SecurityLabel.DEGRADED}
    ),
    SecurityLabel.OBSERVED: frozenset({
        SecurityLabel.TRUSTED, SecurityLabel.DEGRADED,
        SecurityLabel.SUSPICIOUS, SecurityLabel.COMPROMISED,
    }),
    SecurityLabel.TRUSTED: frozenset({
        SecurityLabel.DEGRADED, SecurityLabel.SUSPICIOUS,
        SecurityLabel.COMPROMISED, SecurityLabel.QUARANTINED,
    }),
    SecurityLabel.DEGRADED: frozenset({
        SecurityLabel.SUSPICIOUS, SecurityLabel.COMPROMISED,
        SecurityLabel.QUARANTINED, SecurityLabel.TRUSTED,
    }),
    SecurityLabel.SUSPICIOUS: frozenset({
        SecurityLabel.COMPROMISED, SecurityLabel.QUARANTINED,
        SecurityLabel.OBSERVED, SecurityLabel.DEGRADED,
    }),
    SecurityLabel.COMPROMISED: frozenset({SecurityLabel.QUARANTINED}),
    SecurityLabel.QUARANTINED: frozenset({SecurityLabel.OBSERVED}),
}


@dataclass(frozen=True)
class TransitionRequest:
    subject_id: str
    from_label: SecurityLabel
    to_label: SecurityLabel
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
    permitted = _ALLOWED_ESCALATIONS.get(req.from_label, frozenset())
    if req.to_label not in permitted:
        return TransitionDecision(
            TransitionOutcome.REJECTED_INVALID,
            f"{req.from_label.value} -> {req.to_label.value} not permitted",
        )
    going_better = severity(req.to_label) < severity(req.from_label)
    if going_better and not req.verified:
        return TransitionDecision(
            TransitionOutcome.REQUIRES_VERIFICATION,
            "recovery transitions require verification",
        )
    return TransitionDecision(TransitionOutcome.ALLOWED, "permitted")


# =============================================================================
# SECTION 8 — DERIVATION
# =============================================================================


@dataclass(frozen=True)
class DerivationInputs:
    entity: EntityRef
    trust: TrustState
    privilege: PrivilegeState
    configuration: ConfigurationState
    lineage: LineageGraph
    observations: Tuple[Observation, ...]


_TRUSTED_MIN = 0.85
_OBSERVED_MIN = 0.55
_SUSPICIOUS_MAX = 0.30


def _has_compromise_evidence(observations: Tuple[Observation, ...]) -> bool:
    for obs in observations:
        flag = obs.payload.get("compromise_indicator")
        if flag is True and obs.evidence.confidence >= 0.7:
            return True
    return False


def _integrity_ok(inputs: DerivationInputs) -> bool:
    priv = inputs.privilege
    if priv.selinux.value == "disabled" and priv.apparmor.value == "disabled":
        return False
    for obs in inputs.observations:
        if obs.kind.value == "process.ptrace":
            target = obs.payload.get("target_id")
            if target == inputs.entity.entity_id and obs.evidence.confidence >= 0.5:
                return False
    return True


def derive_label(inputs: DerivationInputs) -> SecurityLabel:
    trust = inputs.trust
    priv = inputs.privilege
    cfg = inputs.configuration

    if _has_compromise_evidence(inputs.observations):
        return SecurityLabel.COMPROMISED

    if cfg.degraded_controls():
        if priv.authority_weight() >= 0.6:
            return SecurityLabel.SUSPICIOUS
        return SecurityLabel.DEGRADED

    if trust.confidence >= 0.4:
        if trust.score < _SUSPICIOUS_MAX:
            return SecurityLabel.SUSPICIOUS
        if trust.score >= _TRUSTED_MIN and _integrity_ok(inputs):
            return SecurityLabel.TRUSTED
        if trust.score >= _OBSERVED_MIN:
            return SecurityLabel.OBSERVED
        return SecurityLabel.DEGRADED

    return SecurityLabel.UNKNOWN


def worse_of(a: SecurityLabel, b: SecurityLabel) -> SecurityLabel:
    return a if severity(a) >= severity(b) else b


# =============================================================================
# SECTION 9 — EXPOSURE
# =============================================================================


@dataclass(frozen=True)
class ExposureNode:
    entity: EntityRef
    privilege: PrivilegeState
    label: SecurityLabel
    trust_score: float


@dataclass(frozen=True)
class ExposurePath:
    steps: Tuple[str, ...]
    reachable_capabilities: FrozenSet[str]
    risk: float
    rationale: str

    def __post_init__(self) -> None:
        if not self.steps:
            raise ValueError("path must have steps")
        if not 0.0 <= self.risk <= 1.0:
            raise ValueError("risk must be within [0,1]")


def _worse_label(a: SecurityLabel, b: SecurityLabel) -> bool:
    return severity(a) > severity(b)


def _chain_between(ancestor: str, node: str, lineage: LineageGraph) -> Tuple[str, ...]:
    chain: List[str] = [node]
    cur = node
    while cur != ancestor:
        parent = lineage.parent_of(cur)
        if parent is None:
            break
        chain.append(parent)
        cur = parent
    chain.reverse()
    return tuple(chain)


def _risk_of(
    chain: Tuple[str, ...],
    nodes: Mapping[str, ExposureNode],
    caps: Iterable[str],
) -> float:
    cap_risk = min(0.6, 0.1 * len(set(caps)))
    weakest = 1.0
    for step in chain:
        n = nodes.get(step)
        if n is None:
            continue
        weakest = min(weakest, n.trust_score)
    path_risk = 1.0 - weakest
    return max(0.0, min(1.0, 0.6 * path_risk + 0.4 * cap_risk))


def analyse_exposure(
    nodes: Mapping[str, ExposureNode],
    lineage: LineageGraph,
    *,
    high_risk_only: bool = True,
) -> Tuple[ExposurePath, ...]:
    paths: List[ExposurePath] = []
    for node_id, node in nodes.items():
        caps = node.privilege.capabilities
        if high_risk_only:
            caps = caps & _HIGH_RISK_CAPS
        if not caps:
            continue
        ancestors = lineage.ancestors(node_id)
        if not ancestors:
            continue
        risky_ancestors = [
            a for a in ancestors
            if a in nodes and _worse_label(nodes[a].label, node.label)
        ]
        if not risky_ancestors:
            continue
        entry = risky_ancestors[0]
        chain = _chain_between(entry, node_id, lineage)
        risk = _risk_of(chain, nodes, caps)
        rationale = (
            f"{entry} ({nodes[entry].label.value}) reaches high-authority "
            f"{node_id} ({sorted(caps)})"
        )
        paths.append(ExposurePath(
            steps=chain,
            reachable_capabilities=frozenset(caps),
            risk=risk,
            rationale=rationale,
        ))
    return tuple(sorted(paths, key=lambda p: p.risk, reverse=True))


# =============================================================================
# SECTION 10 — DEGRADATION
# =============================================================================


class DegradationKind(str, Enum):
    CONTROL_BELOW_FLOOR = "control.below_floor"
    CONTROL_REMOVED = "control.removed"
    CONTROL_REGRESSED = "control.regressed"


@dataclass(frozen=True)
class DegradationFinding:
    control_id: str
    kind: DegradationKind
    previous_posture: float
    current_posture: float
    floor: float
    detected_at: datetime
    source: str

    def __post_init__(self) -> None:
        if not 0.0 <= self.previous_posture <= 1.0:
            raise ValueError("previous_posture must be within [0,1]")
        if not 0.0 <= self.current_posture <= 1.0:
            raise ValueError("current_posture must be within [0,1]")
        if self.detected_at.tzinfo is None:
            raise ValueError("detected_at must be timezone-aware")


def detect_degradation(
    previous: Mapping[str, ControlState],
    current: Mapping[str, ControlState],
    *,
    at: datetime,
    source: str,
) -> Tuple[DegradationFinding, ...]:
    findings: List[DegradationFinding] = []
    for cid, cur in current.items():
        prev = previous.get(cid)
        if prev is None:
            continue
        if cur.posture < prev.posture:
            findings.append(DegradationFinding(
                control_id=cid,
                kind=DegradationKind.CONTROL_REGRESSED,
                previous_posture=prev.posture,
                current_posture=cur.posture,
                floor=cur.floor,
                detected_at=at,
                source=source,
            ))
        if cur.degraded and not prev.degraded:
            findings.append(DegradationFinding(
                control_id=cid,
                kind=DegradationKind.CONTROL_BELOW_FLOOR,
                previous_posture=prev.posture,
                current_posture=cur.posture,
                floor=cur.floor,
                detected_at=at,
                source=source,
            ))
    for cid, prev in previous.items():
        if cid not in current:
            findings.append(DegradationFinding(
                control_id=cid,
                kind=DegradationKind.CONTROL_REMOVED,
                previous_posture=prev.posture,
                current_posture=0.0,
                floor=prev.floor,
                detected_at=at,
                source=source,
            ))
    return tuple(findings)


# =============================================================================
# SECTION 11 — INVARIANTS
# =============================================================================


class InvariantSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class EntitySnapshot:
    entity_id: str
    label: SecurityLabel
    trust: TrustState
    privilege: PrivilegeState
    parent_id: Optional[str]


@dataclass(frozen=True)
class StateSnapshot:
    entities: Mapping[str, EntitySnapshot]
    configuration: ConfigurationState
    exposure_paths: Tuple[ExposurePath, ...] = ()


@dataclass(frozen=True)
class InvariantViolation:
    invariant_id: str
    severity: InvariantSeverity
    subject_id: str
    detail: str


@dataclass(frozen=True)
class Invariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[StateSnapshot], Tuple[InvariantViolation, ...]]
    description: str


def _inv_no_unauthorized_authority(snap: StateSnapshot) -> Tuple[InvariantViolation, ...]:
    out = []
    for eid, e in snap.entities.items():
        if e.label in (SecurityLabel.COMPROMISED, SecurityLabel.QUARANTINED):
            if e.privilege.has_high_risk_cap or e.privilege.is_credential_escalated:
                out.append(InvariantViolation(
                    invariant_id="os.no_unauthorized_authority",
                    severity=InvariantSeverity.CRITICAL,
                    subject_id=eid,
                    detail="compromised/quarantined entity retains high authority",
                ))
    return tuple(out)


def _inv_quarantine_trust_cap(snap: StateSnapshot) -> Tuple[InvariantViolation, ...]:
    out = []
    for eid, e in snap.entities.items():
        if e.label is SecurityLabel.QUARANTINED and e.trust.score > 0.6:
            out.append(InvariantViolation(
                invariant_id="os.quarantine_trust_cap",
                severity=InvariantSeverity.HIGH,
                subject_id=eid,
                detail=f"quarantined entity has high trust ({e.trust.score:.2f})",
            ))
    return tuple(out)


def _inv_critical_control_floor(snap: StateSnapshot) -> Tuple[InvariantViolation, ...]:
    out = []
    for c in snap.configuration.controls.values():
        if c.degraded:
            out.append(InvariantViolation(
                invariant_id="os.critical_control_floor",
                severity=InvariantSeverity.HIGH,
                subject_id=c.control_id,
                detail=(
                    f"control {c.control_id} posture {c.posture:.2f} "
                    f"below floor {c.floor:.2f}"
                ),
            ))
    return tuple(out)


def _inv_no_high_risk_exposure(snap: StateSnapshot) -> Tuple[InvariantViolation, ...]:
    out = []
    for p in snap.exposure_paths:
        if p.risk >= 0.8:
            out.append(InvariantViolation(
                invariant_id="os.high_risk_exposure",
                severity=InvariantSeverity.CRITICAL,
                subject_id=p.steps[-1],
                detail=p.rationale,
            ))
    return tuple(out)


DEFAULT_INVARIANTS: Tuple[Invariant, ...] = (
    Invariant(
        invariant_id="os.no_unauthorized_authority",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_no_unauthorized_authority,
        description="Compromised/quarantined entities must not retain authority.",
    ),
    Invariant(
        invariant_id="os.quarantine_trust_cap",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_quarantine_trust_cap,
        description="Quarantined entities must not carry high trust.",
    ),
    Invariant(
        invariant_id="os.critical_control_floor",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_critical_control_floor,
        description="Security controls must not fall below their floor.",
    ),
    Invariant(
        invariant_id="os.high_risk_exposure",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_no_high_risk_exposure,
        description="No high-risk exposure path may exist.",
    ),
)


def check_invariants(
    snap: StateSnapshot,
    invariants: Iterable[Invariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 12 — STORE
# =============================================================================


@dataclass(frozen=True)
class EntityStateRecord:
    entity: EntityRef
    label: SecurityLabel
    trust_score: float
    trust_confidence: float
    privilege: PrivilegeState
    parent_id: Optional[str]
    updated_at: datetime


class OsStateStore(Protocol):
    def get(self, entity_id: str) -> Optional[EntityStateRecord]: ...
    def put(self, record: EntityStateRecord) -> None: ...
    def all(self) -> Tuple[EntityStateRecord, ...]: ...


class InMemoryOsStateStore:
    def __init__(self) -> None:
        self._data: Dict[str, EntityStateRecord] = {}

    def get(self, entity_id: str) -> Optional[EntityStateRecord]:
        return self._data.get(entity_id)

    def put(self, record: EntityStateRecord) -> None:
        existing = self._data.get(record.entity.entity_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._data[record.entity.entity_id] = record

    def all(self) -> Tuple[EntityStateRecord, ...]:
        return tuple(self._data.values())


def _priv_to_dict(p: PrivilegeState) -> dict:
    return {
        "uid": p.uid, "gid": p.gid, "euid": p.euid, "egid": p.egid,
        "capabilities": sorted(p.capabilities),
        "ambient_capabilities": sorted(p.ambient_capabilities),
        "no_new_privs": p.no_new_privs,
        "seccomp": p.seccomp.value,
        "selinux": p.selinux.value,
        "apparmor": p.apparmor.value,
    }


def _priv_from_dict(d: dict) -> PrivilegeState:
    return PrivilegeState(
        uid=d["uid"], gid=d["gid"], euid=d["euid"], egid=d["egid"],
        capabilities=frozenset(d["capabilities"]),
        ambient_capabilities=frozenset(d.get("ambient_capabilities", [])),
        no_new_privs=d["no_new_privs"],
        seccomp=SeccompMode(d["seccomp"]),
        selinux=LsmEnforcement(d["selinux"]),
        apparmor=LsmEnforcement(d["apparmor"]),
    )


class SqliteOsStateStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS os_entity_state (
                entity_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                label TEXT NOT NULL,
                trust_score REAL NOT NULL,
                trust_confidence REAL NOT NULL,
                privilege_json TEXT NOT NULL,
                parent_id TEXT,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def get(self, entity_id: str) -> Optional[EntityStateRecord]:
        row = self._conn.execute(
            "SELECT tenant_id, kind, label, trust_score, trust_confidence, "
            "privilege_json, parent_id, updated_at "
            "FROM os_entity_state WHERE entity_id = ?",
            (entity_id,),
        ).fetchone()
        if row is None:
            return None
        return self._row_to_record(entity_id, row)

    def put(self, record: EntityStateRecord) -> None:
        existing = self.get(record.entity.entity_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        priv = record.privilege
        self._conn.execute(
            """
            INSERT INTO os_entity_state
              (entity_id, tenant_id, kind, label, trust_score,
               trust_confidence, privilege_json, parent_id, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(entity_id) DO UPDATE SET
              tenant_id=excluded.tenant_id,
              kind=excluded.kind,
              label=excluded.label,
              trust_score=excluded.trust_score,
              trust_confidence=excluded.trust_confidence,
              privilege_json=excluded.privilege_json,
              parent_id=excluded.parent_id,
              updated_at=excluded.updated_at
            """,
            (
                record.entity.entity_id,
                record.entity.tenant_id,
                record.entity.kind.value,
                record.label.value,
                record.trust_score,
                record.trust_confidence,
                json.dumps(_priv_to_dict(priv), sort_keys=True),
                record.parent_id,
                record.updated_at.isoformat(),
            ),
        )
        self._conn.commit()

    def all(self) -> Tuple[EntityStateRecord, ...]:
        rows = self._conn.execute(
            "SELECT entity_id, tenant_id, kind, label, trust_score, "
            "trust_confidence, privilege_json, parent_id, updated_at "
            "FROM os_entity_state"
        ).fetchall()
        return tuple(self._row_to_record(r[0], r[1:]) for r in rows)

    @staticmethod
    def _row_to_record(entity_id: str, row: tuple) -> EntityStateRecord:
        (tenant_id, kind, label, trust_score, trust_conf,
         priv_json, parent_id, updated_at) = row
        return EntityStateRecord(
            entity=EntityRef(entity_id=entity_id, kind=EntityKind(kind), tenant_id=tenant_id),
            label=SecurityLabel(label),
            trust_score=float(trust_score),
            trust_confidence=float(trust_conf),
            privilege=_priv_from_dict(json.loads(priv_json)),
            parent_id=parent_id,
            updated_at=datetime.fromisoformat(updated_at),
        )


# =============================================================================
# SECTION 13 — ENGINE
# =============================================================================


@dataclass
class _EntityAccumulator:
    entity: EntityRef
    privilege: PrivilegeState
    parent_id: Optional[str]
    signals: List[TrustSignal] = field(default_factory=list)
    observations: List[Observation] = field(default_factory=list)
    label: SecurityLabel = SecurityLabel.UNKNOWN
    updated_at: Optional[datetime] = None


def _last_signal_score(acc: _EntityAccumulator) -> float:
    if not acc.signals:
        return 0.5
    return acc.signals[-1].polarity * 0.5 + 0.5


def _is_verified(label: SecurityLabel, acc: _EntityAccumulator) -> bool:
    if label in (SecurityLabel.OBSERVED, SecurityLabel.TRUSTED):
        return any(o.evidence.confidence >= 0.7 for o in acc.observations)
    return False


class OsSecurityStateEngine:
    def __init__(self, *, store: Optional[OsStateStore] = None) -> None:
        self._store: OsStateStore = store or InMemoryOsStateStore()
        self._lineage = LineageGraph()
        self._acc: Dict[str, _EntityAccumulator] = {}
        self._config = ConfigurationState(controls={})
        self._degradation_findings: Tuple[DegradationFinding, ...] = ()
        self._violations: Tuple[InvariantViolation, ...] = ()
        self._exposure_paths: Tuple[ExposurePath, ...] = ()

    # ---- ingest ----------------------------------------------------------

    def record_lineage(self, edge: LineageEdge) -> None:
        self._lineage.add(edge)

    def observe_privilege(
        self,
        entity: EntityRef,
        privilege: PrivilegeState,
        *,
        at: datetime,
        parent_id: Optional[str] = None,
    ) -> None:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        acc = self._acc.setdefault(
            entity.entity_id,
            _EntityAccumulator(entity=entity, privilege=privilege, parent_id=parent_id),
        )
        acc.privilege = privilege
        acc.parent_id = parent_id
        acc.updated_at = at

    def observe_security_event(self, observation: Observation) -> None:
        acc = self._acc.get(observation.subject.entity_id)
        if acc is None:
            acc = _EntityAccumulator(
                entity=observation.subject,
                privilege=PrivilegeState(uid=0, gid=0, euid=0, egid=0,
                                         capabilities=frozenset()),
                parent_id=None,
                updated_at=observation.observed_at,
            )
            self._acc[observation.subject.entity_id] = acc
        acc.observations.append(observation)
        acc.updated_at = observation.observed_at

    def observe_trust_signal(self, entity_id: str, signal: TrustSignal) -> None:
        acc = self._acc.get(entity_id)
        if acc is None:
            raise KeyError(f"unknown entity {entity_id}")
        acc.signals.append(signal)

    def record_control_state(self, control: ControlState, *, at: datetime) -> None:
        previous = dict(self._config.controls)
        self._config = self._config.with_control(control)
        self._degradation_findings = detect_degradation(
            previous, self._config.controls, at=at, source="engine.record_control_state"
        )

    # ---- derive ----------------------------------------------------------

    def recompute(self, *, at: datetime) -> Tuple[EntityStateRecord, ...]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

        propagated = self._propagate_lineage_trust(at)

        records: List[EntityStateRecord] = []
        for eid, acc in self._acc.items():
            trust = combine_trust(acc.signals, at)
            lineage_prior = propagated.get(eid)
            if lineage_prior is not None and lineage_prior < trust.score:
                weight = 0.25
                blended = (1 - weight) * trust.score + weight * lineage_prior
                trust = TrustState(
                    score=blended,
                    confidence=trust.confidence,
                    basis=trust.basis,
                    updated_at=trust.updated_at,
                )

            label = derive_label(DerivationInputs(
                entity=acc.entity,
                trust=trust,
                privilege=acc.privilege,
                configuration=self._config,
                lineage=self._lineage,
                observations=tuple(acc.observations),
            ))

            previous_label = acc.label
            if previous_label is not label:
                decision = evaluate_transition(TransitionRequest(
                    subject_id=eid,
                    from_label=previous_label,
                    to_label=label,
                    reason="recompute",
                    verified=_is_verified(label, acc),
                ))
                if decision.outcome in (
                    TransitionOutcome.REJECTED_INVALID,
                    TransitionOutcome.REJECTED_INVARIANT,
                    TransitionOutcome.REQUIRES_VERIFICATION,
                ):
                    label = previous_label

            acc.label = label

            record = EntityStateRecord(
                entity=acc.entity,
                label=label,
                trust_score=trust.score,
                trust_confidence=trust.confidence,
                privilege=acc.privilege,
                parent_id=acc.parent_id,
                updated_at=at,
            )
            self._store.put(record)
            records.append(record)

        nodes = {
            r.entity.entity_id: ExposureNode(
                entity=r.entity,
                privilege=r.privilege,
                label=r.label,
                trust_score=r.trust_score,
            )
            for r in records
        }
        self._exposure_paths = analyse_exposure(nodes, self._lineage)

        snapshot = StateSnapshot(
            entities={
                r.entity.entity_id: EntitySnapshot(
                    entity_id=r.entity.entity_id,
                    label=r.label,
                    trust=TrustState(
                        score=r.trust_score,
                        confidence=r.trust_confidence,
                        basis=(),
                        updated_at=at,
                    ),
                    privilege=r.privilege,
                    parent_id=r.parent_id,
                )
                for r in records
            },
            configuration=self._config,
            exposure_paths=self._exposure_paths,
        )
        self._violations = check_invariants(snapshot)

        return tuple(records)

    # ---- queries ---------------------------------------------------------

    def current_state(self, entity_id: str) -> Optional[EntityStateRecord]:
        return self._store.get(entity_id)

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return self._violations

    def exposure_paths(self) -> Tuple[ExposurePath, ...]:
        return self._exposure_paths

    def degradation(self) -> Tuple[DegradationFinding, ...]:
        return self._degradation_findings

    # ---- internals -------------------------------------------------------

    def _propagate_lineage_trust(self, at: datetime) -> Mapping[str, float]:
        roots = [
            eid for eid, acc in self._acc.items()
            if acc.parent_id is None or acc.parent_id not in self._acc
        ]
        if not roots:
            return {}
        direct = {eid: _last_signal_score(acc) for eid, acc in self._acc.items()}
        integrity = {
            eid: (1.0 if (acc.privilege.selinux.value == "enforcing"
                          or acc.privilege.apparmor.value == "enforcing") else 0.5)
            for eid, acc in self._acc.items()
        }
        inputs = LineageTrustInputs(direct_scores=direct, integrity_scores=integrity)
        merged: Dict[str, float] = {}
        for root in roots:
            for eid, score in propagate_lineage_trust(self._lineage, root, inputs).items():
                merged[eid] = max(merged.get(eid, 0.0), score)
        return merged


# =============================================================================
# SECTION 14 — TESTS
# =============================================================================


def _t0() -> datetime:
    from datetime import timezone
    return datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def _tz():
    from datetime import timezone
    return timezone.utc


def _ev(at: datetime, conf: float = 0.9) -> Evidence:
    return Evidence(evidence_id="e1", source="test", confidence=conf,
                    observed_at=at, payload={})


def _base_priv(**kw) -> PrivilegeState:
    defaults = dict(
        uid=1000, gid=1000, euid=1000, egid=1000,
        capabilities=frozenset(), no_new_privs=True,
        seccomp=SeccompMode.FILTER,
        selinux=LsmEnforcement.ENFORCING,
        apparmor=LsmEnforcement.ENFORCING,
    )
    defaults.update(kw)
    return PrivilegeState(**defaults)


def _entity_ref(eid: str = "p1") -> EntityRef:
    return EntityRef(entity_id=eid, kind=EntityKind.PROCESS, tenant_id="t1")


def _cfg_empty() -> ConfigurationState:
    return ConfigurationState(controls={})


def _cfg_degraded() -> ConfigurationState:
    return ConfigurationState(controls={
        "selinux": ControlState(control_id="selinux", posture=0.2,
                                floor=0.8, observed_at_source="test")
    })


def _trust_state(at: datetime, score: float, conf: float) -> TrustState:
    return TrustState(score=score, confidence=conf, basis=(), updated_at=at)


# ---- tests ----------------------------------------------------------------


def test_entity_ref_requires_id_and_tenant() -> None:
    try:
        EntityRef(entity_id="", kind=EntityKind.PROCESS, tenant_id="t1")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
    try:
        EntityRef(entity_id="p1", kind=EntityKind.PROCESS, tenant_id="")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_evidence_requires_aware_time() -> None:
    try:
        Evidence(evidence_id="e", source="s", confidence=0.5,
                 observed_at=datetime(2026, 1, 1), payload={})
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_evidence_confidence_bounds() -> None:
    try:
        Evidence(evidence_id="e", source="s", confidence=1.5,
                 observed_at=_t0(), payload={})
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_severity_ordering() -> None:
    assert severity(SecurityLabel.TRUSTED) < severity(SecurityLabel.DEGRADED)
    assert severity(SecurityLabel.DEGRADED) < severity(SecurityLabel.SUSPICIOUS)
    assert severity(SecurityLabel.SUSPICIOUS) < severity(SecurityLabel.COMPROMISED)
    assert severity(SecurityLabel.COMPROMISED) < severity(SecurityLabel.QUARANTINED)


def test_combine_trust_empty_is_neutral() -> None:
    st = combine_trust([], _t0())
    assert st.score == NEUTRAL_SCORE
    assert st.confidence == 0.0


def test_combine_trust_positive_raises_score() -> None:
    s = TrustSignal(signal_id="s1", weight=1.0, polarity=1.0,
                    at=_t0(), evidence=_ev(_t0()))
    st = combine_trust([s], _t0())
    assert st.score == 1.0
    assert 0.0 < st.confidence < 1.0


def test_combine_trust_negative_lowers_score() -> None:
    s = TrustSignal(signal_id="s1", weight=1.0, polarity=-1.0,
                    at=_t0(), evidence=_ev(_t0()))
    st = combine_trust([s], _t0())
    assert st.score == 0.0


def test_decay_trust_never_increases() -> None:
    s = TrustSignal(signal_id="s1", weight=1.0, polarity=1.0,
                    at=_t0(), evidence=_ev(_t0()))
    st = combine_trust([s], _t0())
    later = _t0().replace(minute=10)
    d = decay_trust(st, half_life_seconds=60.0, at=later)
    assert d.score < st.score
    assert d.score >= NEUTRAL_SCORE


def test_decay_trust_requires_positive_half_life() -> None:
    st = neutral_trust(_t0())
    try:
        decay_trust(st, half_life_seconds=0, at=_t0())
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_privilege_rejects_unknown_capability() -> None:
    try:
        _base_priv(capabilities=frozenset({"CAP_NOT_REAL"}))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_privilege_ambient_must_be_subset() -> None:
    try:
        _base_priv(
            capabilities=frozenset({"CAP_NET_RAW"}),
            ambient_capabilities=frozenset({"CAP_SYS_ADMIN"}),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_privilege_root_escalation_detected() -> None:
    assert _base_priv(euid=0).is_credential_escalated


def test_privilege_control_posture_drops_without_mac() -> None:
    strong = _base_priv()
    weak = _base_priv(
        selinux=LsmEnforcement.DISABLED,
        apparmor=LsmEnforcement.DISABLED,
        seccomp=SeccompMode.DISABLED,
        no_new_privs=False,
    )
    assert weak.control_posture_score() < strong.control_posture_score()


def test_privilege_change_risk_root_gain() -> None:
    assert privilege_change_risk(_base_priv(euid=1000), _base_priv(euid=0)) >= 0.4


def test_privilege_change_risk_mac_drop() -> None:
    nxt = _base_priv(selinux=LsmEnforcement.DISABLED,
                     apparmor=LsmEnforcement.DISABLED)
    assert privilege_change_risk(_base_priv(), nxt) >= 0.3


def test_lineage_cycle_rejected() -> None:
    t = _t0()
    g = LineageGraph()
    g.add(LineageEdge("a", "b", LineageKind.FORK, t))
    g.add(LineageEdge("b", "c", LineageKind.FORK, t))
    try:
        g.add(LineageEdge("c", "a", LineageKind.FORK, t))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_lineage_self_edge_rejected() -> None:
    t = _t0()
    g = LineageGraph()
    try:
        g.add(LineageEdge("a", "a", LineageKind.FORK, t))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_lineage_ancestors_and_depth() -> None:
    t = _t0()
    g = LineageGraph()
    g.add(LineageEdge("a", "b", LineageKind.FORK, t))
    g.add(LineageEdge("b", "c", LineageKind.FORK, t))
    assert g.ancestors("c") == ("b", "a")
    assert g.depth("c") == 2


def test_lineage_duplicate_child_rejected() -> None:
    t = _t0()
    g = LineageGraph()
    g.add(LineageEdge("a", "b", LineageKind.FORK, t))
    try:
        g.add(LineageEdge("x", "b", LineageKind.FORK, t))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_propagate_lineage_trust_bounds() -> None:
    t = _t0()
    g = LineageGraph()
    g.add(LineageEdge("root", "child", LineageKind.FORK, t))
    inputs = LineageTrustInputs(
        direct_scores={"root": 0.9, "child": 0.9},
        integrity_scores={"root": 1.0, "child": 1.0},
    )
    scores = propagate_lineage_trust(g, "root", inputs)
    assert 0.0 <= scores["child"] <= 1.0


def test_transition_escalation_allowed() -> None:
    d = evaluate_transition(TransitionRequest(
        subject_id="p1", from_label=SecurityLabel.TRUSTED,
        to_label=SecurityLabel.SUSPICIOUS, reason="test", verified=False,
    ))
    assert d.outcome is TransitionOutcome.ALLOWED


def test_transition_quarantine_cannot_jump_to_trusted() -> None:
    d = evaluate_transition(TransitionRequest(
        subject_id="p1", from_label=SecurityLabel.QUARANTINED,
        to_label=SecurityLabel.TRUSTED, reason="test", verified=True,
    ))
    assert d.outcome is TransitionOutcome.REJECTED_INVALID


def test_transition_compromise_cannot_recover_directly() -> None:
    d = evaluate_transition(TransitionRequest(
        subject_id="p1", from_label=SecurityLabel.COMPROMISED,
        to_label=SecurityLabel.TRUSTED, reason="test", verified=True,
    ))
    assert d.outcome is TransitionOutcome.REJECTED_INVALID


def test_transition_quarantine_recovery_requires_verification() -> None:
    d = evaluate_transition(TransitionRequest(
        subject_id="p1", from_label=SecurityLabel.QUARANTINED,
        to_label=SecurityLabel.OBSERVED, reason="test", verified=False,
    ))
    assert d.outcome is TransitionOutcome.REQUIRES_VERIFICATION


def test_transition_quarantine_recovery_with_verification() -> None:
    d = evaluate_transition(TransitionRequest(
        subject_id="p1", from_label=SecurityLabel.QUARANTINED,
        to_label=SecurityLabel.OBSERVED, reason="test", verified=True,
    ))
    assert d.outcome is TransitionOutcome.ALLOWED


def test_transition_reason_required() -> None:
    d = evaluate_transition(TransitionRequest(
        subject_id="p", from_label=SecurityLabel.OBSERVED,
        to_label=SecurityLabel.TRUSTED, reason="", verified=True,
    ))
    assert d.outcome is TransitionOutcome.REJECTED_INVALID


def test_derive_compromise_evidence_dominates() -> None:
    at = _t0()
    ev = Evidence(evidence_id="e", source="s", confidence=0.9,
                  observed_at=at, payload={})
    obs = Observation(
        observation_id="o", kind=ObservationKind.PROCESS_EXEC,
        subject=_entity_ref(), observed_at=at,
        payload={"compromise_indicator": True}, evidence=ev,
    )
    label = derive_label(DerivationInputs(
        entity=_entity_ref(),
        trust=_trust_state(at, 0.99, 0.9),
        privilege=_base_priv(),
        configuration=_cfg_empty(),
        lineage=LineageGraph(),
        observations=(obs,),
    ))
    assert label is SecurityLabel.COMPROMISED


def test_derive_degraded_control_high_authority_is_suspicious() -> None:
    at = _t0()
    label = derive_label(DerivationInputs(
        entity=_entity_ref(),
        trust=_trust_state(at, 0.9, 0.8),
        privilege=_base_priv(euid=0, capabilities=frozenset({"CAP_SYS_ADMIN"})),
        configuration=_cfg_degraded(),
        lineage=LineageGraph(),
        observations=(),
    ))
    assert label is SecurityLabel.SUSPICIOUS


def test_derive_degraded_control_low_authority_is_degraded() -> None:
    at = _t0()
    label = derive_label(DerivationInputs(
        entity=_entity_ref(),
        trust=_trust_state(at, 0.9, 0.8),
        privilege=_base_priv(),
        configuration=_cfg_degraded(),
        lineage=LineageGraph(),
        observations=(),
    ))
    assert label is SecurityLabel.DEGRADED


def test_derive_insufficient_confidence_never_trusted() -> None:
    at = _t0()
    label = derive_label(DerivationInputs(
        entity=_entity_ref(),
        trust=_trust_state(at, 0.99, 0.1),
        privilege=_base_priv(),
        configuration=_cfg_empty(),
        lineage=LineageGraph(),
        observations=(),
    ))
    assert label is SecurityLabel.UNKNOWN


def test_exposure_no_path_when_ancestor_trusted() -> None:
    t = _t0()
    g = LineageGraph()
    g.add(LineageEdge("a", "b", LineageKind.FORK, t))
    nodes = {
        "a": ExposureNode(entity=_entity_ref("a"), privilege=_base_priv(),
                          label=SecurityLabel.TRUSTED, trust_score=0.95),
        "b": ExposureNode(entity=_entity_ref("b"),
                          privilege=_base_priv(capabilities=frozenset({"CAP_SYS_ADMIN"})),
                          label=SecurityLabel.TRUSTED, trust_score=0.95),
    }
    assert analyse_exposure(nodes, g) == ()


def test_exposure_path_from_suspicious_ancestor() -> None:
    t = _t0()
    g = LineageGraph()
    g.add(LineageEdge("a", "b", LineageKind.FORK, t))
    nodes = {
        "a": ExposureNode(entity=_entity_ref("a"), privilege=_base_priv(),
                          label=SecurityLabel.SUSPICIOUS, trust_score=0.2),
        "b": ExposureNode(entity=_entity_ref("b"),
                          privilege=_base_priv(capabilities=frozenset({"CAP_SYS_ADMIN"})),
                          label=SecurityLabel.TRUSTED, trust_score=0.95),
    }
    paths = analyse_exposure(nodes, g)
    assert len(paths) == 1
    assert paths[0].steps == ("a", "b")
    assert "CAP_SYS_ADMIN" in paths[0].reachable_capabilities


def _ctrl(cid: str, posture: float, floor: float = 0.8) -> ControlState:
    return ControlState(control_id=cid, posture=posture, floor=floor,
                        observed_at_source="test")


def test_degradation_regression_detected() -> None:
    t = _t0()
    prev = {"c1": _ctrl("c1", 0.9)}
    cur = {"c1": _ctrl("c1", 0.5)}
    findings = detect_degradation(prev, cur, at=t, source="test")
    kinds = {f.kind for f in findings}
    assert DegradationKind.CONTROL_REGRESSED in kinds
    assert DegradationKind.CONTROL_BELOW_FLOOR in kinds


def test_degradation_removed_control_detected() -> None:
    t = _t0()
    prev = {"c1": _ctrl("c1", 0.9)}
    findings = detect_degradation(prev, {}, at=t, source="test")
    assert any(f.kind is DegradationKind.CONTROL_REMOVED for f in findings)


def test_degradation_no_false_positive_on_improvement() -> None:
    t = _t0()
    prev = {"c1": _ctrl("c1", 0.5)}
    cur = {"c1": _ctrl("c1", 0.9)}
    assert detect_degradation(prev, cur, at=t, source="test") == ()


def test_invariant_unauthorized_authority() -> None:
    t = _t0()
    snap = StateSnapshot(
        entities={
            "p1": EntitySnapshot(
                entity_id="p1", label=SecurityLabel.COMPROMISED,
                trust=_trust_state(t, 0.1, 0.9),
                privilege=_base_priv(capabilities=frozenset({"CAP_SYS_ADMIN"}), euid=0),
                parent_id=None,
            )
        },
        configuration=ConfigurationState(controls={}),
    )
    assert any(v.invariant_id == "os.no_unauthorized_authority"
               for v in check_invariants(snap))


def test_invariant_quarantine_trust_cap() -> None:
    t = _t0()
    snap = StateSnapshot(
        entities={
            "p1": EntitySnapshot(
                entity_id="p1", label=SecurityLabel.QUARANTINED,
                trust=_trust_state(t, 0.9, 0.9),
                privilege=_base_priv(),
                parent_id=None,
            )
        },
        configuration=ConfigurationState(controls={}),
    )
    assert any(v.invariant_id == "os.quarantine_trust_cap"
               for v in check_invariants(snap))


def test_invariant_control_floor() -> None:
    snap = StateSnapshot(
        entities={},
        configuration=ConfigurationState(controls={
            "selinux": ControlState(control_id="selinux", posture=0.1,
                                    floor=0.8, observed_at_source="t")
        }),
    )
    assert any(v.invariant_id == "os.critical_control_floor"
               for v in check_invariants(snap))


def test_invariant_high_risk_exposure() -> None:
    path = ExposurePath(
        steps=("a", "b"),
        reachable_capabilities=frozenset({"CAP_SYS_ADMIN"}),
        risk=0.9,
        rationale="test",
    )
    snap = StateSnapshot(entities={},
                         configuration=ConfigurationState(controls={}),
                         exposure_paths=(path,))
    assert any(v.invariant_id == "os.high_risk_exposure"
               for v in check_invariants(snap))


def test_invariant_clean_snapshot_no_violations() -> None:
    t = _t0()
    snap = StateSnapshot(
        entities={
            "p1": EntitySnapshot(
                entity_id="p1", label=SecurityLabel.TRUSTED,
                trust=_trust_state(t, 0.95, 0.9),
                privilege=_base_priv(), parent_id=None,
            )
        },
        configuration=ConfigurationState(controls={
            "selinux": ControlState(control_id="selinux", posture=0.95,
                                    floor=0.8, observed_at_source="t")
        }),
    )
    assert check_invariants(snap) == ()


def test_engine_marks_degraded_control_and_suspicious_root() -> None:
    eng = OsSecurityStateEngine()
    t = _t0()
    eng.observe_privilege(
        _entity_ref("p1"),
        _base_priv(euid=0, capabilities=frozenset({"CAP_SYS_ADMIN"})),
        at=t,
    )
    eng.observe_trust_signal(
        "p1",
        TrustSignal(signal_id="s1", weight=1.0, polarity=-0.8,
                    at=t, evidence=_ev(t)),
    )
    eng.record_control_state(
        ControlState(control_id="selinux", posture=0.2, floor=0.8,
                     observed_at_source="test"),
        at=t,
    )
    records = eng.recompute(at=t)
    p1 = next(r for r in records if r.entity.entity_id == "p1")
    assert p1.label in (SecurityLabel.SUSPICIOUS, SecurityLabel.COMPROMISED)
    assert eng.violations()


def test_engine_no_exposure_when_lineage_trusted() -> None:
    eng = OsSecurityStateEngine()
    t = _t0()
    eng.observe_privilege(_entity_ref("parent"), _base_priv(), at=t)
    eng.observe_privilege(
        _entity_ref("child"),
        _base_priv(capabilities=frozenset({"CAP_SYS_ADMIN"})),
        at=t, parent_id="parent",
    )
    eng.record_lineage(LineageEdge("parent", "child", LineageKind.FORK, t))
    for eid in ("parent", "child"):
        eng.observe_trust_signal(
            eid,
            TrustSignal(signal_id=f"s-{eid}", weight=1.0, polarity=1.0,
                        at=t, evidence=_ev(t)),
        )
    eng.recompute(at=t)
    assert eng.exposure_paths() == ()


def test_engine_store_rejects_stale_write() -> None:
    eng = OsSecurityStateEngine()
    t = _t0()
    eng.observe_privilege(_entity_ref("p1"), _base_priv(), at=t)
    eng.recompute(at=t)
    earlier = t.replace(year=t.year - 1)
    try:
        eng._store.put(EntityStateRecord(
            entity=_entity_ref("p1"),
            label=SecurityLabel.TRUSTED,
            trust_score=0.9,
            trust_confidence=0.9,
            privilege=_base_priv(),
            parent_id=None,
            updated_at=earlier,
        ))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_roundtrip(tmp_path=None) -> None:
    import tempfile
    import os as _os
    if tmp_path is None:
        tmp_path = tempfile.mkdtemp()
    db = _os.path.join(tmp_path, "os_state.db")
    store = SqliteOsStateStore(db)
    t = _t0()
    rec = EntityStateRecord(
        entity=_entity_ref("p1"),
        label=SecurityLabel.TRUSTED,
        trust_score=0.9,
        trust_confidence=0.85,
        privilege=_base_priv(capabilities=frozenset({"CAP_NET_RAW"})),
        parent_id="parent",
        updated_at=t,
    )
    store.put(rec)
    got = store.get("p1")
    assert got is not None
    assert got.label is SecurityLabel.TRUSTED
    assert "CAP_NET_RAW" in got.privilege.capabilities
    assert got.parent_id == "parent"


# =============================================================================
# SECTION 15 — MANUAL RUNNER (no pytest required)
# =============================================================================


def _run_all_tests() -> Tuple[int, int]:
    """Execute all test_* functions defined in this module.

    Returns (passed, failed).
    """
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
