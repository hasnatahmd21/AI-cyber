"""
HYDRA POST-CORE — PHASE 2: NETWORK SECURITY STATE DEPTH
========================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * Network domain (zones, nodes, links, segments, labels)
  * Continuous network trust state
  * Link security posture model
  * Network topology graph (directed links)
  * Reachability with defensive attenuation (trust flow)
  * Attack-path emergence (suspicious source → critical target)
  * Network blast-radius analysis
  * Explicit segmentation state transition rules
  * Machine-checkable network invariants
  * In-memory and SQLite stores
  * Phase-2 engine facade
  * Full test suite + manual runner

This is NEW network-state technology, not a generic NDR/SIEM.

Run tests:
    python hydra_phase2_network_security_state.py
    pytest hydra_phase2_network_security_state.py -q
"""
from __future__ import annotations

import json
import sqlite3
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
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


class ZoneKind(str, Enum):
    PUBLIC = "public"
    DMZ = "dmz"
    INTERNAL = "internal"
    MANAGEMENT = "management"
    DATA = "data"
    OT = "ot"
    GUEST = "guest"
    RESTRICTED = "restricted"


class NodeKind(str, Enum):
    HOST = "host"
    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    LOAD_BALANCER = "load_balancer"
    SERVICE = "service"
    GATEWAY = "gateway"
    VPN_ENDPOINT = "vpn_endpoint"
    SENSOR = "sensor"


class LinkKind(str, Enum):
    PHYSICAL = "physical"
    VIRTUAL = "virtual"
    TUNNEL = "tunnel"
    VPN = "vpn"
    WIRELESS = "wireless"
    OVERLAY = "overlay"


class SegmentEnforcement(str, Enum):
    OPEN = "open"
    RESTRICTED = "restricted"
    ISOLATED = "isolated"


class NetworkLabel(str, Enum):
    UNKNOWN = "unknown"
    OBSERVED = "observed"
    TRUSTED = "trusted"
    DEGRADED = "degraded"
    SUSPICIOUS = "suspicious"
    COMPROMISED = "compromised"
    QUARANTINED = "quarantined"


_NET_SEVERITY: Mapping[NetworkLabel, int] = {
    NetworkLabel.UNKNOWN: 0,
    NetworkLabel.OBSERVED: 1,
    NetworkLabel.TRUSTED: 1,
    NetworkLabel.DEGRADED: 2,
    NetworkLabel.SUSPICIOUS: 3,
    NetworkLabel.COMPROMISED: 4,
    NetworkLabel.QUARANTINED: 5,
}


def net_severity(label: NetworkLabel) -> int:
    return _NET_SEVERITY[label]


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
class Zone:
    zone_id: str
    kind: ZoneKind
    trust_ceiling: float

    def __post_init__(self) -> None:
        if not self.zone_id:
            raise ValueError("zone_id is required")
        if not 0.0 <= self.trust_ceiling <= 1.0:
            raise ValueError("trust_ceiling must be within [0,1]")


@dataclass(frozen=True)
class NetworkNode:
    node_id: str
    kind: NodeKind
    zone_id: str
    criticality: float
    os_entity_id: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.node_id:
            raise ValueError("node_id is required")
        if not self.zone_id:
            raise ValueError("zone_id is required")
        if not 0.0 <= self.criticality <= 1.0:
            raise ValueError("criticality must be within [0,1]")


@dataclass(frozen=True)
class LinkSecurityState:
    encrypted: bool
    authenticated: bool
    integrity_protected: bool
    monitored: bool
    least_privilege: bool

    def security_posture(self) -> float:
        score = 0.0
        if self.encrypted:
            score += 0.25
        if self.authenticated:
            score += 0.25
        if self.integrity_protected:
            score += 0.2
        if self.monitored:
            score += 0.15
        if self.least_privilege:
            score += 0.15
        return max(0.0, min(1.0, score))


@dataclass(frozen=True)
class NetworkLink:
    link_id: str
    src: str
    dst: str
    kind: LinkKind
    security: LinkSecurityState

    def __post_init__(self) -> None:
        if not self.link_id:
            raise ValueError("link_id is required")
        if not self.src or not self.dst:
            raise ValueError("src and dst are required")
        if self.src == self.dst:
            raise ValueError("self-links are not allowed")


@dataclass(frozen=True)
class NetworkSegment:
    segment_id: str
    zone_id: str
    enforcement: SegmentEnforcement
    members: FrozenSet[str]

    def __post_init__(self) -> None:
        if not self.segment_id:
            raise ValueError("segment_id is required")
        if not self.zone_id:
            raise ValueError("zone_id is required")


# =============================================================================
# SECTION 3 — NETWORK TRUST STATE
# =============================================================================


NET_NEUTRAL_SCORE = 0.5


@dataclass(frozen=True)
class NetworkTrustSignal:
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
class NetworkTrustState:
    score: float
    confidence: float
    basis: Tuple[NetworkTrustSignal, ...]
    updated_at: datetime

    def __post_init__(self) -> None:
        if not 0.0 <= self.score <= 1.0:
            raise ValueError("score must be within [0,1]")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be within [0,1]")
        if self.updated_at.tzinfo is None:
            raise ValueError("updated_at must be timezone-aware")


def net_neutral(at: datetime) -> NetworkTrustState:
    return NetworkTrustState(score=NET_NEUTRAL_SCORE, confidence=0.0,
                             basis=(), updated_at=at)


def combine_network_trust(
    signals: Iterable[NetworkTrustSignal], at: datetime,
) -> NetworkTrustState:
    basis = tuple(sorted(signals, key=lambda s: s.at))
    if not basis:
        return net_neutral(at)
    num = 0.0
    den = 0.0
    for s in basis:
        num += s.weight * s.polarity
        den += s.weight
    if den <= 0.0:
        return net_neutral(at)
    raw = num / den
    score = max(0.0, min(1.0, (raw + 1.0) / 2.0))
    confidence = den / (den + 2.0)
    return NetworkTrustState(score=score, confidence=confidence,
                             basis=basis, updated_at=at)


def decay_network_trust(
    state: NetworkTrustState, *, half_life_seconds: float, at: datetime,
) -> NetworkTrustState:
    if half_life_seconds <= 0:
        raise ValueError("half_life_seconds must be > 0")
    age = (at - state.updated_at).total_seconds()
    if age <= 0:
        return state
    factor = 0.5 ** (age / half_life_seconds)
    score = NET_NEUTRAL_SCORE + (state.score - NET_NEUTRAL_SCORE) * factor
    return NetworkTrustState(score=score,
                             confidence=state.confidence * factor,
                             basis=state.basis, updated_at=at)


# =============================================================================
# SECTION 4 — TOPOLOGY
# =============================================================================


class NetworkTopology:
    """Directed network graph with zones and segments."""

    def __init__(self) -> None:
        self._zones: Dict[str, Zone] = {}
        self._nodes: Dict[str, NetworkNode] = {}
        self._links: Dict[str, NetworkLink] = {}
        self._out_links: Dict[str, List[NetworkLink]] = {}
        self._segments: Dict[str, NetworkSegment] = {}
        self._node_segment: Dict[str, str] = {}

    # ---- zones ----------------------------------------------------------

    def add_zone(self, zone: Zone) -> None:
        if zone.zone_id in self._zones:
            raise ValueError(f"zone {zone.zone_id} already exists")
        self._zones[zone.zone_id] = zone

    def zone(self, zone_id: str) -> Zone:
        z = self._zones.get(zone_id)
        if z is None:
            raise KeyError(f"unknown zone {zone_id}")
        return z

    def zones(self) -> Tuple[Zone, ...]:
        return tuple(self._zones.values())

    # ---- nodes ----------------------------------------------------------

    def add_node(self, node: NetworkNode) -> None:
        if node.node_id in self._nodes:
            raise ValueError(f"node {node.node_id} already exists")
        if node.zone_id not in self._zones:
            raise ValueError(f"node {node.node_id} references unknown zone {node.zone_id}")
        self._nodes[node.node_id] = node

    def node(self, node_id: str) -> NetworkNode:
        n = self._nodes.get(node_id)
        if n is None:
            raise KeyError(f"unknown node {node_id}")
        return n

    def nodes(self) -> Tuple[NetworkNode, ...]:
        return tuple(self._nodes.values())

    # ---- links ----------------------------------------------------------

    def add_link(self, link: NetworkLink) -> None:
        if link.link_id in self._links:
            raise ValueError(f"link {link.link_id} already exists")
        if link.src not in self._nodes:
            raise ValueError(f"link {link.link_id} src {link.src} not in topology")
        if link.dst not in self._nodes:
            raise ValueError(f"link {link.link_id} dst {link.dst} not in topology")
        self._links[link.link_id] = link
        self._out_links.setdefault(link.src, []).append(link)

    def link(self, link_id: str) -> NetworkLink:
        l = self._links.get(link_id)
        if l is None:
            raise KeyError(f"unknown link {link_id}")
        return l

    def links(self) -> Tuple[NetworkLink, ...]:
        return tuple(self._links.values())

    def out_links(self, node_id: str) -> Tuple[NetworkLink, ...]:
        return tuple(self._out_links.get(node_id, []))

    # ---- segments -------------------------------------------------------

    def add_segment(self, segment: NetworkSegment) -> None:
        if segment.segment_id in self._segments:
            raise ValueError(f"segment {segment.segment_id} already exists")
        if segment.zone_id not in self._zones:
            raise ValueError(
                f"segment {segment.segment_id} references unknown zone "
                f"{segment.zone_id}"
            )
        for member in segment.members:
            if member not in self._nodes:
                raise ValueError(
                    f"segment {segment.segment_id} member {member} not in topology"
                )
            if self._nodes[member].zone_id != segment.zone_id:
                raise ValueError(
                    f"segment {segment.segment_id} member {member} is in zone "
                    f"{self._nodes[member].zone_id}, not {segment.zone_id}"
                )
        self._segments[segment.segment_id] = segment
        for member in segment.members:
            self._node_segment[member] = segment.segment_id

    def segment(self, segment_id: str) -> NetworkSegment:
        s = self._segments.get(segment_id)
        if s is None:
            raise KeyError(f"unknown segment {segment_id}")
        return s

    def segments(self) -> Tuple[NetworkSegment, ...]:
        return tuple(self._segments.values())

    def segment_of(self, node_id: str) -> Optional[NetworkSegment]:
        sid = self._node_segment.get(node_id)
        if sid is None:
            return None
        return self._segments[sid]

    # ---- queries --------------------------------------------------------

    def neighbors(self, node_id: str) -> Tuple[str, ...]:
        return tuple(l.dst for l in self._out_links.get(node_id, []))


# =============================================================================
# SECTION 5 — REACHABILITY (defensive attenuation / trust flow)
# =============================================================================


@dataclass(frozen=True)
class ReachabilityStep:
    """A single link traversal with its attenuation factor."""
    link_id: str
    from_node: str
    to_node: str
    attenuation: float       # ∈ [0,1]; higher = attacker more attenuated
    posture: float           # ∈ [0,1]; link.security_posture()

    def __post_init__(self) -> None:
        if not 0.0 <= self.attenuation <= 1.0:
            raise ValueError("attenuation must be within [0,1]")
        if not 0.0 <= self.posture <= 1.0:
            raise ValueError("posture must be within [0,1]")


@dataclass(frozen=True)
class ReachabilityRecord:
    node_id: str
    reach_weight: float          # ∈ [0,1]; attacker's reach at node
    path: Tuple[str, ...]        # node sequence
    steps: Tuple[ReachabilityStep, ...]
    weakest_posture: float

    def __post_init__(self) -> None:
        if not 0.0 <= self.reach_weight <= 1.0:
            raise ValueError("reach_weight must be within [0,1]")
        if not 0.0 <= self.weakest_posture <= 1.0:
            raise ValueError("weakest_posture must be within [0,1]")


# Zone-boundary attenuations. Crossing into a more restricted zone is
# harder for an attacker, so attenuation is higher.
_ZONE_CROSS_ATTENUATION: float = 0.15
# Additional attenuation applied when the destination lies in a zone
# whose trust_ceiling is lower than the source zone's ceiling.
_RESTRICTION_ATTENUATION: float = 0.1


def _link_attenuation(
    topology: NetworkTopology,
    link: NetworkLink,
) -> float:
    """How much an attacker is attenuated traversing `link`.

    attenuation ∈ [0,1]:
        0 → completely unobstructed (posture 0, no zone penalty)
        1 → fully blocked
    """
    posture = link.security.security_posture()
    src_zone = topology.zone(topology.node(link.src).zone_id)
    dst_zone = topology.zone(topology.node(link.dst).zone_id)

    attenuation = posture
    if src_zone.zone_id != dst_zone.zone_id:
        attenuation += _ZONE_CROSS_ATTENUATION
        if dst_zone.trust_ceiling < src_zone.trust_ceiling:
            attenuation += _RESTRICTION_ATTENUATION
    # Least-privilege links also block egress anomalies.
    if link.security.least_privilege:
        attenuation += 0.05
    return max(0.0, min(1.0, attenuation))


def _traversal_factor(attenuation: float) -> float:
    """Convert attenuation into a multiplicative factor on reach-weight.

    factor ∈ [0,1]:
        1 → attacker passes through unchanged
        0 → attacker fully blocked
    """
    return max(0.0, min(1.0, 1.0 - attenuation))


def compute_reachability(
    topology: NetworkTopology,
    source: str,
    *,
    max_depth: int = 8,
    min_weight: float = 0.05,
) -> Tuple[ReachabilityRecord, ...]:
    """Compute attacker reachability from `source` across the topology.

    Uses best-weight-first BFS. A node is recorded once with its best
    (highest) reach weight, and never revisited with a weaker weight.
    """
    if max_depth < 0:
        raise ValueError("max_depth must be >= 0")
    if not 0.0 <= min_weight <= 1.0:
        raise ValueError("min_weight must be within [0,1]")
    if source not in (n.node_id for n in topology.nodes()):
        raise KeyError(f"unknown source node {source}")

    best: Dict[str, ReachabilityRecord] = {
        source: ReachabilityRecord(
            node_id=source,
            reach_weight=1.0,
            path=(source,),
            steps=(),
            weakest_posture=1.0,
        )
    }

    # Priority queue modeled with a list (small graphs; deterministic).
    frontier: List[Tuple[str, float, Tuple[str, ...], Tuple[ReachabilityStep, ...], float]] = [
        (source, 1.0, (source,), (), 1.0)
    ]

    while frontier:
        # Pop highest-weight entry (best-first).
        frontier.sort(key=lambda x: x[1], reverse=True)
        node_id, weight, path, steps, weakest = frontier.pop(0)

        if len(path) - 1 >= max_depth:
            continue

        for link in topology.out_links(node_id):
            att = _link_attenuation(topology, link)
            factor = _traversal_factor(att)
            new_weight = weight * factor
            if new_weight < min_weight:
                continue

            new_weakest = min(weakest, link.security.security_posture())
            new_steps = steps + (ReachabilityStep(
                link_id=link.link_id,
                from_node=link.src,
                to_node=link.dst,
                attenuation=att,
                posture=link.security.security_posture(),
            ),)
            new_path = path + (link.dst,)

            existing = best.get(link.dst)
            if existing is not None and existing.reach_weight >= new_weight:
                continue

            rec = ReachabilityRecord(
                node_id=link.dst,
                reach_weight=new_weight,
                path=new_path,
                steps=new_steps,
                weakest_posture=new_weakest,
            )
            best[link.dst] = rec
            frontier.append((link.dst, new_weight, new_path, new_steps, new_weakest))

    # Drop the source itself from the result set.
    return tuple(r for r in best.values() if r.node_id != source)


# =============================================================================
# SECTION 6 — ATTACK-PATH EMERGENCE
# =============================================================================


ATTACK_SOURCE_LABELS: FrozenSet[NetworkLabel] = frozenset({
    NetworkLabel.SUSPICIOUS,
    NetworkLabel.COMPROMISED,
    NetworkLabel.QUARANTINED,
})


@dataclass(frozen=True)
class AttackPath:
    source: str
    target: str
    steps: Tuple[str, ...]
    links: Tuple[str, ...]
    reach_weight: float
    target_criticality: float
    risk: float
    rationale: str

    def __post_init__(self) -> None:
        if not self.steps:
            raise ValueError("steps required")
        if not 0.0 <= self.risk <= 1.0:
            raise ValueError("risk must be within [0,1]")


def find_attack_paths(
    topology: NetworkTopology,
    source_labels: Mapping[str, NetworkLabel],
    *,
    min_reach_weight: float = 0.25,
    min_target_criticality: float = 0.5,
    max_depth: int = 8,
) -> Tuple[AttackPath, ...]:
    """Find paths from suspicious/compromised sources to critical targets."""
    sources = [
        nid for nid, label in source_labels.items()
        if label in ATTACK_SOURCE_LABELS and nid in {n.node_id for n in topology.nodes()}
    ]

    paths: List[AttackPath] = []
    for src in sources:
        reach = compute_reachability(topology, src, max_depth=max_depth)
        for rec in reach:
            target_node = topology.node(rec.node_id)
            if target_node.criticality < min_target_criticality:
                continue
            if rec.reach_weight < min_reach_weight:
                continue
            risk = max(0.0, min(1.0, rec.reach_weight * target_node.criticality))
            rationale = (
                f"{source_labels[src].value} source {src} reaches "
                f"critical target {rec.node_id} (crit={target_node.criticality:.2f}) "
                f"with reach weight {rec.reach_weight:.2f}"
            )
            paths.append(AttackPath(
                source=src,
                target=rec.node_id,
                steps=rec.path,
                links=tuple(s.link_id for s in rec.steps),
                reach_weight=rec.reach_weight,
                target_criticality=target_node.criticality,
                risk=risk,
                rationale=rationale,
            ))

    return tuple(sorted(paths, key=lambda p: p.risk, reverse=True))


# =============================================================================
# SECTION 7 — BLAST RADIUS
# =============================================================================


@dataclass(frozen=True)
class BlastRadius:
    origin: str
    reachable_nodes: FrozenSet[str]
    reachable_critical: FrozenSet[str]
    reachable_zones: FrozenSet[str]
    max_criticality: float
    risk: float
    rationale: str

    def __post_init__(self) -> None:
        if not 0.0 <= self.risk <= 1.0:
            raise ValueError("risk must be within [0,1]")
        if not 0.0 <= self.max_criticality <= 1.0:
            raise ValueError("max_criticality must be within [0,1]")


def compute_blast_radius(
    topology: NetworkTopology,
    origin: str,
    *,
    min_reach_weight: float = 0.2,
    critical_threshold: float = 0.7,
    max_depth: int = 8,
) -> BlastRadius:
    reach = compute_reachability(topology, origin, max_depth=max_depth,
                                 min_weight=min_reach_weight)
    reachable = {r.node_id for r in reach}
    reachable_zones = {
        topology.node(nid).zone_id for nid in reachable
    }
    crit = {
        r.node_id for r in reach
        if topology.node(r.node_id).criticality >= critical_threshold
    }
    max_crit = max(
        (topology.node(nid).criticality for nid in reachable),
        default=0.0,
    )
    # Risk scales with breadth and depth of critical reach.
    breadth = min(1.0, len(reachable) / 10.0)
    risk = max(0.0, min(1.0, 0.5 * max_crit + 0.4 * breadth +
                           0.1 * min(1.0, len(crit) / 3.0)))
    rationale = (
        f"origin {origin} reaches {len(reachable)} node(s) across "
        f"{len(reachable_zones)} zone(s); {len(crit)} critical node(s)"
    )
    return BlastRadius(
        origin=origin,
        reachable_nodes=frozenset(reachable),
        reachable_critical=frozenset(crit),
        reachable_zones=frozenset(reachable_zones),
        max_criticality=max_crit,
        risk=risk,
        rationale=rationale,
    )


# =============================================================================
# SECTION 8 — SEGMENTATION TRANSITIONS
# =============================================================================


class TransitionOutcome(str, Enum):
    ALLOWED = "allowed"
    REJECTED_INVALID = "rejected_invalid"
    REQUIRES_VERIFICATION = "requires_verification"


_SEGMENT_ALLOWED: Mapping[SegmentEnforcement, FrozenSet[SegmentEnforcement]] = {
    SegmentEnforcement.OPEN: frozenset({
        SegmentEnforcement.RESTRICTED,
        SegmentEnforcement.ISOLATED,
    }),
    SegmentEnforcement.RESTRICTED: frozenset({
        SegmentEnforcement.OPEN,
        SegmentEnforcement.ISOLATED,
    }),
    SegmentEnforcement.ISOLATED: frozenset({
        SegmentEnforcement.RESTRICTED,
    }),
}


@dataclass(frozen=True)
class SegmentTransitionRequest:
    segment_id: str
    from_state: SegmentEnforcement
    to_state: SegmentEnforcement
    reason: str
    verified: bool


@dataclass(frozen=True)
class SegmentTransitionDecision:
    outcome: TransitionOutcome
    rationale: str


def evaluate_segment_transition(
    req: SegmentTransitionRequest,
) -> SegmentTransitionDecision:
    if not req.reason:
        return SegmentTransitionDecision(
            TransitionOutcome.REJECTED_INVALID, "reason is required"
        )
    if req.from_state is req.to_state:
        return SegmentTransitionDecision(TransitionOutcome.ALLOWED, "no-op")

    permitted = _SEGMENT_ALLOWED.get(req.from_state, frozenset())
    if req.to_state not in permitted:
        return SegmentTransitionDecision(
            TransitionOutcome.REJECTED_INVALID,
            f"segment {req.from_state.value} -> {req.to_state.value} not permitted",
        )

    # Loosening enforcement requires verification.
    loosen_order = {
        SegmentEnforcement.ISOLATED: 2,
        SegmentEnforcement.RESTRICTED: 1,
        SegmentEnforcement.OPEN: 0,
    }
    loosening = loosen_order[req.to_state] < loosen_order[req.from_state]
    if loosening and not req.verified:
        return SegmentTransitionDecision(
            TransitionOutcome.REQUIRES_VERIFICATION,
            "loosening segmentation requires verification",
        )
    return SegmentTransitionDecision(TransitionOutcome.ALLOWED, "permitted")


# =============================================================================
# SECTION 9 — NETWORK INVARIANTS
# =============================================================================


class InvariantSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class NodeSnapshot:
    node_id: str
    label: NetworkLabel
    trust: NetworkTrustState
    zone_id: str


@dataclass(frozen=True)
class SegmentSnapshot:
    segment_id: str
    enforcement: SegmentEnforcement
    zone_id: str


@dataclass(frozen=True)
class NetworkStateSnapshot:
    topology: NetworkTopology
    nodes: Mapping[str, NodeSnapshot]
    segments: Mapping[str, SegmentSnapshot]
    attack_paths: Tuple[AttackPath, ...] = ()
    blast_radii: Tuple[BlastRadius, ...] = ()


@dataclass(frozen=True)
class NetworkInvariantViolation:
    invariant_id: str
    severity: InvariantSeverity
    subject_id: str
    detail: str


@dataclass(frozen=True)
class NetworkInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[NetworkStateSnapshot], Tuple[NetworkInvariantViolation, ...]]
    description: str


def _inv_no_public_to_data_path(
    snap: NetworkStateSnapshot,
) -> Tuple[NetworkInvariantViolation, ...]:
    out: List[NetworkInvariantViolation] = []
    for ap in snap.attack_paths:
        try:
            src_zone = snap.topology.zone(snap.topology.node(ap.source).zone_id)
            dst_zone = snap.topology.zone(snap.topology.node(ap.target).zone_id)
        except KeyError:
            continue
        if src_zone.kind is ZoneKind.PUBLIC and dst_zone.kind in (
            ZoneKind.DATA, ZoneKind.RESTRICTED, ZoneKind.MANAGEMENT
        ):
            out.append(NetworkInvariantViolation(
                invariant_id="net.no_public_to_protected_path",
                severity=InvariantSeverity.CRITICAL,
                subject_id=ap.source,
                detail=(
                    f"public source {ap.source} has live path to "
                    f"{dst_zone.kind.value} zone node {ap.target}"
                ),
            ))
    return tuple(out)


def _inv_isolated_segments_airgapped(
    snap: NetworkStateSnapshot,
) -> Tuple[NetworkInvariantViolation, ...]:
    out: List[NetworkInvariantViolation] = []
    isolated = {
        s.segment_id for s in snap.segments.values()
        if s.enforcement is SegmentEnforcement.ISOLATED
    }
    if not isolated:
        return ()
    for link in snap.topology.links():
        src_seg = snap.topology.segment_of(link.src)
        dst_seg = snap.topology.segment_of(link.dst)
        if src_seg is None and dst_seg is None:
            continue
        if (src_seg is not None and src_seg.segment_id in isolated and
                (dst_seg is None or dst_seg.segment_id not in isolated)):
            out.append(NetworkInvariantViolation(
                invariant_id="net.isolated_segment_airgapped",
                severity=InvariantSeverity.CRITICAL,
                subject_id=src_seg.segment_id,
                detail=f"isolated segment {src_seg.segment_id} has egress "
                       f"link {link.link_id}",
            ))
        if (dst_seg is not None and dst_seg.segment_id in isolated and
                (src_seg is None or src_seg.segment_id not in isolated)):
            out.append(NetworkInvariantViolation(
                invariant_id="net.isolated_segment_airgapped",
                severity=InvariantSeverity.CRITICAL,
                subject_id=dst_seg.segment_id,
                detail=f"isolated segment {dst_seg.segment_id} has ingress "
                       f"link {link.link_id}",
            ))
    return tuple(out)


def _inv_zone_trust_ceiling(
    snap: NetworkStateSnapshot,
) -> Tuple[NetworkInvariantViolation, ...]:
    out: List[NetworkInvariantViolation] = []
    for nid, n in snap.nodes.items():
        try:
            z = snap.topology.zone(n.zone_id)
        except KeyError:
            continue
        if n.trust.score > z.trust_ceiling + 1e-9:
            out.append(NetworkInvariantViolation(
                invariant_id="net.zone_trust_ceiling",
                severity=InvariantSeverity.HIGH,
                subject_id=nid,
                detail=(
                    f"node {nid} trust {n.trust.score:.2f} exceeds "
                    f"zone {z.zone_id} ceiling {z.trust_ceiling:.2f}"
                ),
            ))
    return tuple(out)


def _inv_no_high_risk_attack_path(
    snap: NetworkStateSnapshot,
) -> Tuple[NetworkInvariantViolation, ...]:
    out: List[NetworkInvariantViolation] = []
    for ap in snap.attack_paths:
        if ap.risk >= 0.8:
            out.append(NetworkInvariantViolation(
                invariant_id="net.no_high_risk_attack_path",
                severity=InvariantSeverity.CRITICAL,
                subject_id=ap.source,
                detail=ap.rationale,
            ))
    return tuple(out)


DEFAULT_NETWORK_INVARIANTS: Tuple[NetworkInvariant, ...] = (
    NetworkInvariant(
        invariant_id="net.no_public_to_protected_path",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_no_public_to_data_path,
        description="Public sources must not have live paths to protected zones.",
    ),
    NetworkInvariant(
        invariant_id="net.isolated_segment_airgapped",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_isolated_segments_airgapped,
        description="Isolated segments must have no links crossing their boundary.",
    ),
    NetworkInvariant(
        invariant_id="net.zone_trust_ceiling",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_zone_trust_ceiling,
        description="Node trust must not exceed its zone's trust ceiling.",
    ),
    NetworkInvariant(
        invariant_id="net.no_high_risk_attack_path",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_no_high_risk_attack_path,
        description="No high-risk attack path may exist.",
    ),
)


def check_network_invariants(
    snap: NetworkStateSnapshot,
    invariants: Iterable[NetworkInvariant] = DEFAULT_NETWORK_INVARIANTS,
) -> Tuple[NetworkInvariantViolation, ...]:
    out: List[NetworkInvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 10 — STORE
# =============================================================================


@dataclass(frozen=True)
class NetworkNodeStateRecord:
    node_id: str
    zone_id: str
    label: NetworkLabel
    trust_score: float
    trust_confidence: float
    updated_at: datetime


class NetworkStateStore(Protocol):
    def get(self, node_id: str) -> Optional[NetworkNodeStateRecord]: ...
    def put(self, record: NetworkNodeStateRecord) -> None: ...
    def all(self) -> Tuple[NetworkNodeStateRecord, ...]: ...


class InMemoryNetworkStore:
    def __init__(self) -> None:
        self._data: Dict[str, NetworkNodeStateRecord] = {}

    def get(self, node_id: str) -> Optional[NetworkNodeStateRecord]:
        return self._data.get(node_id)

    def put(self, record: NetworkNodeStateRecord) -> None:
        existing = self._data.get(record.node_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._data[record.node_id] = record

    def all(self) -> Tuple[NetworkNodeStateRecord, ...]:
        return tuple(self._data.values())


class SqliteNetworkStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS net_node_state (
                node_id TEXT PRIMARY KEY,
                zone_id TEXT NOT NULL,
                label TEXT NOT NULL,
                trust_score REAL NOT NULL,
                trust_confidence REAL NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def get(self, node_id: str) -> Optional[NetworkNodeStateRecord]:
        row = self._conn.execute(
            "SELECT zone_id, label, trust_score, trust_confidence, updated_at "
            "FROM net_node_state WHERE node_id = ?",
            (node_id,),
        ).fetchone()
        if row is None:
            return None
        return NetworkNodeStateRecord(
            node_id=node_id,
            zone_id=row[0],
            label=NetworkLabel(row[1]),
            trust_score=float(row[2]),
            trust_confidence=float(row[3]),
            updated_at=datetime.fromisoformat(row[4]),
        )

    def put(self, record: NetworkNodeStateRecord) -> None:
        existing = self.get(record.node_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._conn.execute(
            """
            INSERT INTO net_node_state
              (node_id, zone_id, label, trust_score, trust_confidence, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(node_id) DO UPDATE SET
              zone_id=excluded.zone_id,
              label=excluded.label,
              trust_score=excluded.trust_score,
              trust_confidence=excluded.trust_confidence,
              updated_at=excluded.updated_at
            """,
            (record.node_id, record.zone_id, record.label.value,
             record.trust_score, record.trust_confidence,
             record.updated_at.isoformat()),
        )
        self._conn.commit()

    def all(self) -> Tuple[NetworkNodeStateRecord, ...]:
        rows = self._conn.execute(
            "SELECT node_id, zone_id, label, trust_score, trust_confidence, "
            "updated_at FROM net_node_state"
        ).fetchall()
        return tuple(
            NetworkNodeStateRecord(
                node_id=r[0], zone_id=r[1], label=NetworkLabel(r[2]),
                trust_score=float(r[3]), trust_confidence=float(r[4]),
                updated_at=datetime.fromisoformat(r[5]),
            )
            for r in rows
        )


# =============================================================================
# SECTION 11 — ENGINE
# =============================================================================


def _derive_network_label(trust: NetworkTrustState) -> NetworkLabel:
    if trust.confidence < 0.4:
        return NetworkLabel.UNKNOWN
    if trust.score < 0.30:
        return NetworkLabel.SUSPICIOUS
    if trust.score < 0.55:
        return NetworkLabel.DEGRADED
    if trust.score < 0.85:
        return NetworkLabel.OBSERVED
    return NetworkLabel.TRUSTED


class NetworkSecurityStateEngine:
    """Models network security state: reachability, attack paths,
    blast radii, and network invariants."""

    def __init__(self, *, store: Optional[NetworkStateStore] = None) -> None:
        self._topology = NetworkTopology()
        self._store: NetworkStateStore = store or InMemoryNetworkStore()
        self._signals: Dict[str, List[NetworkTrustSignal]] = {}
        self._labels: Dict[str, NetworkLabel] = {}
        self._attack_paths: Tuple[AttackPath, ...] = ()
        self._blast_radii: Tuple[BlastRadius, ...] = ()
        self._violations: Tuple[NetworkInvariantViolation, ...] = ()

    # ---- topology ingestion ---------------------------------------------

    def add_zone(self, zone: Zone) -> None:
        self._topology.add_zone(zone)

    def add_node(self, node: NetworkNode) -> None:
        self._topology.add_node(node)

    def add_link(self, link: NetworkLink) -> None:
        self._topology.add_link(link)

    def add_segment(self, segment: NetworkSegment) -> None:
        self._topology.add_segment(segment)

    def topology(self) -> NetworkTopology:
        return self._topology

    # ---- trust signals ---------------------------------------------------

    def observe_signal(self, node_id: str, signal: NetworkTrustSignal) -> None:
        if signal.at.tzinfo is None:
            raise ValueError("signal.at must be timezone-aware")
        self._signals.setdefault(node_id, []).append(signal)

    # ---- recompute -------------------------------------------------------

    def recompute(self, *, at: datetime) -> Tuple[NetworkNodeStateRecord, ...]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

        records: List[NetworkNodeStateRecord] = []

        # 1. Derive trust per node.
        for node in self._topology.nodes():
            trust = combine_network_trust(self._signals.get(node.node_id, []), at)
            label = _derive_network_label(trust)
            self._labels[node.node_id] = label
            rec = NetworkNodeStateRecord(
                node_id=node.node_id,
                zone_id=node.zone_id,
                label=label,
                trust_score=trust.score,
                trust_confidence=trust.confidence,
                updated_at=at,
            )
            self._store.put(rec)
            records.append(rec)

        # 2. Attack-path emergence.
        self._attack_paths = find_attack_paths(self._topology, self._labels)

        # 3. Blast radius from each suspicious/compromised source.
        radii: List[BlastRadius] = []
        for nid, label in self._labels.items():
            if label in ATTACK_SOURCE_LABELS:
                radii.append(compute_blast_radius(self._topology, nid))
        self._blast_radii = tuple(sorted(radii, key=lambda b: b.risk, reverse=True))

        # 4. Invariants.
        node_snapshots: Dict[str, NodeSnapshot] = {}
        for rec in records:
            node_snapshots[rec.node_id] = NodeSnapshot(
                node_id=rec.node_id,
                label=rec.label,
                trust=NetworkTrustState(
                    score=rec.trust_score,
                    confidence=rec.trust_confidence,
                    basis=(),
                    updated_at=at,
                ),
                zone_id=rec.zone_id,
            )
        segment_snapshots: Dict[str, SegmentSnapshot] = {
            s.segment_id: SegmentSnapshot(
                segment_id=s.segment_id,
                enforcement=s.enforcement,
                zone_id=s.zone_id,
            )
            for s in self._topology.segments()
        }
        snapshot = NetworkStateSnapshot(
            topology=self._topology,
            nodes=node_snapshots,
            segments=segment_snapshots,
            attack_paths=self._attack_paths,
            blast_radii=self._blast_radii,
        )
        self._violations = check_network_invariants(snapshot)

        return tuple(records)

    # ---- queries ---------------------------------------------------------

    def current_state(self, node_id: str) -> Optional[NetworkNodeStateRecord]:
        return self._store.get(node_id)

    def attack_paths(self) -> Tuple[AttackPath, ...]:
        return self._attack_paths

    def blast_radii(self) -> Tuple[BlastRadius, ...]:
        return self._blast_radii

    def violations(self) -> Tuple[NetworkInvariantViolation, ...]:
        return self._violations

    def reachability_from(self, source: str) -> Tuple[ReachabilityRecord, ...]:
        return compute_reachability(self._topology, source)


# =============================================================================
# SECTION 12 — TESTS
# =============================================================================


def _t0() -> datetime:
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _ev(at: datetime, conf: float = 0.9) -> Evidence:
    return Evidence(evidence_id="e", source="test", confidence=conf,
                    observed_at=at, payload={})


def _strong_link(link_id: str, src: str, dst: str, kind: LinkKind = LinkKind.PHYSICAL) -> NetworkLink:
    return NetworkLink(
        link_id=link_id, src=src, dst=dst, kind=kind,
        security=LinkSecurityState(
            encrypted=True, authenticated=True, integrity_protected=True,
            monitored=True, least_privilege=True,
        ),
    )


def _weak_link(link_id: str, src: str, dst: str, kind: LinkKind = LinkKind.PHYSICAL) -> NetworkLink:
    return NetworkLink(
        link_id=link_id, src=src, dst=dst, kind=kind,
        security=LinkSecurityState(
            encrypted=False, authenticated=False, integrity_protected=False,
            monitored=False, least_privilege=False,
        ),
    )


def _mid_link(link_id: str, src: str, dst: str, kind: LinkKind = LinkKind.PHYSICAL) -> NetworkLink:
    return NetworkLink(
        link_id=link_id, src=src, dst=dst, kind=kind,
        security=LinkSecurityState(
            encrypted=True, authenticated=False, integrity_protected=True,
            monitored=False, least_privilege=False,
        ),
    )


def _basic_topology() -> NetworkTopology:
    t = NetworkTopology()
    t.add_zone(Zone("z-public", ZoneKind.PUBLIC, trust_ceiling=0.6))
    t.add_zone(Zone("z-dmz", ZoneKind.DMZ, trust_ceiling=0.8))
    t.add_zone(Zone("z-internal", ZoneKind.INTERNAL, trust_ceiling=1.0))
    t.add_zone(Zone("z-data", ZoneKind.DATA, trust_ceiling=1.0))

    t.add_node(NetworkNode("web", NodeKind.HOST, "z-public", criticality=0.3))
    t.add_node(NetworkNode("lb", NodeKind.LOAD_BALANCER, "z-dmz", criticality=0.5))
    t.add_node(NetworkNode("app", NodeKind.SERVICE, "z-internal", criticality=0.7))
    t.add_node(NetworkNode("db", NodeKind.HOST, "z-data", criticality=0.95))
    return t


# ---- domain tests ---------------------------------------------------------

def test_zone_trust_ceiling_bounds() -> None:
    try:
        Zone("z", ZoneKind.PUBLIC, 1.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_node_criticality_bounds() -> None:
    try:
        NetworkNode("n", NodeKind.HOST, "z", 1.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_link_self_rejected() -> None:
    try:
        NetworkLink("l", "a", "a", LinkKind.PHYSICAL,
                    LinkSecurityState(True, True, True, True, True))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_link_security_posture_full() -> None:
    s = LinkSecurityState(True, True, True, True, True)
    assert s.security_posture() == 1.0


def test_link_security_posture_zero() -> None:
    s = LinkSecurityState(False, False, False, False, False)
    assert s.security_posture() == 0.0


def test_net_severity_ordering() -> None:
    assert net_severity(NetworkLabel.TRUSTED) < net_severity(NetworkLabel.DEGRADED)
    assert net_severity(NetworkLabel.DEGRADED) < net_severity(NetworkLabel.SUSPICIOUS)
    assert net_severity(NetworkLabel.SUSPICIOUS) < net_severity(NetworkLabel.COMPROMISED)


# ---- trust tests ----------------------------------------------------------

def test_combine_network_trust_empty_is_neutral() -> None:
    st = combine_network_trust([], _t0())
    assert st.score == NET_NEUTRAL_SCORE
    assert st.confidence == 0.0


def test_combine_network_trust_positive() -> None:
    s = NetworkTrustSignal(signal_id="s", weight=1.0, polarity=1.0,
                           at=_t0(), evidence=_ev(_t0()))
    st = combine_network_trust([s], _t0())
    assert st.score == 1.0


def test_combine_network_trust_negative() -> None:
    s = NetworkTrustSignal(signal_id="s", weight=1.0, polarity=-1.0,
                           at=_t0(), evidence=_ev(_t0()))
    st = combine_network_trust([s], _t0())
    assert st.score == 0.0


def test_decay_network_trust_toward_neutral() -> None:
    s = NetworkTrustSignal(signal_id="s", weight=1.0, polarity=1.0,
                           at=_t0(), evidence=_ev(_t0()))
    st = combine_network_trust([s], _t0())
    later = _t0().replace(minute=10)
    d = decay_network_trust(st, half_life_seconds=60.0, at=later)
    assert d.score < st.score
    assert d.score >= NET_NEUTRAL_SCORE


def test_decay_network_trust_requires_positive_half_life() -> None:
    try:
        decay_network_trust(net_neutral(_t0()), half_life_seconds=0, at=_t0())
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- topology tests -------------------------------------------------------

def test_topology_rejects_duplicate_zone() -> None:
    t = NetworkTopology()
    t.add_zone(Zone("z1", ZoneKind.INTERNAL, 1.0))
    try:
        t.add_zone(Zone("z1", ZoneKind.PUBLIC, 1.0))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_topology_rejects_node_unknown_zone() -> None:
    t = NetworkTopology()
    try:
        t.add_node(NetworkNode("n", NodeKind.HOST, "z-missing", 0.5))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_topology_rejects_link_unknown_node() -> None:
    t = NetworkTopology()
    t.add_zone(Zone("z", ZoneKind.INTERNAL, 1.0))
    t.add_node(NetworkNode("a", NodeKind.HOST, "z", 0.5))
    try:
        t.add_link(_strong_link("l", "a", "b"))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_topology_segment_member_zone_mismatch() -> None:
    t = NetworkTopology()
    t.add_zone(Zone("z1", ZoneKind.INTERNAL, 1.0))
    t.add_zone(Zone("z2", ZoneKind.DATA, 1.0))
    t.add_node(NetworkNode("a", NodeKind.HOST, "z1", 0.5))
    try:
        t.add_segment(NetworkSegment("s1", "z2",
                                     SegmentEnforcement.OPEN, frozenset({"a"})))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_topology_segment_of() -> None:
    t = NetworkTopology()
    t.add_zone(Zone("z", ZoneKind.INTERNAL, 1.0))
    t.add_node(NetworkNode("a", NodeKind.HOST, "z", 0.5))
    t.add_node(NetworkNode("b", NodeKind.HOST, "z", 0.5))
    seg = NetworkSegment("s1", "z", SegmentEnforcement.RESTRICTED,
                         frozenset({"a", "b"}))
    t.add_segment(seg)
    assert t.segment_of("a") is seg
    assert t.segment_of("b") is seg


def test_topology_neighbors() -> None:
    t = _basic_topology()
    t.add_link(_strong_link("l1", "web", "lb"))
    t.add_link(_strong_link("l2", "lb", "app"))
    assert "lb" in t.neighbors("web")
    assert "app" in t.neighbors("lb")


# ---- reachability tests ---------------------------------------------------

def test_reachability_weak_path_full_weight() -> None:
    t = _basic_topology()
    t.add_link(_weak_link("l1", "web", "lb"))
    recs = compute_reachability(t, "web")
    lb_rec = next(r for r in recs if r.node_id == "lb")
    # weak link posture 0, cross-zone penalty → not full 1.0, but present
    assert lb_rec.reach_weight > 0.3
    assert lb_rec.path == ("web", "lb")


def test_reachability_strong_path_blocked() -> None:
    t = _basic_topology()
    t.add_link(_strong_link("l1", "web", "lb"))
    recs = compute_reachability(t, "web", min_weight=0.05)
    lb_rec = next((r for r in recs if r.node_id == "lb"), None)
    # Strong cross-zone link (posture 1 + zone cross + restriction penalty)
    # should attenuate enough to fall below min_weight.
    assert lb_rec is None


def test_reachability_zone_cross_penalty_applied() -> None:
    t = NetworkTopology()
    t.add_zone(Zone("z-public", ZoneKind.PUBLIC, 1.0))
    t.add_zone(Zone("z-data", ZoneKind.DATA, 1.0))
    t.add_node(NetworkNode("a", NodeKind.HOST, "z-public", 0.5))
    t.add_node(NetworkNode("b", NodeKind.HOST, "z-data", 0.5))
    t.add_link(_mid_link("l", "a", "b"))
    recs = compute_reachability(t, "a", min_weight=0.0)
    b_rec = next(r for r in recs if r.node_id == "b")
    # attenuation should include both zone-cross and restriction penalties
    assert b_rec.steps[0].attenuation > 0.15


def test_reachability_unknown_source_raises() -> None:
    t = _basic_topology()
    try:
        compute_reachability(t, "nonexistent")
    except KeyError:
        return
    raise AssertionError("expected KeyError")


# ---- attack path tests ---------------------------------------------------

def test_attack_path_emerges_from_suspicious_source() -> None:
    t = _basic_topology()
    t.add_link(_weak_link("l1", "web", "lb"))
    t.add_link(_weak_link("l2", "lb", "app"))
    t.add_link(_weak_link("l3", "app", "db"))
    labels = {"web": NetworkLabel.SUSPICIOUS}
    paths = find_attack_paths(t, labels)
    targets = {p.target for p in paths}
    assert "db" in targets
    assert all(p.source == "web" for p in paths)


def test_attack_path_absent_when_target_has_low_criticality() -> None:
    t = _basic_topology()
    t.add_link(_weak_link("l1", "web", "lb"))
    labels = {"web": NetworkLabel.SUSPICIOUS}
    paths = find_attack_paths(t, labels, min_target_criticality=0.9)
    assert paths == ()


def test_attack_path_absent_when_source_trusted() -> None:
    t = _basic_topology()
    t.add_link(_weak_link("l1", "web", "lb"))
    t.add_link(_weak_link("l2", "lb", "app"))
    t.add_link(_weak_link("l3", "app", "db"))
    labels = {"web": NetworkLabel.TRUSTED}
    assert find_attack_paths(t, labels) == ()


def test_attack_paths_sorted_by_risk() -> None:
    t = _basic_topology()
    t.add_link(_weak_link("l1", "web", "lb"))
    t.add_link(_weak_link("l2", "lb", "app"))
    t.add_link(_weak_link("l3", "app", "db"))
    labels = {"web": NetworkLabel.COMPROMISED}
    paths = find_attack_paths(t, labels)
    risks = [p.risk for p in paths]
    assert risks == sorted(risks, reverse=True)


# ---- blast radius tests --------------------------------------------------

def test_blast_radius_empty_when_no_outbound_links() -> None:
    t = _basic_topology()
    b = compute_blast_radius(t, "web")
    assert b.reachable_nodes == frozenset()
    assert b.risk == 0.0


def test_blast_radius_reaches_critical_db() -> None:
    t = _basic_topology()
    t.add_link(_weak_link("l1", "web", "lb"))
    t.add_link(_weak_link("l2", "lb", "app"))
    t.add_link(_weak_link("l3", "app", "db"))
    b = compute_blast_radius(t, "web")
    assert "db" in b.reachable_critical
    assert b.max_criticality >= 0.9


def test_blast_radius_risk_scales_with_reach() -> None:
    t = _basic_topology()
    t.add_link(_weak_link("l1", "web", "lb"))
    t.add_link(_weak_link("l2", "lb", "app"))
    t.add_link(_weak_link("l3", "app", "db"))
    wide = compute_blast_radius(t, "web")

    t2 = NetworkTopology()
    t2.add_zone(Zone("z-public", ZoneKind.PUBLIC, 1.0))
    t2.add_node(NetworkNode("web", NodeKind.HOST, "z-public", 0.3))
    narrow = compute_blast_radius(t2, "web")

    assert wide.risk > narrow.risk


# ---- transition tests ----------------------------------------------------

def test_segment_transition_open_to_isolated_allowed() -> None:
    d = evaluate_segment_transition(SegmentTransitionRequest(
        segment_id="s1",
        from_state=SegmentEnforcement.OPEN,
        to_state=SegmentEnforcement.ISOLATED,
        reason="incident",
        verified=False,
    ))
    assert d.outcome is TransitionOutcome.ALLOWED


def test_segment_transition_isolated_to_open_rejected() -> None:
    d = evaluate_segment_transition(SegmentTransitionRequest(
        segment_id="s1",
        from_state=SegmentEnforcement.ISOLATED,
        to_state=SegmentEnforcement.OPEN,
        reason="incident",
        verified=True,
    ))
    assert d.outcome is TransitionOutcome.REJECTED_INVALID


def test_segment_transition_isolated_to_restricted_requires_verification() -> None:
    d = evaluate_segment_transition(SegmentTransitionRequest(
        segment_id="s1",
        from_state=SegmentEnforcement.ISOLATED,
        to_state=SegmentEnforcement.RESTRICTED,
        reason="recovery",
        verified=False,
    ))
    assert d.outcome is TransitionOutcome.REQUIRES_VERIFICATION


def test_segment_transition_isolated_to_restricted_with_verification() -> None:
    d = evaluate_segment_transition(SegmentTransitionRequest(
        segment_id="s1",
        from_state=SegmentEnforcement.ISOLATED,
        to_state=SegmentEnforcement.RESTRICTED,
        reason="recovery",
        verified=True,
    ))
    assert d.outcome is TransitionOutcome.ALLOWED


def test_segment_transition_reason_required() -> None:
    d = evaluate_segment_transition(SegmentTransitionRequest(
        segment_id="s1",
        from_state=SegmentEnforcement.OPEN,
        to_state=SegmentEnforcement.RESTRICTED,
        reason="",
        verified=True,
    ))
    assert d.outcome is TransitionOutcome.REJECTED_INVALID


# ---- invariant tests -----------------------------------------------------

def test_invariant_isolated_segment_airgapped() -> None:
    t = _basic_topology()
    t.add_link(_weak_link("l1", "web", "lb"))
    t.add_segment(NetworkSegment("s-iso", "z-internal",
                                 SegmentEnforcement.ISOLATED,
                                 frozenset({"app"})))
    # link lb -> app crosses into isolated segment
    t.add_link(_weak_link("l2", "lb", "app"))
    snapshot = NetworkStateSnapshot(
        topology=t,
        nodes={
            "web": NodeSnapshot("web", NetworkLabel.TRUSTED,
                                net_neutral(_t0()), "z-public"),
            "lb": NodeSnapshot("lb", NetworkLabel.TRUSTED,
                               net_neutral(_t0()), "z-dmz"),
            "app": NodeSnapshot("app", NetworkLabel.TRUSTED,
                                net_neutral(_t0()), "z-internal"),
            "db": NodeSnapshot("db", NetworkLabel.TRUSTED,
                               net_neutral(_t0()), "z-data"),
        },
        segments={
            "s-iso": SegmentSnapshot("s-iso",
                                     SegmentEnforcement.ISOLATED, "z-internal")
        },
    )
    v = check_network_invariants(snapshot)
    assert any(x.invariant_id == "net.isolated_segment_airgapped" for x in v)


def test_invariant_zone_trust_ceiling_enforced() -> None:
    t = _basic_topology()
    snapshot = NetworkStateSnapshot(
        topology=t,
        nodes={
            "web": NodeSnapshot(
                "web", NetworkLabel.TRUSTED,
                NetworkTrustState(score=0.9, confidence=0.9,
                                  basis=(), updated_at=_t0()),
                "z-public",
            ),
        },
        segments={},
    )
    v = check_network_invariants(snapshot)
    assert any(x.invariant_id == "net.zone_trust_ceiling" for x in v)


def test_invariant_no_high_risk_attack_path() -> None:
    t = _basic_topology()
    ap = AttackPath(
        source="web", target="db",
        steps=("web", "lb", "app", "db"),
        links=("l1", "l2", "l3"),
        reach_weight=0.9, target_criticality=0.95,
        risk=0.9, rationale="test",
    )
    snapshot = NetworkStateSnapshot(
        topology=t, nodes={}, segments={}, attack_paths=(ap,),
    )
    v = check_network_invariants(snapshot)
    assert any(x.invariant_id == "net.no_high_risk_attack_path" for x in v)


def test_invariant_no_public_to_protected_path() -> None:
    t = _basic_topology()
    ap = AttackPath(
        source="web", target="db",
        steps=("web", "lb", "app", "db"),
        links=("l1", "l2", "l3"),
        reach_weight=0.5, target_criticality=0.95,
        risk=0.475, rationale="test",
    )
    snapshot = NetworkStateSnapshot(
        topology=t, nodes={}, segments={}, attack_paths=(ap,),
    )
    v = check_network_invariants(snapshot)
    assert any(x.invariant_id == "net.no_public_to_protected_path" for x in v)


# ---- store tests ---------------------------------------------------------

def test_in_memory_store_rejects_stale_write() -> None:
    s = InMemoryNetworkStore()
    t = _t0()
    s.put(NetworkNodeStateRecord("n", "z", NetworkLabel.TRUSTED, 0.9, 0.9, t))
    earlier = t.replace(year=t.year - 1)
    try:
        s.put(NetworkNodeStateRecord("n", "z", NetworkLabel.UNKNOWN, 0.5, 0.5, earlier))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "net.db")
    store = SqliteNetworkStore(db)
    t = _t0()
    store.put(NetworkNodeStateRecord(
        node_id="web", zone_id="z-public", label=NetworkLabel.SUSPICIOUS,
        trust_score=0.2, trust_confidence=0.9, updated_at=t,
    ))
    got = store.get("web")
    assert got is not None
    assert got.label is NetworkLabel.SUSPICIOUS
    assert got.zone_id == "z-public"


# ---- engine integration tests -------------------------------------------

def test_engine_end_to_end_emerges_attack_paths() -> None:
    eng = NetworkSecurityStateEngine()
    t = _t0()
    eng.add_zone(Zone("z-public", ZoneKind.PUBLIC, 0.7))
    eng.add_zone(Zone("z-dmz", ZoneKind.DMZ, 0.85))
    eng.add_zone(Zone("z-internal", ZoneKind.INTERNAL, 1.0))
    eng.add_zone(Zone("z-data", ZoneKind.DATA, 1.0))
    eng.add_node(NetworkNode("web", NodeKind.HOST, "z-public", 0.3))
    eng.add_node(NetworkNode("lb", NodeKind.LOAD_BALANCER, "z-dmz", 0.5))
    eng.add_node(NetworkNode("app", NodeKind.SERVICE, "z-internal", 0.7))
    eng.add_node(NetworkNode("db", NodeKind.HOST, "z-data", 0.95))
    eng.add_link(_weak_link("l1", "web", "lb"))
    eng.add_link(_weak_link("l2", "lb", "app"))
    eng.add_link(_weak_link("l3", "app", "db"))

    neg = NetworkTrustSignal(signal_id="s1", weight=1.0, polarity=-1.0,
                             at=t, evidence=_ev(t))
    neg2 = NetworkTrustSignal(signal_id="s2", weight=1.0, polarity=-1.0,
                              at=t, evidence=_ev(t))
    eng.observe_signal("web", neg)
    eng.observe_signal("web", neg2)
    records = eng.recompute(at=t)
    web_rec = next(r for r in records if r.node_id == "web")
    assert web_rec.label is NetworkLabel.SUSPICIOUS
    paths = eng.attack_paths()
    assert any(p.target == "db" for p in paths)


def test_engine_blast_radius_from_suspicious() -> None:
    eng = NetworkSecurityStateEngine()
    t = _t0()
    eng.add_zone(Zone("z1", ZoneKind.PUBLIC, 1.0))
    eng.add_zone(Zone("z2", ZoneKind.DATA, 1.0))
    eng.add_node(NetworkNode("a", NodeKind.HOST, "z1", 0.3))
    eng.add_node(NetworkNode("b", NodeKind.HOST, "z2", 0.9))
    eng.add_link(_weak_link("l", "a", "b"))
    eng.observe_signal("a", NetworkTrustSignal(
        signal_id="s1", weight=1.0, polarity=-1.0, at=t, evidence=_ev(t),
    ))
    eng.observe_signal("a", NetworkTrustSignal(
        signal_id="s2", weight=1.0, polarity=-1.0, at=t, evidence=_ev(t),
    ))
    eng.recompute(at=t)
    radii = eng.blast_radii()
    assert any("b" in r.reachable_critical for r in radii)


def test_engine_invariants_fire_on_isolated_ingress() -> None:
    eng = NetworkSecurityStateEngine()
    t = _t0()
    eng.add_zone(Zone("z1", ZoneKind.DMZ, 1.0))
    eng.add_zone(Zone("z2", ZoneKind.INTERNAL, 1.0))
    eng.add_node(NetworkNode("a", NodeKind.HOST, "z1", 0.3))
    eng.add_node(NetworkNode("b", NodeKind.HOST, "z2", 0.7))
    eng.add_link(_weak_link("l", "a", "b"))
    eng.add_segment(NetworkSegment("s-iso", "z2",
                                   SegmentEnforcement.ISOLATED,
                                   frozenset({"b"})))
    eng.recompute(at=t)
    assert any(v.invariant_id == "net.isolated_segment_airgapped"
               for v in eng.violations())


def test_engine_trust_ceiling_violation_fires() -> None:
    eng = NetworkSecurityStateEngine()
    t = _t0()
    eng.add_zone(Zone("z-pub", ZoneKind.PUBLIC, trust_ceiling=0.6))
    eng.add_node(NetworkNode("web", NodeKind.HOST, "z-pub", 0.3))
    pos = NetworkTrustSignal(signal_id="s", weight=1.0, polarity=1.0,
                             at=t, evidence=_ev(t))
    eng.observe_signal("web", pos)
    eng.recompute(at=t)
    assert any(v.invariant_id == "net.zone_trust_ceiling"
               for v in eng.violations())


def test_engine_trusted_source_produces_no_attack_paths() -> None:
    eng = NetworkSecurityStateEngine()
    t = _t0()
    eng.add_zone(Zone("z1", ZoneKind.INTERNAL, 1.0))
    eng.add_zone(Zone("z2", ZoneKind.DATA, 1.0))
    eng.add_node(NetworkNode("a", NodeKind.HOST, "z1", 0.3))
    eng.add_node(NetworkNode("b", NodeKind.HOST, "z2", 0.9))
    eng.add_link(_weak_link("l", "a", "b"))
    pos = NetworkTrustSignal(signal_id="s", weight=1.0, polarity=1.0,
                             at=t, evidence=_ev(t))
    eng.observe_signal("a", pos)
    eng.recompute(at=t)
    assert eng.attack_paths() == ()


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
