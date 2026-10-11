"""
HYDRA POST-CORE — PHASE 28: AI DEPENDENCY / SOVEREIGNTY / CONCENTRATION
RESILIENCE
=========================================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * Domain — 6 node kinds, 5 sovereign zones, 9 dependency kinds,
    4 portability classes
  * Dependency chain graph:
        Application → Agent → Model → Provider → Infrastructure → Data
  * Ecosystem concentration analysis (HHI + effective number of
    options) across four dimensions: provider, model, infrastructure,
    region
  * Per-application option analysis (how many substitutable options
    an application actually has)
  * Sovereignty analysis — residency constraints vs actual flow
  * Substitution difficulty via weakest-link portability along the
    reachable chain
  * Failover / degraded-operation / trusted-fallback analysis
  * Findings — 11 concentrated-dependency and sovereignty kinds
  * Machine-checkable resilience invariants
  * In-memory + SQLite stores
  * Phase-28 engine facade
  * Full test suite + manual runner

This is NEW resilience-analysis technology for AI dependency chains.
It is NOT another governance or risk tool. It maps the *structural*
dependence of applications on AI assets and quantifies concentration,
sovereignty, substitutability, and degraded-operation capability.

No third-party dependencies.

Run tests:
    python hydra_phase28_ai_sovereignty_resilience.py
    pytest hydra_phase28_ai_sovereignty_resilience.py -q
"""
from __future__ import annotations

import json
import sqlite3
from collections import deque
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
# SECTION 2 — DOMAIN
# =============================================================================


class NodeKind(str, Enum):
    APPLICATION = "application"
    AGENT = "agent"
    MODEL = "model"
    PROVIDER = "provider"
    INFRASTRUCTURE = "infrastructure"
    DATA = "data"


ALL_NODE_KINDS: Tuple[NodeKind, ...] = tuple(NodeKind)


# Terminal kinds we compute concentration over.
_CONCENTRATION_DIMENSIONS: Tuple[NodeKind, ...] = (
    NodeKind.PROVIDER,
    NodeKind.MODEL,
    NodeKind.INFRASTRUCTURE,
)


class SovereignZone(str, Enum):
    EU = "eu"
    US = "us"
    UK = "uk"
    CN = "cn"
    IN = "in"
    OTHER = "other"


class DependencyEdgeKind(str, Enum):
    APP_USES_AGENT = "app_uses_agent"
    APP_USES_MODEL = "app_uses_model"
    APP_READS_DATA = "app_reads_data"
    AGENT_USES_MODEL = "agent_uses_model"
    AGENT_USES_TOOL = "agent_uses_tool"
    MODEL_SERVED_BY = "model_served_by"
    MODEL_DERIVED_FROM = "model_derived_from"
    HOSTED_ON = "hosted_on"
    RUNS_IN = "runs_in"
    GENERIC = "generic"


class PortabilityClass(str, Enum):
    """How easily a dependency can be moved/substituted."""
    PORTABLE = "portable"
    EXPORTABLE = "exportable"
    STICKY = "sticky"
    LOCKED = "locked"


_PORTABILITY_RANK: Mapping[PortabilityClass, int] = {
    PortabilityClass.LOCKED: 0,
    PortabilityClass.STICKY: 1,
    PortabilityClass.EXPORTABLE: 2,
    PortabilityClass.PORTABLE: 3,
}


def portability_rank(p: PortabilityClass) -> int:
    return _PORTABILITY_RANK[p]


class OperationalStatus(str, Enum):
    NORMAL = "normal"
    DEGRADED = "degraded"
    DOWN = "down"


class FindingKind(str, Enum):
    HIGH_VENDOR_CONCENTRATION = "high_vendor_concentration"
    HIGH_MODEL_CONCENTRATION = "high_model_concentration"
    HIGH_PROVIDER_DEPENDENCY = "high_provider_dependency"
    HIGH_INFRASTRUCTURE_DEPENDENCY = "high_infrastructure_dependency"
    HIGH_REGION_CONCENTRATION = "high_region_concentration"
    DATA_SOVEREIGNTY_VIOLATION = "data_sovereignty_violation"
    CROSS_SOVEREIGN_FLOW = "cross_sovereign_flow"
    SUBSTITUTION_DIFFICULTY_HIGH = "substitution_difficulty_high"
    SINGLE_POINT_OF_FAILURE = "single_point_of_failure"
    UNTRUSTED_FALLBACK = "untrusted_fallback"
    NO_DEGRADED_MODE = "no_degraded_mode"


@dataclass(frozen=True)
class ResilienceFinding:
    kind: FindingKind
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
# SECTION 3 — NODES + EDGES
# =============================================================================


@dataclass(frozen=True)
class DependencyNode:
    node_id: str
    kind: NodeKind
    name: str
    region: Optional[str]
    sovereign_zone: Optional[SovereignZone]
    portability: PortabilityClass
    criticality: float
    has_fallback: bool
    fallback_node_id: Optional[str] = None
    fallback_trusted: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.node_id:
            raise ValueError("node_id is required")
        if not self.name:
            raise ValueError("name is required")
        if not 0.0 <= self.criticality <= 1.0:
            raise ValueError("criticality must be within [0,1]")
        if self.has_fallback and not self.fallback_node_id:
            raise ValueError(
                "has_fallback requires fallback_node_id"
            )
        if self.fallback_node_id == self.node_id:
            raise ValueError("fallback_node_id cannot be self")
        if self.region is not None and self.sovereign_zone is None:
            raise ValueError(
                "region requires sovereign_zone to be set"
            )


@dataclass(frozen=True)
class DependencyEdge:
    edge_id: str
    src_id: str
    dst_id: str
    kind: DependencyEdgeKind
    weight: float = 1.0
    at: Optional[datetime] = None

    def __post_init__(self) -> None:
        if not self.edge_id:
            raise ValueError("edge_id is required")
        if not self.src_id or not self.dst_id:
            raise ValueError("src_id and dst_id are required")
        if self.src_id == self.dst_id:
            raise ValueError("self-edges are not allowed")
        if not 0.0 < self.weight <= 1.0:
            raise ValueError("weight must be in (0,1]")
        if self.at is not None and self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


# =============================================================================
# SECTION 4 — GRAPH
# =============================================================================


class DependencyGraph:
    """Directed acyclic dependency graph across AI layers."""

    def __init__(self) -> None:
        self._nodes: Dict[str, DependencyNode] = {}
        self._out: Dict[str, List[DependencyEdge]] = {}
        self._in: Dict[str, List[DependencyEdge]] = {}
        self._edges: Dict[str, DependencyEdge] = {}

    def add_node(self, node: DependencyNode) -> None:
        if node.node_id in self._nodes:
            raise ValueError(f"node {node.node_id} already exists")
        if node.has_fallback and node.fallback_node_id \
           and node.fallback_node_id != node.node_id:
            # fallback node must be added BEFORE the node that references it
            if node.fallback_node_id not in self._nodes:
                raise KeyError(
                    f"fallback node {node.fallback_node_id} not registered"
                )
        self._nodes[node.node_id] = node
        self._out.setdefault(node.node_id, [])
        self._in.setdefault(node.node_id, [])

    def add_edge(self, edge: DependencyEdge) -> None:
        if edge.edge_id in self._edges:
            raise ValueError(f"edge {edge.edge_id} already exists")
        if edge.src_id not in self._nodes:
            raise KeyError(f"src {edge.src_id} not registered")
        if edge.dst_id not in self._nodes:
            raise KeyError(f"dst {edge.dst_id} not registered")
        if self._would_create_cycle(edge.src_id, edge.dst_id):
            raise ValueError(
                f"edge {edge.src_id}->{edge.dst_id} creates a cycle"
            )
        self._edges[edge.edge_id] = edge
        self._out[edge.src_id].append(edge)
        self._in[edge.dst_id].append(edge)

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
            for e in self._out.get(cur, ()):
                stack.append(e.dst_id)
        return False

    def node(self, node_id: str) -> DependencyNode:
        n = self._nodes.get(node_id)
        if n is None:
            raise KeyError(f"unknown node {node_id}")
        return n

    def nodes(self) -> Tuple[DependencyNode, ...]:
        return tuple(self._nodes.values())

    def edges(self) -> Tuple[DependencyEdge, ...]:
        return tuple(self._edges.values())

    def children(self, node_id: str) -> Tuple[str, ...]:
        return tuple(e.dst_id for e in self._out.get(node_id, ()))

    def parents(self, node_id: str) -> Tuple[str, ...]:
        return tuple(e.src_id for e in self._in.get(node_id, ()))

    def roots(self, kind: Optional[NodeKind] = None) -> Tuple[str, ...]:
        out: List[str] = []
        for nid, node in self._nodes.items():
            if kind is not None and node.kind is not kind:
                continue
            if not self._in.get(nid):
                out.append(nid)
        return tuple(out)

    def reachable(
        self, root: str, *, kinds: Optional[FrozenSet[NodeKind]] = None,
    ) -> FrozenSet[str]:
        out: set = set()
        stack = [root]
        while stack:
            cur = stack.pop()
            for c in self.children(cur):
                if c in out:
                    continue
                out.add(c)
                stack.append(c)
        if kinds is not None:
            out = {nid for nid in out
                   if self._nodes[nid].kind in kinds}
        return frozenset(out)

    def terminals(
        self, root: str, kind: NodeKind,
    ) -> FrozenSet[str]:
        """All nodes of the given kind reachable from `root`."""
        return self.reachable(root, kinds=frozenset({kind}))


# =============================================================================
# SECTION 5 — CONCENTRATION
# =============================================================================


def hhi(counts: Mapping[str, int]) -> float:
    """Herfindahl-Hirschman Index in [0,1]. Higher = more concentrated."""
    total = sum(counts.values())
    if total == 0:
        return 0.0
    return sum((c / total) ** 2 for c in counts.values())


def effective_options(counts: Mapping[str, int]) -> float:
    """1 / HHI — the effective number of independent options."""
    h = hhi(counts)
    if h <= 0:
        return 0.0
    return 1.0 / h


@dataclass(frozen=True)
class ConcentrationReport:
    dimension: NodeKind
    ecosystem_hhi: float
    effective_options: float
    distinct_holders: int
    top_holder: Optional[str]
    top_share: float
    holder_counts: Mapping[str, int]

    def __post_init__(self) -> None:
        for n, v in (
            ("ecosystem_hhi", self.ecosystem_hhi),
            ("effective_options", self.effective_options),
            ("top_share", self.top_share),
        ):
            if v < 0:
                raise ValueError(f"{n} must be non-negative")


@dataclass(frozen=True)
class PerAppConcentration:
    app_id: str
    dimension: NodeKind
    option_count: int
    app_hhi: float
    effective_options: float


def ecosystem_concentration(
    graph: DependencyGraph,
    *,
    apps: Sequence[str],
    dimension: NodeKind,
) -> ConcentrationReport:
    if dimension not in _CONCENTRATION_DIMENSIONS:
        raise ValueError(
            f"unsupported dimension {dimension.value}"
        )
    counts: Dict[str, int] = {}
    for app in apps:
        for t in graph.terminals(app, dimension):
            counts[t] = counts.get(t, 0) + 1
    h = hhi(counts)
    top_holder: Optional[str] = None
    top_share = 0.0
    if counts:
        top_holder = max(counts.items(), key=lambda kv: (kv[1], kv[0]))[0]
        total = sum(counts.values())
        top_share = counts[top_holder] / total if total else 0.0
    return ConcentrationReport(
        dimension=dimension,
        ecosystem_hhi=h,
        effective_options=(1.0 / h if h > 0 else 0.0),
        distinct_holders=len(counts),
        top_holder=top_holder,
        top_share=top_share,
        holder_counts=dict(counts),
    )


def per_app_concentration(
    graph: DependencyGraph, *,
    app_id: str, dimension: NodeKind,
) -> PerAppConcentration:
    terminals = graph.terminals(app_id, dimension)
    n = len(terminals)
    if n == 0:
        return PerAppConcentration(
            app_id=app_id, dimension=dimension, option_count=0,
            app_hhi=0.0, effective_options=0.0,
        )
    # Equal weighting for terminals from a single root
    h = 1.0 / n
    return PerAppConcentration(
        app_id=app_id, dimension=dimension, option_count=n,
        app_hhi=h, effective_options=float(n),
    )


# =============================================================================
# SECTION 6 — SOVEREIGNTY
# =============================================================================


@dataclass(frozen=True)
class SovereigntyReport:
    app_id: str
    allowed_zones: FrozenSet[SovereignZone]
    observed_zones: FrozenSet[SovereignZone]
    violations: Tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.app_id:
            raise ValueError("app_id is required")


def analyse_sovereignty(
    graph: DependencyGraph, *,
    app_id: str,
    allowed_zones: FrozenSet[SovereignZone],
) -> SovereigntyReport:
    reachable = graph.reachable(app_id)
    observed: set = set()
    violations: List[str] = []
    for nid in reachable:
        n = graph.node(nid)
        if n.sovereign_zone is None:
            continue
        observed.add(n.sovereign_zone)
        if n.sovereign_zone not in allowed_zones:
            violations.append(
                f"{nid} ({n.kind.value}) is in "
                f"{n.sovereign_zone.value}, not in allowed zones"
            )
    return SovereigntyReport(
        app_id=app_id,
        allowed_zones=allowed_zones,
        observed_zones=frozenset(observed),
        violations=tuple(violations),
    )


def cross_sovereign_flows(
    graph: DependencyGraph, *,
    app_id: str,
) -> Tuple[Tuple[str, str], ...]:
    """Edges crossing a sovereign zone boundary along the app's subgraph."""
    reachable = graph.reachable(app_id) | {app_id}
    out: List[Tuple[str, str]] = []
    for nid in reachable:
        src = graph.node(nid)
        if src.sovereign_zone is None:
            continue
        for e in graph._out.get(nid, ()):
            if e.dst_id not in reachable:
                continue
            dst = graph.node(e.dst_id)
            if dst.sovereign_zone is None:
                continue
            if dst.sovereign_zone is not src.sovereign_zone:
                out.append((nid, e.dst_id))
    return tuple(out)


# =============================================================================
# SECTION 7 — SUBSTITUTION / FAILOVER
# =============================================================================


@dataclass(frozen=True)
class SubstitutionReport:
    app_id: str
    weakest_portability: PortabilityClass
    substitution_difficulty: float       # 0 (easy) .. 1 (locked)
    bottleneck_node_id: Optional[str]


def analyse_substitution(
    graph: DependencyGraph, *, app_id: str,
) -> SubstitutionReport:
    reachable = graph.reachable(app_id)
    if not reachable:
        return SubstitutionReport(
            app_id=app_id,
            weakest_portability=PortabilityClass.PORTABLE,
            substitution_difficulty=0.0,
            bottleneck_node_id=None,
        )
    weakest_rank = 3
    bottleneck: Optional[str] = None
    # deterministic tie-break: first lexicographic node
    for nid in sorted(reachable):
        n = graph.node(nid)
        r = portability_rank(n.portability)
        if r < weakest_rank:
            weakest_rank = r
            bottleneck = nid
    port = PortabilityClass(
        [k for k, v in _PORTABILITY_RANK.items() if v == weakest_rank][0]
    )
    difficulty = 1.0 - (weakest_rank / 3.0)
    return SubstitutionReport(
        app_id=app_id,
        weakest_portability=port,
        substitution_difficulty=max(0.0, min(1.0, difficulty)),
        bottleneck_node_id=bottleneck,
    )


@dataclass(frozen=True)
class FailoverReport:
    app_id: str
    single_points_of_failure: Tuple[str, ...]
    untrusted_fallbacks: Tuple[str, ...]
    critical_nodes: int
    degraded_availability: float
    status_if_any_spof_fails: OperationalStatus


def analyse_failover(
    graph: DependencyGraph, *, app_id: str,
) -> FailoverReport:
    reachable = graph.reachable(app_id)
    spof: List[str] = []
    untrusted: List[str] = []
    critical = 0
    for nid in sorted(reachable):
        n = graph.node(nid)
        if n.criticality >= 0.5 or n.kind in (
            NodeKind.PROVIDER, NodeKind.INFRASTRUCTURE,
        ):
            critical += 1
        if not n.has_fallback:
            spof.append(nid)
        elif not n.fallback_trusted:
            untrusted.append(nid)
    total = max(1, critical)
    availability = max(0.0, 1.0 - (len(spof) / total))
    if not spof:
        status = OperationalStatus.NORMAL
    elif availability > 0.0:
        status = OperationalStatus.DEGRADED
    else:
        status = OperationalStatus.DOWN
    return FailoverReport(
        app_id=app_id,
        single_points_of_failure=tuple(spof),
        untrusted_fallbacks=tuple(untrusted),
        critical_nodes=critical,
        degraded_availability=availability,
        status_if_any_spof_fails=status,
    )


def region_concentration(
    graph: DependencyGraph, *,
    apps: Sequence[str],
) -> ConcentrationReport:
    counts: Dict[str, int] = {}
    for app in apps:
        reachable = graph.reachable(app)
        regions: set = set()
        for nid in reachable:
            n = graph.node(nid)
            if n.region is None:
                continue
            regions.add(n.region)
        for r in regions:
            counts[r] = counts.get(r, 0) + 1
    h = hhi(counts)
    top: Optional[str] = None
    top_share = 0.0
    if counts:
        top = max(counts.items(), key=lambda kv: (kv[1], kv[0]))[0]
        total = sum(counts.values())
        top_share = counts[top] / total if total else 0.0
    return ConcentrationReport(
        dimension=NodeKind.INFRASTRUCTURE,
        ecosystem_hhi=h,
        effective_options=(1.0 / h if h > 0 else 0.0),
        distinct_holders=len(counts),
        top_holder=top,
        top_share=top_share,
        holder_counts=dict(counts),
    )


# =============================================================================
# SECTION 8 — INVARIANTS
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
class ResilienceSnapshot:
    graph: DependencyGraph
    findings: Tuple[ResilienceFinding, ...]
    concentration: Mapping[str, ConcentrationReport]
    sovereignty: Mapping[str, SovereigntyReport]
    substitution: Mapping[str, SubstitutionReport]
    failover: Mapping[str, FailoverReport]


@dataclass(frozen=True)
class ResilienceInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[ResilienceSnapshot],
                        Tuple[InvariantViolation, ...]]
    description: str


def _inv_hhi_bounded(snap: ResilienceSnapshot) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for dim, r in snap.concentration.items():
        if not 0.0 <= r.ecosystem_hhi <= 1.0:
            out.append(InvariantViolation(
                invariant_id="res.hhi_bounded",
                severity=InvariantSeverity.HIGH,
                subject_id=dim,
                detail=f"HHI {r.ecosystem_hhi}",
            ))
    return tuple(out)


def _inv_fallback_registered(
    snap: ResilienceSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for n in snap.graph.nodes():
        if n.has_fallback and n.fallback_node_id is not None:
            try:
                snap.graph.node(n.fallback_node_id)
            except KeyError:
                out.append(InvariantViolation(
                    invariant_id="res.fallback_registered",
                    severity=InvariantSeverity.CRITICAL,
                    subject_id=n.node_id,
                    detail=(
                        f"fallback {n.fallback_node_id} not in graph"
                    ),
                ))
    return tuple(out)


def _inv_region_requires_zone(
    snap: ResilienceSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for n in snap.graph.nodes():
        if n.region is not None and n.sovereign_zone is None:
            out.append(InvariantViolation(
                invariant_id="res.region_requires_zone",
                severity=InvariantSeverity.HIGH,
                subject_id=n.node_id,
                detail="region set without sovereign zone",
            ))
    return tuple(out)


def _inv_sovereignty_violations_consistent(
    snap: ResilienceSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for aid, r in snap.sovereignty.items():
        if r.violations and not r.observed_zones - r.allowed_zones:
            out.append(InvariantViolation(
                invariant_id="res.sovereignty_consistent",
                severity=InvariantSeverity.HIGH,
                subject_id=aid,
                detail=(
                    "violations present but no zone outside allowed"
                ),
            ))
    return tuple(out)


def _inv_substitution_bounded(
    snap: ResilienceSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for aid, s in snap.substitution.items():
        if not 0.0 <= s.substitution_difficulty <= 1.0:
            out.append(InvariantViolation(
                invariant_id="res.substitution_bounded",
                severity=InvariantSeverity.HIGH,
                subject_id=aid,
                detail=f"difficulty {s.substitution_difficulty}",
            ))
    return tuple(out)


DEFAULT_INVARIANTS: Tuple[ResilienceInvariant, ...] = (
    ResilienceInvariant(
        invariant_id="res.hhi_bounded",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_hhi_bounded,
        description="HHI must lie within [0,1].",
    ),
    ResilienceInvariant(
        invariant_id="res.fallback_registered",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_fallback_registered,
        description="Fallback nodes must be registered in the graph.",
    ),
    ResilienceInvariant(
        invariant_id="res.region_requires_zone",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_region_requires_zone,
        description="A region must map to a sovereign zone.",
    ),
    ResilienceInvariant(
        invariant_id="res.sovereignty_consistent",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_sovereignty_violations_consistent,
        description="Sovereignty violations must reference a foreign zone.",
    ),
    ResilienceInvariant(
        invariant_id="res.substitution_bounded",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_substitution_bounded,
        description="Substitution difficulty must be within [0,1].",
    ),
)


def check_invariants(
    snap: ResilienceSnapshot,
    invariants: Iterable[ResilienceInvariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 9 — STORE
# =============================================================================


@dataclass(frozen=True)
class AppSummaryRecord:
    app_id: str
    provider_options: int
    model_options: int
    infra_options: int
    substitution_difficulty: float
    sovereignty_violations: int
    single_points_of_failure: int
    degraded_availability: float
    updated_at: datetime


class ResilienceStore(Protocol):
    def put(self, record: AppSummaryRecord) -> None: ...
    def get(self, app_id: str) -> Optional[AppSummaryRecord]: ...
    def all(self) -> Tuple[AppSummaryRecord, ...]: ...


class InMemoryResilienceStore:
    def __init__(self) -> None:
        self._data: Dict[str, AppSummaryRecord] = {}

    def put(self, record: AppSummaryRecord) -> None:
        existing = self._data.get(record.app_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._data[record.app_id] = record

    def get(self, app_id: str) -> Optional[AppSummaryRecord]:
        return self._data.get(app_id)

    def all(self) -> Tuple[AppSummaryRecord, ...]:
        return tuple(self._data.values())


class SqliteResilienceStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS res_app_summary (
                app_id TEXT PRIMARY KEY,
                provider_options INTEGER NOT NULL,
                model_options INTEGER NOT NULL,
                infra_options INTEGER NOT NULL,
                substitution_difficulty REAL NOT NULL,
                sovereignty_violations INTEGER NOT NULL,
                single_points_of_failure INTEGER NOT NULL,
                degraded_availability REAL NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS res_nodes (
                node_id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS res_findings (
                finding_id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def put(self, record: AppSummaryRecord) -> None:
        existing = self.get(record.app_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._conn.execute(
            """
            INSERT INTO res_app_summary
              (app_id, provider_options, model_options, infra_options,
               substitution_difficulty, sovereignty_violations,
               single_points_of_failure, degraded_availability,
               updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(app_id) DO UPDATE SET
              provider_options=excluded.provider_options,
              model_options=excluded.model_options,
              infra_options=excluded.infra_options,
              substitution_difficulty=excluded.substitution_difficulty,
              sovereignty_violations=excluded.sovereignty_violations,
              single_points_of_failure=excluded.single_points_of_failure,
              degraded_availability=excluded.degraded_availability,
              updated_at=excluded.updated_at
            """,
            (
                record.app_id, record.provider_options,
                record.model_options, record.infra_options,
                record.substitution_difficulty,
                record.sovereignty_violations,
                record.single_points_of_failure,
                record.degraded_availability,
                record.updated_at.isoformat(),
            ),
        )
        self._conn.commit()

    def get(self, app_id: str) -> Optional[AppSummaryRecord]:
        row = self._conn.execute(
            "SELECT provider_options, model_options, infra_options, "
            "substitution_difficulty, sovereignty_violations, "
            "single_points_of_failure, degraded_availability, updated_at "
            "FROM res_app_summary WHERE app_id = ?",
            (app_id,),
        ).fetchone()
        if row is None:
            return None
        return AppSummaryRecord(
            app_id=app_id,
            provider_options=int(row[0]), model_options=int(row[1]),
            infra_options=int(row[2]),
            substitution_difficulty=float(row[3]),
            sovereignty_violations=int(row[4]),
            single_points_of_failure=int(row[5]),
            degraded_availability=float(row[6]),
            updated_at=datetime.fromisoformat(row[7]),
        )

    def all(self) -> Tuple[AppSummaryRecord, ...]:
        rows = self._conn.execute(
            "SELECT app_id FROM res_app_summary"
        ).fetchall()
        return tuple(
            r for r in (self.get(x[0]) for x in rows) if r is not None
        )

    def put_node(self, n: DependencyNode) -> None:
        payload = {
            "node_id": n.node_id,
            "kind": n.kind.value,
            "name": n.name,
            "region": n.region,
            "sovereign_zone": n.sovereign_zone.value
            if n.sovereign_zone else None,
            "portability": n.portability.value,
            "criticality": n.criticality,
            "has_fallback": n.has_fallback,
            "fallback_node_id": n.fallback_node_id,
            "fallback_trusted": n.fallback_trusted,
        }
        self._conn.execute(
            "INSERT OR REPLACE INTO res_nodes (node_id, payload_json) "
            "VALUES (?, ?)",
            (n.node_id, json.dumps(payload, sort_keys=True)),
        )
        self._conn.commit()

    def put_finding(self, finding_id: str, f: ResilienceFinding) -> None:
        payload = {
            "finding_id": finding_id,
            "kind": f.kind.value,
            "subject_id": f.subject_id,
            "detail": f.detail,
            "severity": f.severity,
            "at": f.at.isoformat(),
        }
        self._conn.execute(
            "INSERT OR REPLACE INTO res_findings "
            "(finding_id, payload_json) VALUES (?, ?)",
            (finding_id, json.dumps(payload, sort_keys=True)),
        )
        self._conn.commit()


# =============================================================================
# SECTION 10 — ENGINE
# =============================================================================


@dataclass(frozen=True)
class ResilienceConfig:
    ecosystem_hhi_threshold: float = 0.4
    app_option_minimum: int = 2
    substitution_difficulty_threshold: float = 0.6
    spof_count_threshold: int = 1
    degraded_availability_floor: float = 0.5

    def __post_init__(self) -> None:
        for n, v in (
            ("ecosystem_hhi_threshold", self.ecosystem_hhi_threshold),
            ("substitution_difficulty_threshold",
             self.substitution_difficulty_threshold),
            ("degraded_availability_floor",
             self.degraded_availability_floor),
        ):
            if not 0.0 <= v <= 1.0:
                raise ValueError(f"{n} must be within [0,1]")
        if self.app_option_minimum < 1:
            raise ValueError("app_option_minimum must be >= 1")
        if self.spof_count_threshold < 0:
            raise ValueError("spof_count_threshold must be >= 0")


class AIResilienceEngine:
    """AI dependency / sovereignty / concentration resilience engine."""

    def __init__(
        self,
        *,
        store: Optional[ResilienceStore] = None,
        config: Optional[ResilienceConfig] = None,
    ) -> None:
        self._store: ResilienceStore = store or InMemoryResilienceStore()
        self._config = config or ResilienceConfig()
        self._graph = DependencyGraph()
        self._app_residency: Dict[str, FrozenSet[SovereignZone]] = {}
        self._concentration: Dict[str, ConcentrationReport] = {}
        self._sovereignty: Dict[str, SovereigntyReport] = {}
        self._substitution: Dict[str, SubstitutionReport] = {}
        self._failover: Dict[str, FailoverReport] = {}
        self._findings: List[ResilienceFinding] = []
        self._violations: Tuple[InvariantViolation, ...] = ()

    # ---- registration ----------------------------------------------------

    def add_node(self, node: DependencyNode) -> None:
        self._graph.add_node(node)
        if isinstance(self._store, SqliteResilienceStore):
            self._store.put_node(node)

    def add_edge(self, edge: DependencyEdge) -> None:
        self._graph.add_edge(edge)

    def set_residency(
        self, app_id: str, allowed: Iterable[SovereignZone],
    ) -> None:
        # register must be validated via graph
        try:
            n = self._graph.node(app_id)
        except KeyError:
            raise KeyError(f"unknown application {app_id}")
        if n.kind is not NodeKind.APPLICATION:
            raise ValueError(
                f"{app_id} is not an APPLICATION"
            )
        self._app_residency[app_id] = frozenset(allowed)

    def graph(self) -> DependencyGraph:
        return self._graph

    def config(self) -> ResilienceConfig:
        return self._config

    def set_config(self, config: ResilienceConfig) -> None:
        self._config = config

    # ---- recompute -------------------------------------------------------

    def recompute(self, *, at: datetime) -> Tuple[AppSummaryRecord, ...]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        cfg = self._config
        apps = tuple(sorted(self._graph.roots(NodeKind.APPLICATION)))
        self._findings = []

        # Ecosystem concentration per dimension
        self._concentration = {}
        for dim in _CONCENTRATION_DIMENSIONS:
            report = ecosystem_concentration(
                self._graph, apps=apps, dimension=dim,
            )
            self._concentration[dim.value] = report
            if report.ecosystem_hhi >= cfg.ecosystem_hhi_threshold:
                kind = {
                    NodeKind.PROVIDER: FindingKind.HIGH_VENDOR_CONCENTRATION,
                    NodeKind.MODEL: FindingKind.HIGH_MODEL_CONCENTRATION,
                    NodeKind.INFRASTRUCTURE:
                        FindingKind.HIGH_INFRASTRUCTURE_DEPENDENCY,
                }[dim]
                self._findings.append(ResilienceFinding(
                    kind=kind,
                    subject_id=dim.value,
                    detail=(
                        f"ecosystem HHI {report.ecosystem_hhi:.3f} "
                        f"(top holder {report.top_holder} with share "
                        f"{report.top_share:.2f})"
                    ),
                    severity=4, at=at,
                ))

        # Region concentration
        region_report = region_concentration(self._graph, apps=apps)
        self._concentration["region"] = region_report
        if region_report.ecosystem_hhi >= cfg.ecosystem_hhi_threshold:
            self._findings.append(ResilienceFinding(
                kind=FindingKind.HIGH_REGION_CONCENTRATION,
                subject_id="region",
                detail=(
                    f"region HHI {region_report.ecosystem_hhi:.3f} "
                    f"(top {region_report.top_holder})"
                ),
                severity=4, at=at,
            ))

        # Per-app analysis
        self._sovereignty = {}
        self._substitution = {}
        self._failover = {}
        records: List[AppSummaryRecord] = []

        for app in apps:
            # Sovereignty
            allowed = self._app_residency.get(app, frozenset())
            sov = analyse_sovereignty(
                self._graph, app_id=app, allowed_zones=allowed,
            )
            self._sovereignty[app] = sov
            if sov.violations:
                self._findings.append(ResilienceFinding(
                    kind=FindingKind.DATA_SOVEREIGNTY_VIOLATION,
                    subject_id=app,
                    detail=(
                        f"{len(sov.violations)} zone violation(s); "
                        f"observed={sorted(z.value for z in sov.observed_zones)}"
                    ),
                    severity=5, at=at,
                ))
            # Cross-sovereign flows (informational)
            flows = cross_sovereign_flows(self._graph, app_id=app)
            if flows:
                self._findings.append(ResilienceFinding(
                    kind=FindingKind.CROSS_SOVEREIGN_FLOW,
                    subject_id=app,
                    detail=(
                        f"{len(flows)} cross-zone edge(s) on the "
                        f"application path"
                    ),
                    severity=3, at=at,
                ))

            # Substitution
            sub = analyse_substitution(self._graph, app_id=app)
            self._substitution[app] = sub
            if sub.substitution_difficulty >= \
               cfg.substitution_difficulty_threshold:
                self._findings.append(ResilienceFinding(
                    kind=FindingKind.SUBSTITUTION_DIFFICULTY_HIGH,
                    subject_id=app,
                    detail=(
                        f"substitution difficulty "
                        f"{sub.substitution_difficulty:.2f} "
                        f"(weakest {sub.weakest_portability.value} at "
                        f"{sub.bottleneck_node_id})"
                    ),
                    severity=4, at=at,
                ))

            # Failover
            fo = analyse_failover(self._graph, app_id=app)
            self._failover[app] = fo
            if len(fo.single_points_of_failure) >= cfg.spof_count_threshold \
               and fo.single_points_of_failure:
                self._findings.append(ResilienceFinding(
                    kind=FindingKind.SINGLE_POINT_OF_FAILURE,
                    subject_id=app,
                    detail=(
                        f"{len(fo.single_points_of_failure)} SPOF(s): "
                        f"{list(fo.single_points_of_failure[:5])}"
                    ),
                    severity=4, at=at,
                ))
            if fo.untrusted_fallbacks:
                self._findings.append(ResilienceFinding(
                    kind=FindingKind.UNTRUSTED_FALLBACK,
                    subject_id=app,
                    detail=(
                        f"{len(fo.untrusted_fallbacks)} untrusted "
                        f"fallback(s): {list(fo.untrusted_fallbacks[:5])}"
                    ),
                    severity=5, at=at,
                ))
            if fo.degraded_availability < cfg.degraded_availability_floor:
                self._findings.append(ResilienceFinding(
                    kind=FindingKind.NO_DEGRADED_MODE,
                    subject_id=app,
                    detail=(
                        f"degraded availability "
                        f"{fo.degraded_availability:.2f} below floor "
                        f"{cfg.degraded_availability_floor:.2f}"
                    ),
                    severity=4, at=at,
                ))

            # Per-app concentration
            prov = per_app_concentration(
                self._graph, app_id=app, dimension=NodeKind.PROVIDER,
            )
            mdl = per_app_concentration(
                self._graph, app_id=app, dimension=NodeKind.MODEL,
            )
            inf = per_app_concentration(
                self._graph, app_id=app, dimension=NodeKind.INFRASTRUCTURE,
            )
            if prov.option_count and \
               prov.option_count < cfg.app_option_minimum:
                self._findings.append(ResilienceFinding(
                    kind=FindingKind.HIGH_PROVIDER_DEPENDENCY,
                    subject_id=app,
                    detail=(
                        f"only {prov.option_count} provider(s) reachable"
                    ),
                    severity=4, at=at,
                ))

            rec = AppSummaryRecord(
                app_id=app,
                provider_options=prov.option_count,
                model_options=mdl.option_count,
                infra_options=inf.option_count,
                substitution_difficulty=sub.substitution_difficulty,
                sovereignty_violations=len(sov.violations),
                single_points_of_failure=len(fo.single_points_of_failure),
                degraded_availability=fo.degraded_availability,
                updated_at=at,
            )
            self._store.put(rec)
            records.append(rec)

        if isinstance(self._store, SqliteResilienceStore):
            for i, f in enumerate(self._findings):
                self._store.put_finding(
                    f"f-{i:08d}-{f.kind.value}", f,
                )

        self._violations = check_invariants(self.snapshot())
        return tuple(records)

    # ---- queries ---------------------------------------------------------

    def concentration_report(
        self, dimension: str,
    ) -> Optional[ConcentrationReport]:
        return self._concentration.get(dimension)

    def concentration_by_kind(
        self, kind: NodeKind,
    ) -> Optional[ConcentrationReport]:
        return self._concentration.get(kind.value)

    def sovereignty_report(
        self, app_id: str,
    ) -> Optional[SovereigntyReport]:
        return self._sovereignty.get(app_id)

    def substitution_report(
        self, app_id: str,
    ) -> Optional[SubstitutionReport]:
        return self._substitution.get(app_id)

    def failover_report(self, app_id: str) -> Optional[FailoverReport]:
        return self._failover.get(app_id)

    def findings(self) -> Tuple[ResilienceFinding, ...]:
        return tuple(self._findings)

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return self._violations

    def record(self, app_id: str) -> Optional[AppSummaryRecord]:
        return self._store.get(app_id)

    def snapshot(self) -> ResilienceSnapshot:
        return ResilienceSnapshot(
            graph=self._graph,
            findings=tuple(self._findings),
            concentration=dict(self._concentration),
            sovereignty=dict(self._sovereignty),
            substitution=dict(self._substitution),
            failover=dict(self._failover),
        )


# =============================================================================
# SECTION 11 — TESTS
# =============================================================================


def _t0() -> datetime:
    from datetime import timezone
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _node(
    nid: str, kind: NodeKind = NodeKind.MODEL, *,
    name: Optional[str] = None,
    region: Optional[str] = None,
    sovereign_zone: Optional[SovereignZone] = None,
    portability: PortabilityClass = PortabilityClass.PORTABLE,
    criticality: float = 0.5,
    has_fallback: bool = False,
    fallback_node_id: Optional[str] = None,
    fallback_trusted: bool = True,
) -> DependencyNode:
    return DependencyNode(
        node_id=nid, kind=kind, name=name or nid,
        region=region, sovereign_zone=sovereign_zone,
        portability=portability, criticality=criticality,
        has_fallback=has_fallback,
        fallback_node_id=fallback_node_id,
        fallback_trusted=fallback_trusted,
    )


def _edge(
    eid: str, src: str, dst: str,
    kind: DependencyEdgeKind = DependencyEdgeKind.GENERIC,
    weight: float = 1.0,
) -> DependencyEdge:
    return DependencyEdge(
        edge_id=eid, src_id=src, dst_id=dst, kind=kind,
        weight=weight, at=_t0(),
    )


def _app_graph() -> DependencyGraph:
    """app → agent → model → provider → infra → data"""
    g = DependencyGraph()
    g.add_node(_node("app", NodeKind.APPLICATION,
                     region="eu-west-1",
                     sovereign_zone=SovereignZone.EU))
    g.add_node(_node("agent", NodeKind.AGENT,
                     region="eu-west-1",
                     sovereign_zone=SovereignZone.EU))
    g.add_node(_node("model", NodeKind.MODEL,
                     region="eu-west-1",
                     sovereign_zone=SovereignZone.EU))
    g.add_node(_node("provider", NodeKind.PROVIDER,
                     region="eu-west-1",
                     sovereign_zone=SovereignZone.EU))
    g.add_node(_node("infra", NodeKind.INFRASTRUCTURE,
                     region="eu-west-1",
                     sovereign_zone=SovereignZone.EU))
    g.add_node(_node("data", NodeKind.DATA,
                     region="eu-west-1",
                     sovereign_zone=SovereignZone.EU))
    g.add_edge(_edge("e1", "app", "agent"))
    g.add_edge(_edge("e2", "agent", "model"))
    g.add_edge(_edge("e3", "model", "provider"))
    g.add_edge(_edge("e4", "provider", "infra"))
    g.add_edge(_edge("e5", "app", "data"))
    return g


# ---- domain ----

def test_node_requires_id() -> None:
    try:
        DependencyNode(
            node_id="", kind=NodeKind.MODEL, name="n", region=None,
            sovereign_zone=None, portability=PortabilityClass.PORTABLE,
            criticality=0.5, has_fallback=False,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_node_has_fallback_requires_id() -> None:
    try:
        _node("a", has_fallback=True)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_node_fallback_not_self() -> None:
    try:
        DependencyNode(
            node_id="a", kind=NodeKind.MODEL, name="a", region=None,
            sovereign_zone=None, portability=PortabilityClass.PORTABLE,
            criticality=0.5, has_fallback=True, fallback_node_id="a",
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_node_region_requires_zone() -> None:
    try:
        _node("a", region="eu-west-1")
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_node_criticality_bounds() -> None:
    try:
        _node("a", criticality=1.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_edge_self_rejected() -> None:
    try:
        DependencyEdge(
            edge_id="e", src_id="a", dst_id="a",
            kind=DependencyEdgeKind.GENERIC, at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_edge_weight_bounds() -> None:
    try:
        DependencyEdge(
            edge_id="e", src_id="a", dst_id="b",
            kind=DependencyEdgeKind.GENERIC, weight=0.0, at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_portability_rank_ordering() -> None:
    assert portability_rank(PortabilityClass.LOCKED) < \
        portability_rank(PortabilityClass.STICKY)
    assert portability_rank(PortabilityClass.STICKY) < \
        portability_rank(PortabilityClass.EXPORTABLE)
    assert portability_rank(PortabilityClass.EXPORTABLE) < \
        portability_rank(PortabilityClass.PORTABLE)


# ---- HHI ----

def test_hhi_empty_is_zero() -> None:
    assert hhi({}) == 0.0


def test_hhi_single_holder_is_one() -> None:
    assert hhi({"a": 5}) == 1.0


def test_hhi_uniform_two_is_half() -> None:
    assert abs(hhi({"a": 5, "b": 5}) - 0.5) < 1e-9


def test_hhi_uniform_four_is_quarter() -> None:
    assert abs(hhi({"a": 1, "b": 1, "c": 1, "d": 1}) - 0.25) < 1e-9


def test_effective_options_inverse() -> None:
    assert abs(effective_options({"a": 1, "b": 1}) - 2.0) < 1e-9


def test_effective_options_single() -> None:
    assert effective_options({"a": 10}) == 1.0


# ---- graph ----

def test_graph_duplicate_node() -> None:
    g = DependencyGraph()
    g.add_node(_node("a"))
    try:
        g.add_node(_node("a"))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_graph_duplicate_edge() -> None:
    g = DependencyGraph()
    g.add_node(_node("a"))
    g.add_node(_node("b"))
    g.add_edge(_edge("e", "a", "b"))
    try:
        g.add_edge(_edge("e", "a", "b"))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_graph_cycle_rejected() -> None:
    g = DependencyGraph()
    g.add_node(_node("a"))
    g.add_node(_node("b"))
    g.add_node(_node("c"))
    g.add_edge(_edge("e1", "a", "b"))
    g.add_edge(_edge("e2", "b", "c"))
    try:
        g.add_edge(_edge("e3", "c", "a"))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_graph_unknown_endpoint() -> None:
    g = DependencyGraph()
    g.add_node(_node("a"))
    try:
        g.add_edge(_edge("e", "a", "missing"))
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_graph_reachable() -> None:
    g = _app_graph()
    reach = g.reachable("app")
    assert "agent" in reach
    assert "provider" in reach
    assert "data" in reach


def test_graph_terminals_by_kind() -> None:
    g = _app_graph()
    providers = g.terminals("app", NodeKind.PROVIDER)
    assert providers == frozenset({"provider"})


def test_graph_roots_by_kind() -> None:
    g = _app_graph()
    assert "app" in g.roots(NodeKind.APPLICATION)


# ---- concentration ----

def test_ecosystem_concentration_single_provider() -> None:
    g = _app_graph()
    r = ecosystem_concentration(
        g, apps=("app",), dimension=NodeKind.PROVIDER,
    )
    assert r.ecosystem_hhi == 1.0
    assert r.top_holder == "provider"


def test_ecosystem_concentration_diverse() -> None:
    g = DependencyGraph()
    for i, app in enumerate(("a1", "a2", "a3")):
        g.add_node(_node(app, NodeKind.APPLICATION))
        g.add_node(_node(f"p{i}", NodeKind.PROVIDER))
        g.add_edge(_edge(f"e{i}", app, f"p{i}"))
    r = ecosystem_concentration(
        g, apps=("a1", "a2", "a3"), dimension=NodeKind.PROVIDER,
    )
    # Each provider used by one app → uniform distribution
    assert abs(r.ecosystem_hhi - 1.0 / 3.0) < 1e-9


def test_ecosystem_concentration_rejects_unknown_dimension() -> None:
    g = _app_graph()
    try:
        ecosystem_concentration(
            g, apps=("app",), dimension=NodeKind.AGENT,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_per_app_concentration_counts() -> None:
    g = _app_graph()
    r = per_app_concentration(g, app_id="app", dimension=NodeKind.PROVIDER)
    assert r.option_count == 1
    assert r.app_hhi == 1.0


def test_per_app_concentration_zero_when_no_terminals() -> None:
    g = DependencyGraph()
    g.add_node(_node("app", NodeKind.APPLICATION))
    r = per_app_concentration(g, app_id="app", dimension=NodeKind.PROVIDER)
    assert r.option_count == 0
    assert r.app_hhi == 0.0


# ---- sovereignty ----

def test_sovereignty_clean() -> None:
    g = _app_graph()
    r = analyse_sovereignty(
        g, app_id="app",
        allowed_zones=frozenset({SovereignZone.EU}),
    )
    assert r.violations == ()
    assert SovereignZone.EU in r.observed_zones


def test_sovereignty_violation_when_foreign_zone() -> None:
    g = DependencyGraph()
    g.add_node(_node("app", NodeKind.APPLICATION,
                     region="eu-west-1",
                     sovereign_zone=SovereignZone.EU))
    g.add_node(_node("model", NodeKind.MODEL,
                     region="us-east-1",
                     sovereign_zone=SovereignZone.US))
    g.add_edge(_edge("e", "app", "model"))
    r = analyse_sovereignty(
        g, app_id="app",
        allowed_zones=frozenset({SovereignZone.EU}),
    )
    assert r.violations
    assert SovereignZone.US in r.observed_zones


def test_cross_sovereign_flow_detected() -> None:
    g = DependencyGraph()
    g.add_node(_node("app", NodeKind.APPLICATION,
                     region="eu-west-1",
                     sovereign_zone=SovereignZone.EU))
    g.add_node(_node("model", NodeKind.MODEL,
                     region="us-east-1",
                     sovereign_zone=SovereignZone.US))
    g.add_edge(_edge("e", "app", "model"))
    flows = cross_sovereign_flows(g, app_id="app")
    assert ("app", "model") in flows


# ---- substitution ----

def test_substitution_weakest_link() -> None:
    g = DependencyGraph()
    g.add_node(_node("app", NodeKind.APPLICATION))
    g.add_node(_node("m1", NodeKind.MODEL,
                     portability=PortabilityClass.PORTABLE))
    g.add_node(_node("p1", NodeKind.PROVIDER,
                     portability=PortabilityClass.LOCKED))
    g.add_edge(_edge("e1", "app", "m1"))
    g.add_edge(_edge("e2", "m1", "p1"))
    r = analyse_substitution(g, app_id="app")
    assert r.weakest_portability is PortabilityClass.LOCKED
    assert r.substitution_difficulty == 1.0
    assert r.bottleneck_node_id == "p1"


def test_substitution_no_reachable() -> None:
    g = DependencyGraph()
    g.add_node(_node("app", NodeKind.APPLICATION))
    r = analyse_substitution(g, app_id="app")
    assert r.substitution_difficulty == 0.0


# ---- failover ----

def test_failover_no_spof() -> None:
    g = DependencyGraph()
    g.add_node(_node("app", NodeKind.APPLICATION))
    g.add_node(_node("f1", NodeKind.PROVIDER))
    g.add_node(_node(
        "p1", NodeKind.PROVIDER,
        has_fallback=True, fallback_node_id="f1",
    ))
    g.add_edge(_edge("e", "app", "p1"))
    r = analyse_failover(g, app_id="app")
    assert "p1" not in r.single_points_of_failure
    assert r.status_if_any_spof_fails in (
        OperationalStatus.NORMAL, OperationalStatus.DEGRADED,
    )


def test_failover_spof_detected() -> None:
    g = _app_graph()   # no fallbacks defined → everything is a SPOF
    r = analyse_failover(g, app_id="app")
    assert "provider" in r.single_points_of_failure


def test_failover_untrusted_fallback_detected() -> None:
    g = DependencyGraph()
    g.add_node(_node("app", NodeKind.APPLICATION))
    g.add_node(_node("alt", NodeKind.PROVIDER))
    g.add_node(_node(
        "p1", NodeKind.PROVIDER,
        has_fallback=True, fallback_node_id="alt",
        fallback_trusted=False,
    ))
    g.add_edge(_edge("e", "app", "p1"))
    r = analyse_failover(g, app_id="app")
    assert "p1" in r.untrusted_fallbacks


# ---- region concentration ----

def test_region_concentration_detects_single_region() -> None:
    g = _app_graph()
    r = region_concentration(g, apps=("app",))
    assert r.top_holder == "eu-west-1"
    assert r.ecosystem_hhi == 1.0


# ---- engine ----

def _build_engine() -> AIResilienceEngine:
    eng = AIResilienceEngine()
    for n in _app_graph().nodes():
        eng.add_node(n)
    for e in _app_graph().edges():
        eng.add_edge(e)
    eng.set_residency("app", (SovereignZone.EU,))
    return eng


def test_engine_registers_graph() -> None:
    eng = _build_engine()
    assert eng.graph().node("app").kind is NodeKind.APPLICATION


def test_engine_recompute_returns_records() -> None:
    eng = _build_engine()
    records = eng.recompute(at=_t0())
    assert len(records) == 1
    assert records[0].app_id == "app"


def test_engine_high_provider_concentration_finding() -> None:
    eng = _build_engine()
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.HIGH_VENDOR_CONCENTRATION in kinds


def test_engine_high_model_concentration_finding() -> None:
    eng = _build_engine()
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.HIGH_MODEL_CONCENTRATION in kinds


def test_engine_sovereignty_violation_finding() -> None:
    eng = AIResilienceEngine()
    eng.add_node(_node("app", NodeKind.APPLICATION,
                       region="eu-west-1",
                       sovereign_zone=SovereignZone.EU))
    eng.add_node(_node("model", NodeKind.MODEL,
                       region="us-east-1",
                       sovereign_zone=SovereignZone.US))
    eng.add_edge(_edge("e", "app", "model"))
    eng.set_residency("app", (SovereignZone.EU,))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.DATA_SOVEREIGNTY_VIOLATION in kinds


def test_engine_spof_finding() -> None:
    eng = _build_engine()
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.SINGLE_POINT_OF_FAILURE in kinds


def test_engine_substitution_difficulty_finding() -> None:
    eng = AIResilienceEngine()
    eng.add_node(_node("app", NodeKind.APPLICATION))
    eng.add_node(_node("model", NodeKind.MODEL,
                       portability=PortabilityClass.LOCKED))
    eng.add_edge(_edge("e", "app", "model"))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.SUBSTITUTION_DIFFICULTY_HIGH in kinds


def test_engine_untrusted_fallback_finding() -> None:
    eng = AIResilienceEngine()
    eng.add_node(_node("app", NodeKind.APPLICATION))
    eng.add_node(_node("alt", NodeKind.PROVIDER))
    eng.add_node(_node(
        "p1", NodeKind.PROVIDER,
        has_fallback=True, fallback_node_id="alt",
        fallback_trusted=False,
    ))
    eng.add_edge(_edge("e", "app", "p1"))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.UNTRUSTED_FALLBACK in kinds


def test_engine_no_degraded_mode_finding() -> None:
    eng = AIResilienceEngine(
        config=ResilienceConfig(degraded_availability_floor=0.9),
    )
    eng.add_node(_node("app", NodeKind.APPLICATION))
    for i in range(3):
        eng.add_node(_node(f"p{i}", NodeKind.PROVIDER))
        eng.add_edge(_edge(f"e{i}", "app", f"p{i}"))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.NO_DEGRADED_MODE in kinds


def test_engine_region_concentration_finding() -> None:
    eng = _build_engine()
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.HIGH_REGION_CONCENTRATION in kinds


def test_engine_recompute_requires_aware_time() -> None:
    from datetime import datetime as dt
    eng = _build_engine()
    try:
        eng.recompute(at=dt(2026, 1, 1))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_set_residency_requires_application_kind() -> None:
    eng = AIResilienceEngine()
    eng.add_node(_node("m", NodeKind.MODEL))
    try:
        eng.set_residency("m", (SovereignZone.EU,))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_set_residency_unknown_app() -> None:
    eng = AIResilienceEngine()
    try:
        eng.set_residency("ghost", (SovereignZone.EU,))
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_engine_report_lookup() -> None:
    eng = _build_engine()
    eng.recompute(at=_t0())
    assert eng.concentration_by_kind(NodeKind.PROVIDER) is not None
    assert eng.sovereignty_report("app") is not None
    assert eng.substitution_report("app") is not None
    assert eng.failover_report("app") is not None


def test_engine_record_lookup() -> None:
    eng = _build_engine()
    eng.recompute(at=_t0())
    rec = eng.record("app")
    assert rec is not None
    assert rec.provider_options == 1


def test_engine_config_validation() -> None:
    try:
        ResilienceConfig(ecosystem_hhi_threshold=1.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_set_config() -> None:
    eng = AIResilienceEngine()
    cfg = ResilienceConfig(app_option_minimum=3)
    eng.set_config(cfg)
    assert eng.config() is cfg


def test_engine_multi_app_aggregation() -> None:
    eng = AIResilienceEngine()
    for i in range(3):
        eng.add_node(_node(f"app{i}", NodeKind.APPLICATION))
        eng.add_node(_node(f"model{i}", NodeKind.MODEL))
        eng.add_edge(_edge(f"e{i}", f"app{i}", f"model{i}"))
    records = eng.recompute(at=_t0())
    assert len(records) == 3
    rep = eng.concentration_by_kind(NodeKind.MODEL)
    assert rep is not None
    assert rep.distinct_holders == 3


# ---- invariants ----

def test_invariant_clean_snapshot() -> None:
    eng = _build_engine()
    eng.recompute(at=_t0())
    assert eng.violations() == ()


def test_invariant_fallback_registered() -> None:
    # Manually craft a node referencing a missing fallback by direct
    # manipulation (bypassing __post_init__ check via graph internals)
    g = DependencyGraph()
    g.add_node(_node("app", NodeKind.APPLICATION))
    bad = object.__new__(DependencyNode)
    object.__setattr__(bad, "node_id", "p")
    object.__setattr__(bad, "kind", NodeKind.PROVIDER)
    object.__setattr__(bad, "name", "p")
    object.__setattr__(bad, "region", None)
    object.__setattr__(bad, "sovereign_zone", None)
    object.__setattr__(bad, "portability", PortabilityClass.PORTABLE)
    object.__setattr__(bad, "criticality", 0.5)
    object.__setattr__(bad, "has_fallback", True)
    object.__setattr__(bad, "fallback_node_id", "missing")
    object.__setattr__(bad, "fallback_trusted", True)
    object.__setattr__(bad, "metadata", {})
    g._nodes["p"] = bad
    g._out.setdefault("p", [])
    g._in.setdefault("p", [])
    snap = ResilienceSnapshot(
        graph=g, findings=(), concentration={}, sovereignty={},
        substitution={}, failover={},
    )
    v = check_invariants(snap)
    assert any(
        x.invariant_id == "res.fallback_registered" for x in v
    )


def test_invariant_hhi_bounded() -> None:
    bad = ConcentrationReport(
        dimension=NodeKind.PROVIDER,
        ecosystem_hhi=1.5, effective_options=1.0,
        distinct_holders=1, top_holder="x", top_share=1.0,
        holder_counts={"x": 1},
    )
    snap = ResilienceSnapshot(
        graph=DependencyGraph(), findings=(),
        concentration={"provider": bad}, sovereignty={},
        substitution={}, failover={},
    )
    v = check_invariants(snap)
    assert any(x.invariant_id == "res.hhi_bounded" for x in v)


def test_invariant_region_requires_zone() -> None:
    g = DependencyGraph()
    # inject a node with region but no zone directly
    bad = object.__new__(DependencyNode)
    object.__setattr__(bad, "node_id", "x")
    object.__setattr__(bad, "kind", NodeKind.MODEL)
    object.__setattr__(bad, "name", "x")
    object.__setattr__(bad, "region", "eu-west-1")
    object.__setattr__(bad, "sovereign_zone", None)
    object.__setattr__(bad, "portability", PortabilityClass.PORTABLE)
    object.__setattr__(bad, "criticality", 0.5)
    object.__setattr__(bad, "has_fallback", False)
    object.__setattr__(bad, "fallback_node_id", None)
    object.__setattr__(bad, "fallback_trusted", True)
    object.__setattr__(bad, "metadata", {})
    g._nodes["x"] = bad
    snap = ResilienceSnapshot(
        graph=g, findings=(), concentration={}, sovereignty={},
        substitution={}, failover={},
    )
    v = check_invariants(snap)
    assert any(
        x.invariant_id == "res.region_requires_zone" for x in v
    )


# ---- store ----

def test_in_memory_store_rejects_stale() -> None:
    s = InMemoryResilienceStore()
    t = _t0()
    s.put(AppSummaryRecord(
        "a", 1, 1, 1, 0.5, 0, 0, 1.0, t,
    ))
    earlier = t.replace(year=t.year - 1)
    try:
        s.put(AppSummaryRecord(
            "a", 2, 2, 2, 0.1, 0, 0, 1.0, earlier,
        ))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "res.db")
    store = SqliteResilienceStore(db)
    store.put(AppSummaryRecord(
        "app", 2, 3, 1, 0.4, 1, 2, 0.6, _t0(),
    ))
    got = store.get("app")
    assert got is not None
    assert got.provider_options == 2
    assert got.sovereignty_violations == 1


def test_sqlite_store_node_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "res.db")
    store = SqliteResilienceStore(db)
    n = _node("m", NodeKind.MODEL, region="eu-west-1",
              sovereign_zone=SovereignZone.EU)
    store.put_node(n)
    row = store._conn.execute(
        "SELECT payload_json FROM res_nodes WHERE node_id = 'm'"
    ).fetchone()
    assert row is not None
    payload = json.loads(row[0])
    assert payload["sovereign_zone"] == "eu"
    assert payload["kind"] == "model"


def test_sqlite_store_finding_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "res.db")
    store = SqliteResilienceStore(db)
    f = ResilienceFinding(
        kind=FindingKind.SINGLE_POINT_OF_FAILURE,
        subject_id="app", detail="x", severity=4, at=_t0(),
    )
    store.put_finding("fid-1", f)
    row = store._conn.execute(
        "SELECT payload_json FROM res_findings WHERE finding_id = 'fid-1'"
    ).fetchone()
    assert row is not None
    payload = json.loads(row[0])
    assert payload["kind"] == "single_point_of_failure"


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
