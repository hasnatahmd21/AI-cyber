"""
HYDRA POST-CORE — PHASE 29: NOVEL ATTACK-SURFACE DISCOVERY
=============================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * Domain — 7 node kinds, 5 zones, 5 edge kinds, 10 surface kinds,
    confidence and novelty classes
  * Discovery graph — entities, edges, indexes for bounded traversal
  * Ten orthogonal discovery rules, each producing *candidates* with
    explicit provenance:
      1. TRUST_TRANSITIVITY           (A→B→C trust without declared A→C)
      2. CROSS_ZONE_TRUST             (trust crossing zone boundary)
      3. TRUST_CYCLE                  (mutual/reinforcing trust)
      4. AUTHORITY_CHAIN              (reachable capability not declared)
      5. HIDDEN_DEPENDENCY            (undeclared transitive dependency)
      6. TOOL_PATHWAY                 (agent→tool→agent→tool composition)
      7. STATE_COMBINATION            (individually benign states whose
                                       combination is dangerous)
      8. CONTROL_INTERACTION          (control that requires another
                                       control which is not enabled)
      9. BENIGN_COMBINATION           (individually benign capabilities
                                       whose composition is unsafe)
     10. UNEXPECTED_TRUST_DIRECTION   (trust flowing toward more
                                       sensitive resources)
  * Candidate carries: component ids, edge ids, supporting signals,
    rationale, severity, confidence class, novelty class, and an
    explicit `not_a_compromise_claim=True` invariant
  * Findings roll-up
  * Machine-checkable discovery invariants
  * In-memory + SQLite stores
  * Phase-29 engine facade
  * Full test suite + manual runner

Doctrine: this phase produces *candidate novel attack surface* — a
hypothesis with provenance — NOT a compromise claim. Every candidate
explicitly asserts `not_a_compromise_claim=True`.

This is NEW attack-surface-discovery technology. It is NOT another
scan engine. It systematically composes observed entities, trust,
authority, dependencies, tool invocations, states, and controls
to propose surfaces that were not enumerated beforehand.

No third-party dependencies.

Run tests:
    python hydra_phase29_novel_attack_surface_discovery.py
    pytest hydra_phase29_novel_attack_surface_discovery.py -q
"""
from __future__ import annotations

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


class Zone(str, Enum):
    PUBLIC = "public"
    GUEST = "guest"
    INTERNAL = "internal"
    RESTRICTED = "restricted"
    CRITICAL = "critical"


_ZONE_RANK: Mapping[Zone, int] = {
    Zone.PUBLIC: 0,
    Zone.GUEST: 1,
    Zone.INTERNAL: 2,
    Zone.RESTRICTED: 3,
    Zone.CRITICAL: 4,
}


def zone_rank(z: Zone) -> int:
    return _ZONE_RANK[z]


class NodeKind(str, Enum):
    PRINCIPAL = "principal"
    AGENT = "agent"
    TOOL = "tool"
    SERVICE = "service"
    DATASET = "dataset"
    CONTROL = "control"
    DEVICE = "device"


class EdgeKind(str, Enum):
    TRUSTS = "trusts"
    DELEGATES_TO = "delegates_to"
    DEPENDS_ON = "depends_on"
    CALLS = "calls"
    CONTROLS = "controls"


class SurfaceKind(str, Enum):
    TRUST_TRANSITIVITY = "trust_transitivity"
    CROSS_ZONE_TRUST = "cross_zone_trust"
    TRUST_CYCLE = "trust_cycle"
    AUTHORITY_CHAIN = "authority_chain"
    HIDDEN_DEPENDENCY = "hidden_dependency"
    TOOL_PATHWAY = "tool_pathway"
    STATE_COMBINATION = "state_combination"
    CONTROL_INTERACTION = "control_interaction"
    BENIGN_COMBINATION = "benign_combination"
    UNEXPECTED_TRUST_DIRECTION = "unexpected_trust_direction"


class ConfidenceClass(str, Enum):
    SPECULATIVE = "speculative"
    INFERRED = "inferred"
    OBSERVED = "observed"


class NoveltyClass(str, Enum):
    VARIANT_OF_KNOWN = "variant_of_known"
    NEW_COMBINATION = "new_combination"
    NEWLY_OBSERVED = "newly_observed"


# --- Known dangerous state combinations (individually benign) ---------------

_DANGEROUS_STATE_COMBOS: Tuple[
    Tuple[Tuple[str, str], ...], ...
] = (
    (("debug", "on"), ("env", "production")),
    (("auth_mfa", "off"), ("env", "production")),
    (("network_egress", "unrestricted"), ("data_class", "secret")),
    (("model_guardrails", "off"), ("agent_autonomy", "high")),
    (("audit_logging", "off"), ("data_class", "regulated")),
)

# --- Known dangerous capability sets (individually benign) -----------------

_DANGEROUS_CAPABILITY_SETS: Tuple[FrozenSet[str], ...] = (
    frozenset({"data_read", "network_egress"}),
    frozenset({"data_read", "network_egress", "no_human_review"}),
    frozenset({"credential_access", "network_egress"}),
    frozenset({"execute_code", "network_egress"}),
    frozenset({"data_write", "credential_access"}),
    frozenset({"agent_autonomy_high", "data_read", "network_egress"}),
)


# =============================================================================
# SECTION 3 — ENTITY + EDGE
# =============================================================================


@dataclass(frozen=True)
class EntityNode:
    node_id: str
    kind: NodeKind
    name: str
    zone: Zone
    sensitivity: int                  # 0..4
    capabilities: FrozenSet[str]
    tags: FrozenSet[str] = frozenset()
    states: Mapping[str, str] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.node_id:
            raise ValueError("node_id is required")
        if not self.name:
            raise ValueError("name is required")
        if not 0 <= self.sensitivity <= 4:
            raise ValueError("sensitivity must be in [0,4]")


@dataclass(frozen=True)
class Edge:
    edge_id: str
    src_id: str
    dst_id: str
    kind: EdgeKind
    weight: float = 1.0
    at: Optional[datetime] = None
    declared: bool = True           # whether the relationship is declared
    detail: str = ""

    def __post_init__(self) -> None:
        if not self.edge_id:
            raise ValueError("edge_id is required")
        if not self.src_id or not self.dst_id:
            raise ValueError("src_id and dst_id are required")
        if self.src_id == self.dst_id:
            raise ValueError("self-edges are not allowed")
        if not 0.0 <= self.weight <= 1.0:
            raise ValueError("weight must be within [0,1]")
        if self.at is not None and self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


# =============================================================================
# SECTION 4 — CANDIDATE
# =============================================================================


@dataclass(frozen=True)
class NovelSurfaceCandidate:
    candidate_id: str
    kind: SurfaceKind
    confidence: ConfidenceClass
    novelty: NoveltyClass
    component_ids: Tuple[str, ...]
    edge_ids: Tuple[str, ...]
    supporting_signals: Tuple[str, ...]
    rationale: str
    severity: int
    not_a_compromise_claim: bool
    at: datetime

    def __post_init__(self) -> None:
        if not self.candidate_id:
            raise ValueError("candidate_id is required")
        if not self.component_ids:
            raise ValueError("component_ids must be non-empty")
        if self.not_a_compromise_claim is not True:
            raise ValueError(
                "candidates must not claim compromise "
                "(not_a_compromise_claim must be True)"
            )
        if not 1 <= self.severity <= 5:
            raise ValueError("severity must be in [1,5]")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


# =============================================================================
# SECTION 5 — GRAPH
# =============================================================================


class DiscoveryGraph:
    """Typed, directed graph over entities with bounded traversal helpers."""

    def __init__(self) -> None:
        self._nodes: Dict[str, EntityNode] = {}
        self._edges: Dict[str, Edge] = {}
        self._out: Dict[str, List[str]] = defaultdict(list)
        self._in: Dict[str, List[str]] = defaultdict(list)
        self._out_by_kind: Dict[EdgeKind, Dict[str, List[str]]] = {
            k: defaultdict(list) for k in EdgeKind
        }

    # ---- nodes ----------------------------------------------------------

    def add_node(self, node: EntityNode) -> None:
        if node.node_id in self._nodes:
            raise ValueError(f"node {node.node_id} already exists")
        self._nodes[node.node_id] = node

    def node(self, node_id: str) -> EntityNode:
        n = self._nodes.get(node_id)
        if n is None:
            raise KeyError(f"unknown node {node_id}")
        return n

    def nodes(self) -> Tuple[EntityNode, ...]:
        return tuple(self._nodes.values())

    def has_node(self, node_id: str) -> bool:
        return node_id in self._nodes

    # ---- edges ----------------------------------------------------------

    def add_edge(self, edge: Edge) -> None:
        if edge.edge_id in self._edges:
            raise ValueError(f"edge {edge.edge_id} already exists")
        if edge.src_id not in self._nodes:
            raise KeyError(f"src {edge.src_id} not registered")
        if edge.dst_id not in self._nodes:
            raise KeyError(f"dst {edge.dst_id} not registered")
        self._edges[edge.edge_id] = edge
        self._out[edge.src_id].append(edge.edge_id)
        self._in[edge.dst_id].append(edge.edge_id)
        self._out_by_kind[edge.kind][edge.src_id].append(edge.edge_id)

    def edge(self, edge_id: str) -> Edge:
        e = self._edges.get(edge_id)
        if e is None:
            raise KeyError(f"unknown edge {edge_id}")
        return e

    def edges(self) -> Tuple[Edge, ...]:
        return tuple(self._edges.values())

    def out_edges(
        self, node_id: str, kind: Optional[EdgeKind] = None,
    ) -> Tuple[Edge, ...]:
        if kind is None:
            return tuple(self._edges[eid] for eid in self._out.get(node_id, ()))
        return tuple(
            self._edges[eid]
            for eid in self._out_by_kind[kind].get(node_id, ())
        )

    def in_edges(
        self, node_id: str, kind: Optional[EdgeKind] = None,
    ) -> Tuple[Edge, ...]:
        return tuple(
            self._edges[eid]
            for eid in self._in.get(node_id, ())
            if kind is None or self._edges[eid].kind is kind
        )

    def children(
        self, node_id: str, kind: Optional[EdgeKind] = None,
    ) -> Tuple[str, ...]:
        return tuple(e.dst_id for e in self.out_edges(node_id, kind))

    def parents(
        self, node_id: str, kind: Optional[EdgeKind] = None,
    ) -> Tuple[str, ...]:
        return tuple(e.src_id for e in self.in_edges(node_id, kind))

    def has_edge(
        self, src_id: str, dst_id: str, kind: EdgeKind,
    ) -> bool:
        for e in self.out_edges(src_id, kind):
            if e.dst_id == dst_id:
                return True
        return False

    # ---- bounded traversal ----------------------------------------------

    def reachable_edges(
        self, start: str, *,
        kinds: FrozenSet[EdgeKind],
        max_depth: int = 4,
    ) -> Tuple[Tuple[Edge, ...], ...]:
        """Bounded DFS enumeration of edge-paths (edge sequences)."""
        if max_depth < 1:
            raise ValueError("max_depth must be >= 1")
        results: List[Tuple[Edge, ...]] = []

        def visit(cur: str, path: Tuple[Edge, ...]) -> None:
            if len(path) >= max_depth:
                return
            for eid in self._out.get(cur, ()):
                e = self._edges[eid]
                if e.kind not in kinds:
                    continue
                new_path = path + (e,)
                results.append(new_path)
                visit(e.dst_id, new_path)

        visit(start, ())
        return tuple(results)

    def capability_closure(
        self, start: str, *,
        kinds: FrozenSet[EdgeKind] = frozenset({
            EdgeKind.CALLS, EdgeKind.DELEGATES_TO,
        }),
        max_depth: int = 5,
    ) -> FrozenSet[str]:
        """Union of capabilities of all nodes reachable via given edges."""
        caps: set = set()
        seen: set = {start}
        q: deque = deque([(start, 0)])
        while q:
            cur, depth = q.popleft()
            if depth >= max_depth:
                continue
            for e in self.out_edges(cur):
                if e.kind not in kinds:
                    continue
                caps.update(self._nodes[e.dst_id].capabilities)
                if e.dst_id not in seen:
                    seen.add(e.dst_id)
                    q.append((e.dst_id, depth + 1))
        return frozenset(caps)

    def strongly_connected_components(
        self, *, kinds: FrozenSet[EdgeKind],
    ) -> Tuple[Tuple[str, ...], ...]:
        """Tarjan's SCC restricted to the given edge kinds."""
        index_counter = [0]
        stack: List[str] = []
        on_stack: Dict[str, bool] = {}
        index: Dict[str, int] = {}
        lowlink: Dict[str, int] = {}
        result: List[Tuple[str, ...]] = []

        # Restricted adjacency (deterministic)
        adj: Dict[str, List[str]] = {
            nid: [e.dst_id for e in self.out_edges(nid) if e.kind in kinds]
            for nid in self._nodes
        }

        def strongconnect(v: str) -> None:
            index[v] = index_counter[0]
            lowlink[v] = index_counter[0]
            index_counter[0] += 1
            stack.append(v)
            on_stack[v] = True
            for w in sorted(adj.get(v, ())):
                if w not in index:
                    strongconnect(w)
                    lowlink[v] = min(lowlink[v], lowlink[w])
                elif on_stack.get(w, False):
                    lowlink[v] = min(lowlink[v], index[w])
            if lowlink[v] == index[v]:
                comp: List[str] = []
                while True:
                    w = stack.pop()
                    on_stack[w] = False
                    comp.append(w)
                    if w == v:
                        break
                result.append(tuple(sorted(comp)))

        for v in sorted(self._nodes):
            if v not in index:
                strongconnect(v)
        return tuple(result)

    # ---- indexes --------------------------------------------------------

    def nodes_of_kind(self, kind: NodeKind) -> Tuple[EntityNode, ...]:
        return tuple(n for n in self._nodes.values() if n.kind is kind)


# =============================================================================
# SECTION 6 — DISCOVERY CONFIG
# =============================================================================


@dataclass(frozen=True)
class DiscoveryConfig:
    trust_transitivity_threshold: float = 0.4
    trust_transitivity_depth: int = 2
    cross_zone_trust_uphill: bool = True      # trust flowing to stronger zone
    authority_chain_max_length: int = 4
    hidden_dependency_min_sensitivity: int = 3
    tool_pathway_max_length: int = 3
    benign_combination_min_component_count: int = 2
    unexpected_trust_sensitivity_gap: int = 2
    max_candidates: int = 5000

    def __post_init__(self) -> None:
        if not 0.0 <= self.trust_transitivity_threshold <= 1.0:
            raise ValueError("threshold must be within [0,1]")
        if self.trust_transitivity_depth < 2:
            raise ValueError("trust_transitivity_depth must be >= 2")
        if self.authority_chain_max_length < 1:
            raise ValueError("authority_chain_max_length must be >= 1")
        if not 0 <= self.hidden_dependency_min_sensitivity <= 4:
            raise ValueError("sensitivity threshold must be in [0,4]")
        if self.tool_pathway_max_length < 1:
            raise ValueError("tool_pathway_max_length must be >= 1")
        if self.benign_combination_min_component_count < 2:
            raise ValueError("min component count must be >= 2")
        if not 0 <= self.unexpected_trust_sensitivity_gap <= 4:
            raise ValueError("sensitivity gap must be in [0,4]")
        if self.max_candidates < 1:
            raise ValueError("max_candidates must be >= 1")


# =============================================================================
# SECTION 7 — DISCOVERY RULES
# =============================================================================


def _candidate_id(kind: SurfaceKind, components: Sequence[str]) -> str:
    return f"{kind.value}:{'|'.join(sorted(components))}"


def _mk_candidate(
    *,
    kind: SurfaceKind,
    confidence: ConfidenceClass,
    components: Sequence[str],
    edges: Sequence[str],
    signals: Sequence[str],
    rationale: str,
    severity: int,
    at: datetime,
) -> NovelSurfaceCandidate:
    return NovelSurfaceCandidate(
        candidate_id=_candidate_id(kind, components),
        kind=kind,
        confidence=confidence,
        novelty=NoveltyClass.NEWLY_OBSERVED,
        component_ids=tuple(sorted(components)),
        edge_ids=tuple(sorted(edges)),
        supporting_signals=tuple(signals),
        rationale=rationale,
        severity=severity,
        not_a_compromise_claim=True,
        at=at,
    )


# --- 1. Trust transitivity --------------------------------------------------


def discover_trust_transitivity(
    g: DiscoveryGraph,
    *,
    config: DiscoveryConfig,
    at: datetime,
) -> List[NovelSurfaceCandidate]:
    out: List[NovelSurfaceCandidate] = []
    trust_edges = [e for e in g.edges() if e.kind is EdgeKind.TRUSTS]

    # A →TRUSTS→ B →TRUSTS→ C with no direct A →TRUSTS→ C
    for e1 in trust_edges:
        a, b = e1.src_id, e1.dst_id
        for e2 in g.out_edges(b, EdgeKind.TRUSTS):
            c = e2.dst_id
            if c == a:
                continue
            if g.has_edge(a, c, EdgeKind.TRUSTS):
                continue
            effective = e1.weight * e2.weight
            if effective < config.trust_transitivity_threshold:
                continue
            # Higher severity when the effective trust lands in a
            # more sensitive destination.
            sev = 3 if g.node(c).sensitivity > g.node(a).sensitivity else 2
            out.append(_mk_candidate(
                kind=SurfaceKind.TRUST_TRANSITIVITY,
                confidence=ConfidenceClass.INFERRED,
                components=(a, b, c),
                edges=(e1.edge_id, e2.edge_id),
                signals=(
                    f"effective_trust={effective:.3f}",
                    f"threshold={config.trust_transitivity_threshold:.3f}",
                ),
                rationale=(
                    f"{a} trusts {b} trusts {c}; no declared A→C trust; "
                    f"effective={effective:.3f}"
                ),
                severity=sev, at=at,
            ))
    return out


# --- 2. Cross-zone trust ----------------------------------------------------


def discover_cross_zone_trust(
    g: DiscoveryGraph,
    *,
    config: DiscoveryConfig,
    at: datetime,
) -> List[NovelSurfaceCandidate]:
    out: List[NovelSurfaceCandidate] = []
    for e in g.edges():
        if e.kind is not EdgeKind.TRUSTS:
            continue
        a = g.node(e.src_id)
        b = g.node(e.dst_id)
        if a.zone is b.zone:
            continue
        # The unusual case: a source in a *weaker* zone trusts a
        # destination in a *stronger* zone (trust flowing uphill).
        src_rank = zone_rank(a.zone)
        dst_rank = zone_rank(b.zone)
        if config.cross_zone_trust_uphill and dst_rank > src_rank:
            out.append(_mk_candidate(
                kind=SurfaceKind.CROSS_ZONE_TRUST,
                confidence=ConfidenceClass.OBSERVED,
                components=(a.node_id, b.node_id),
                edges=(e.edge_id,),
                signals=(
                    f"src_zone={a.zone.value}",
                    f"dst_zone={b.zone.value}",
                    f"weight={e.weight:.2f}",
                ),
                rationale=(
                    f"trust from {a.zone.value} (rank {src_rank}) to "
                    f"{b.zone.value} (rank {dst_rank}) flows uphill"
                ),
                severity=3, at=at,
            ))
    return out


# --- 3. Trust cycle ---------------------------------------------------------


def discover_trust_cycles(
    g: DiscoveryGraph, *, at: datetime,
) -> List[NovelSurfaceCandidate]:
    sccs = g.strongly_connected_components(
        kinds=frozenset({EdgeKind.TRUSTS}),
    )
    out: List[NovelSurfaceCandidate] = []
    for comp in sccs:
        if len(comp) < 2:
            continue
        # Collect edges inside the SCC
        comp_set = set(comp)
        edges: List[str] = []
        for nid in comp:
            for e in g.out_edges(nid, EdgeKind.TRUSTS):
                if e.dst_id in comp_set:
                    edges.append(e.edge_id)
        out.append(_mk_candidate(
            kind=SurfaceKind.TRUST_CYCLE,
            confidence=ConfidenceClass.OBSERVED,
            components=tuple(comp),
            edges=tuple(edges),
            signals=(
                f"component_size={len(comp)}",
                f"component={list(comp)}",
            ),
            rationale=(
                f"trust strongly-connected component of size {len(comp)} "
                f"({list(comp)}) — mutual reinforcement"
            ),
            severity=3, at=at,
        ))
    return out


# --- 4. Authority chain -----------------------------------------------------


def discover_authority_chains(
    g: DiscoveryGraph,
    *,
    config: DiscoveryConfig,
    at: datetime,
) -> List[NovelSurfaceCandidate]:
    out: List[NovelSurfaceCandidate] = []
    deleg_kinds = frozenset({EdgeKind.DELEGATES_TO})
    for principal in g.nodes_of_kind(NodeKind.PRINCIPAL):
        # capabilities reached via DELEGATES_TO edges only
        reachable_caps: Set[str] = set()
        reached_via: Dict[str, Tuple[str, ...]] = {}
        for path in g.reachable_edges(
            principal.node_id,
            kinds=deleg_kinds,
            max_depth=config.authority_chain_max_length,
        ):
            last = path[-1]
            for cap in g.node(last.dst_id).capabilities:
                reachable_caps.add(cap)
                if cap not in reached_via:
                    reached_via[cap] = tuple(e.edge_id for e in path)
        undeclared = reachable_caps - principal.capabilities
        for cap in sorted(undeclared):
            edge_ids = reached_via.get(cap, ())
            out.append(_mk_candidate(
                kind=SurfaceKind.AUTHORITY_CHAIN,
                confidence=ConfidenceClass.INFERRED,
                components=(principal.node_id,),
                edges=edge_ids,
                signals=(
                    f"capability={cap}",
                    f"chain_length={len(edge_ids)}",
                ),
                rationale=(
                    f"{principal.node_id} can reach capability {cap} "
                    f"via {len(edge_ids)} delegation edge(s) without "
                    f"declaring it"
                ),
                severity=4, at=at,
            ))
    return out


# --- 5. Hidden dependency ---------------------------------------------------


def discover_hidden_dependencies(
    g: DiscoveryGraph,
    *,
    config: DiscoveryConfig,
    at: datetime,
) -> List[NovelSurfaceCandidate]:
    out: List[NovelSurfaceCandidate] = []
    for e1 in [e for e in g.edges() if e.kind is EdgeKind.DEPENDS_ON]:
        a, b = e1.src_id, e1.dst_id
        for e2 in g.out_edges(b, EdgeKind.DEPENDS_ON):
            c = e2.dst_id
            if c == a:
                continue
            if g.has_edge(a, c, EdgeKind.DEPENDS_ON):
                continue
            tc = g.node(c)
            if tc.sensitivity < config.hidden_dependency_min_sensitivity \
               and "critical" not in tc.tags:
                continue
            out.append(_mk_candidate(
                kind=SurfaceKind.HIDDEN_DEPENDENCY,
                confidence=ConfidenceClass.INFERRED,
                components=(a, b, c),
                edges=(e1.edge_id, e2.edge_id),
                signals=(
                    f"dst_sensitivity={tc.sensitivity}",
                    f"dst_tags={sorted(tc.tags)}",
                ),
                rationale=(
                    f"{a} → {b} → {c} but {a} never declared {c}; "
                    f"{c} is critical"
                ),
                severity=3, at=at,
            ))
    return out


# --- 6. Tool pathway --------------------------------------------------------


def discover_tool_pathways(
    g: DiscoveryGraph,
    *,
    config: DiscoveryConfig,
    at: datetime,
) -> List[NovelSurfaceCandidate]:
    out: List[NovelSurfaceCandidate] = []
    call_kinds = frozenset({EdgeKind.CALLS})
    for agent in g.nodes_of_kind(NodeKind.AGENT):
        for path in g.reachable_edges(
            agent.node_id,
            kinds=call_kinds,
            max_depth=config.tool_pathway_max_length,
        ):
            # Only consider paths that begin and end with a CALLS edge
            # and pass through a tool.
            if not any(
                g.node(e.src_id).kind is NodeKind.TOOL
                or g.node(e.dst_id).kind is NodeKind.TOOL
                for e in path
            ):
                continue
            first, last = path[0], path[-1]
            # Compute capability composition
            caps = set()
            for e in path:
                caps.update(g.node(e.dst_id).capabilities)
            # Flag when the reachable composition contains any dangerous set
            matched_sets: List[str] = []
            for ds in _DANGEROUS_CAPABILITY_SETS:
                if ds.issubset(caps):
                    matched_sets.append("+".join(sorted(ds)))
            if not matched_sets:
                continue
            out.append(_mk_candidate(
                kind=SurfaceKind.TOOL_PATHWAY,
                confidence=ConfidenceClass.INFERRED,
                components=tuple(
                    [agent.node_id] + [e.dst_id for e in path]
                ),
                edges=tuple(e.edge_id for e in path),
                signals=(
                    f"path_length={len(path)}",
                    f"dangerous_sets={matched_sets}",
                ),
                rationale=(
                    f"agent {agent.node_id} reaches composite capability "
                    f"via tool pathway: {matched_sets}"
                ),
                severity=4, at=at,
            ))
    return out


# --- 7. State combination ---------------------------------------------------


def discover_state_combinations(
    g: DiscoveryGraph, *, at: datetime,
) -> List[NovelSurfaceCandidate]:
    out: List[NovelSurfaceCandidate] = []
    for node in g.nodes():
        for combo in _DANGEROUS_STATE_COMBOS:
            if all(
                node.states.get(k) == v for (k, v) in combo
            ):
                comps = (node.node_id,)
                sig = "+".join(f"{k}={v}" for (k, v) in combo)
                out.append(_mk_candidate(
                    kind=SurfaceKind.STATE_COMBINATION,
                    confidence=ConfidenceClass.OBSERVED,
                    components=comps,
                    edges=(),
                    signals=(f"state_combo={sig}",),
                    rationale=(
                        f"{node.node_id} carries individually benign "
                        f"states whose combination is dangerous: {sig}"
                    ),
                    severity=4, at=at,
                ))
    return out


# --- 8. Control interaction -------------------------------------------------


def discover_control_interactions(
    g: DiscoveryGraph, *, at: datetime,
) -> List[NovelSurfaceCandidate]:
    out: List[NovelSurfaceCandidate] = []
    controls = g.nodes_of_kind(NodeKind.CONTROL)
    by_id = {c.node_id: c for c in controls}
    for c in controls:
        # A control may declare required peers via its tags:
        #   requires:<peer_id>
        required_ids = [
            t.split(":", 1)[1]
            for t in c.tags
            if t.startswith("requires:")
        ]
        if not required_ids:
            continue
        enabled = c.states.get("enabled", "on") == "on"
        if not enabled:
            continue
        for req in required_ids:
            peer = by_id.get(req)
            if peer is None:
                continue
            peer_enabled = peer.states.get("enabled", "on") == "on"
            if peer_enabled:
                continue
            out.append(_mk_candidate(
                kind=SurfaceKind.CONTROL_INTERACTION,
                confidence=ConfidenceClass.OBSERVED,
                components=(c.node_id, peer.node_id),
                edges=(),
                signals=(
                    f"control={c.node_id}",
                    f"required_peer={peer.node_id}",
                    f"peer_enabled={peer_enabled}",
                ),
                rationale=(
                    f"{c.node_id} is enabled but requires "
                    f"{peer.node_id} which is disabled"
                ),
                severity=5, at=at,
            ))
    return out


# --- 9. Benign combination --------------------------------------------------


def discover_benign_combinations(
    g: DiscoveryGraph,
    *,
    config: DiscoveryConfig,
    at: datetime,
) -> List[NovelSurfaceCandidate]:
    out: List[NovelSurfaceCandidate] = []
    call_or_deleg = frozenset({EdgeKind.CALLS, EdgeKind.DELEGATES_TO})
    for node in g.nodes():
        # Direct capabilities
        direct = set(node.capabilities)
        # Composite capabilities through call/delegate chain
        composite = set(g.capability_closure(
            node.node_id, kinds=call_or_deleg,
        ))
        all_caps = direct | composite
        for ds in _DANGEROUS_CAPABILITY_SETS:
            if not ds.issubset(all_caps):
                continue
            # Require the composition to involve more than one node,
            # and require the individually-benign property: each
            # capability on its own must not be in the dangerous set
            # — i.e. at least one capability is only reachable
            # through the composite path.
            only_via_composite = ds & composite - direct
            if not only_via_composite:
                continue
            if len(ds) < config.benign_combination_min_component_count:
                continue
            sig = "+".join(sorted(ds))
            out.append(_mk_candidate(
                kind=SurfaceKind.BENIGN_COMBINATION,
                confidence=ConfidenceClass.INFERRED,
                components=(node.node_id,),
                edges=(),
                signals=(
                    f"dangerous_set={sig}",
                    f"only_via_composite={sorted(only_via_composite)}",
                ),
                rationale=(
                    f"{node.node_id} composes individually benign "
                    f"capabilities into an unsafe set: {sig}"
                ),
                severity=4, at=at,
            ))
    return out


# --- 10. Unexpected trust direction -----------------------------------------


def discover_unexpected_trust_direction(
    g: DiscoveryGraph,
    *,
    config: DiscoveryConfig,
    at: datetime,
) -> List[NovelSurfaceCandidate]:
    out: List[NovelSurfaceCandidate] = []
    for e in g.edges():
        if e.kind is not EdgeKind.TRUSTS:
            continue
        a = g.node(e.src_id)
        b = g.node(e.dst_id)
        gap = b.sensitivity - a.sensitivity
        if gap < config.unexpected_trust_sensitivity_gap:
            continue
        # Only unusual if A is not flagged as a broker.
        if "broker" in a.tags:
            continue
        out.append(_mk_candidate(
            kind=SurfaceKind.UNEXPECTED_TRUST_DIRECTION,
            confidence=ConfidenceClass.OBSERVED,
            components=(a.node_id, b.node_id),
            edges=(e.edge_id,),
            signals=(
                f"src_sensitivity={a.sensitivity}",
                f"dst_sensitivity={b.sensitivity}",
                f"gap={gap}",
            ),
            rationale=(
                f"trust from {a.node_id} (sens {a.sensitivity}) flows "
                f"toward more sensitive {b.node_id} (sens {b.sensitivity})"
            ),
            severity=3, at=at,
        ))
    return out


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
class DiscoverySnapshot:
    graph: DiscoveryGraph
    candidates: Tuple[NovelSurfaceCandidate, ...]


@dataclass(frozen=True)
class DiscoveryInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[DiscoverySnapshot],
                        Tuple[InvariantViolation, ...]]
    description: str


def _inv_no_compromise_claim(
    snap: DiscoverySnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for c in snap.candidates:
        if c.not_a_compromise_claim is not True:
            out.append(InvariantViolation(
                invariant_id="disc.no_compromise_claim",
                severity=InvariantSeverity.CRITICAL,
                subject_id=c.candidate_id,
                detail="candidate claims compromise",
            ))
    return tuple(out)


def _inv_candidates_have_provenance(
    snap: DiscoverySnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for c in snap.candidates:
        if not c.component_ids:
            out.append(InvariantViolation(
                invariant_id="disc.candidates_have_provenance",
                severity=InvariantSeverity.HIGH,
                subject_id=c.candidate_id,
                detail="candidate has no components",
            ))
        if not c.supporting_signals:
            out.append(InvariantViolation(
                invariant_id="disc.candidates_have_provenance",
                severity=InvariantSeverity.HIGH,
                subject_id=c.candidate_id,
                detail="candidate has no supporting signals",
            ))
    return tuple(out)


def _inv_components_registered(
    snap: DiscoverySnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for c in snap.candidates:
        for nid in c.component_ids:
            if not snap.graph.has_node(nid):
                out.append(InvariantViolation(
                    invariant_id="disc.components_registered",
                    severity=InvariantSeverity.CRITICAL,
                    subject_id=c.candidate_id,
                    detail=f"component {nid} not in graph",
                ))
    return tuple(out)


def _inv_edges_registered(
    snap: DiscoverySnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for c in snap.candidates:
        for eid in c.edge_ids:
            try:
                snap.graph.edge(eid)
            except KeyError:
                out.append(InvariantViolation(
                    invariant_id="disc.edges_registered",
                    severity=InvariantSeverity.CRITICAL,
                    subject_id=c.candidate_id,
                    detail=f"edge {eid} not in graph",
                ))
    return tuple(out)


def _inv_severity_bounded(
    snap: DiscoverySnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for c in snap.candidates:
        if not 1 <= c.severity <= 5:
            out.append(InvariantViolation(
                invariant_id="disc.severity_bounded",
                severity=InvariantSeverity.HIGH,
                subject_id=c.candidate_id,
                detail=f"severity {c.severity}",
            ))
    return tuple(out)


DEFAULT_INVARIANTS: Tuple[DiscoveryInvariant, ...] = (
    DiscoveryInvariant(
        invariant_id="disc.no_compromise_claim",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_no_compromise_claim,
        description="Every candidate must declare no-compromise.",
    ),
    DiscoveryInvariant(
        invariant_id="disc.candidates_have_provenance",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_candidates_have_provenance,
        description="Candidates must carry components and signals.",
    ),
    DiscoveryInvariant(
        invariant_id="disc.components_registered",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_components_registered,
        description="Candidate components must be registered in the graph.",
    ),
    DiscoveryInvariant(
        invariant_id="disc.edges_registered",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_edges_registered,
        description="Candidate edges must be registered in the graph.",
    ),
    DiscoveryInvariant(
        invariant_id="disc.severity_bounded",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_severity_bounded,
        description="Severity must lie within [1,5].",
    ),
)


def check_invariants(
    snap: DiscoverySnapshot,
    invariants: Iterable[DiscoveryInvariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 9 — STORE
# =============================================================================


@dataclass(frozen=True)
class CandidateRecord:
    candidate_id: str
    kind: SurfaceKind
    confidence: ConfidenceClass
    novelty: NoveltyClass
    component_count: int
    severity: int
    updated_at: datetime


class DiscoveryStore(Protocol):
    def put(self, record: CandidateRecord) -> None: ...
    def get(self, candidate_id: str) -> Optional[CandidateRecord]: ...
    def all(self) -> Tuple[CandidateRecord, ...]: ...


class InMemoryDiscoveryStore:
    def __init__(self) -> None:
        self._data: Dict[str, CandidateRecord] = {}

    def put(self, record: CandidateRecord) -> None:
        existing = self._data.get(record.candidate_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._data[record.candidate_id] = record

    def get(self, candidate_id: str) -> Optional[CandidateRecord]:
        return self._data.get(candidate_id)

    def all(self) -> Tuple[CandidateRecord, ...]:
        return tuple(self._data.values())


class SqliteDiscoveryStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS disc_candidates (
                candidate_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                confidence TEXT NOT NULL,
                novelty TEXT NOT NULL,
                component_count INTEGER NOT NULL,
                severity INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS disc_signatures (
                signature TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                first_seen_at TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def put(self, record: CandidateRecord) -> None:
        existing = self.get(record.candidate_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._conn.execute(
            """
            INSERT INTO disc_candidates
              (candidate_id, kind, confidence, novelty, component_count,
               severity, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(candidate_id) DO UPDATE SET
              kind=excluded.kind,
              confidence=excluded.confidence,
              novelty=excluded.novelty,
              component_count=excluded.component_count,
              severity=excluded.severity,
              updated_at=excluded.updated_at
            """,
            (
                record.candidate_id, record.kind.value,
                record.confidence.value, record.novelty.value,
                record.component_count, record.severity,
                record.updated_at.isoformat(),
            ),
        )
        self._conn.commit()

    def get(self, candidate_id: str) -> Optional[CandidateRecord]:
        row = self._conn.execute(
            "SELECT kind, confidence, novelty, component_count, severity, "
            "updated_at FROM disc_candidates WHERE candidate_id = ?",
            (candidate_id,),
        ).fetchone()
        if row is None:
            return None
        return CandidateRecord(
            candidate_id=candidate_id, kind=SurfaceKind(row[0]),
            confidence=ConfidenceClass(row[1]),
            novelty=NoveltyClass(row[2]),
            component_count=int(row[3]),
            severity=int(row[4]),
            updated_at=datetime.fromisoformat(row[5]),
        )

    def all(self) -> Tuple[CandidateRecord, ...]:
        rows = self._conn.execute(
            "SELECT candidate_id FROM disc_candidates"
        ).fetchall()
        return tuple(
            r for r in (self.get(x[0]) for x in rows) if r is not None
        )

    def record_signature(
        self, signature: str, kind: SurfaceKind, at: datetime,
    ) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO disc_signatures "
            "(signature, kind, first_seen_at) VALUES (?, ?, ?)",
            (signature, kind.value, at.isoformat()),
        )
        self._conn.commit()

    def signature_known(self, signature: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM disc_signatures WHERE signature = ?",
            (signature,),
        ).fetchone()
        return row is not None


# =============================================================================
# SECTION 10 — ENGINE
# =============================================================================


class NovelSurfaceDiscoveryEngine:
    """Discovery engine for candidate novel attack surfaces."""

    def __init__(
        self,
        *,
        store: Optional[DiscoveryStore] = None,
        config: Optional[DiscoveryConfig] = None,
    ) -> None:
        self._store: DiscoveryStore = store or InMemoryDiscoveryStore()
        self._config = config or DiscoveryConfig()
        self._graph = DiscoveryGraph()
        self._candidates: Tuple[NovelSurfaceCandidate, ...] = ()
        self._violations: Tuple[InvariantViolation, ...] = ()
        self._seen_signatures: Set[Tuple[SurfaceKind, Tuple[str, ...]]] = set()

    # ---- registration ----------------------------------------------------

    def add_node(self, node: EntityNode) -> None:
        self._graph.add_node(node)

    def add_edge(self, edge: Edge) -> None:
        self._graph.add_edge(edge)

    def graph(self) -> DiscoveryGraph:
        return self._graph

    def config(self) -> DiscoveryConfig:
        return self._config

    def set_config(self, config: DiscoveryConfig) -> None:
        self._config = config

    def reset_novelty(self) -> None:
        self._seen_signatures = set()

    # ---- discovery ------------------------------------------------------

    def recompute(
        self, *, at: datetime,
    ) -> Tuple[NovelSurfaceCandidate, ...]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        cfg = self._config

        raw: List[NovelSurfaceCandidate] = []
        raw.extend(discover_trust_transitivity(
            self._graph, config=cfg, at=at,
        ))
        raw.extend(discover_cross_zone_trust(
            self._graph, config=cfg, at=at,
        ))
        raw.extend(discover_trust_cycles(self._graph, at=at))
        raw.extend(discover_authority_chains(
            self._graph, config=cfg, at=at,
        ))
        raw.extend(discover_hidden_dependencies(
            self._graph, config=cfg, at=at,
        ))
        raw.extend(discover_tool_pathways(
            self._graph, config=cfg, at=at,
        ))
        raw.extend(discover_state_combinations(self._graph, at=at))
        raw.extend(discover_control_interactions(self._graph, at=at))
        raw.extend(discover_benign_combinations(
            self._graph, config=cfg, at=at,
        ))
        raw.extend(discover_unexpected_trust_direction(
            self._graph, config=cfg, at=at,
        ))

        # Novelty labelling against in-memory seen set
        labelled: List[NovelSurfaceCandidate] = []
        for c in raw:
            sig = (c.kind, c.component_ids)
            if sig in self._seen_signatures:
                novelty = NoveltyClass.NEW_COMBINATION
            else:
                # Is this kind seen at all with different components?
                kind_seen = any(
                    s[0] is c.kind for s in self._seen_signatures
                )
                novelty = (
                    NoveltyClass.VARIANT_OF_KNOWN if kind_seen
                    else NoveltyClass.NEWLY_OBSERVED
                )
            labelled.append(NovelSurfaceCandidate(
                candidate_id=c.candidate_id, kind=c.kind,
                confidence=c.confidence, novelty=novelty,
                component_ids=c.component_ids, edge_ids=c.edge_ids,
                supporting_signals=c.supporting_signals,
                rationale=c.rationale, severity=c.severity,
                not_a_compromise_claim=True, at=c.at,
            ))

        # Deduplicate by candidate_id (same signature may be produced by
        # multiple rules — keep the first, deterministic ordering).
        dedup: Dict[str, NovelSurfaceCandidate] = {}
        for c in labelled:
            dedup.setdefault(c.candidate_id, c)

        # Sort by severity desc, then kind, then id — deterministic.
        ordered = sorted(
            dedup.values(),
            key=lambda c: (-c.severity, c.kind.value, c.candidate_id),
        )
        if len(ordered) > cfg.max_candidates:
            ordered = ordered[: cfg.max_candidates]

        self._candidates = tuple(ordered)

        # Persist + update signatures
        for c in self._candidates:
            rec = CandidateRecord(
                candidate_id=c.candidate_id, kind=c.kind,
                confidence=c.confidence, novelty=c.novelty,
                component_count=len(c.component_ids),
                severity=c.severity, updated_at=at,
            )
            self._store.put(rec)
            self._seen_signatures.add((c.kind, c.component_ids))

        self._violations = check_invariants(self.snapshot())
        return self._candidates

    # ---- queries ---------------------------------------------------------

    def candidates(self) -> Tuple[NovelSurfaceCandidate, ...]:
        return self._candidates

    def candidates_of_kind(
        self, kind: SurfaceKind,
    ) -> Tuple[NovelSurfaceCandidate, ...]:
        return tuple(c for c in self._candidates if c.kind is kind)

    def top_candidates(
        self, *, k: int = 10,
    ) -> Tuple[NovelSurfaceCandidate, ...]:
        if k <= 0:
            raise ValueError("k must be > 0")
        return tuple(self._candidates[:k])

    def findings_by_kind(self) -> Mapping[SurfaceKind, int]:
        out: Dict[SurfaceKind, int] = {k: 0 for k in SurfaceKind}
        for c in self._candidates:
            out[c.kind] += 1
        return out

    def findings_by_confidence(self) -> Mapping[ConfidenceClass, int]:
        out: Dict[ConfidenceClass, int] = {k: 0 for k in ConfidenceClass}
        for c in self._candidates:
            out[c.confidence] += 1
        return out

    def findings_by_novelty(self) -> Mapping[NoveltyClass, int]:
        out: Dict[NoveltyClass, int] = {k: 0 for k in NoveltyClass}
        for c in self._candidates:
            out[c.novelty] += 1
        return out

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return self._violations

    def record(self, candidate_id: str) -> Optional[CandidateRecord]:
        return self._store.get(candidate_id)

    def snapshot(self) -> DiscoverySnapshot:
        return DiscoverySnapshot(
            graph=self._graph,
            candidates=self._candidates,
        )


# =============================================================================
# SECTION 11 — TESTS
# =============================================================================


def _t0() -> datetime:
    from datetime import timezone
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _node(
    nid: str, kind: NodeKind = NodeKind.SERVICE, *,
    name: Optional[str] = None,
    zone: Zone = Zone.INTERNAL,
    sensitivity: int = 1,
    capabilities: Iterable[str] = (),
    tags: Iterable[str] = (),
    states: Optional[Mapping[str, str]] = None,
) -> EntityNode:
    return EntityNode(
        node_id=nid, kind=kind, name=name or nid, zone=zone,
        sensitivity=sensitivity,
        capabilities=frozenset(capabilities),
        tags=frozenset(tags),
        states=dict(states or {}),
    )


def _edge(
    eid: str, src: str, dst: str,
    kind: EdgeKind = EdgeKind.DEPENDS_ON,
    weight: float = 1.0,
    *,
    declared: bool = True,
) -> Edge:
    return Edge(
        edge_id=eid, src_id=src, dst_id=dst, kind=kind,
        weight=weight, at=_t0(), declared=declared,
    )


# ---- domain ----

def test_node_requires_id() -> None:
    try:
        EntityNode(
            node_id="", kind=NodeKind.SERVICE, name="n",
            zone=Zone.INTERNAL, sensitivity=0,
            capabilities=frozenset(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_node_sensitivity_bounds() -> None:
    try:
        _node("a", sensitivity=5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_edge_self_rejected() -> None:
    try:
        Edge(
            edge_id="e", src_id="a", dst_id="a",
            kind=EdgeKind.DEPENDS_ON, at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_edge_weight_bounds() -> None:
    try:
        _edge("e", "a", "b", weight=1.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_zone_rank_monotonic() -> None:
    assert zone_rank(Zone.PUBLIC) < zone_rank(Zone.INTERNAL)
    assert zone_rank(Zone.INTERNAL) < zone_rank(Zone.CRITICAL)


def test_candidate_requires_no_compromise() -> None:
    try:
        NovelSurfaceCandidate(
            candidate_id="c", kind=SurfaceKind.TRUST_TRANSITIVITY,
            confidence=ConfidenceClass.INFERRED,
            novelty=NoveltyClass.NEWLY_OBSERVED,
            component_ids=("a",), edge_ids=(),
            supporting_signals=("s",), rationale="x",
            severity=3, not_a_compromise_claim=False, at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- graph ----

def test_graph_duplicate_node_rejected() -> None:
    g = DiscoveryGraph()
    g.add_node(_node("a"))
    try:
        g.add_node(_node("a"))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_graph_duplicate_edge_rejected() -> None:
    g = DiscoveryGraph()
    g.add_node(_node("a"))
    g.add_node(_node("b"))
    g.add_edge(_edge("e", "a", "b"))
    try:
        g.add_edge(_edge("e", "a", "b"))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_graph_unknown_endpoint_rejected() -> None:
    g = DiscoveryGraph()
    g.add_node(_node("a"))
    try:
        g.add_edge(_edge("e", "a", "ghost"))
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_graph_children_and_parents() -> None:
    g = DiscoveryGraph()
    g.add_node(_node("a"))
    g.add_node(_node("b"))
    g.add_edge(_edge("e", "a", "b"))
    assert g.children("a") == ("b",)
    assert g.parents("b") == ("a",)


def test_graph_children_filtered_by_kind() -> None:
    g = DiscoveryGraph()
    g.add_node(_node("a"))
    g.add_node(_node("b"))
    g.add_node(_node("c"))
    g.add_edge(_edge("e1", "a", "b", kind=EdgeKind.TRUSTS))
    g.add_edge(_edge("e2", "a", "c", kind=EdgeKind.DEPENDS_ON))
    assert g.children("a", EdgeKind.TRUSTS) == ("b",)
    assert g.children("a", EdgeKind.DEPENDS_ON) == ("c",)


def test_graph_scc_finds_cycle() -> None:
    g = DiscoveryGraph()
    g.add_node(_node("a"))
    g.add_node(_node("b"))
    g.add_node(_node("c"))
    g.add_edge(_edge("e1", "a", "b", kind=EdgeKind.TRUSTS))
    g.add_edge(_edge("e2", "b", "c", kind=EdgeKind.TRUSTS))
    g.add_edge(_edge("e3", "c", "a", kind=EdgeKind.TRUSTS))
    sccs = g.strongly_connected_components(
        kinds=frozenset({EdgeKind.TRUSTS}),
    )
    assert any(len(s) >= 2 for s in sccs)


# ---- rule 1: trust transitivity ----

def test_trust_transitivity_detected() -> None:
    g = DiscoveryGraph()
    g.add_node(_node("a"))
    g.add_node(_node("b"))
    g.add_node(_node("c", sensitivity=3))
    g.add_edge(_edge("e1", "a", "b", kind=EdgeKind.TRUSTS, weight=0.9))
    g.add_edge(_edge("e2", "b", "c", kind=EdgeKind.TRUSTS, weight=0.9))
    out = discover_trust_transitivity(
        g, config=DiscoveryConfig(), at=_t0(),
    )
    assert len(out) == 1
    assert out[0].kind is SurfaceKind.TRUST_TRANSITIVITY


def test_trust_transitivity_skips_when_declared() -> None:
    g = DiscoveryGraph()
    g.add_node(_node("a"))
    g.add_node(_node("b"))
    g.add_node(_node("c"))
    g.add_edge(_edge("e1", "a", "b", kind=EdgeKind.TRUSTS, weight=0.9))
    g.add_edge(_edge("e2", "b", "c", kind=EdgeKind.TRUSTS, weight=0.9))
    g.add_edge(_edge("e3", "a", "c", kind=EdgeKind.TRUSTS, weight=0.9))
    out = discover_trust_transitivity(
        g, config=DiscoveryConfig(), at=_t0(),
    )
    assert out == []


def test_trust_transitivity_skips_below_threshold() -> None:
    g = DiscoveryGraph()
    g.add_node(_node("a"))
    g.add_node(_node("b"))
    g.add_node(_node("c"))
    g.add_edge(_edge("e1", "a", "b", kind=EdgeKind.TRUSTS, weight=0.3))
    g.add_edge(_edge("e2", "b", "c", kind=EdgeKind.TRUSTS, weight=0.3))
    out = discover_trust_transitivity(
        g, config=DiscoveryConfig(trust_transitivity_threshold=0.5),
        at=_t0(),
    )
    assert out == []


# ---- rule 2: cross-zone trust ----

def test_cross_zone_trust_uphill_flagged() -> None:
    g = DiscoveryGraph()
    g.add_node(_node("a", zone=Zone.GUEST))
    g.add_node(_node("b", zone=Zone.CRITICAL))
    g.add_edge(_edge("e", "a", "b", kind=EdgeKind.TRUSTS))
    out = discover_cross_zone_trust(
        g, config=DiscoveryConfig(), at=_t0(),
    )
    assert len(out) == 1
    assert out[0].kind is SurfaceKind.CROSS_ZONE_TRUST


def test_cross_zone_trust_downhill_not_flagged() -> None:
    g = DiscoveryGraph()
    g.add_node(_node("a", zone=Zone.CRITICAL))
    g.add_node(_node("b", zone=Zone.INTERNAL))
    g.add_edge(_edge("e", "a", "b", kind=EdgeKind.TRUSTS))
    out = discover_cross_zone_trust(
        g, config=DiscoveryConfig(), at=_t0(),
    )
    assert out == []


def test_cross_zone_trust_same_zone_not_flagged() -> None:
    g = DiscoveryGraph()
    g.add_node(_node("a", zone=Zone.INTERNAL))
    g.add_node(_node("b", zone=Zone.INTERNAL))
    g.add_edge(_edge("e", "a", "b", kind=EdgeKind.TRUSTS))
    assert discover_cross_zone_trust(
        g, config=DiscoveryConfig(), at=_t0(),
    ) == []


# ---- rule 3: trust cycle ----

def test_trust_cycle_detected() -> None:
    g = DiscoveryGraph()
    g.add_node(_node("a"))
    g.add_node(_node("b"))
    g.add_node(_node("c"))
    g.add_edge(_edge("e1", "a", "b", kind=EdgeKind.TRUSTS))
    g.add_edge(_edge("e2", "b", "c", kind=EdgeKind.TRUSTS))
    g.add_edge(_edge("e3", "c", "a", kind=EdgeKind.TRUSTS))
    out = discover_trust_cycles(g, at=_t0())
    assert len(out) == 1
    assert out[0].kind is SurfaceKind.TRUST_CYCLE


def test_trust_cycle_none_when_acyclic() -> None:
    g = DiscoveryGraph()
    g.add_node(_node("a"))
    g.add_node(_node("b"))
    g.add_node(_node("c"))
    g.add_edge(_edge("e1", "a", "b", kind=EdgeKind.TRUSTS))
    g.add_edge(_edge("e2", "b", "c", kind=EdgeKind.TRUSTS))
    assert discover_trust_cycles(g, at=_t0()) == []


# ---- rule 4: authority chain ----

def test_authority_chain_detected() -> None:
    g = DiscoveryGraph()
    g.add_node(_node(
        "user", NodeKind.PRINCIPAL,
        capabilities=frozenset({"read"}),
    ))
    g.add_node(_node(
        "svc", NodeKind.SERVICE,
        capabilities=frozenset({"admin_write"}),
    ))
    g.add_edge(_edge("e", "user", "svc", kind=EdgeKind.DELEGATES_TO))
    out = discover_authority_chains(
        g, config=DiscoveryConfig(), at=_t0(),
    )
    assert len(out) == 1
    assert out[0].kind is SurfaceKind.AUTHORITY_CHAIN


def test_authority_chain_no_undeclared_capability() -> None:
    g = DiscoveryGraph()
    g.add_node(_node(
        "user", NodeKind.PRINCIPAL,
        capabilities=frozenset({"read", "admin_write"}),
    ))
    g.add_node(_node(
        "svc", NodeKind.SERVICE,
        capabilities=frozenset({"admin_write"}),
    ))
    g.add_edge(_edge("e", "user", "svc", kind=EdgeKind.DELEGATES_TO))
    assert discover_authority_chains(
        g, config=DiscoveryConfig(), at=_t0(),
    ) == []


# ---- rule 5: hidden dependency ----

def test_hidden_dependency_detected() -> None:
    g = DiscoveryGraph()
    g.add_node(_node("a"))
    g.add_node(_node("b"))
    g.add_node(_node("c", sensitivity=4, tags=("critical",)))
    g.add_edge(_edge("e1", "a", "b"))
    g.add_edge(_edge("e2", "b", "c"))
    out = discover_hidden_dependencies(
        g, config=DiscoveryConfig(), at=_t0(),
    )
    assert len(out) == 1
    assert out[0].kind is SurfaceKind.HIDDEN_DEPENDENCY


def test_hidden_dependency_skips_when_declared() -> None:
    g = DiscoveryGraph()
    g.add_node(_node("a"))
    g.add_node(_node("b"))
    g.add_node(_node("c", sensitivity=4))
    g.add_edge(_edge("e1", "a", "b"))
    g.add_edge(_edge("e2", "b", "c"))
    g.add_edge(_edge("e3", "a", "c"))
    assert discover_hidden_dependencies(
        g, config=DiscoveryConfig(), at=_t0(),
    ) == []


def test_hidden_dependency_skips_low_sensitivity() -> None:
    g = DiscoveryGraph()
    g.add_node(_node("a"))
    g.add_node(_node("b"))
    g.add_node(_node("c", sensitivity=1))
    g.add_edge(_edge("e1", "a", "b"))
    g.add_edge(_edge("e2", "b", "c"))
    assert discover_hidden_dependencies(
        g, config=DiscoveryConfig(), at=_t0(),
    ) == []


# ---- rule 6: tool pathway ----

def test_tool_pathway_detected() -> None:
    g = DiscoveryGraph()
    g.add_node(_node("agent1", NodeKind.AGENT,
                     capabilities=frozenset({"agent_autonomy_high"})))
    g.add_node(_node("tool1", NodeKind.TOOL,
                     capabilities=frozenset({"data_read"})))
    g.add_node(_node("agent2", NodeKind.AGENT))
    g.add_node(_node("tool2", NodeKind.TOOL,
                     capabilities=frozenset({"network_egress"})))
    g.add_edge(_edge("e1", "agent1", "tool1", kind=EdgeKind.CALLS))
    g.add_edge(_edge("e2", "tool1", "agent2", kind=EdgeKind.CALLS))
    g.add_edge(_edge("e3", "agent2", "tool2", kind=EdgeKind.CALLS))
    out = discover_tool_pathways(
        g, config=DiscoveryConfig(), at=_t0(),
    )
    assert len(out) >= 1
    assert out[0].kind is SurfaceKind.TOOL_PATHWAY


def test_tool_pathway_absent_when_caps_benign() -> None:
    g = DiscoveryGraph()
    g.add_node(_node("agent1", NodeKind.AGENT))
    g.add_node(_node("tool1", NodeKind.TOOL,
                     capabilities=frozenset({"data_read"})))
    g.add_edge(_edge("e", "agent1", "tool1", kind=EdgeKind.CALLS))
    assert discover_tool_pathways(
        g, config=DiscoveryConfig(), at=_t0(),
    ) == []


# ---- rule 7: state combination ----

def test_state_combination_detected() -> None:
    g = DiscoveryGraph()
    g.add_node(_node(
        "svc", states={"debug": "on", "env": "production"},
    ))
    out = discover_state_combinations(g, at=_t0())
    assert len(out) == 1
    assert out[0].kind is SurfaceKind.STATE_COMBINATION


def test_state_combination_absent_when_benign() -> None:
    g = DiscoveryGraph()
    g.add_node(_node(
        "svc", states={"debug": "off", "env": "production"},
    ))
    assert discover_state_combinations(g, at=_t0()) == []


# ---- rule 8: control interaction ----

def test_control_interaction_detected() -> None:
    g = DiscoveryGraph()
    g.add_node(_node(
        "c1", NodeKind.CONTROL, tags=("requires:c2",),
        states={"enabled": "on"},
    ))
    g.add_node(_node(
        "c2", NodeKind.CONTROL, states={"enabled": "off"},
    ))
    out = discover_control_interactions(g, at=_t0())
    assert len(out) == 1
    assert out[0].kind is SurfaceKind.CONTROL_INTERACTION


def test_control_interaction_absent_when_both_enabled() -> None:
    g = DiscoveryGraph()
    g.add_node(_node(
        "c1", NodeKind.CONTROL, tags=("requires:c2",),
        states={"enabled": "on"},
    ))
    g.add_node(_node(
        "c2", NodeKind.CONTROL, states={"enabled": "on"},
    ))
    assert discover_control_interactions(g, at=_t0()) == []


def test_control_interaction_absent_when_control_disabled() -> None:
    g = DiscoveryGraph()
    g.add_node(_node(
        "c1", NodeKind.CONTROL, tags=("requires:c2",),
        states={"enabled": "off"},
    ))
    g.add_node(_node(
        "c2", NodeKind.CONTROL, states={"enabled": "off"},
    ))
    assert discover_control_interactions(g, at=_t0()) == []


# ---- rule 9: benign combination ----

def test_benign_combination_detected() -> None:
    g = DiscoveryGraph()
    g.add_node(_node(
        "agent", NodeKind.AGENT,
        capabilities=frozenset({"data_read"}),
    ))
    g.add_node(_node(
        "tool", NodeKind.TOOL,
        capabilities=frozenset({"network_egress"}),
    ))
    g.add_edge(_edge("e", "agent", "tool", kind=EdgeKind.CALLS))
    out = discover_benign_combinations(
        g, config=DiscoveryConfig(), at=_t0(),
    )
    assert any(
        c.kind is SurfaceKind.BENIGN_COMBINATION for c in out
    )


def test_benign_combination_absent_when_direct_has_dangerous() -> None:
    g = DiscoveryGraph()
    g.add_node(_node(
        "agent", NodeKind.AGENT,
        capabilities=frozenset({"data_read", "network_egress"}),
    ))
    out = discover_benign_combinations(
        g, config=DiscoveryConfig(), at=_t0(),
    )
    assert out == []


# ---- rule 10: unexpected trust direction ----

def test_unexpected_trust_direction_flagged() -> None:
    g = DiscoveryGraph()
    g.add_node(_node("a", sensitivity=0))
    g.add_node(_node("b", sensitivity=4))
    g.add_edge(_edge("e", "a", "b", kind=EdgeKind.TRUSTS))
    out = discover_unexpected_trust_direction(
        g, config=DiscoveryConfig(), at=_t0(),
    )
    assert len(out) == 1
    assert out[0].kind is SurfaceKind.UNEXPECTED_TRUST_DIRECTION


def test_unexpected_trust_direction_skips_broker() -> None:
    g = DiscoveryGraph()
    g.add_node(_node("a", sensitivity=0, tags=("broker",)))
    g.add_node(_node("b", sensitivity=4))
    g.add_edge(_edge("e", "a", "b", kind=EdgeKind.TRUSTS))
    assert discover_unexpected_trust_direction(
        g, config=DiscoveryConfig(), at=_t0(),
    ) == []


def test_unexpected_trust_direction_skips_small_gap() -> None:
    g = DiscoveryGraph()
    g.add_node(_node("a", sensitivity=3))
    g.add_node(_node("b", sensitivity=4))
    g.add_edge(_edge("e", "a", "b", kind=EdgeKind.TRUSTS))
    assert discover_unexpected_trust_direction(
        g, config=DiscoveryConfig(), at=_t0(),
    ) == []


# ---- engine ----

def test_engine_adds_nodes_and_edges() -> None:
    eng = NovelSurfaceDiscoveryEngine()
    eng.add_node(_node("a"))
    eng.add_node(_node("b"))
    eng.add_edge(_edge("e", "a", "b"))
    assert len(eng.graph().edges()) == 1


def test_engine_recompute_requires_aware_time() -> None:
    from datetime import datetime as dt
    eng = NovelSurfaceDiscoveryEngine()
    try:
        eng.recompute(at=dt(2026, 1, 1))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_no_candidates_on_empty_graph() -> None:
    eng = NovelSurfaceDiscoveryEngine()
    out = eng.recompute(at=_t0())
    assert out == ()


def test_engine_multiple_rules_fire() -> None:
    eng = NovelSurfaceDiscoveryEngine()
    for n in (
        _node("a", sensitivity=0),
        _node("b", sensitivity=4),
        _node("c", sensitivity=3),
    ):
        eng.add_node(n)
    eng.add_edge(_edge("e1", "a", "b", kind=EdgeKind.TRUSTS))
    eng.add_edge(_edge("e2", "b", "c", kind=EdgeKind.TRUSTS))
    out = eng.recompute(at=_t0())
    kinds = {c.kind for c in out}
    assert SurfaceKind.TRUST_TRANSITIVITY in kinds or \
        SurfaceKind.UNEXPECTED_TRUST_DIRECTION in kinds


def test_engine_novelty_newly_observed_first_run() -> None:
    eng = NovelSurfaceDiscoveryEngine()
    eng.add_node(_node("a", sensitivity=0))
    eng.add_node(_node("b", sensitivity=4))
    eng.add_edge(_edge("e", "a", "b", kind=EdgeKind.TRUSTS))
    out = eng.recompute(at=_t0())
    assert any(
        c.novelty is NoveltyClass.NEWLY_OBSERVED for c in out
    )


def test_engine_novelty_new_combination_second_run() -> None:
    eng = NovelSurfaceDiscoveryEngine()
    eng.add_node(_node("a", sensitivity=0))
    eng.add_node(_node("b", sensitivity=4))
    eng.add_edge(_edge("e", "a", "b", kind=EdgeKind.TRUSTS))
    eng.recompute(at=_t0())
    # Second run with same graph → NEW_COMBINATION
    out = eng.recompute(at=_t0())
    assert any(
        c.novelty is NoveltyClass.NEW_COMBINATION for c in out
    )


def test_engine_reset_novelty() -> None:
    eng = NovelSurfaceDiscoveryEngine()
    eng.add_node(_node("a", sensitivity=0))
    eng.add_node(_node("b", sensitivity=4))
    eng.add_edge(_edge("e", "a", "b", kind=EdgeKind.TRUSTS))
    eng.recompute(at=_t0())
    eng.reset_novelty()
    out = eng.recompute(at=_t0())
    assert any(
        c.novelty is NoveltyClass.NEWLY_OBSERVED for c in out
    )


def test_engine_candidates_of_kind() -> None:
    eng = NovelSurfaceDiscoveryEngine()
    eng.add_node(_node("a", sensitivity=0))
    eng.add_node(_node("b", sensitivity=4))
    eng.add_edge(_edge("e", "a", "b", kind=EdgeKind.TRUSTS))
    eng.recompute(at=_t0())
    trust_dir = eng.candidates_of_kind(
        SurfaceKind.UNEXPECTED_TRUST_DIRECTION,
    )
    assert len(trust_dir) >= 1


def test_engine_top_candidates_invalid_k() -> None:
    eng = NovelSurfaceDiscoveryEngine()
    try:
        eng.top_candidates(k=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_findings_by_kind_and_confidence() -> None:
    eng = NovelSurfaceDiscoveryEngine()
    eng.add_node(_node(
        "svc", states={"debug": "on", "env": "production"},
    ))
    eng.recompute(at=_t0())
    by_kind = eng.findings_by_kind()
    assert by_kind[SurfaceKind.STATE_COMBINATION] >= 1
    by_conf = eng.findings_by_confidence()
    assert by_conf[ConfidenceClass.OBSERVED] >= 1


def test_engine_record_lookup() -> None:
    eng = NovelSurfaceDiscoveryEngine()
    eng.add_node(_node(
        "svc", states={"debug": "on", "env": "production"},
    ))
    out = eng.recompute(at=_t0())
    rec = eng.record(out[0].candidate_id)
    assert rec is not None
    assert rec.kind is SurfaceKind.STATE_COMBINATION


def test_engine_max_candidates_bound() -> None:
    eng = NovelSurfaceDiscoveryEngine(
        config=DiscoveryConfig(max_candidates=2),
    )
    eng.add_node(_node(
        "svc", states={"debug": "on", "env": "production",
                       "auth_mfa": "off"},
    ))
    out = eng.recompute(at=_t0())
    assert len(out) <= 2


def test_engine_deterministic_ordering() -> None:
    eng1 = NovelSurfaceDiscoveryEngine()
    eng2 = NovelSurfaceDiscoveryEngine()
    for eng in (eng1, eng2):
        for n in (
            _node("a", sensitivity=0),
            _node("b", sensitivity=4),
        ):
            eng.add_node(n)
        eng.add_edge(_edge("e", "a", "b", kind=EdgeKind.TRUSTS))
    out1 = eng1.recompute(at=_t0())
    out2 = eng2.recompute(at=_t0())
    assert [c.candidate_id for c in out1] == \
        [c.candidate_id for c in out2]


# ---- invariants ----

def test_invariant_clean_snapshot() -> None:
    eng = NovelSurfaceDiscoveryEngine()
    eng.add_node(_node(
        "svc", states={"debug": "on", "env": "production"},
    ))
    eng.recompute(at=_t0())
    assert eng.violations() == ()


def test_invariant_candidate_components_must_exist() -> None:
    # Craft a candidate referencing missing components
    g = DiscoveryGraph()
    g.add_node(_node("a"))
    bad = NovelSurfaceCandidate(
        candidate_id="c", kind=SurfaceKind.TRUST_CYCLE,
        confidence=ConfidenceClass.INFERRED,
        novelty=NoveltyClass.NEWLY_OBSERVED,
        component_ids=("ghost",), edge_ids=(),
        supporting_signals=("s",), rationale="x", severity=3,
        not_a_compromise_claim=True, at=_t0(),
    )
    snap = DiscoverySnapshot(graph=g, candidates=(bad,))
    v = check_invariants(snap)
    assert any(
        x.invariant_id == "disc.components_registered" for x in v
    )


def test_invariant_candidate_edges_must_exist() -> None:
    g = DiscoveryGraph()
    g.add_node(_node("a"))
    bad = NovelSurfaceCandidate(
        candidate_id="c", kind=SurfaceKind.TRUST_CYCLE,
        confidence=ConfidenceClass.INFERRED,
        novelty=NoveltyClass.NEWLY_OBSERVED,
        component_ids=("a",), edge_ids=("ghost-edge",),
        supporting_signals=("s",), rationale="x", severity=3,
        not_a_compromise_claim=True, at=_t0(),
    )
    snap = DiscoverySnapshot(graph=g, candidates=(bad,))
    v = check_invariants(snap)
    assert any(
        x.invariant_id == "disc.edges_registered" for x in v
    )


# ---- store ----

def test_in_memory_store_rejects_stale() -> None:
    s = InMemoryDiscoveryStore()
    t = _t0()
    s.put(CandidateRecord(
        "c1", SurfaceKind.TRUST_CYCLE, ConfidenceClass.OBSERVED,
        NoveltyClass.NEWLY_OBSERVED, 3, 3, t,
    ))
    earlier = t.replace(year=t.year - 1)
    try:
        s.put(CandidateRecord(
            "c1", SurfaceKind.TRUST_CYCLE, ConfidenceClass.OBSERVED,
            NoveltyClass.NEWLY_OBSERVED, 3, 3, earlier,
        ))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "disc.db")
    store = SqliteDiscoveryStore(db)
    store.put(CandidateRecord(
        "c1", SurfaceKind.TRUST_CYCLE, ConfidenceClass.INFERRED,
        NoveltyClass.NEWLY_OBSERVED, 3, 3, _t0(),
    ))
    got = store.get("c1")
    assert got is not None
    assert got.kind is SurfaceKind.TRUST_CYCLE


def test_sqlite_store_signature_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "disc.db")
    store = SqliteDiscoveryStore(db)
    assert not store.signature_known("sig1")
    store.record_signature("sig1", SurfaceKind.TRUST_CYCLE, _t0())
    assert store.signature_known("sig1")


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
