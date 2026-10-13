"""
HYDRA POST-CORE — PHASE 24: CROSS-LAYER SECURITY CAUSALITY
=============================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * Domain — 13 abstraction-ranked layers, 10 semantic relationship
    kinds, direction semantics (upward/downward/lateral)
  * Cross-layer causal graph — edges carry *semantic relationship*
    labels in addition to strength/confidence
  * Stack model with expected mediators — for any (from, to) pair
    the layers that *should* mediate the causality
  * Path analysis:
      - path layers (full stack trace)
      - expected vs actual mediators
      - bypass detection (a required layer was skipped)
      - upward / downward / mixed direction classification
      - stack coverage (how many distinct layers a chain touches)
  * Convergence analysis — multiple origins → same effect
  * Findings — HIGH_IMPACT_CROSS_LAYER, LAYER_BYPASS, STACK_DISCONTINUITY,
    CONVERGENCE, DOWNWARD_VIOLATION, DECORATIVE_LAYER
  * Machine-checkable cross-layer invariants
  * In-memory + SQLite stores
  * Phase-24 engine facade
  * Full test suite + manual runner

Purpose: unify security causality across the full stack — hardware →
firmware → OS → network → identity → application → API → cloud →
container → data → AI → agent → supply chain — on top of the existing
causal foundation (Phase 17). We do NOT create a separate causal engine;
we extend cross-layer semantics.

No third-party dependencies.

Run tests:
    python hydra_phase24_cross_layer_security_causality.py
    pytest hydra_phase24_cross_layer_security_causality.py -q
"""
from __future__ import annotations

import json
import math
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


class Layer(str, Enum):
    """Abstraction-ranked security layers.

    rank is a global ordering: 0 = most concrete (physical hardware),
    12 = most abstract (autonomous agents). This gives us a total
    order to classify edge direction (upward / downward / lateral).
    """
    HARDWARE = "hardware"
    FIRMWARE = "firmware"
    OS = "os"
    CONTAINER = "container"
    NETWORK = "network"
    CLOUD = "cloud"
    SUPPLY_CHAIN = "supply_chain"
    IDENTITY = "identity"
    APPLICATION = "application"
    API = "api"
    DATA = "data"
    AI = "ai"
    AGENT = "agent"


ALL_LAYERS: Tuple[Layer, ...] = tuple(Layer)


_LAYER_RANK: Mapping[Layer, int] = {
    Layer.HARDWARE: 0,
    Layer.FIRMWARE: 1,
    Layer.OS: 2,
    Layer.CONTAINER: 3,
    Layer.NETWORK: 4,
    Layer.CLOUD: 5,
    Layer.SUPPLY_CHAIN: 6,
    Layer.IDENTITY: 7,
    Layer.APPLICATION: 8,
    Layer.API: 9,
    Layer.DATA: 10,
    Layer.AI: 11,
    Layer.AGENT: 12,
}


def layer_rank(layer: Layer) -> int:
    return _LAYER_RANK[layer]


class Direction(str, Enum):
    UPWARD = "upward"
    DOWNWARD = "downward"
    LATERAL = "lateral"


def edge_direction(src: Layer, dst: Layer) -> Direction:
    a, b = layer_rank(src), layer_rank(dst)
    if b > a:
        return Direction.UPWARD
    if b < a:
        return Direction.DOWNWARD
    return Direction.LATERAL


class RelationshipKind(str, Enum):
    """Semantic relationships between layers.

    These are stricter than Phase-17 causal edges: they carry an
    explicit *meaning* about the nature of the cross-layer dependency.
    """
    ANCHORS = "anchors"            # lower provides root of trust
    ROOTS = "roots"                # establishes a platform baseline
    CARRIES = "carries"            # transports a context
    BINDS = "binds"                # binds identity to a resource
    EXPOSES = "exposes"            # makes a surface available
    CONSUMES = "consumes"          # uses a resource
    PERSISTS_TO = "persists_to"    # writes state downstream
    DERIVES_FROM = "derives_from"  # built from another artifact
    DELEGATES_TO = "delegates_to"  # hands off authority
    MEDIATES = "mediates"          # inserts a control between two layers


# Direction constraints per relationship kind. This is the invariant we
# enforce: certain relationships only make sense in a given direction.
_RELATIONSHIP_DIRECTION: Mapping[RelationshipKind, Direction] = {
    RelationshipKind.ANCHORS: Direction.UPWARD,
    RelationshipKind.ROOTS: Direction.UPWARD,
    RelationshipKind.CARRIES: Direction.UPWARD,
    RelationshipKind.BINDS: Direction.UPWARD,
    RelationshipKind.EXPOSES: Direction.UPWARD,
    RelationshipKind.CONSUMES: Direction.UPWARD,
    RelationshipKind.PERSISTS_TO: Direction.UPWARD,
    RelationshipKind.DERIVES_FROM: Direction.UPWARD,
    RelationshipKind.DELEGATES_TO: Direction.UPWARD,
    # MEDIATES can be upward or lateral (a control layer sits between
    # two other layers on the same path).
}


def relationship_allows(
    kind: RelationshipKind, src: Layer, dst: Layer,
) -> bool:
    direction = edge_direction(src, dst)
    expected = _RELATIONSHIP_DIRECTION.get(kind)
    if expected is None:
        return True
    return expected is direction


class CauseCategory(str, Enum):
    MALICIOUS = "malicious"
    FAILURE = "failure"
    MISCONFIGURATION = "misconfiguration"
    UNKNOWN = "unknown"


class CrossLayerFindingKind(str, Enum):
    HIGH_IMPACT_CROSS_LAYER_CHAIN = "high_impact_cross_layer_chain"
    LAYER_BYPASS = "layer_bypass"
    STACK_DISCONTINUITY = "stack_discontinuity"
    CONVERGENCE = "convergence"
    DOWNWARD_VIOLATION = "downward_violation"
    DECORATIVE_LAYER = "decorative_layer"
    RELATIONSHIP_DIRECTION_VIOLATION = "relationship_direction_violation"
    ANALYSIS_TRUNCATED = "analysis_truncated"


@dataclass(frozen=True)
class CrossLayerFinding:
    kind: CrossLayerFindingKind
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
# SECTION 3 — GRAPH ELEMENTS
# =============================================================================


@dataclass(frozen=True)
class CrossLayerNode:
    node_id: str
    layer: Layer
    entity_id: str
    label: str
    at: datetime

    def __post_init__(self) -> None:
        if not self.node_id:
            raise ValueError("node_id is required")
        if not self.entity_id:
            raise ValueError("entity_id is required")
        if not self.label:
            raise ValueError("label is required")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


@dataclass(frozen=True)
class CrossLayerEdge:
    edge_id: str
    src_id: str
    dst_id: str
    relationship: RelationshipKind
    strength: float
    confidence: float
    provenance: str
    at: datetime

    def __post_init__(self) -> None:
        if not self.edge_id:
            raise ValueError("edge_id is required")
        if not self.src_id or not self.dst_id:
            raise ValueError("src_id and dst_id are required")
        if self.src_id == self.dst_id:
            raise ValueError("self-edges are not allowed")
        if not 0.0 <= self.strength <= 1.0:
            raise ValueError("strength must be within [0,1]")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be within [0,1]")
        if not self.provenance:
            raise ValueError("provenance is required")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

    @property
    def weighted_strength(self) -> float:
        return self.strength * self.confidence


# =============================================================================
# SECTION 4 — GRAPH
# =============================================================================


class CrossLayerGraph:
    """Directed cross-layer causal graph.

    Nodes carry a Layer (with an abstraction rank). Edges carry a
    semantic RelationshipKind and a direction that must be consistent
    with that relationship.
    """

    def __init__(self) -> None:
        self._nodes: Dict[str, CrossLayerNode] = {}
        self._out: Dict[str, List[CrossLayerEdge]] = {}
        self._in: Dict[str, List[CrossLayerEdge]] = {}
        self._edges: Dict[str, CrossLayerEdge] = {}

    # ---- nodes -----------------------------------------------------------

    def add_node(self, node: CrossLayerNode) -> None:
        if node.node_id in self._nodes:
            raise ValueError(f"node {node.node_id} already exists")
        self._nodes[node.node_id] = node
        self._out.setdefault(node.node_id, [])
        self._in.setdefault(node.node_id, [])

    def node(self, node_id: str) -> CrossLayerNode:
        n = self._nodes.get(node_id)
        if n is None:
            raise KeyError(f"unknown node {node_id}")
        return n

    def nodes(self) -> Tuple[CrossLayerNode, ...]:
        return tuple(self._nodes.values())

    def nodes_of_layer(self, layer: Layer) -> Tuple[CrossLayerNode, ...]:
        return tuple(n for n in self._nodes.values() if n.layer is layer)

    def present_layers(self) -> FrozenSet[Layer]:
        return frozenset(n.layer for n in self._nodes.values())

    # ---- edges -----------------------------------------------------------

    def add_edge(self, edge: CrossLayerEdge) -> None:
        if edge.edge_id in self._edges:
            raise ValueError(f"edge {edge.edge_id} already exists")
        if edge.src_id not in self._nodes:
            raise KeyError(f"src {edge.src_id} not registered")
        if edge.dst_id not in self._nodes:
            raise KeyError(f"dst {edge.dst_id} not registered")

        src = self._nodes[edge.src_id]
        dst = self._nodes[edge.dst_id]
        if not relationship_allows(edge.relationship, src.layer, dst.layer):
            raise ValueError(
                f"relationship {edge.relationship.value} is not valid "
                f"from {src.layer.value} → {dst.layer.value}"
            )

        if self._would_create_cycle(edge.src_id, edge.dst_id):
            raise ValueError(
                f"cross-layer edge {edge.src_id}->{edge.dst_id} "
                f"creates a cycle"
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
            for e in self._out.get(cur, []):
                stack.append(e.dst_id)
        return False

    def edge(self, edge_id: str) -> CrossLayerEdge:
        e = self._edges.get(edge_id)
        if e is None:
            raise KeyError(f"unknown edge {edge_id}")
        return e

    def edges(self) -> Tuple[CrossLayerEdge, ...]:
        return tuple(self._edges.values())

    def out_edges(self, node_id: str) -> Tuple[CrossLayerEdge, ...]:
        return tuple(self._out.get(node_id, []))

    def in_edges(self, node_id: str) -> Tuple[CrossLayerEdge, ...]:
        return tuple(self._in.get(node_id, []))

    def parents(self, node_id: str) -> Tuple[str, ...]:
        return tuple(e.src_id for e in self._in.get(node_id, []))

    def children(self, node_id: str) -> Tuple[str, ...]:
        return tuple(e.dst_id for e in self._out.get(node_id, []))

    # ---- path enumeration -------------------------------------------------

    def enumerate_paths(
        self,
        *,
        source_id: Optional[str] = None,
        target_id: Optional[str] = None,
        max_depth: int = 6,
        max_paths: int = 500,
        min_strength: float = 0.05,
    ) -> Tuple[Tuple[CrossLayerEdge, ...], ...]:
        if max_depth < 1:
            raise ValueError("max_depth must be >= 1")
        if max_paths < 1:
            raise ValueError("max_paths must be >= 1")
        if not 0.0 <= min_strength <= 1.0:
            raise ValueError("min_strength must be within [0,1]")

        if source_id is not None:
            self.node(source_id)
            starts: Sequence[str] = [source_id]
        else:
            starts = tuple(
                nid for nid in self._nodes if not self._in.get(nid)
            )

        results: List[Tuple[CrossLayerEdge, ...]] = []
        self._last_enumeration_truncated = False
        for s in starts:
            self._dfs(
                s, (), max_depth, min_strength, target_id, results,
                max_paths,
            )
            if len(results) >= max_paths:
                self._last_enumeration_truncated = True
                break
        return tuple(results[:max_paths])

    def _dfs(
        self,
        node_id: str,
        path: Tuple[CrossLayerEdge, ...],
        max_depth: int,
        min_strength: float,
        target_id: Optional[str],
        out: List[Tuple[CrossLayerEdge, ...]],
        max_paths: int,
    ) -> None:
        if len(out) >= max_paths:
            return
        if len(path) == max_depth:
            return
        for edge in self._out.get(node_id, []):
            if edge.weighted_strength < min_strength:
                continue
            new_path = path + (edge,)
            reached_target = (
                target_id is not None and edge.dst_id == target_id
            )
            if target_id is None or reached_target:
                out.append(new_path)
                if len(out) >= max_paths:
                    return
            if not reached_target:
                self._dfs(
                    edge.dst_id, new_path, max_depth, min_strength,
                    target_id, out, max_paths,
                )


# =============================================================================
# SECTION 5 — EXPECTED MEDIATORS
# =============================================================================


# For a causality that starts at layer A and ends at layer B, the stack
# *should* pass through certain intermediate layers. We encode a compact
# mediation table: for a given (from_layer, to_layer), the layers that
# must appear somewhere on the path in order.
#
# This is intentionally small and physical: it expresses real
# architectural expectations (e.g. hardware → data must go through OS
# and identity, not straight from hardware to data).
_MEDIATION_TABLE: Mapping[Tuple[Layer, Layer], Tuple[Layer, ...]] = {
    # Physical root → data / AI / agent must cross the whole stack.
    (Layer.HARDWARE, Layer.DATA): (
        Layer.OS, Layer.IDENTITY, Layer.APPLICATION,
    ),
    (Layer.HARDWARE, Layer.AI): (
        Layer.OS, Layer.IDENTITY, Layer.APPLICATION, Layer.DATA,
    ),
    (Layer.HARDWARE, Layer.AGENT): (
        Layer.OS, Layer.IDENTITY, Layer.APPLICATION, Layer.API,
    ),
    (Layer.FIRMWARE, Layer.DATA): (
        Layer.OS, Layer.IDENTITY, Layer.APPLICATION,
    ),
    (Layer.FIRMWARE, Layer.AI): (
        Layer.OS, Layer.IDENTITY, Layer.APPLICATION, Layer.DATA,
    ),
    (Layer.OS, Layer.DATA): (
        Layer.IDENTITY, Layer.APPLICATION,
    ),
    (Layer.OS, Layer.AI): (
        Layer.IDENTITY, Layer.APPLICATION, Layer.DATA,
    ),
    (Layer.OS, Layer.AGENT): (
        Layer.IDENTITY, Layer.APPLICATION, Layer.API,
    ),
    (Layer.NETWORK, Layer.DATA): (
        Layer.IDENTITY, Layer.APPLICATION,
    ),
    (Layer.NETWORK, Layer.AGENT): (
        Layer.IDENTITY, Layer.APPLICATION, Layer.API,
    ),
    (Layer.IDENTITY, Layer.DATA): (
        Layer.APPLICATION,
    ),
    (Layer.IDENTITY, Layer.AI): (
        Layer.APPLICATION, Layer.DATA,
    ),
    (Layer.IDENTITY, Layer.AGENT): (
        Layer.APPLICATION, Layer.API,
    ),
    (Layer.APPLICATION, Layer.AI): (
        Layer.DATA,
    ),
    (Layer.API, Layer.AGENT): (),
    (Layer.CLOUD, Layer.DATA): (
        Layer.IDENTITY, Layer.APPLICATION,
    ),
    (Layer.CONTAINER, Layer.DATA): (
        Layer.IDENTITY, Layer.APPLICATION,
    ),
    (Layer.SUPPLY_CHAIN, Layer.AGENT): (
        Layer.APPLICATION, Layer.API,
    ),
}


def expected_mediators(src: Layer, dst: Layer) -> Tuple[Layer, ...]:
    """Layers that must appear on any causal path from src to dst."""
    key = (src, dst)
    if key in _MEDIATION_TABLE:
        return _MEDIATION_TABLE[key]
    # If to is same-or-lower than from, no mediation is expected.
    if layer_rank(dst) <= layer_rank(src):
        return ()
    # Otherwise: default expectation is that we pass through all ranks
    # strictly between src and dst. This catches obvious jumps.
    lo, hi = layer_rank(src), layer_rank(dst)
    return tuple(
        l for l in ALL_LAYERS
        if lo < layer_rank(l) < hi
    )


# =============================================================================
# SECTION 6 — CHAIN ANALYSIS
# =============================================================================


@dataclass(frozen=True)
class CrossLayerChain:
    chain_id: str
    node_ids: Tuple[str, ...]
    edge_ids: Tuple[str, ...]
    layer_sequence: Tuple[Layer, ...]
    distinct_layers: int
    chain_strength: float
    chain_confidence: float
    direction: Direction
    expected_mediators: Tuple[Layer, ...]
    missing_mediators: Tuple[Layer, ...]
    bypass: bool
    at: datetime

    def __post_init__(self) -> None:
        if len(self.node_ids) < 2:
            raise ValueError("chain must have at least 2 nodes")
        if len(self.edge_ids) != len(self.node_ids) - 1:
            raise ValueError("edge count must equal node count − 1")
        if len(self.layer_sequence) != len(self.node_ids):
            raise ValueError("layer sequence must match node count")
        for n, v in (
            ("chain_strength", self.chain_strength),
            ("chain_confidence", self.chain_confidence),
        ):
            if not 0.0 <= v <= 1.0:
                raise ValueError(f"{n} must be within [0,1]")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

    @property
    def length(self) -> int:
        return len(self.edge_ids)

    @property
    def src_layer(self) -> Layer:
        return self.layer_sequence[0]

    @property
    def dst_layer(self) -> Layer:
        return self.layer_sequence[-1]


def _classify_chain_direction(seq: Sequence[Layer]) -> Direction:
    ranks = [layer_rank(l) for l in seq]
    upward = all(ranks[i] <= ranks[i + 1] for i in range(len(ranks) - 1))
    downward = all(ranks[i] >= ranks[i + 1] for i in range(len(ranks) - 1))
    if upward and not downward:
        return Direction.UPWARD
    if downward and not upward:
        return Direction.DOWNWARD
    return Direction.LATERAL


def build_chain(
    graph: CrossLayerGraph,
    path: Tuple[CrossLayerEdge, ...],
    *,
    at: datetime,
) -> CrossLayerChain:
    if not path:
        raise ValueError("path must be non-empty")
    node_ids: List[str] = [path[0].src_id]
    for e in path:
        node_ids.append(e.dst_id)
    layers: Tuple[Layer, ...] = tuple(
        graph.node(nid).layer for nid in node_ids
    )

    # Geometric mean of weighted strengths
    prod = 1.0
    for e in path:
        prod *= max(1e-9, e.weighted_strength)
    strength = prod ** (1.0 / len(path))
    conf = sum(e.confidence for e in path) / len(path)

    src_layer, dst_layer = layers[0], layers[-1]
    expected = expected_mediators(src_layer, dst_layer)
    present = set(layers)
    missing = tuple(m for m in expected if m not in present)
    bypass = len(missing) > 0

    chain_id = "|".join(node_ids)

    return CrossLayerChain(
        chain_id=chain_id,
        node_ids=tuple(node_ids),
        edge_ids=tuple(e.edge_id for e in path),
        layer_sequence=layers,
        distinct_layers=len(set(layers)),
        chain_strength=strength,
        chain_confidence=conf,
        direction=_classify_chain_direction(layers),
        expected_mediators=expected,
        missing_mediators=missing,
        bypass=bypass,
        at=at,
    )


# =============================================================================
# SECTION 7 — CONVERGENCE ANALYSIS
# =============================================================================


@dataclass(frozen=True)
class Convergence:
    target_node_id: str
    target_layer: Layer
    origin_node_ids: Tuple[str, ...]
    origin_layers: Tuple[Layer, ...]
    distinct_origin_layers: int
    at: datetime

    def __post_init__(self) -> None:
        if not self.target_node_id:
            raise ValueError("target_node_id is required")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


def find_convergence(
    graph: CrossLayerGraph,
    *,
    min_distinct_layers: int = 2,
    at: datetime,
) -> Tuple[Convergence, ...]:
    if min_distinct_layers < 2:
        raise ValueError("min_distinct_layers must be >= 2")
    if at.tzinfo is None:
        raise ValueError("at must be timezone-aware")

    out: List[Convergence] = []
    for n in graph.nodes():
        parents = graph.parents(n.node_id)
        if len(parents) < 2:
            continue
        origin_layers = tuple(graph.node(p).layer for p in parents)
        distinct = len(set(origin_layers))
        if distinct < min_distinct_layers:
            continue
        out.append(Convergence(
            target_node_id=n.node_id,
            target_layer=n.layer,
            origin_node_ids=parents,
            origin_layers=origin_layers,
            distinct_origin_layers=distinct,
            at=at,
        ))
    return tuple(out)


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
class CausalitySnapshot:
    graph: CrossLayerGraph
    chains: Tuple[CrossLayerChain, ...]
    convergences: Tuple[Convergence, ...]


@dataclass(frozen=True)
class CausalityInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[CausalitySnapshot],
                        Tuple[InvariantViolation, ...]]
    description: str


def _inv_edge_relationship_direction(
    snap: CausalitySnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for e in snap.graph.edges():
        src = snap.graph.node(e.src_id).layer
        dst = snap.graph.node(e.dst_id).layer
        if not relationship_allows(e.relationship, src, dst):
            out.append(InvariantViolation(
                invariant_id="xl.edge_relationship_direction",
                severity=InvariantSeverity.CRITICAL,
                subject_id=e.edge_id,
                detail=(
                    f"relationship {e.relationship.value} invalid from "
                    f"{src.value} → {dst.value}"
                ),
            ))
    return tuple(out)


def _inv_chain_strength_positive(
    snap: CausalitySnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for c in snap.chains:
        if not 0.0 <= c.chain_strength <= 1.0:
            out.append(InvariantViolation(
                invariant_id="xl.chain_strength_bounded",
                severity=InvariantSeverity.HIGH,
                subject_id=c.chain_id,
                detail=f"chain strength {c.chain_strength}",
            ))
    return tuple(out)


def _inv_chain_layer_sequence_matches(
    snap: CausalitySnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for c in snap.chains:
        for nid, layer in zip(c.node_ids, c.layer_sequence):
            try:
                node = snap.graph.node(nid)
            except KeyError:
                continue
            if node.layer is not layer:
                out.append(InvariantViolation(
                    invariant_id="xl.chain_layer_sequence_matches",
                    severity=InvariantSeverity.CRITICAL,
                    subject_id=c.chain_id,
                    detail=(
                        f"node {nid} layer {node.layer.value} != "
                        f"sequence {layer.value}"
                    ),
                ))
    return tuple(out)


def _inv_missing_mediators_implies_bypass(
    snap: CausalitySnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for c in snap.chains:
        if (len(c.missing_mediators) > 0) is not c.bypass:
            out.append(InvariantViolation(
                invariant_id="xl.bypass_consistent",
                severity=InvariantSeverity.HIGH,
                subject_id=c.chain_id,
                detail=(
                    f"missing_mediators={len(c.missing_mediators)} "
                    f"but bypass={c.bypass}"
                ),
            ))
    return tuple(out)


def _inv_convergence_has_multiple_parents(
    snap: CausalitySnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for cv in snap.convergences:
        if len(cv.origin_node_ids) < 2:
            out.append(InvariantViolation(
                invariant_id="xl.convergence_multiple_parents",
                severity=InvariantSeverity.HIGH,
                subject_id=cv.target_node_id,
                detail="convergence with <2 origins",
            ))
        if cv.distinct_origin_layers < 2:
            out.append(InvariantViolation(
                invariant_id="xl.convergence_multiple_parents",
                severity=InvariantSeverity.MEDIUM,
                subject_id=cv.target_node_id,
                detail="convergence with <2 distinct origin layers",
            ))
    return tuple(out)


def _inv_direction_consistent_with_ranks(
    snap: CausalitySnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for c in snap.chains:
        expected = _classify_chain_direction(c.layer_sequence)
        if expected is not c.direction:
            out.append(InvariantViolation(
                invariant_id="xl.direction_consistent",
                severity=InvariantSeverity.HIGH,
                subject_id=c.chain_id,
                detail=(
                    f"direction {c.direction.value} != recomputed "
                    f"{expected.value}"
                ),
            ))
    return tuple(out)


DEFAULT_INVARIANTS: Tuple[CausalityInvariant, ...] = (
    CausalityInvariant(
        invariant_id="xl.edge_relationship_direction",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_edge_relationship_direction,
        description="Every edge's relationship must be valid in its direction.",
    ),
    CausalityInvariant(
        invariant_id="xl.chain_strength_bounded",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_chain_strength_positive,
        description="Chain strength must lie within [0,1].",
    ),
    CausalityInvariant(
        invariant_id="xl.chain_layer_sequence_matches",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_chain_layer_sequence_matches,
        description="Chain layer sequence must match each node's layer.",
    ),
    CausalityInvariant(
        invariant_id="xl.bypass_consistent",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_missing_mediators_implies_bypass,
        description="Bypass flag must exactly reflect missing mediators.",
    ),
    CausalityInvariant(
        invariant_id="xl.convergence_multiple_parents",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_convergence_has_multiple_parents,
        description="Convergence must have multiple origin layers.",
    ),
    CausalityInvariant(
        invariant_id="xl.direction_consistent",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_direction_consistent_with_ranks,
        description="Chain direction must match rank ordering.",
    ),
)


def check_invariants(
    snap: CausalitySnapshot,
    invariants: Iterable[CausalityInvariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 9 — STORE
# =============================================================================


@dataclass(frozen=True)
class ChainRecord:
    chain_id: str
    src_layer: Layer
    dst_layer: Layer
    length: int
    distinct_layers: int
    chain_strength: float
    direction: Direction
    bypass: bool
    updated_at: datetime


class CrossLayerStore(Protocol):
    def put(self, record: ChainRecord) -> None: ...
    def get(self, chain_id: str) -> Optional[ChainRecord]: ...
    def all(self) -> Tuple[ChainRecord, ...]: ...


class InMemoryCrossLayerStore:
    def __init__(self) -> None:
        self._data: Dict[str, ChainRecord] = {}

    def put(self, record: ChainRecord) -> None:
        existing = self._data.get(record.chain_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._data[record.chain_id] = record

    def get(self, chain_id: str) -> Optional[ChainRecord]:
        return self._data.get(chain_id)

    def all(self) -> Tuple[ChainRecord, ...]:
        return tuple(self._data.values())


class SqliteCrossLayerStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS xl_chains (
                chain_id TEXT PRIMARY KEY,
                src_layer TEXT NOT NULL,
                dst_layer TEXT NOT NULL,
                length INTEGER NOT NULL,
                distinct_layers INTEGER NOT NULL,
                chain_strength REAL NOT NULL,
                direction TEXT NOT NULL,
                bypass INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS xl_nodes (
                node_id TEXT PRIMARY KEY,
                layer TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                label TEXT NOT NULL,
                at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS xl_edges (
                edge_id TEXT PRIMARY KEY,
                src_id TEXT NOT NULL,
                dst_id TEXT NOT NULL,
                relationship TEXT NOT NULL,
                strength REAL NOT NULL,
                confidence REAL NOT NULL,
                provenance TEXT NOT NULL,
                at TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def put(self, record: ChainRecord) -> None:
        existing = self.get(record.chain_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._conn.execute(
            """
            INSERT INTO xl_chains
              (chain_id, src_layer, dst_layer, length, distinct_layers,
               chain_strength, direction, bypass, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(chain_id) DO UPDATE SET
              src_layer=excluded.src_layer,
              dst_layer=excluded.dst_layer,
              length=excluded.length,
              distinct_layers=excluded.distinct_layers,
              chain_strength=excluded.chain_strength,
              direction=excluded.direction,
              bypass=excluded.bypass,
              updated_at=excluded.updated_at
            """,
            (
                record.chain_id, record.src_layer.value,
                record.dst_layer.value, record.length,
                record.distinct_layers, record.chain_strength,
                record.direction.value, int(record.bypass),
                record.updated_at.isoformat(),
            ),
        )
        self._conn.commit()

    def get(self, chain_id: str) -> Optional[ChainRecord]:
        row = self._conn.execute(
            "SELECT src_layer, dst_layer, length, distinct_layers, "
            "chain_strength, direction, bypass, updated_at "
            "FROM xl_chains WHERE chain_id = ?",
            (chain_id,),
        ).fetchone()
        if row is None:
            return None
        return ChainRecord(
            chain_id=chain_id,
            src_layer=Layer(row[0]), dst_layer=Layer(row[1]),
            length=int(row[2]), distinct_layers=int(row[3]),
            chain_strength=float(row[4]),
            direction=Direction(row[5]), bypass=bool(row[6]),
            updated_at=datetime.fromisoformat(row[7]),
        )

    def all(self) -> Tuple[ChainRecord, ...]:
        rows = self._conn.execute("SELECT chain_id FROM xl_chains").fetchall()
        return tuple(
            r for r in (self.get(x[0]) for x in rows) if r is not None
        )

    def put_node(self, node: CrossLayerNode) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO xl_nodes "
            "(node_id, layer, entity_id, label, at) VALUES (?, ?, ?, ?, ?)",
            (node.node_id, node.layer.value, node.entity_id,
             node.label, node.at.isoformat()),
        )
        self._conn.commit()

    def put_edge(self, edge: CrossLayerEdge) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO xl_edges "
            "(edge_id, src_id, dst_id, relationship, strength, confidence, "
            "provenance, at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (edge.edge_id, edge.src_id, edge.dst_id,
             edge.relationship.value, edge.strength, edge.confidence,
             edge.provenance, edge.at.isoformat()),
        )
        self._conn.commit()


# =============================================================================
# SECTION 10 — ENGINE
# =============================================================================


@dataclass(frozen=True)
class CrossLayerConfig:
    max_depth: int = 8
    max_paths: int = 1000
    min_chain_strength: float = 0.05
    min_cross_layer_span: int = 3
    high_strength_threshold: float = 0.55
    convergence_min_layers: int = 2

    def __post_init__(self) -> None:
        if self.max_depth < 1:
            raise ValueError("max_depth must be >= 1")
        if self.max_paths < 1:
            raise ValueError("max_paths must be >= 1")
        if not 0.0 <= self.min_chain_strength <= 1.0:
            raise ValueError("min_chain_strength must be within [0,1]")
        if self.min_cross_layer_span < 2:
            raise ValueError("min_cross_layer_span must be >= 2")
        if not 0.0 <= self.high_strength_threshold <= 1.0:
            raise ValueError(
                "high_strength_threshold must be within [0,1]"
            )
        if self.convergence_min_layers < 2:
            raise ValueError("convergence_min_layers must be >= 2")


class CrossLayerCausalityEngine:
    """Cross-layer causality engine.

    Builds on the causal foundation by adding *layer-aware* semantics:
    every edge carries a relationship kind that constrains its
    direction, every path is checked against expected mediators, and
    chains are analysed for bypass, direction, and convergence.
    """

    def __init__(
        self,
        *,
        store: Optional[CrossLayerStore] = None,
        config: Optional[CrossLayerConfig] = None,
    ) -> None:
        self._store: CrossLayerStore = store or InMemoryCrossLayerStore()
        self._config = config or CrossLayerConfig()
        self._graph = CrossLayerGraph()
        self._chains: Tuple[CrossLayerChain, ...] = ()
        self._convergences: Tuple[Convergence, ...] = ()
        self._findings: List[CrossLayerFinding] = []
        self._violations: Tuple[InvariantViolation, ...] = ()

    # ---- registration ----------------------------------------------------

    def add_node(self, node: CrossLayerNode) -> None:
        self._graph.add_node(node)
        if isinstance(self._store, SqliteCrossLayerStore):
            self._store.put_node(node)

    def add_edge(self, edge: CrossLayerEdge) -> None:
        self._graph.add_edge(edge)
        if isinstance(self._store, SqliteCrossLayerStore):
            self._store.put_edge(edge)

    def graph(self) -> CrossLayerGraph:
        return self._graph

    def config(self) -> CrossLayerConfig:
        return self._config

    def set_config(self, config: CrossLayerConfig) -> None:
        self._config = config

    # ---- recompute -------------------------------------------------------

    def recompute(self, *, at: datetime) -> Tuple[ChainRecord, ...]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

        cfg = self._config
        paths = self._graph.enumerate_paths(
            max_depth=cfg.max_depth,
            max_paths=cfg.max_paths,
            min_strength=cfg.min_chain_strength,
        )

        chains: List[CrossLayerChain] = []
        for p in paths:
            c = build_chain(self._graph, p, at=at)
            chains.append(c)
        chains.sort(
            key=lambda c: (-c.chain_strength, -c.distinct_layers,
                           c.chain_id),
        )
        self._chains = tuple(chains)

        self._convergences = find_convergence(
            self._graph,
            min_distinct_layers=cfg.convergence_min_layers,
            at=at,
        )

        self._findings = []

        if getattr(self._graph, "_last_enumeration_truncated", False):
            self._findings.append(CrossLayerFinding(
                kind=CrossLayerFindingKind.ANALYSIS_TRUNCATED,
                subject_id="cross_layer_scan",
                detail=(
                    f"path enumeration hit max_paths="
                    f"{cfg.max_paths} - results may be incomplete, "
                    f"additional bypass chains may exist beyond what "
                    f"was explored"
                ),
                severity=3, at=at,
            ))

        # High-impact cross-layer chains
        for c in self._chains:
            if c.chain_strength >= cfg.high_strength_threshold \
               and c.distinct_layers >= cfg.min_cross_layer_span:
                self._findings.append(CrossLayerFinding(
                    kind=CrossLayerFindingKind.HIGH_IMPACT_CROSS_LAYER_CHAIN,
                    subject_id=c.chain_id,
                    detail=(
                        f"strength {c.chain_strength:.3f} spanning "
                        f"{c.distinct_layers} layer(s): "
                        f"{[l.value for l in c.layer_sequence]}"
                    ),
                    severity=4, at=at,
                ))

        # Bypass detection
        for c in self._chains:
            if not c.bypass:
                continue
            self._findings.append(CrossLayerFinding(
                kind=CrossLayerFindingKind.LAYER_BYPASS,
                subject_id=c.chain_id,
                detail=(
                    f"chain {c.chain_id} from {c.src_layer.value} to "
                    f"{c.dst_layer.value} missing mediator(s): "
                    f"{[m.value for m in c.missing_mediators]}"
                ),
                severity=5, at=at,
            ))

        # Direction violations — a *downward* chain is unusual and
        # potentially a hardcoded bypass (e.g. agent directly writes
        # to firmware).
        for c in self._chains:
            if c.direction is Direction.DOWNWARD:
                self._findings.append(CrossLayerFinding(
                    kind=CrossLayerFindingKind.DOWNWARD_VIOLATION,
                    subject_id=c.chain_id,
                    detail=(
                        f"downward chain from {c.src_layer.value} to "
                        f"{c.dst_layer.value}"
                    ),
                    severity=4, at=at,
                ))

        # Stack discontinuity — chain skips more than half the expected
        # intermediate layers.
        for c in self._chains:
            expected = len(c.expected_mediators)
            if expected >= 2 \
               and len(c.missing_mediators) >= (expected + 1) // 2:
                self._findings.append(CrossLayerFinding(
                    kind=CrossLayerFindingKind.STACK_DISCONTINUITY,
                    subject_id=c.chain_id,
                    detail=(
                        f"{len(c.missing_mediators)}/{expected} expected "
                        f"mediators missing"
                    ),
                    severity=5, at=at,
                ))

        # Convergence
        for cv in self._convergences:
            self._findings.append(CrossLayerFinding(
                kind=CrossLayerFindingKind.CONVERGENCE,
                subject_id=cv.target_node_id,
                detail=(
                    f"{len(cv.origin_node_ids)} origins across "
                    f"{cv.distinct_origin_layers} layer(s) converge on "
                    f"{cv.target_node_id} ({cv.target_layer.value})"
                ),
                severity=3, at=at,
            ))

        # Persist
        records: List[ChainRecord] = []
        for c in self._chains:
            rec = ChainRecord(
                chain_id=c.chain_id,
                src_layer=c.src_layer, dst_layer=c.dst_layer,
                length=c.length, distinct_layers=c.distinct_layers,
                chain_strength=c.chain_strength,
                direction=c.direction, bypass=c.bypass,
                updated_at=at,
            )
            self._store.put(rec)
            records.append(rec)

        self._violations = check_invariants(self.snapshot())
        return tuple(records)

    # ---- queries ---------------------------------------------------------

    def chains(self) -> Tuple[CrossLayerChain, ...]:
        return self._chains

    def convergences(self) -> Tuple[Convergence, ...]:
        return self._convergences

    def findings(self) -> Tuple[CrossLayerFinding, ...]:
        return tuple(self._findings)

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return self._violations

    def top_chains(
        self, *, k: int = 10,
    ) -> Tuple[CrossLayerChain, ...]:
        if k <= 0:
            raise ValueError("k must be > 0")
        return tuple(self._chains[:k])

    def bypasses(self) -> Tuple[CrossLayerChain, ...]:
        return tuple(c for c in self._chains if c.bypass)

    def snapshot(self) -> CausalitySnapshot:
        return CausalitySnapshot(
            graph=self._graph,
            chains=self._chains,
            convergences=self._convergences,
        )


# =============================================================================
# SECTION 11 — TESTS
# =============================================================================


def _t0() -> datetime:
    from datetime import timezone
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _node(
    nid: str, layer: Layer, *, entity: str = "e",
    label: str = "l", at: Optional[datetime] = None,
) -> CrossLayerNode:
    return CrossLayerNode(
        node_id=nid, layer=layer, entity_id=entity, label=label,
        at=at or _t0(),
    )


def _edge(
    eid: str, src: str, dst: str, *,
    relationship: RelationshipKind = RelationshipKind.EXPOSES,
    strength: float = 0.9, confidence: float = 0.9,
    at: Optional[datetime] = None,
) -> CrossLayerEdge:
    return CrossLayerEdge(
        edge_id=eid, src_id=src, dst_id=dst,
        relationship=relationship, strength=strength,
        confidence=confidence, provenance="test", at=at or _t0(),
    )


def _stack_graph() -> CrossLayerGraph:
    """A clean hardware → ... → data stack."""
    g = CrossLayerGraph()
    g.add_node(_node("hw", Layer.HARDWARE))
    g.add_node(_node("fw", Layer.FIRMWARE))
    g.add_node(_node("os", Layer.OS))
    g.add_node(_node("net", Layer.NETWORK))
    g.add_node(_node("idn", Layer.IDENTITY))
    g.add_node(_node("app", Layer.APPLICATION))
    g.add_node(_node("api", Layer.API))
    g.add_node(_node("data", Layer.DATA))
    g.add_node(_node("agent", Layer.AGENT))

    g.add_edge(_edge("e1", "hw", "fw", relationship=RelationshipKind.ANCHORS))
    g.add_edge(_edge("e2", "fw", "os", relationship=RelationshipKind.ROOTS))
    g.add_edge(_edge("e3", "os", "net", relationship=RelationshipKind.CARRIES))
    g.add_edge(_edge("e4", "net", "idn", relationship=RelationshipKind.CARRIES))
    g.add_edge(_edge("e5", "idn", "app", relationship=RelationshipKind.BINDS))
    g.add_edge(_edge("e6", "app", "api", relationship=RelationshipKind.EXPOSES))
    g.add_edge(_edge("e7", "api", "data", relationship=RelationshipKind.CONSUMES))
    g.add_edge(_edge("e8", "app", "agent", relationship=RelationshipKind.DELEGATES_TO))
    return g


# ---- domain ----

def test_layer_rank_monotonic() -> None:
    assert layer_rank(Layer.HARDWARE) < layer_rank(Layer.FIRMWARE)
    assert layer_rank(Layer.OS) < layer_rank(Layer.IDENTITY)
    assert layer_rank(Layer.AGENT) == 12


def test_edge_direction_upward() -> None:
    assert edge_direction(Layer.OS, Layer.IDENTITY) is Direction.UPWARD


def test_edge_direction_downward() -> None:
    assert edge_direction(Layer.AGENT, Layer.FIRMWARE) is Direction.DOWNWARD


def test_edge_direction_lateral_same_layer() -> None:
    assert edge_direction(Layer.OS, Layer.OS) is Direction.LATERAL


def test_relationship_allows_anchors_upward() -> None:
    assert relationship_allows(
        RelationshipKind.ANCHORS, Layer.HARDWARE, Layer.FIRMWARE,
    )


def test_relationship_rejects_anchors_downward() -> None:
    assert not relationship_allows(
        RelationshipKind.ANCHORS, Layer.FIRMWARE, Layer.HARDWARE,
    )


def test_relationship_mediates_all_directions() -> None:
    # MEDIATES is unrestricted
    assert relationship_allows(
        RelationshipKind.MEDIATES, Layer.OS, Layer.NETWORK,
    )
    assert relationship_allows(
        RelationshipKind.MEDIATES, Layer.NETWORK, Layer.OS,
    )


def test_node_requires_id() -> None:
    try:
        CrossLayerNode(
            node_id="", layer=Layer.OS, entity_id="e", label="l",
            at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_node_requires_aware_time() -> None:
    from datetime import datetime as dt
    try:
        CrossLayerNode(
            node_id="n", layer=Layer.OS, entity_id="e", label="l",
            at=dt(2026, 1, 1),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_edge_rejects_self() -> None:
    try:
        CrossLayerEdge(
            edge_id="e", src_id="a", dst_id="a",
            relationship=RelationshipKind.CARRIES,
            strength=0.5, confidence=0.5, provenance="p", at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_edge_rejects_bad_strength() -> None:
    try:
        CrossLayerEdge(
            edge_id="e", src_id="a", dst_id="b",
            relationship=RelationshipKind.CARRIES,
            strength=1.5, confidence=0.5, provenance="p", at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_edge_weighted_strength() -> None:
    e = _edge("e", "a", "b", strength=0.8, confidence=0.9)
    assert abs(e.weighted_strength - 0.72) < 1e-9


# ---- graph ----

def test_graph_rejects_duplicate_node() -> None:
    g = CrossLayerGraph()
    g.add_node(_node("a", Layer.OS))
    try:
        g.add_node(_node("a", Layer.OS))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_graph_rejects_missing_endpoint() -> None:
    g = CrossLayerGraph()
    g.add_node(_node("a", Layer.OS))
    try:
        g.add_edge(_edge("e", "a", "missing"))
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_graph_rejects_relationship_direction_violation() -> None:
    g = CrossLayerGraph()
    g.add_node(_node("a", Layer.HARDWARE))
    g.add_node(_node("b", Layer.FIRMWARE))
    try:
        # ANCHORS is upward only — downward must be rejected
        g.add_edge(_edge("e", "b", "a",
                         relationship=RelationshipKind.ANCHORS))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_graph_rejects_cycle() -> None:
    g = CrossLayerGraph()
    g.add_node(_node("a", Layer.OS))
    g.add_node(_node("b", Layer.IDENTITY))
    g.add_node(_node("c", Layer.APPLICATION))
    g.add_edge(_edge("e1", "a", "b"))
    g.add_edge(_edge("e2", "b", "c"))
    try:
        g.add_edge(_edge("e3", "c", "a",
                         relationship=RelationshipKind.MEDIATES))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_graph_nodes_of_layer() -> None:
    g = _stack_graph()
    assert len(g.nodes_of_layer(Layer.OS)) == 1


def test_graph_present_layers() -> None:
    g = _stack_graph()
    assert Layer.HARDWARE in g.present_layers()
    assert Layer.DATA in g.present_layers()


def test_graph_parents_children() -> None:
    g = _stack_graph()
    assert "fw" in g.children("hw")
    assert "hw" in g.parents("fw")


# ---- mediation ----

def test_expected_mediators_for_known_pair() -> None:
    m = expected_mediators(Layer.HARDWARE, Layer.DATA)
    assert Layer.OS in m
    assert Layer.IDENTITY in m
    assert Layer.APPLICATION in m


def test_expected_mediators_same_layer_empty() -> None:
    assert expected_mediators(Layer.OS, Layer.OS) == ()


def test_expected_mediators_default_intermediate() -> None:
    # Container → Data has a specific entry, but e.g. Firmware → API
    # falls back to "all strictly between".
    m = expected_mediators(Layer.FIRMWARE, Layer.API)
    assert Layer.OS in m
    assert Layer.IDENTITY in m


# ---- chain building ----

def test_build_chain_full_stack() -> None:
    g = _stack_graph()
    paths = g.enumerate_paths(
        source_id="hw", target_id="data", max_depth=10,
    )
    # We expect at least one path hw → ... → data
    assert len(paths) >= 1
    c = build_chain(g, paths[0], at=_t0())
    assert c.src_layer is Layer.HARDWARE
    assert c.dst_layer is Layer.DATA
    assert c.direction is Direction.UPWARD
    assert not c.bypass


def test_build_chain_strength_geometric_mean() -> None:
    g = CrossLayerGraph()
    g.add_node(_node("a", Layer.OS))
    g.add_node(_node("b", Layer.IDENTITY))
    g.add_node(_node("c", Layer.APPLICATION))
    g.add_edge(_edge("e1", "a", "b", strength=0.9, confidence=0.9))
    g.add_edge(_edge("e2", "b", "c", strength=0.8, confidence=0.9))
    paths = g.enumerate_paths(
        source_id="a", target_id="c", max_depth=5,
    )
    c = build_chain(g, paths[0], at=_t0())
    # (0.9*0.9=0.81) and (0.8*0.9=0.72); geometric mean sqrt(0.81*0.72)
    expected = (0.81 * 0.72) ** 0.5
    assert abs(c.chain_strength - expected) < 1e-9


def test_build_chain_rejects_empty() -> None:
    g = _stack_graph()
    try:
        build_chain(g, (), at=_t0())
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- bypass detection ----

def test_bypass_detected_when_mediator_skipped() -> None:
    # Construct a graph where HARDWARE connects directly to DATA without
    # going through OS/IDENTITY/APPLICATION. Use MEDIATES as the only
    # relationship that allows this.
    g = CrossLayerGraph()
    g.add_node(_node("hw", Layer.HARDWARE))
    g.add_node(_node("data", Layer.DATA))
    g.add_edge(_edge("e1", "hw", "data",
                     relationship=RelationshipKind.MEDIATES))
    paths = g.enumerate_paths(
        source_id="hw", target_id="data", max_depth=3,
    )
    c = build_chain(g, paths[0], at=_t0())
    assert c.bypass
    assert Layer.OS in c.missing_mediators


def test_no_bypass_when_all_mediators_present() -> None:
    g = _stack_graph()
    paths = g.enumerate_paths(
        source_id="hw", target_id="data", max_depth=10,
    )
    assert paths
    c = build_chain(g, paths[0], at=_t0())
    # Full hardware → ... → data goes through OS + IDENTITY + APPLICATION
    assert not c.bypass


# ---- convergence ----

def test_convergence_detected() -> None:
    g = CrossLayerGraph()
    g.add_node(_node("a", Layer.IDENTITY))
    g.add_node(_node("b", Layer.NETWORK))
    g.add_node(_node("c", Layer.DATA))
    g.add_edge(_edge("e1", "a", "c",
                     relationship=RelationshipKind.MEDIATES))
    g.add_edge(_edge("e2", "b", "c",
                     relationship=RelationshipKind.MEDIATES))
    convs = find_convergence(g, at=_t0())
    assert len(convs) == 1
    assert convs[0].target_node_id == "c"


def test_convergence_single_parent_not_detected() -> None:
    g = _stack_graph()
    assert find_convergence(g, at=_t0()) == ()


def test_convergence_requires_min_layers() -> None:
    g = CrossLayerGraph()
    g.add_node(_node("a", Layer.IDENTITY))
    g.add_node(_node("b", Layer.IDENTITY))
    g.add_node(_node("c", Layer.DATA))
    g.add_edge(_edge("e1", "a", "c",
                     relationship=RelationshipKind.MEDIATES))
    g.add_edge(_edge("e2", "b", "c",
                     relationship=RelationshipKind.MEDIATES))
    # Both parents are IDENTITY layer — distinct layers = 1 → not flagged
    assert find_convergence(g, at=_t0(), min_distinct_layers=2) == ()


def test_convergence_requires_aware_time() -> None:
    from datetime import datetime as dt
    g = CrossLayerGraph()
    try:
        find_convergence(g, at=dt(2026, 1, 1))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- engine ----

def test_engine_adds_nodes_and_edges() -> None:
    eng = CrossLayerCausalityEngine()
    eng.add_node(_node("a", Layer.OS))
    eng.add_node(_node("b", Layer.IDENTITY))
    eng.add_edge(_edge("e", "a", "b", relationship=RelationshipKind.CARRIES))
    assert len(eng.graph().edges()) == 1


def test_engine_recompute_produces_chains() -> None:
    eng = CrossLayerCausalityEngine()
    for n in _stack_graph().nodes():
        eng.add_node(n)
    for e in _stack_graph().edges():
        eng.add_edge(e)
    records = eng.recompute(at=_t0())
    assert len(records) >= 1


def test_engine_high_impact_finding() -> None:
    eng = CrossLayerCausalityEngine()
    for n in _stack_graph().nodes():
        eng.add_node(n)
    for e in _stack_graph().edges():
        eng.add_edge(e)
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert CrossLayerFindingKind.HIGH_IMPACT_CROSS_LAYER_CHAIN in kinds


def test_engine_bypass_finding() -> None:
    eng = CrossLayerCausalityEngine()
    eng.add_node(_node("hw", Layer.HARDWARE))
    eng.add_node(_node("data", Layer.DATA))
    eng.add_edge(_edge("e", "hw", "data",
                       relationship=RelationshipKind.MEDIATES))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert CrossLayerFindingKind.LAYER_BYPASS in kinds


def test_engine_convergence_finding() -> None:
    eng = CrossLayerCausalityEngine()
    eng.add_node(_node("a", Layer.IDENTITY))
    eng.add_node(_node("b", Layer.NETWORK))
    eng.add_node(_node("c", Layer.DATA))
    eng.add_edge(_edge("e1", "a", "c",
                       relationship=RelationshipKind.MEDIATES))
    eng.add_edge(_edge("e2", "b", "c",
                       relationship=RelationshipKind.MEDIATES))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert CrossLayerFindingKind.CONVERGENCE in kinds


def test_engine_bypasses_filter() -> None:
    eng = CrossLayerCausalityEngine()
    eng.add_node(_node("hw", Layer.HARDWARE))
    eng.add_node(_node("data", Layer.DATA))
    eng.add_edge(_edge("e", "hw", "data",
                       relationship=RelationshipKind.MEDIATES))
    eng.recompute(at=_t0())
    bypasses = eng.bypasses()
    assert len(bypasses) >= 1


def test_engine_top_chains_sorted() -> None:
    eng = CrossLayerCausalityEngine()
    for n in _stack_graph().nodes():
        eng.add_node(n)
    for e in _stack_graph().edges():
        eng.add_edge(e)
    eng.recompute(at=_t0())
    top = eng.top_chains(k=10)
    strengths = [c.chain_strength for c in top]
    assert strengths == sorted(strengths, reverse=True)


def test_engine_top_chains_invalid_k() -> None:
    eng = CrossLayerCausalityEngine()
    try:
        eng.top_chains(k=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_recompute_rejects_naive_time() -> None:
    from datetime import datetime as dt
    eng = CrossLayerCausalityEngine()
    try:
        eng.recompute(at=dt(2026, 1, 1))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_downward_finding() -> None:
    # A downgrade chain (agent → data via MEDIATES) → DOWNWARD
    eng = CrossLayerCausalityEngine()
    eng.add_node(_node("agent", Layer.AGENT))
    eng.add_node(_node("data", Layer.DATA))
    eng.add_edge(_edge("e", "agent", "data",
                       relationship=RelationshipKind.MEDIATES))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert CrossLayerFindingKind.DOWNWARD_VIOLATION in kinds


def test_engine_stack_discontinuity_finding() -> None:
    # Jump hardware → data (missing OS, IDENTITY, APPLICATION) — should
    # also register stack discontinuity.
    eng = CrossLayerCausalityEngine()
    eng.add_node(_node("hw", Layer.HARDWARE))
    eng.add_node(_node("data", Layer.DATA))
    eng.add_edge(_edge("e", "hw", "data",
                       relationship=RelationshipKind.MEDIATES))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert CrossLayerFindingKind.STACK_DISCONTINUITY in kinds


def test_engine_config_validation() -> None:
    try:
        CrossLayerConfig(max_depth=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_config_setter() -> None:
    eng = CrossLayerCausalityEngine()
    cfg = CrossLayerConfig(min_cross_layer_span=4)
    eng.set_config(cfg)
    assert eng.config() is cfg


# ---- invariants ----

def test_invariant_clean_snapshot() -> None:
    eng = CrossLayerCausalityEngine()
    for n in _stack_graph().nodes():
        eng.add_node(n)
    for e in _stack_graph().edges():
        eng.add_edge(e)
    eng.recompute(at=_t0())
    assert eng.violations() == ()


def test_invariant_bypass_consistent() -> None:
    # Fake a chain with a bypass flag that doesn't match
    fake = object.__new__(CrossLayerChain)
    object.__setattr__(fake, "chain_id", "fake")
    object.__setattr__(fake, "node_ids", ("a", "b"))
    object.__setattr__(fake, "edge_ids", ("e1",))
    object.__setattr__(fake, "layer_sequence",
                       (Layer.HARDWARE, Layer.DATA))
    object.__setattr__(fake, "distinct_layers", 2)
    object.__setattr__(fake, "chain_strength", 0.5)
    object.__setattr__(fake, "chain_confidence", 0.9)
    object.__setattr__(fake, "direction", Direction.UPWARD)
    object.__setattr__(fake, "expected_mediators", ())
    object.__setattr__(fake, "missing_mediators", ())
    object.__setattr__(fake, "bypass", True)   # inconsistent!
    object.__setattr__(fake, "at", _t0())
    snap = CausalitySnapshot(
        graph=CrossLayerGraph(), chains=(fake,), convergences=(),
    )
    v = check_invariants(snap)
    assert any(x.invariant_id == "xl.bypass_consistent" for x in v)


def test_invariant_direction_consistent() -> None:
    fake = object.__new__(CrossLayerChain)
    object.__setattr__(fake, "chain_id", "fake")
    object.__setattr__(fake, "node_ids", ("a", "b"))
    object.__setattr__(fake, "edge_ids", ("e1",))
    object.__setattr__(fake, "layer_sequence",
                       (Layer.HARDWARE, Layer.DATA))
    object.__setattr__(fake, "distinct_layers", 2)
    object.__setattr__(fake, "chain_strength", 0.5)
    object.__setattr__(fake, "chain_confidence", 0.9)
    # Deliberately wrong: HARDWARE→DATA is UPWARD, but marked DOWNWARD
    object.__setattr__(fake, "direction", Direction.DOWNWARD)
    object.__setattr__(fake, "expected_mediators", ())
    object.__setattr__(fake, "missing_mediators", ())
    object.__setattr__(fake, "bypass", False)
    object.__setattr__(fake, "at", _t0())
    snap = CausalitySnapshot(
        graph=CrossLayerGraph(), chains=(fake,), convergences=(),
    )
    v = check_invariants(snap)
    assert any(x.invariant_id == "xl.direction_consistent" for x in v)


def test_invariant_convergence_multiple_parents() -> None:
    bad = Convergence(
        target_node_id="t", target_layer=Layer.DATA,
        origin_node_ids=("a",), origin_layers=(Layer.IDENTITY,),
        distinct_origin_layers=1, at=_t0(),
    )
    snap = CausalitySnapshot(
        graph=CrossLayerGraph(), chains=(), convergences=(bad,),
    )
    v = check_invariants(snap)
    assert any(
        x.invariant_id == "xl.convergence_multiple_parents"
        for x in v
    )


# ---- store ----

def test_in_memory_store_rejects_stale() -> None:
    s = InMemoryCrossLayerStore()
    t = _t0()
    s.put(ChainRecord(
        "c1", Layer.HARDWARE, Layer.DATA, 3, 4,
        0.8, Direction.UPWARD, False, t,
    ))
    earlier = t.replace(year=t.year - 1)
    try:
        s.put(ChainRecord(
            "c1", Layer.HARDWARE, Layer.DATA, 2, 3,
            0.5, Direction.UPWARD, False, earlier,
        ))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_chain_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "xl.db")
    store = SqliteCrossLayerStore(db)
    t = _t0()
    store.put(ChainRecord(
        "c1", Layer.HARDWARE, Layer.DATA, length=5,
        distinct_layers=6, chain_strength=0.9,
        direction=Direction.UPWARD, bypass=False, updated_at=t,
    ))
    got = store.get("c1")
    assert got is not None
    assert got.src_layer is Layer.HARDWARE
    assert got.bypass is False


def test_sqlite_store_node_and_edge_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "xl.db")
    store = SqliteCrossLayerStore(db)
    n = _node("a", Layer.OS)
    e = _edge("e1", "a", "a") if False else CrossLayerEdge(
        edge_id="e1", src_id="a", dst_id="b",
        relationship=RelationshipKind.CARRIES,
        strength=0.9, confidence=0.9, provenance="p", at=_t0(),
    )
    store.put_node(n)
    store.put_edge(e)
    row = store._conn.execute(
        "SELECT relationship FROM xl_edges WHERE edge_id = 'e1'"
    ).fetchone()
    assert row is not None and row[0] == "carries"


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
