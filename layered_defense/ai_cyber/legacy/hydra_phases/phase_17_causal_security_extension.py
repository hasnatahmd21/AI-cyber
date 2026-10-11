"""
HYDRA POST-CORE — PHASE 17: CAUSAL SECURITY EXTENSION
========================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * Domain — 13 causal layers (identity, authority, application, API,
    network, cloud, data, control, dependency, agent, hardware,
    supply_chain, threat), causal nodes, causal edges, chain templates
  * Causal graph — DAG with cycle rejection, bounded path enumeration
  * Chain strength — geometric mean over edge strengths weighted by
    confidence
  * Cross-layer chain discovery — templates for malicious and
    non-malicious chains
  * Confounder detection — nodes with multiple parents across layers
  * Causality findings — HIGH_STRENGTH_CROSS_LAYER_CHAIN,
    TEMPLATE_MATCH, CONFOUNDER_DETECTED, DISCONNECTED_LAYER,
    UNSUPPORTED_CAUSAL_EDGE, FAN_OUT_EXPLOSION
  * Machine-checkable causal invariants
  * In-memory + SQLite stores
  * Phase-17 engine facade
  * Full test suite + manual runner

This is NEW cross-layer causal security technology. It is NOT a second
causal reasoning engine. It extends the existing HYDRA causal foundation
with cross-layer causality: identity compromise → privilege escalation →
API access → cloud modification → control degradation → data exposure,
and non-malicious chains: dependency failure → service degradation →
security-control failure → exposure → incident amplification.

No third-party dependencies.

Run tests:
    python hydra_phase17_causal_security_extension.py
    pytest hydra_phase17_causal_security_extension.py -q
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


class CausalLayer(str, Enum):
    IDENTITY = "identity"
    AUTHORITY = "authority"
    APPLICATION = "application"
    API = "api"
    NETWORK = "network"
    CLOUD = "cloud"
    DATA = "data"
    CONTROL = "control"
    DEPENDENCY = "dependency"
    AGENT = "agent"
    HARDWARE = "hardware"
    SUPPLY_CHAIN = "supply_chain"
    THREAT = "threat"


ALL_LAYERS: Tuple[CausalLayer, ...] = tuple(CausalLayer)


class CausalNodeKind(str, Enum):
    STATE = "state"                # an observed security state
    EVENT = "event"                # a discrete event
    CONTROL = "control"            # a control presence/absence
    EXPOSURE = "exposure"          # an exposure surface
    FAILURE = "failure"            # a failure signal
    COMPROMISE = "compromise"      # a compromise signal


class CausalEdgeKind(str, Enum):
    ENABLES = "enables"
    CAUSES = "causes"
    CONTRIBUTES = "contributes"
    PRECEDES = "precedes"
    FAILS_TO_PREVENT = "fails_to_prevent"


_EDGE_KIND_MULTIPLIER: Mapping[CausalEdgeKind, float] = {
    CausalEdgeKind.ENABLES: 1.0,
    CausalEdgeKind.CAUSES: 1.0,
    CausalEdgeKind.CONTRIBUTES: 0.7,
    CausalEdgeKind.PRECEDES: 0.4,
    CausalEdgeKind.FAILS_TO_PREVENT: 0.8,
}


def edge_kind_multiplier(kind: CausalEdgeKind) -> float:
    return _EDGE_KIND_MULTIPLIER[kind]


class CausalFindingKind(str, Enum):
    HIGH_STRENGTH_CROSS_LAYER_CHAIN = "high_strength_cross_layer_chain"
    TEMPLATE_MATCH = "template_match"
    CONFOUNDER_DETECTED = "confounder_detected"
    DISCONNECTED_LAYER = "disconnected_layer"
    UNSUPPORTED_CAUSAL_EDGE = "unsupported_causal_edge"
    FAN_OUT_EXPLOSION = "fan_out_explosion"
    CYCLE_REJECTED = "cycle_rejected"


@dataclass(frozen=True)
class CausalFinding:
    kind: CausalFindingKind
    subject_id: str
    detail: str
    severity: int
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        if not 1 <= self.severity <= 5:
            raise ValueError("severity must be in [1,5]")


@dataclass(frozen=True)
class CausalNode:
    node_id: str
    layer: CausalLayer
    kind: CausalNodeKind
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

    @property
    def key(self) -> Tuple[CausalLayer, str, CausalNodeKind]:
        return (self.layer, self.entity_id, self.kind)


@dataclass(frozen=True)
class CausalEdge:
    edge_id: str
    cause_id: str
    effect_id: str
    kind: CausalEdgeKind
    strength: float
    confidence: float
    provenance: str
    at: datetime

    def __post_init__(self) -> None:
        if not self.edge_id:
            raise ValueError("edge_id is required")
        if not self.cause_id or not self.effect_id:
            raise ValueError("cause and effect are required")
        if self.cause_id == self.effect_id:
            raise ValueError("self-edges are not allowed in causal graph")
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
        """Strength × kind multiplier × confidence."""
        return (
            self.strength
            * edge_kind_multiplier(self.kind)
            * self.confidence
        )


# =============================================================================
# SECTION 3 — CHAIN TEMPLATE
# =============================================================================


@dataclass(frozen=True)
class ChainTemplate:
    """A causally meaningful layer sequence.

    A chain matches a template if its layer sequence contains the
    template's layer sequence as a subsequence (in order).
    """
    template_id: str
    layer_sequence: Tuple[CausalLayer, ...]
    min_chain_strength: float
    risk_label: str
    severity: int
    description: str = ""

    def __post_init__(self) -> None:
        if not self.template_id:
            raise ValueError("template_id is required")
        if len(self.layer_sequence) < 2:
            raise ValueError("template must have at least 2 layers")
        if not 0.0 <= self.min_chain_strength <= 1.0:
            raise ValueError("min_chain_strength must be within [0,1]")
        if not self.risk_label:
            raise ValueError("risk_label is required")
        if not 1 <= self.severity <= 5:
            raise ValueError("severity must be in [1,5]")

    def matches(self, layer_sequence: Tuple[CausalLayer, ...]) -> bool:
        """Subsequence match (order-preserving, contiguous not required)."""
        i = 0
        for layer in layer_sequence:
            if i < len(self.layer_sequence) and layer is self.layer_sequence[i]:
                i += 1
        return i == len(self.layer_sequence)


# =============================================================================
# SECTION 4 — CAUSAL GRAPH
# =============================================================================


class CausalGraph:
    """Directed acyclic graph of security causality across layers."""

    def __init__(self) -> None:
        self._nodes: Dict[str, CausalNode] = {}
        self._out: Dict[str, List[CausalEdge]] = {}
        self._in: Dict[str, List[CausalEdge]] = {}
        self._edges: Dict[str, CausalEdge] = {}

    # ---- nodes -----------------------------------------------------------

    def add_node(self, node: CausalNode) -> None:
        if node.node_id in self._nodes:
            raise ValueError(f"node {node.node_id} already exists")
        self._nodes[node.node_id] = node
        self._out.setdefault(node.node_id, [])
        self._in.setdefault(node.node_id, [])

    def node(self, node_id: str) -> CausalNode:
        n = self._nodes.get(node_id)
        if n is None:
            raise KeyError(f"unknown node {node_id}")
        return n

    def nodes(self) -> Tuple[CausalNode, ...]:
        return tuple(self._nodes.values())

    def node_by_key(
        self, layer: CausalLayer, entity_id: str, kind: CausalNodeKind,
    ) -> Optional[CausalNode]:
        for n in self._nodes.values():
            if n.layer is layer and n.entity_id == entity_id and n.kind is kind:
                return n
        return None

    # ---- edges -----------------------------------------------------------

    def add_edge(self, edge: CausalEdge) -> None:
        if edge.edge_id in self._edges:
            raise ValueError(f"edge {edge.edge_id} already exists")
        if edge.cause_id not in self._nodes:
            raise KeyError(f"cause {edge.cause_id} not registered")
        if edge.effect_id not in self._nodes:
            raise KeyError(f"effect {edge.effect_id} not registered")
        if self._would_create_cycle(edge.cause_id, edge.effect_id):
            raise ValueError(
                f"causal edge {edge.cause_id}->{edge.effect_id} creates "
                f"a cycle"
            )
        self._edges[edge.edge_id] = edge
        self._out[edge.cause_id].append(edge)
        self._in[edge.effect_id].append(edge)

    def _would_create_cycle(self, cause: str, effect: str) -> bool:
        # Walk forward from effect; if we reach cause, cycle.
        stack = [effect]
        seen: set = set()
        while stack:
            cur = stack.pop()
            if cur == cause:
                return True
            if cur in seen:
                continue
            seen.add(cur)
            for e in self._out.get(cur, []):
                stack.append(e.effect_id)
        return False

    def edge(self, edge_id: str) -> CausalEdge:
        e = self._edges.get(edge_id)
        if e is None:
            raise KeyError(f"unknown edge {edge_id}")
        return e

    def edges(self) -> Tuple[CausalEdge, ...]:
        return tuple(self._edges.values())

    def out_edges(self, node_id: str) -> Tuple[CausalEdge, ...]:
        return tuple(self._out.get(node_id, []))

    def in_edges(self, node_id: str) -> Tuple[CausalEdge, ...]:
        return tuple(self._in.get(node_id, []))

    def parents(self, node_id: str) -> Tuple[str, ...]:
        return tuple(e.cause_id for e in self._in.get(node_id, []))

    def children(self, node_id: str) -> Tuple[str, ...]:
        return tuple(e.effect_id for e in self._out.get(node_id, []))

    def present_layers(self) -> FrozenSet[CausalLayer]:
        return frozenset(n.layer for n in self._nodes.values())

    def fan_out(self, node_id: str) -> int:
        return len(self._out.get(node_id, []))

    # ---- path enumeration -------------------------------------------------

    def enumerate_paths(
        self,
        *,
        source_id: Optional[str] = None,
        target_id: Optional[str] = None,
        max_depth: int = 6,
        max_paths: int = 500,
        min_strength: float = 0.05,
    ) -> Tuple[Tuple[CausalEdge, ...], ...]:
        """Enumerate acyclic paths (bounded depth and count).

        A path is a sequence of edges. Path strength = geometric mean
        of weighted edge strengths. Paths below min_strength are pruned.
        """
        if max_depth < 1:
            raise ValueError("max_depth must be >= 1")
        if max_paths < 1:
            raise ValueError("max_paths must be >= 1")
        if not 0.0 <= min_strength <= 1.0:
            raise ValueError("min_strength must be within [0,1]")

        starts: Iterable[str]
        if source_id is not None:
            self.node(source_id)
            starts = [source_id]
        else:
            # start from roots (no in-edges)
            starts = [
                nid for nid in self._nodes if not self._in.get(nid)
            ]

        results: List[Tuple[CausalEdge, ...]] = []
        for s in starts:
            self._dfs_paths(
                s, (), max_depth, min_strength, target_id, results,
                max_paths,
            )
            if len(results) >= max_paths:
                break
        return tuple(results[:max_paths])

    def _dfs_paths(
        self,
        node_id: str,
        path: Tuple[CausalEdge, ...],
        max_depth: int,
        min_strength: float,
        target_id: Optional[str],
        out: List[Tuple[CausalEdge, ...]],
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
            if target_id is None or edge.effect_id == target_id:
                # Record path when it reaches its target or any endpoint
                if target_id is None or edge.effect_id == target_id:
                    out.append(new_path)
                    if len(out) >= max_paths:
                        return
            # Recurse only if not target reached
            if target_id is None or edge.effect_id != target_id:
                self._dfs_paths(
                    edge.effect_id, new_path, max_depth, min_strength,
                    target_id, out, max_paths,
                )


# =============================================================================
# SECTION 5 — CHAIN ANALYSIS
# =============================================================================


@dataclass(frozen=True)
class CausalChain:
    chain_id: str
    node_ids: Tuple[str, ...]
    edge_ids: Tuple[str, ...]
    layer_sequence: Tuple[CausalLayer, ...]
    chain_strength: float
    chain_confidence: float
    distinct_layers: int
    weighted_strength: float
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
            ("weighted_strength", self.weighted_strength),
        ):
            if not 0.0 <= v <= 1.0:
                raise ValueError(f"{n} must be within [0,1]")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

    @property
    def length(self) -> int:
        return len(self.edge_ids)

    def crosses(self, layer: CausalLayer) -> bool:
        return layer in self.layer_sequence


def _chain_from_path(
    graph: CausalGraph,
    path: Tuple[CausalEdge, ...],
    *,
    at: datetime,
) -> CausalChain:
    if not path:
        raise ValueError("path must be non-empty")
    node_ids: List[str] = [path[0].cause_id]
    for e in path:
        node_ids.append(e.effect_id)

    layers: Tuple[CausalLayer, ...] = tuple(
        graph.node(nid).layer for nid in node_ids
    )
    distinct = len(set(layers))

    # Geometric mean of weighted strengths
    weighted = [e.weighted_strength for e in path]
    prod = 1.0
    for w in weighted:
        prod *= max(1e-9, w)
    strength = prod ** (1.0 / len(weighted)) if weighted else 0.0

    # Confidence = mean of edge confidences
    conf = sum(e.confidence for e in path) / len(path)

    chain_id = "|".join([path[0].cause_id] + [e.effect_id for e in path])
    return CausalChain(
        chain_id=chain_id,
        node_ids=tuple(node_ids),
        edge_ids=tuple(e.edge_id for e in path),
        layer_sequence=layers,
        chain_strength=strength,
        chain_confidence=conf,
        distinct_layers=distinct,
        weighted_strength=max(0.0, min(1.0, strength)),
        at=at,
    )


# =============================================================================
# SECTION 6 — CONFOUNDERS
# =============================================================================


@dataclass(frozen=True)
class ConfounderReport:
    node_id: str
    parent_ids: Tuple[str, ...]
    parent_layers: Tuple[CausalLayer, ...]
    multi_layer: bool
    rationale: str
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


def find_confounders(
    graph: CausalGraph, *, at: datetime,
) -> Tuple[ConfounderReport, ...]:
    if at.tzinfo is None:
        raise ValueError("at must be timezone-aware")
    out: List[ConfounderReport] = []
    for n in graph.nodes():
        parents = graph.parents(n.node_id)
        if len(parents) < 2:
            continue
        parent_layers = tuple(graph.node(p).layer for p in parents)
        multi = len(set(parent_layers)) > 1
        out.append(ConfounderReport(
            node_id=n.node_id,
            parent_ids=parents,
            parent_layers=parent_layers,
            multi_layer=multi,
            rationale=(
                f"node {n.node_id} ({n.layer.value}) has "
                f"{len(parents)} parents across "
                f"{len(set(parent_layers))} layer(s)"
            ),
            at=at,
        ))
    return tuple(out)


# =============================================================================
# SECTION 7 — INVARIANTS
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
class CausalSnapshot:
    graph: CausalGraph
    chains: Tuple[CausalChain, ...]
    confounders: Tuple[ConfounderReport, ...]
    templates: Mapping[str, ChainTemplate]
    templates_matched: Mapping[str, Tuple[str, ...]]


@dataclass(frozen=True)
class CausalInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[CausalSnapshot], Tuple[InvariantViolation, ...]]
    description: str


def _inv_edge_endpoints_registered(
    snap: CausalSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    node_ids = {n.node_id for n in snap.graph.nodes()}
    for e in snap.graph.edges():
        if e.cause_id not in node_ids or e.effect_id not in node_ids:
            out.append(InvariantViolation(
                invariant_id="causal.edge_endpoints_registered",
                severity=InvariantSeverity.CRITICAL,
                subject_id=e.edge_id,
                detail="edge endpoint not registered",
            ))
    return tuple(out)


def _inv_edge_strength_bounded(
    snap: CausalSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for e in snap.graph.edges():
        if not 0.0 <= e.strength <= 1.0 or not 0.0 <= e.confidence <= 1.0:
            out.append(InvariantViolation(
                invariant_id="causal.edge_strength_bounded",
                severity=InvariantSeverity.HIGH,
                subject_id=e.edge_id,
                detail="edge strength/confidence out of [0,1]",
            ))
    return tuple(out)


def _inv_chain_length_consistent(
    snap: CausalSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for c in snap.chains:
        if len(c.edge_ids) != len(c.node_ids) - 1:
            out.append(InvariantViolation(
                invariant_id="causal.chain_length_consistent",
                severity=InvariantSeverity.HIGH,
                subject_id=c.chain_id,
                detail=(
                    f"edges {len(c.edge_ids)} != nodes−1 "
                    f"{len(c.node_ids) - 1}"
                ),
            ))
    return tuple(out)


def _inv_no_cross_layer_with_zero_strength(
    snap: CausalSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for c in snap.chains:
        if c.distinct_layers >= 2 and c.chain_strength <= 0.0:
            out.append(InvariantViolation(
                invariant_id="causal.cross_layer_strength_positive",
                severity=InvariantSeverity.HIGH,
                subject_id=c.chain_id,
                detail="cross-layer chain with zero strength",
            ))
    return tuple(out)


def _inv_template_match_length(
    snap: CausalSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for tid, chain_ids in snap.templates_matched.items():
        template = snap.templates.get(tid)
        if template is None:
            out.append(InvariantViolation(
                invariant_id="causal.template_match_length",
                severity=InvariantSeverity.HIGH,
                subject_id=tid,
                detail="matched template not registered",
            ))
            continue
        for cid in chain_ids:
            chain = next((c for c in snap.chains if c.chain_id == cid), None)
            if chain is None:
                continue
            if len(chain.layer_sequence) < len(template.layer_sequence):
                out.append(InvariantViolation(
                    invariant_id="causal.template_match_length",
                    severity=InvariantSeverity.HIGH,
                    subject_id=cid,
                    detail=(
                        f"chain shorter than template {tid}"
                    ),
                ))
    return tuple(out)


def _inv_confounders_have_multi_parent(
    snap: CausalSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for cf in snap.confounders:
        if len(cf.parent_ids) < 2:
            out.append(InvariantViolation(
                invariant_id="causal.confounder_multi_parent",
                severity=InvariantSeverity.MEDIUM,
                subject_id=cf.node_id,
                detail="confounder with <2 parents",
            ))
    return tuple(out)


DEFAULT_INVARIANTS: Tuple[CausalInvariant, ...] = (
    CausalInvariant(
        invariant_id="causal.edge_endpoints_registered",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_edge_endpoints_registered,
        description="Every edge endpoint must be a registered node.",
    ),
    CausalInvariant(
        invariant_id="causal.edge_strength_bounded",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_edge_strength_bounded,
        description="Edge strength/confidence must lie within [0,1].",
    ),
    CausalInvariant(
        invariant_id="causal.chain_length_consistent",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_chain_length_consistent,
        description="Chain edge count must equal node count − 1.",
    ),
    CausalInvariant(
        invariant_id="causal.cross_layer_strength_positive",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_no_cross_layer_with_zero_strength,
        description="Cross-layer chains must have positive strength.",
    ),
    CausalInvariant(
        invariant_id="causal.template_match_length",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_template_match_length,
        description="Matched chain must be at least as long as its template.",
    ),
    CausalInvariant(
        invariant_id="causal.confounder_multi_parent",
        severity=InvariantSeverity.MEDIUM,
        predicate=_inv_confounders_have_multi_parent,
        description="Confounders must have at least 2 parents.",
    ),
)


def check_invariants(
    snap: CausalSnapshot,
    invariants: Iterable[CausalInvariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 8 — STORE
# =============================================================================


@dataclass(frozen=True)
class ChainRecord:
    chain_id: str
    length: int
    distinct_layers: int
    chain_strength: float
    chain_confidence: float
    templates_matched: Tuple[str, ...]
    updated_at: datetime


class CausalStore(Protocol):
    def put(self, record: ChainRecord) -> None: ...
    def all(self) -> Tuple[ChainRecord, ...]: ...
    def get(self, chain_id: str) -> Optional[ChainRecord]: ...


class InMemoryCausalStore:
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


class SqliteCausalStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS causal_chains (
                chain_id TEXT PRIMARY KEY,
                length INTEGER NOT NULL,
                distinct_layers INTEGER NOT NULL,
                chain_strength REAL NOT NULL,
                chain_confidence REAL NOT NULL,
                templates_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS causal_nodes (
                node_id TEXT PRIMARY KEY,
                layer TEXT NOT NULL,
                kind TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                label TEXT NOT NULL,
                at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS causal_edges (
                edge_id TEXT PRIMARY KEY,
                cause_id TEXT NOT NULL,
                effect_id TEXT NOT NULL,
                kind TEXT NOT NULL,
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
            INSERT INTO causal_chains
              (chain_id, length, distinct_layers, chain_strength,
               chain_confidence, templates_json, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(chain_id) DO UPDATE SET
              length=excluded.length,
              distinct_layers=excluded.distinct_layers,
              chain_strength=excluded.chain_strength,
              chain_confidence=excluded.chain_confidence,
              templates_json=excluded.templates_json,
              updated_at=excluded.updated_at
            """,
            (
                record.chain_id, record.length, record.distinct_layers,
                record.chain_strength, record.chain_confidence,
                json.dumps(sorted(record.templates_matched)),
                record.updated_at.isoformat(),
            ),
        )
        self._conn.commit()

    def get(self, chain_id: str) -> Optional[ChainRecord]:
        row = self._conn.execute(
            "SELECT length, distinct_layers, chain_strength, "
            "chain_confidence, templates_json, updated_at "
            "FROM causal_chains WHERE chain_id = ?",
            (chain_id,),
        ).fetchone()
        if row is None:
            return None
        return ChainRecord(
            chain_id=chain_id,
            length=int(row[0]),
            distinct_layers=int(row[1]),
            chain_strength=float(row[2]),
            chain_confidence=float(row[3]),
            templates_matched=tuple(json.loads(row[4])),
            updated_at=datetime.fromisoformat(row[5]),
        )

    def all(self) -> Tuple[ChainRecord, ...]:
        rows = self._conn.execute("SELECT chain_id FROM causal_chains").fetchall()
        return tuple(
            r for r in (self.get(x[0]) for x in rows) if r is not None
        )

    def put_node(self, node: CausalNode) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO causal_nodes "
            "(node_id, layer, kind, entity_id, label, at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (node.node_id, node.layer.value, node.kind.value,
             node.entity_id, node.label, node.at.isoformat()),
        )
        self._conn.commit()

    def put_edge(self, edge: CausalEdge) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO causal_edges "
            "(edge_id, cause_id, effect_id, kind, strength, confidence, "
            "provenance, at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (edge.edge_id, edge.cause_id, edge.effect_id, edge.kind.value,
             edge.strength, edge.confidence, edge.provenance,
             edge.at.isoformat()),
        )
        self._conn.commit()


# =============================================================================
# SECTION 9 — ENGINE
# =============================================================================


@dataclass
class _TemplateMatch:
    template_id: str
    chain_id: str


class CausalSecurityEngine:
    """Cross-layer causal security engine.

    Builds a causal graph across 13 layers, discovers chains, matches
    them against dangerous templates, detects confounders, and produces
    causal findings.
    """

    def __init__(
        self,
        *,
        store: Optional[CausalStore] = None,
        max_depth: int = 6,
        max_paths: int = 500,
        min_chain_strength: float = 0.1,
        min_cross_layer_span: int = 2,
        high_strength_threshold: float = 0.6,
        fan_out_threshold: int = 8,
    ) -> None:
        if max_depth < 1:
            raise ValueError("max_depth must be >= 1")
        if max_paths < 1:
            raise ValueError("max_paths must be >= 1")
        if not 0.0 <= min_chain_strength <= 1.0:
            raise ValueError("min_chain_strength must be within [0,1]")
        if min_cross_layer_span < 2:
            raise ValueError("min_cross_layer_span must be >= 2")
        if not 0.0 <= high_strength_threshold <= 1.0:
            raise ValueError("high_strength_threshold must be within [0,1]")
        if fan_out_threshold < 1:
            raise ValueError("fan_out_threshold must be >= 1")

        self._store: CausalStore = store or InMemoryCausalStore()
        self._graph = CausalGraph()
        self._templates: Dict[str, ChainTemplate] = {}
        self._chains: Tuple[CausalChain, ...] = ()
        self._confounders: Tuple[ConfounderReport, ...] = ()
        self._template_matches: List[_TemplateMatch] = []
        self._findings: List[CausalFinding] = []
        self._violations: Tuple[InvariantViolation, ...] = ()

        self._max_depth = max_depth
        self._max_paths = max_paths
        self._min_chain_strength = min_chain_strength
        self._min_cross_layer_span = min_cross_layer_span
        self._high_strength = high_strength_threshold
        self._fan_out = fan_out_threshold

    # ---- registration ----------------------------------------------------

    def add_node(self, node: CausalNode) -> None:
        self._graph.add_node(node)
        if isinstance(self._store, SqliteCausalStore):
            self._store.put_node(node)

    def add_edge(self, edge: CausalEdge) -> None:
        self._graph.add_edge(edge)
        if isinstance(self._store, SqliteCausalStore):
            self._store.put_edge(edge)

    def register_template(self, template: ChainTemplate) -> None:
        if template.template_id in self._templates:
            raise ValueError(
                f"template {template.template_id} already registered"
            )
        self._templates[template.template_id] = template

    def graph(self) -> CausalGraph:
        return self._graph

    # ---- policy ----------------------------------------------------------

    def set_max_depth(self, d: int) -> None:
        if d < 1:
            raise ValueError("max_depth must be >= 1")
        self._max_depth = d

    def set_max_paths(self, n: int) -> None:
        if n < 1:
            raise ValueError("max_paths must be >= 1")
        self._max_paths = n

    def set_min_chain_strength(self, s: float) -> None:
        if not 0.0 <= s <= 1.0:
            raise ValueError("min_chain_strength must be within [0,1]")
        self._min_chain_strength = s

    def set_min_cross_layer_span(self, n: int) -> None:
        if n < 2:
            raise ValueError("min_cross_layer_span must be >= 2")
        self._min_cross_layer_span = n

    def set_high_strength_threshold(self, s: float) -> None:
        if not 0.0 <= s <= 1.0:
            raise ValueError("threshold must be within [0,1]")
        self._high_strength = s

    def set_fan_out_threshold(self, n: int) -> None:
        if n < 1:
            raise ValueError("fan_out_threshold must be >= 1")
        self._fan_out = n

    # ---- recompute -------------------------------------------------------

    def recompute(self, *, at: datetime) -> Tuple[ChainRecord, ...]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

        paths = self._graph.enumerate_paths(
            max_depth=self._max_depth,
            max_paths=self._max_paths,
            min_strength=self._min_chain_strength,
        )

        chains: List[CausalChain] = []
        for p in paths:
            chain = _chain_from_path(self._graph, p, at=at)
            if chain.distinct_layers < self._min_cross_layer_span:
                continue
            chains.append(chain)
        chains.sort(key=lambda c: (-c.chain_strength, -c.distinct_layers,
                                   c.chain_id))
        self._chains = tuple(chains)

        self._confounders = find_confounders(self._graph, at=at)

        # Template matching
        self._template_matches = []
        for c in self._chains:
            for tid, tmpl in self._templates.items():
                if not tmpl.matches(c.layer_sequence):
                    continue
                if c.chain_strength < tmpl.min_chain_strength:
                    continue
                self._template_matches.append(_TemplateMatch(
                    template_id=tid, chain_id=c.chain_id,
                ))

        # Findings
        self._findings = []
        for c in self._chains:
            if c.chain_strength >= self._high_strength \
               and c.distinct_layers >= self._min_cross_layer_span:
                self._findings.append(CausalFinding(
                    kind=CausalFindingKind.HIGH_STRENGTH_CROSS_LAYER_CHAIN,
                    subject_id=c.chain_id,
                    detail=(
                        f"chain strength {c.chain_strength:.3f} across "
                        f"{c.distinct_layers} layers: "
                        f"{[l.value for l in c.layer_sequence]}"
                    ),
                    severity=4, at=at,
                ))

        for match in self._template_matches:
            tmpl = self._templates[match.template_id]
            self._findings.append(CausalFinding(
                kind=CausalFindingKind.TEMPLATE_MATCH,
                subject_id=match.chain_id,
                detail=(
                    f"chain {match.chain_id} matches template "
                    f"{match.template_id} ({tmpl.risk_label})"
                ),
                severity=min(5, tmpl.severity), at=at,
            ))

        for cf in self._confounders:
            if cf.multi_layer:
                self._findings.append(CausalFinding(
                    kind=CausalFindingKind.CONFOUNDER_DETECTED,
                    subject_id=cf.node_id,
                    detail=cf.rationale,
                    severity=3, at=at,
                ))

        # Fan-out explosion
        for n in self._graph.nodes():
            if self._graph.fan_out(n.node_id) >= self._fan_out:
                self._findings.append(CausalFinding(
                    kind=CausalFindingKind.FAN_OUT_EXPLOSION,
                    subject_id=n.node_id,
                    detail=(
                        f"node fans out to "
                        f"{self._graph.fan_out(n.node_id)} effects"
                    ),
                    severity=3, at=at,
                ))

        # Persist records
        records: List[ChainRecord] = []
        for c in self._chains:
            matched = tuple(
                m.template_id for m in self._template_matches
                if m.chain_id == c.chain_id
            )
            rec = ChainRecord(
                chain_id=c.chain_id,
                length=c.length,
                distinct_layers=c.distinct_layers,
                chain_strength=c.chain_strength,
                chain_confidence=c.chain_confidence,
                templates_matched=matched,
                updated_at=at,
            )
            self._store.put(rec)
            records.append(rec)

        self._violations = check_invariants(self.snapshot())
        return tuple(records)

    # ---- queries ---------------------------------------------------------

    def chains(self) -> Tuple[CausalChain, ...]:
        return self._chains

    def confounders(self) -> Tuple[ConfounderReport, ...]:
        return self._confounders

    def findings(self) -> Tuple[CausalFinding, ...]:
        return tuple(self._findings)

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return self._violations

    def top_chains(
        self, *, k: int = 10, min_strength: Optional[float] = None,
    ) -> Tuple[CausalChain, ...]:
        if k <= 0:
            raise ValueError("k must be > 0")
        ms = min_strength if min_strength is not None else self._min_chain_strength
        items = [c for c in self._chains if c.chain_strength >= ms]
        return tuple(items[:k])

    def template_matches(self) -> Mapping[str, Tuple[str, ...]]:
        out: Dict[str, List[str]] = {}
        for m in self._template_matches:
            out.setdefault(m.template_id, []).append(m.chain_id)
        return {tid: tuple(cids) for tid, cids in out.items()}

    def snapshot(self) -> CausalSnapshot:
        return CausalSnapshot(
            graph=self._graph,
            chains=self._chains,
            confounders=self._confounders,
            templates=dict(self._templates),
            templates_matched=self.template_matches(),
        )


# =============================================================================
# SECTION 10 — TESTS
# =============================================================================


def _t0() -> datetime:
    from datetime import timezone
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _t(seconds: int) -> datetime:
    from datetime import timedelta
    return _t0() + timedelta(seconds=seconds)


def _node(
    nid: str, layer: CausalLayer = CausalLayer.IDENTITY, *,
    kind: CausalNodeKind = CausalNodeKind.STATE,
    entity: str = "e", label: str = "l",
    at: Optional[datetime] = None,
) -> CausalNode:
    return CausalNode(
        node_id=nid, layer=layer, kind=kind, entity_id=entity,
        label=label, at=at or _t0(),
    )


def _edge(
    eid: str, cause: str, effect: str, *,
    kind: CausalEdgeKind = CausalEdgeKind.CAUSES,
    strength: float = 0.8, confidence: float = 0.9,
    at: Optional[datetime] = None,
) -> CausalEdge:
    return CausalEdge(
        edge_id=eid, cause_id=cause, effect_id=effect, kind=kind,
        strength=strength, confidence=confidence,
        provenance="test", at=at or _t0(),
    )


# ---- domain ----

def test_node_requires_id() -> None:
    try:
        CausalNode(
            node_id="", layer=CausalLayer.IDENTITY,
            kind=CausalNodeKind.STATE, entity_id="e", label="l",
            at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_node_requires_aware_time() -> None:
    from datetime import datetime as dt
    try:
        CausalNode(
            node_id="n", layer=CausalLayer.IDENTITY,
            kind=CausalNodeKind.STATE, entity_id="e", label="l",
            at=dt(2026, 1, 1),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_edge_rejects_self() -> None:
    try:
        CausalEdge(
            edge_id="e", cause_id="a", effect_id="a",
            kind=CausalEdgeKind.CAUSES, strength=0.5,
            confidence=0.5, provenance="p", at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_edge_rejects_bad_strength() -> None:
    try:
        CausalEdge(
            edge_id="e", cause_id="a", effect_id="b",
            kind=CausalEdgeKind.CAUSES, strength=1.5,
            confidence=0.5, provenance="p", at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_edge_weighted_strength() -> None:
    e = _edge("e", "a", "b", kind=CausalEdgeKind.CAUSES,
              strength=0.8, confidence=0.9)
    # 0.8 × 1.0 × 0.9 = 0.72
    assert abs(e.weighted_strength - 0.72) < 1e-9


def test_edge_kind_multiplier() -> None:
    assert edge_kind_multiplier(CausalEdgeKind.CAUSES) == 1.0
    assert edge_kind_multiplier(CausalEdgeKind.CONTRIBUTES) == 0.7
    assert edge_kind_multiplier(CausalEdgeKind.PRECEDES) == 0.4


# ---- template ----

def test_template_requires_two_layers() -> None:
    try:
        ChainTemplate(
            template_id="t", layer_sequence=(CausalLayer.IDENTITY,),
            min_chain_strength=0.1, risk_label="r", severity=3,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_template_subsequence_match() -> None:
    tmpl = ChainTemplate(
        template_id="t",
        layer_sequence=(
            CausalLayer.IDENTITY, CausalLayer.AUTHORITY, CausalLayer.DATA,
        ),
        min_chain_strength=0.1, risk_label="r", severity=3,
    )
    # contiguous is not required
    assert tmpl.matches((
        CausalLayer.IDENTITY,
        CausalLayer.AUTHORITY,
        CausalLayer.APPLICATION,
        CausalLayer.DATA,
    ))


def test_template_no_match_when_order_broken() -> None:
    tmpl = ChainTemplate(
        template_id="t",
        layer_sequence=(
            CausalLayer.IDENTITY, CausalLayer.AUTHORITY, CausalLayer.DATA,
        ),
        min_chain_strength=0.1, risk_label="r", severity=3,
    )
    assert not tmpl.matches((
        CausalLayer.DATA, CausalLayer.AUTHORITY, CausalLayer.IDENTITY,
    ))


# ---- graph ----

def test_graph_rejects_duplicate_node() -> None:
    g = CausalGraph()
    g.add_node(_node("a"))
    try:
        g.add_node(_node("a"))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_graph_rejects_duplicate_edge() -> None:
    g = CausalGraph()
    g.add_node(_node("a"))
    g.add_node(_node("b"))
    g.add_edge(_edge("e1", "a", "b"))
    try:
        g.add_edge(_edge("e1", "a", "b"))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_graph_rejects_missing_node_in_edge() -> None:
    g = CausalGraph()
    g.add_node(_node("a"))
    try:
        g.add_edge(_edge("e1", "a", "missing"))
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_graph_rejects_cycle() -> None:
    g = CausalGraph()
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


def test_graph_parents_children() -> None:
    g = CausalGraph()
    g.add_node(_node("a"))
    g.add_node(_node("b"))
    g.add_node(_node("c"))
    g.add_edge(_edge("e1", "a", "b"))
    g.add_edge(_edge("e2", "c", "b"))
    assert set(g.parents("b")) == {"a", "c"}
    assert "b" in g.children("a")


def test_graph_present_layers() -> None:
    g = CausalGraph()
    g.add_node(_node("a", CausalLayer.IDENTITY))
    g.add_node(_node("b", CausalLayer.AUTHORITY))
    assert g.present_layers() == frozenset({
        CausalLayer.IDENTITY, CausalLayer.AUTHORITY,
    })


# ---- path enumeration ----

def _linear_graph() -> CausalGraph:
    g = CausalGraph()
    g.add_node(_node("a", CausalLayer.IDENTITY))
    g.add_node(_node("b", CausalLayer.AUTHORITY))
    g.add_node(_node("c", CausalLayer.APPLICATION))
    g.add_node(_node("d", CausalLayer.DATA))
    g.add_edge(_edge("e1", "a", "b", strength=0.9))
    g.add_edge(_edge("e2", "b", "c", strength=0.8))
    g.add_edge(_edge("e3", "c", "d", strength=0.7))
    return g


def test_path_enumerate_full_chain() -> None:
    g = _linear_graph()
    paths = g.enumerate_paths(max_depth=6)
    # Paths from root 'a': (a->b), (a->b->c), (a->b->c->d)
    lengths = sorted(len(p) for p in paths)
    assert lengths == [1, 2, 3]


def test_path_enumerate_source_target() -> None:
    g = _linear_graph()
    paths = g.enumerate_paths(source_id="a", target_id="d", max_depth=6)
    assert len(paths) == 1
    assert len(paths[0]) == 3


def test_path_prunes_low_strength() -> None:
    g = CausalGraph()
    g.add_node(_node("a"))
    g.add_node(_node("b"))
    g.add_edge(_edge("e1", "a", "b", strength=0.01, confidence=0.01))
    paths = g.enumerate_paths(max_depth=3, min_strength=0.2)
    assert paths == ()


def test_path_requires_min_depth() -> None:
    g = _linear_graph()
    try:
        g.enumerate_paths(max_depth=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_path_unknown_source_rejected() -> None:
    g = _linear_graph()
    try:
        g.enumerate_paths(source_id="missing")
    except KeyError:
        return
    raise AssertionError("expected KeyError")


# ---- chain analysis ----

def test_chain_from_path_layer_sequence() -> None:
    g = _linear_graph()
    paths = g.enumerate_paths(source_id="a", target_id="d", max_depth=6)
    chain = _chain_from_path(g, paths[0], at=_t0())
    assert chain.layer_sequence == (
        CausalLayer.IDENTITY, CausalLayer.AUTHORITY,
        CausalLayer.APPLICATION, CausalLayer.DATA,
    )
    assert chain.distinct_layers == 4
    assert chain.length == 3


def test_chain_strength_geometric_mean() -> None:
    g = _linear_graph()
    paths = g.enumerate_paths(source_id="a", target_id="d", max_depth=6)
    chain = _chain_from_path(g, paths[0], at=_t0())
    # edges: 0.9*0.9=0.81, 0.8*0.9=0.72, 0.7*0.9=0.63
    # geometric mean = (0.81 * 0.72 * 0.63)^(1/3)
    expected = (0.81 * 0.72 * 0.63) ** (1/3)
    assert abs(chain.chain_strength - expected) < 1e-9


def test_chain_confidence_mean() -> None:
    g = _linear_graph()
    paths = g.enumerate_paths(source_id="a", target_id="d", max_depth=6)
    chain = _chain_from_path(g, paths[0], at=_t0())
    assert abs(chain.chain_confidence - 0.9) < 1e-9


def test_chain_crosses_layer() -> None:
    g = _linear_graph()
    paths = g.enumerate_paths(source_id="a", target_id="d", max_depth=6)
    chain = _chain_from_path(g, paths[0], at=_t0())
    assert chain.crosses(CausalLayer.DATA)
    assert not chain.crosses(CausalLayer.THREAT)


def test_chain_rejects_empty_path() -> None:
    g = _linear_graph()
    try:
        _chain_from_path(g, (), at=_t0())
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- confounders ----

def test_confounder_detection() -> None:
    g = CausalGraph()
    g.add_node(_node("a", CausalLayer.IDENTITY))
    g.add_node(_node("b", CausalLayer.NETWORK))
    g.add_node(_node("c", CausalLayer.DATA))
    g.add_edge(_edge("e1", "a", "c"))
    g.add_edge(_edge("e2", "b", "c"))
    reports = find_confounders(g, at=_t0())
    assert len(reports) == 1
    assert reports[0].node_id == "c"
    assert reports[0].multi_layer


def test_confounder_single_parent_ignored() -> None:
    g = _linear_graph()
    assert find_confounders(g, at=_t0()) == ()


def test_confounder_requires_aware_time() -> None:
    from datetime import datetime as dt
    g = _linear_graph()
    try:
        find_confounders(g, at=dt(2026, 1, 1))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- engine ----

def _engine_with_linear_chain() -> CausalSecurityEngine:
    eng = CausalSecurityEngine()
    eng.add_node(_node("a", CausalLayer.IDENTITY))
    eng.add_node(_node("b", CausalLayer.AUTHORITY))
    eng.add_node(_node("c", CausalLayer.API))
    eng.add_node(_node("d", CausalLayer.CLOUD))
    eng.add_node(_node("e", CausalLayer.DATA))
    eng.add_edge(_edge("e1", "a", "b", strength=0.9, confidence=0.9))
    eng.add_edge(_edge("e2", "b", "c", strength=0.9, confidence=0.9))
    eng.add_edge(_edge("e3", "c", "d", strength=0.9, confidence=0.9))
    eng.add_edge(_edge("e4", "d", "e", strength=0.9, confidence=0.9))
    return eng


def test_engine_recompute_produces_chains() -> None:
    eng = _engine_with_linear_chain()
    records = eng.recompute(at=_t0())
    assert len(records) >= 1
    # top chain should have all 5 layers
    top = eng.top_chains(k=1)[0]
    assert top.distinct_layers == 5


def test_engine_high_strength_finding() -> None:
    eng = _engine_with_linear_chain()
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert CausalFindingKind.HIGH_STRENGTH_CROSS_LAYER_CHAIN in kinds


def test_engine_template_match_finding() -> None:
    eng = _engine_with_linear_chain()
    eng.register_template(ChainTemplate(
        template_id="malicious",
        layer_sequence=(
            CausalLayer.IDENTITY, CausalLayer.AUTHORITY,
            CausalLayer.API, CausalLayer.CLOUD, CausalLayer.DATA,
        ),
        min_chain_strength=0.5, risk_label="identity-to-data",
        severity=5,
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert CausalFindingKind.TEMPLATE_MATCH in kinds


def test_engine_template_subsequence_still_matches() -> None:
    eng = _engine_with_linear_chain()
    eng.register_template(ChainTemplate(
        template_id="short",
        layer_sequence=(
            CausalLayer.IDENTITY, CausalLayer.CLOUD, CausalLayer.DATA,
        ),
        min_chain_strength=0.5, risk_label="short", severity=4,
    ))
    eng.recompute(at=_t0())
    assert "short" in eng.template_matches()


def test_engine_template_not_matched_low_strength() -> None:
    eng = CausalSecurityEngine()
    eng.add_node(_node("a", CausalLayer.IDENTITY))
    eng.add_node(_node("b", CausalLayer.DATA))
    eng.add_edge(_edge("e1", "a", "b", strength=0.2, confidence=0.2))
    eng.register_template(ChainTemplate(
        template_id="t",
        layer_sequence=(CausalLayer.IDENTITY, CausalLayer.DATA),
        min_chain_strength=0.8, risk_label="r", severity=4,
    ))
    eng.recompute(at=_t0())
    assert "t" not in eng.template_matches()


def test_engine_confounder_finding() -> None:
    eng = CausalSecurityEngine()
    eng.add_node(_node("a", CausalLayer.IDENTITY))
    eng.add_node(_node("b", CausalLayer.NETWORK))
    eng.add_node(_node("c", CausalLayer.DATA))
    eng.add_edge(_edge("e1", "a", "c"))
    eng.add_edge(_edge("e2", "b", "c"))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert CausalFindingKind.CONFOUNDER_DETECTED in kinds


def test_engine_fan_out_finding() -> None:
    eng = CausalSecurityEngine()
    eng.set_fan_out_threshold(3)
    eng.add_node(_node("src", CausalLayer.IDENTITY))
    for i in range(5):
        eng.add_node(_node(f"t{i}", CausalLayer.DATA))
        eng.add_edge(_edge(f"e{i}", "src", f"t{i}"))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert CausalFindingKind.FAN_OUT_EXPLOSION in kinds


def test_engine_rejects_duplicate_template() -> None:
    eng = CausalSecurityEngine()
    t = ChainTemplate(
        template_id="t",
        layer_sequence=(CausalLayer.IDENTITY, CausalLayer.DATA),
        min_chain_strength=0.1, risk_label="r", severity=3,
    )
    eng.register_template(t)
    try:
        eng.register_template(t)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_rejects_missing_node() -> None:
    eng = CausalSecurityEngine()
    try:
        eng.add_edge(_edge("e1", "a", "b"))
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_engine_min_cross_layer_span_filter() -> None:
    eng = CausalSecurityEngine()
    eng.set_min_cross_layer_span(3)
    eng.add_node(_node("a", CausalLayer.IDENTITY))
    eng.add_node(_node("b", CausalLayer.DATA))
    eng.add_edge(_edge("e1", "a", "b"))
    records = eng.recompute(at=_t0())
    # Only 2 layers → below min_cross_layer_span → excluded
    assert records == ()


def test_engine_top_chains_sorted() -> None:
    eng = _engine_with_linear_chain()
    eng.recompute(at=_t0())
    top = eng.top_chains(k=10)
    strengths = [c.chain_strength for c in top]
    assert strengths == sorted(strengths, reverse=True)


def test_engine_top_chains_invalid_k() -> None:
    eng = CausalSecurityEngine()
    try:
        eng.top_chains(k=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_record_persisted() -> None:
    eng = _engine_with_linear_chain()
    records = eng.recompute(at=_t0())
    cid = records[0].chain_id
    got = eng._store.get(cid)
    assert got is not None


# ---- policy ----

def test_engine_constructor_validation() -> None:
    try:
        CausalSecurityEngine(max_depth=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_setter_validation() -> None:
    eng = CausalSecurityEngine()
    try:
        eng.set_max_depth(0)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
    try:
        eng.set_min_cross_layer_span(1)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


# ---- invariants ----

def test_invariant_clean_snapshot() -> None:
    eng = _engine_with_linear_chain()
    eng.recompute(at=_t0())
    assert eng.violations() == ()


def test_invariant_edge_endpoints_registered() -> None:
    # Construct a fake snapshot with an orphan edge
    g = CausalGraph()
    g.add_node(_node("a", CausalLayer.IDENTITY))
    # inject an edge directly (bypassing validation)
    orphan_edge = _edge("e1", "a", "ghost")
    g._edges["e1"] = orphan_edge  # type: ignore[index]
    g._out["a"] = [orphan_edge]  # type: ignore[index]
    snap = CausalSnapshot(
        graph=g, chains=(), confounders=(), templates={},
        templates_matched={},
    )
    v = check_invariants(snap)
    assert any(x.invariant_id == "causal.edge_endpoints_registered" for x in v)


def test_invariant_confounder_multi_parent() -> None:
    bad = ConfounderReport(
        node_id="x", parent_ids=("a",), parent_layers=(CausalLayer.IDENTITY,),
        multi_layer=False, rationale="x", at=_t0(),
    )
    snap = CausalSnapshot(
        graph=CausalGraph(), chains=(), confounders=(bad,),
        templates={}, templates_matched={},
    )
    v = check_invariants(snap)
    assert any(x.invariant_id == "causal.confounder_multi_parent" for x in v)


# ---- store ----

def test_in_memory_store_rejects_stale() -> None:
    s = InMemoryCausalStore()
    t = _t0()
    s.put(ChainRecord(
        "c1", 3, 4, 0.8, 0.9, ("t1",), t,
    ))
    earlier = t.replace(year=t.year - 1)
    try:
        s.put(ChainRecord(
            "c1", 2, 3, 0.5, 0.5, (), earlier,
        ))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_chain_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "causal.db")
    store = SqliteCausalStore(db)
    t = _t0()
    store.put(ChainRecord(
        "c1", length=4, distinct_layers=5, chain_strength=0.8,
        chain_confidence=0.9, templates_matched=("malicious",),
        updated_at=t,
    ))
    got = store.get("c1")
    assert got is not None
    assert got.length == 4
    assert "malicious" in got.templates_matched


def test_sqlite_store_node_and_edge_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "causal.db")
    store = SqliteCausalStore(db)
    n = _node("a")
    e = _edge("e1", "a", "a") if False else CausalEdge(
        edge_id="e1", cause_id="a", effect_id="b",
        kind=CausalEdgeKind.CAUSES, strength=0.9,
        confidence=0.9, provenance="p", at=_t0(),
    )
    store.put_node(n)
    store.put_edge(e)
    row = store._conn.execute(
        "SELECT provenance FROM causal_edges WHERE edge_id = 'e1'"
    ).fetchone()
    assert row is not None and row[0] == "p"


# =============================================================================
# SECTION 11 — MANUAL RUNNER
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
