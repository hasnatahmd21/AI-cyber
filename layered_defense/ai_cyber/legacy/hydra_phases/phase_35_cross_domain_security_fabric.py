"""
HYDRA POST-CORE — PHASE 35: CROSS-DOMAIN SECURITY FABRIC
============================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * Domain — 13 fabric stages composing the full post-core lifecycle
  * A *fabric* is a first-class, queryable graph over the 13 stages:

        DIGITAL_ESTATE
          ↓
        SECURITY_STATE
          ↓
        TRUST_STATE
          ↓
        EVIDENCE_STATE
          ↓
        AUTHORITY_STATE
          ↓
        INVARIANTS
          ↓
        STATE_TRANSITION_CONTROL
          ↓
        INTERVENTION
          ↓
        VERIFICATION
          ↓
        RECOVERY_REGENERATION
          ↓
        LEARNING
          ↓
        FUTURE_THREAT_DISCOVERY
          ↓
        DEFENSIVE_INNOVATION

  * Each stage carries:
      - input contracts  (required artifacts from earlier stages)
      - output contracts (artifacts it produces)
      - state references (which phase supplied it)
      - provenance (which phase documented it)
      - a health status
  * Fabric flow — bounded forward traversal with propagation
  * Coherence rules — no stage can be ACTIVE without all its
    input contracts being produced upstream
  * Coherence invariants
  * Fabric findings — 10 kinds
  * In-memory + SQLite stores
  * Phase-35 engine facade
  * Full test suite + manual runner

Doctrine: this is a *fabric*, not a bundle of products. Every stage
must plug into its upstream and downstream with named contracts; a
stage with unmet input contracts is flagged, not silently accepted.

No third-party dependencies.

Run tests:
    python hydra_phase35_cross_domain_security_fabric.py
    pytest hydra_phase35_cross_domain_security_fabric.py -q
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


class FabricStage(str, Enum):
    DIGITAL_ESTATE = "digital_estate"
    SECURITY_STATE = "security_state"
    TRUST_STATE = "trust_state"
    EVIDENCE_STATE = "evidence_state"
    AUTHORITY_STATE = "authority_state"
    INVARIANTS = "invariants"
    STATE_TRANSITION_CONTROL = "state_transition_control"
    INTERVENTION = "intervention"
    VERIFICATION = "verification"
    RECOVERY_REGENERATION = "recovery_regeneration"
    LEARNING = "learning"
    FUTURE_THREAT_DISCOVERY = "future_threat_discovery"
    DEFENSIVE_INNOVATION = "defensive_innovation"


FABRIC_ORDER: Tuple[FabricStage, ...] = (
    FabricStage.DIGITAL_ESTATE,
    FabricStage.SECURITY_STATE,
    FabricStage.TRUST_STATE,
    FabricStage.EVIDENCE_STATE,
    FabricStage.AUTHORITY_STATE,
    FabricStage.INVARIANTS,
    FabricStage.STATE_TRANSITION_CONTROL,
    FabricStage.INTERVENTION,
    FabricStage.VERIFICATION,
    FabricStage.RECOVERY_REGENERATION,
    FabricStage.LEARNING,
    FabricStage.FUTURE_THREAT_DISCOVERY,
    FabricStage.DEFENSIVE_INNOVATION,
)


def stage_index(s: FabricStage) -> int:
    return FABRIC_ORDER.index(s)


# Canonical mapping from stage → the Phase that produced the
# underlying capability. This is *documentation as data*: it makes the
# fabric explicitly plug every stage into an existing phase.
STAGE_PHASE_SOURCE: Mapping[FabricStage, str] = {
    FabricStage.DIGITAL_ESTATE: "phase-05..10",
    FabricStage.SECURITY_STATE: "phase-01..05",
    FabricStage.TRUST_STATE: "phase-04..11",
    FabricStage.EVIDENCE_STATE: "phase-06",
    FabricStage.AUTHORITY_STATE: "phase-03",
    FabricStage.INVARIANTS: "phase-21",
    FabricStage.STATE_TRANSITION_CONTROL: "phase-20",
    FabricStage.INTERVENTION: "phase-19",
    FabricStage.VERIFICATION: "phase-16",
    FabricStage.RECOVERY_REGENERATION: "phase-21",
    FabricStage.LEARNING: "phase-11..12",
    FabricStage.FUTURE_THREAT_DISCOVERY: "phase-32..33",
    FabricStage.DEFENSIVE_INNOVATION: "phase-34",
}


class StageHealth(str, Enum):
    ABSENT = "absent"
    DEGRADED = "degraded"
    PARTIAL = "partial"
    HEALTHY = "healthy"


_HEALTH_RANK: Mapping[StageHealth, int] = {
    StageHealth.ABSENT: 0,
    StageHealth.DEGRADED: 1,
    StageHealth.PARTIAL: 2,
    StageHealth.HEALTHY: 3,
}


def health_rank(h: StageHealth) -> int:
    return _HEALTH_RANK.get(h, -1)


class FindingKind(str, Enum):
    FABRIC_COHERENT = "fabric_coherent"
    STAGE_MISSING = "stage_missing"
    STAGE_DEGRADED = "stage_degraded"
    INPUT_CONTRACT_UNMET = "input_contract_unmet"
    OUTPUT_CONTRACT_MISSING = "output_contract_missing"
    ORPHAN_STAGE = "orphan_stage"
    BROKEN_CHAIN = "broken_chain"
    UNPLUGGED_STAGE = "unplugged_stage"
    CYCLE_REJECTED = "cycle_rejected"
    COVERAGE_GAP = "coverage_gap"


@dataclass(frozen=True)
class FabricFinding:
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
# SECTION 3 — CONTRACTS (Stage-level)
# =============================================================================


@dataclass(frozen=True)
class Contract:
    """A named artifact produced/consumed by a stage."""
    name: str
    description: str = ""

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("contract name is required")


@dataclass(frozen=True)
class StageNode:
    """A node in the fabric."""
    stage: FabricStage
    phase_source: str
    health: StageHealth
    inputs: FrozenSet[Contract]
    outputs: FrozenSet[Contract]
    state_ref: Optional[str] = None     # reference to the underlying state object
    at: Optional[datetime] = None

    def __post_init__(self) -> None:
        if not self.phase_source:
            raise ValueError("phase_source is required")
        if self.at is not None and self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


@dataclass(frozen=True)
class StageEdge:
    """A producer → consumer edge between two stages."""
    edge_id: str
    producer: FabricStage
    consumer: FabricStage
    contracts: FrozenSet[Contract]

    def __post_init__(self) -> None:
        if not self.edge_id:
            raise ValueError("edge_id is required")
        if self.producer == self.consumer:
            raise ValueError("self-edge is not allowed")
        if stage_index(self.producer) >= stage_index(self.consumer):
            raise ValueError(
                "fabric edges must be strictly forward"
            )
        if not self.contracts:
            raise ValueError("edge must carry at least one contract")


# =============================================================================
# SECTION 4 — FABRIC
# =============================================================================


class SecurityFabric:
    """A first-class graph over the 13 fabric stages."""

    def __init__(self) -> None:
        self._nodes: Dict[FabricStage, StageNode] = {}
        self._edges: Dict[str, StageEdge] = {}
        self._out: Dict[FabricStage, List[str]] = {}
        self._in: Dict[FabricStage, List[str]] = {}

    # ---- nodes -----------------------------------------------------------

    def add_stage(self, node: StageNode) -> None:
        if node.stage in self._nodes:
            raise ValueError(
                f"stage {node.stage.value} already registered"
            )
        self._nodes[node.stage] = node
        self._out.setdefault(node.stage, [])
        self._in.setdefault(node.stage, [])

    def stage(self, s: FabricStage) -> StageNode:
        n = self._nodes.get(s)
        if n is None:
            raise KeyError(f"stage {s.value} not registered")
        return n

    def stages(self) -> Tuple[StageNode, ...]:
        return tuple(
            self._nodes[s] for s in FABRIC_ORDER if s in self._nodes
        )

    def has_stage(self, s: FabricStage) -> bool:
        return s in self._nodes

    def present_stages(self) -> FrozenSet[FabricStage]:
        return frozenset(self._nodes.keys())

    # ---- edges -----------------------------------------------------------

    def add_edge(self, edge: StageEdge) -> None:
        if edge.edge_id in self._edges:
            raise ValueError(f"edge {edge.edge_id} already exists")
        if edge.producer not in self._nodes:
            raise KeyError(f"producer {edge.producer.value} not registered")
        if edge.consumer not in self._nodes:
            raise KeyError(f"consumer {edge.consumer.value} not registered")
        # Each contract on the edge must be an output of the producer
        # and an input of the consumer.
        p_out = {c.name for c in self._nodes[edge.producer].outputs}
        c_in = {c.name for c in self._nodes[edge.consumer].inputs}
        for c in edge.contracts:
            if c.name not in p_out:
                raise ValueError(
                    f"contract {c.name} is not an output of "
                    f"{edge.producer.value}"
                )
            if c.name not in c_in:
                raise ValueError(
                    f"contract {c.name} is not an input of "
                    f"{edge.consumer.value}"
                )
        self._edges[edge.edge_id] = edge
        self._out.setdefault(edge.producer, []).append(edge.edge_id)
        self._in.setdefault(edge.consumer, []).append(edge.edge_id)

    def edges(self) -> Tuple[StageEdge, ...]:
        return tuple(self._edges.values())

    def in_edges(self, s: FabricStage) -> Tuple[StageEdge, ...]:
        return tuple(
            self._edges[eid] for eid in self._in.get(s, ())
        )

    def out_edges(self, s: FabricStage) -> Tuple[StageEdge, ...]:
        return tuple(
            self._edges[eid] for eid in self._out.get(s, ())
        )

    # ---- flow ------------------------------------------------------------

    def reachable(self, s: FabricStage) -> FrozenSet[FabricStage]:
        out: set = set()
        stack = [s]
        seen: set = set()
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            for e in self.out_edges(cur):
                if e.consumer not in out:
                    out.add(e.consumer)
                    stack.append(e.consumer)
        return frozenset(out)

    def upstream_of(self, s: FabricStage) -> FrozenSet[FabricStage]:
        out: set = set()
        stack = [s]
        seen: set = set()
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            for e in self.in_edges(cur):
                if e.producer not in out:
                    out.add(e.producer)
                    stack.append(e.producer)
        return frozenset(out)


# =============================================================================
# SECTION 5 — CANONICAL FABRIC CONTRACTS
# =============================================================================


# Standard output contracts per stage, and the inputs required by the
# next stage. These are the canonical plugs.
def _c(name: str) -> Contract:
    return Contract(name=name)


CANONICAL_INPUTS: Mapping[FabricStage, FrozenSet[Contract]] = {
    FabricStage.DIGITAL_ESTATE: frozenset(),
    FabricStage.SECURITY_STATE: frozenset({
        _c("estate_inventory"),
    }),
    FabricStage.TRUST_STATE: frozenset({
        _c("security_state_snapshot"),
    }),
    FabricStage.EVIDENCE_STATE: frozenset({
        _c("trust_state_record"),
    }),
    FabricStage.AUTHORITY_STATE: frozenset({
        _c("evidence_basis"),
    }),
    FabricStage.INVARIANTS: frozenset({
        _c("authority_state"),
        _c("trust_state_record"),
    }),
    FabricStage.STATE_TRANSITION_CONTROL: frozenset({
        _c("invariant_set"),
    }),
    FabricStage.INTERVENTION: frozenset({
        _c("transition_decision"),
    }),
    FabricStage.VERIFICATION: frozenset({
        _c("intervention_plan"),
    }),
    FabricStage.RECOVERY_REGENERATION: frozenset({
        _c("verified_outcome"),
    }),
    FabricStage.LEARNING: frozenset({
        _c("recovery_state"),
    }),
    FabricStage.FUTURE_THREAT_DISCOVERY: frozenset({
        _c("learned_model"),
    }),
    FabricStage.DEFENSIVE_INNOVATION: frozenset({
        _c("future_threat_set"),
    }),
}

CANONICAL_OUTPUTS: Mapping[FabricStage, FrozenSet[Contract]] = {
    FabricStage.DIGITAL_ESTATE: frozenset({
        _c("estate_inventory"),
    }),
    FabricStage.SECURITY_STATE: frozenset({
        _c("security_state_snapshot"),
    }),
    FabricStage.TRUST_STATE: frozenset({
        _c("trust_state_record"),
    }),
    FabricStage.EVIDENCE_STATE: frozenset({
        _c("evidence_basis"),
    }),
    FabricStage.AUTHORITY_STATE: frozenset({
        _c("authority_state"),
    }),
    FabricStage.INVARIANTS: frozenset({
        _c("invariant_set"),
    }),
    FabricStage.STATE_TRANSITION_CONTROL: frozenset({
        _c("transition_decision"),
    }),
    FabricStage.INTERVENTION: frozenset({
        _c("intervention_plan"),
    }),
    FabricStage.VERIFICATION: frozenset({
        _c("verified_outcome"),
    }),
    FabricStage.RECOVERY_REGENERATION: frozenset({
        _c("recovery_state"),
    }),
    FabricStage.LEARNING: frozenset({
        _c("learned_model"),
    }),
    FabricStage.FUTURE_THREAT_DISCOVERY: frozenset({
        _c("future_threat_set"),
    }),
    FabricStage.DEFENSIVE_INNOVATION: frozenset(),
}


def canonical_stage(
    stage: FabricStage, *,
    health: StageHealth = StageHealth.HEALTHY,
    state_ref: Optional[str] = None,
    at: Optional[datetime] = None,
) -> StageNode:
    return StageNode(
        stage=stage,
        phase_source=STAGE_PHASE_SOURCE[stage],
        health=health,
        inputs=CANONICAL_INPUTS[stage],
        outputs=CANONICAL_OUTPUTS[stage],
        state_ref=state_ref,
        at=at,
    )


def canonical_edge(
    producer: FabricStage, consumer: FabricStage, *,
    edge_id: Optional[str] = None,
) -> StageEdge:
    """Create the canonical forward edge; carries the producer's outputs
    that are also required by the consumer."""
    p_out = {c.name: c for c in CANONICAL_OUTPUTS[producer]}
    c_in = {c.name for c in CANONICAL_INPUTS[consumer]}
    carried = frozenset(
        c for name, c in p_out.items() if name in c_in
    )
    if not carried:
        raise ValueError(
            f"no canonical contracts flow {producer.value} → "
            f"{consumer.value}"
        )
    eid = edge_id or f"edge:{producer.value}:{consumer.value}"
    return StageEdge(
        edge_id=eid,
        producer=producer,
        consumer=consumer,
        contracts=carried,
    )


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
class FabricSnapshot:
    fabric: SecurityFabric
    findings: Tuple[FabricFinding, ...]


@dataclass(frozen=True)
class FabricInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[FabricSnapshot],
                        Tuple[InvariantViolation, ...]]
    description: str


def _inv_edges_strictly_forward(
    snap: FabricSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for e in snap.fabric.edges():
        if stage_index(e.producer) >= stage_index(e.consumer):
            out.append(InvariantViolation(
                invariant_id="fabric.edges_forward",
                severity=InvariantSeverity.CRITICAL,
                subject_id=e.edge_id,
                detail=(
                    f"edge {e.producer.value} → {e.consumer.value} "
                    f"is not forward"
                ),
            ))
    return tuple(out)


def _inv_no_orphan_stages(
    snap: FabricSnapshot,
) -> Tuple[InvariantViolation, ...]:
    """Every present stage (except the first and last) must be
    connected in both directions."""
    out: List[InvariantViolation] = []
    for s in snap.fabric.present_stages():
        idx = stage_index(s)
        if idx == 0 or idx == len(FABRIC_ORDER) - 1:
            continue
        if not snap.fabric.in_edges(s):
            out.append(InvariantViolation(
                invariant_id="fabric.no_orphan_stages",
                severity=InvariantSeverity.HIGH,
                subject_id=s.value,
                detail="stage has no incoming edge",
            ))
        if not snap.fabric.out_edges(s):
            out.append(InvariantViolation(
                invariant_id="fabric.no_orphan_stages",
                severity=InvariantSeverity.HIGH,
                subject_id=s.value,
                detail="stage has no outgoing edge",
            ))
    return tuple(out)


def _inv_health_bounded(
    snap: FabricSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for s in snap.fabric.stages():
        if not 0 <= health_rank(s.health) <= 3:
            out.append(InvariantViolation(
                invariant_id="fabric.health_bounded",
                severity=InvariantSeverity.HIGH,
                subject_id=s.stage.value,
                detail=f"health rank out of range for {getattr(s.health, 'value', s.health)}",
            ))
    return tuple(out)


def _inv_healthy_requires_state_ref(
    snap: FabricSnapshot,
) -> Tuple[InvariantViolation, ...]:
    """A stage marked HEALTHY must carry a state_ref."""
    out: List[InvariantViolation] = []
    for s in snap.fabric.stages():
        if s.health is StageHealth.HEALTHY and not s.state_ref:
            out.append(InvariantViolation(
                invariant_id="fabric.healthy_requires_state_ref",
                severity=InvariantSeverity.MEDIUM,
                subject_id=s.stage.value,
                detail="HEALTHY stage lacks state_ref",
            ))
    return tuple(out)


def _inv_contracts_wired(
    snap: FabricSnapshot,
) -> Tuple[InvariantViolation, ...]:
    """Every declared input contract (except for the first stage) must
    be provided by some incoming edge."""
    out: List[InvariantViolation] = []
    for s in snap.fabric.stages():
        if stage_index(s.stage) == 0:
            continue
        satisfied: set = set()
        for e in snap.fabric.in_edges(s.stage):
            for c in e.contracts:
                satisfied.add(c.name)
        missing = {c.name for c in s.inputs} - satisfied
        for name in sorted(missing):
            out.append(InvariantViolation(
                invariant_id="fabric.contracts_wired",
                severity=InvariantSeverity.HIGH,
                subject_id=s.stage.value,
                detail=f"input contract '{name}' not satisfied upstream",
            ))
    return tuple(out)


DEFAULT_INVARIANTS: Tuple[FabricInvariant, ...] = (
    FabricInvariant(
        invariant_id="fabric.edges_forward",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_edges_strictly_forward,
        description="Fabric edges must be strictly forward.",
    ),
    FabricInvariant(
        invariant_id="fabric.no_orphan_stages",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_no_orphan_stages,
        description="Present stages must be connected in both directions.",
    ),
    FabricInvariant(
        invariant_id="fabric.health_bounded",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_health_bounded,
        description="Stage health rank must be within [0,3].",
    ),
    FabricInvariant(
        invariant_id="fabric.healthy_requires_state_ref",
        severity=InvariantSeverity.MEDIUM,
        predicate=_inv_healthy_requires_state_ref,
        description="HEALTHY stages must carry a state_ref.",
    ),
    FabricInvariant(
        invariant_id="fabric.contracts_wired",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_contracts_wired,
        description="Every input contract must be satisfied upstream.",
    ),
)


def check_invariants(
    snap: FabricSnapshot,
    invariants: Iterable[FabricInvariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 7 — STORE
# =============================================================================


@dataclass(frozen=True)
class StageRecord:
    stage: FabricStage
    health: StageHealth
    phase_source: str
    input_count: int
    output_count: int
    state_ref: Optional[str]
    updated_at: datetime


class FabricStore(Protocol):
    def put(self, record: StageRecord) -> None: ...
    def get(self, stage: FabricStage) -> Optional[StageRecord]: ...
    def all(self) -> Tuple[StageRecord, ...]: ...


class InMemoryFabricStore:
    def __init__(self) -> None:
        self._data: Dict[FabricStage, StageRecord] = {}

    def put(self, record: StageRecord) -> None:
        existing = self._data.get(record.stage)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._data[record.stage] = record

    def get(self, stage: FabricStage) -> Optional[StageRecord]:
        return self._data.get(stage)

    def all(self) -> Tuple[StageRecord, ...]:
        return tuple(
            self._data[s] for s in FABRIC_ORDER if s in self._data
        )


class SqliteFabricStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS fabric_stages (
                stage TEXT PRIMARY KEY,
                health TEXT NOT NULL,
                phase_source TEXT NOT NULL,
                input_count INTEGER NOT NULL,
                output_count INTEGER NOT NULL,
                state_ref TEXT,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS fabric_findings (
                finding_id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def put(self, record: StageRecord) -> None:
        existing = self.get(record.stage)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._conn.execute(
            """
            INSERT INTO fabric_stages
              (stage, health, phase_source, input_count, output_count,
               state_ref, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(stage) DO UPDATE SET
              health=excluded.health,
              phase_source=excluded.phase_source,
              input_count=excluded.input_count,
              output_count=excluded.output_count,
              state_ref=excluded.state_ref,
              updated_at=excluded.updated_at
            """,
            (
                record.stage.value, record.health.value,
                record.phase_source, record.input_count,
                record.output_count, record.state_ref,
                record.updated_at.isoformat(),
            ),
        )
        self._conn.commit()

    def get(self, stage: FabricStage) -> Optional[StageRecord]:
        row = self._conn.execute(
            "SELECT health, phase_source, input_count, output_count, "
            "state_ref, updated_at FROM fabric_stages WHERE stage = ?",
            (stage.value,),
        ).fetchone()
        if row is None:
            return None
        return StageRecord(
            stage=stage, health=StageHealth(row[0]),
            phase_source=row[1], input_count=int(row[2]),
            output_count=int(row[3]), state_ref=row[4],
            updated_at=datetime.fromisoformat(row[5]),
        )

    def all(self) -> Tuple[StageRecord, ...]:
        rows = self._conn.execute(
            "SELECT stage FROM fabric_stages"
        ).fetchall()
        return tuple(
            r for r in (self.get(FabricStage(x[0])) for x in rows)
            if r is not None
        )

    def put_finding(self, finding_id: str, f: FabricFinding) -> None:
        payload = {
            "finding_id": finding_id,
            "kind": f.kind.value,
            "subject_id": f.subject_id,
            "detail": f.detail,
            "severity": f.severity,
            "at": f.at.isoformat(),
        }
        self._conn.execute(
            "INSERT OR REPLACE INTO fabric_findings "
            "(finding_id, payload_json) VALUES (?, ?)",
            (finding_id, json.dumps(payload, sort_keys=True)),
        )
        self._conn.commit()


# =============================================================================
# SECTION 8 — ENGINE
# =============================================================================


@dataclass(frozen=True)
class FabricConfig:
    min_health_for_coherent: StageHealth = StageHealth.PARTIAL
    require_full_chain: bool = True

    def __post_init__(self) -> None:
        # rank must be <= HEALTHY
        if health_rank(self.min_health_for_coherent) > \
                health_rank(StageHealth.HEALTHY):
            raise ValueError("min_health_for_coherent out of range")


class CrossDomainFabricEngine:
    """Cross-domain security fabric engine.

    Plugs all 13 stages into a coherent graph, verifies contract
    wiring, and produces coherence findings.
    """

    def __init__(
        self,
        *,
        store: Optional[FabricStore] = None,
        config: Optional[FabricConfig] = None,
    ) -> None:
        self._store: FabricStore = store or InMemoryFabricStore()
        self._config = config or FabricConfig()
        self._fabric = SecurityFabric()
        self._findings: List[FabricFinding] = []
        self._violations: Tuple[InvariantViolation, ...] = ()

    # ---- configuration ---------------------------------------------------

    def config(self) -> FabricConfig:
        return self._config

    def set_config(self, config: FabricConfig) -> None:
        self._config = config

    # ---- construction ----------------------------------------------------

    def add_stage(self, node: StageNode) -> None:
        self._fabric.add_stage(node)

    def add_edge(self, edge: StageEdge) -> None:
        self._fabric.add_edge(edge)

    def fabric(self) -> SecurityFabric:
        return self._fabric

    def plug_canonical_stage(
        self,
        stage: FabricStage,
        *,
        health: StageHealth = StageHealth.HEALTHY,
        state_ref: Optional[str] = None,
        at: Optional[datetime] = None,
    ) -> StageNode:
        """Register a stage using canonical contracts."""
        node = canonical_stage(
            stage, health=health, state_ref=state_ref, at=at,
        )
        self._fabric.add_stage(node)
        return node

    def plug_canonical_chain(
        self,
        *,
        health_by_stage: Optional[Mapping[FabricStage, StageHealth]] = None,
        state_refs: Optional[Mapping[FabricStage, str]] = None,
        at: Optional[datetime] = None,
    ) -> SecurityFabric:
        """Plug all 13 stages in canonical order and wire the forward
        edges."""
        hb = dict(health_by_stage or {})
        sr = dict(state_refs or {})
        for s in FABRIC_ORDER:
            self.plug_canonical_stage(
                s,
                health=hb.get(s, StageHealth.HEALTHY),
                state_ref=sr.get(s, f"ref:{s.value}"),
                at=at,
            )
        for i in range(len(FABRIC_ORDER) - 1):
            self.add_edge(canonical_edge(
                FABRIC_ORDER[i], FABRIC_ORDER[i + 1],
            ))
        # INVARIANTS also needs TRUST_STATE's output directly (not just
        # via the intervening EVIDENCE_STATE/AUTHORITY_STATE hops) - see
        # CANONICAL_INPUTS[FabricStage.INVARIANTS].
        self.add_edge(canonical_edge(
            FabricStage.TRUST_STATE, FabricStage.INVARIANTS,
            edge_id="edge:trust_state:invariants:direct",
        ))
        return self._fabric

    # ---- recompute -------------------------------------------------------

    def recompute(self, *, at: datetime) -> Tuple[StageRecord, ...]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

        self._findings = []
        cfg = self._config

        # Per-stage findings
        for s in self._fabric.stages():
            if s.health is StageHealth.ABSENT:
                self._findings.append(FabricFinding(
                    kind=FindingKind.STAGE_MISSING,
                    subject_id=s.stage.value,
                    detail="stage is ABSENT",
                    severity=4, at=at,
                ))
            elif s.health is StageHealth.DEGRADED:
                self._findings.append(FabricFinding(
                    kind=FindingKind.STAGE_DEGRADED,
                    subject_id=s.stage.value,
                    detail="stage is DEGRADED",
                    severity=3, at=at,
                ))

        # Contract-satisfaction findings
        for s in self._fabric.stages():
            if stage_index(s.stage) == 0:
                continue
            satisfied: set = set()
            for e in self._fabric.in_edges(s.stage):
                for c in e.contracts:
                    satisfied.add(c.name)
            missing = {c.name for c in s.inputs} - satisfied
            for name in sorted(missing):
                self._findings.append(FabricFinding(
                    kind=FindingKind.INPUT_CONTRACT_UNMET,
                    subject_id=s.stage.value,
                    detail=f"missing input contract '{name}'",
                    severity=4, at=at,
                ))

        # Orphan findings
        for s in self._fabric.stages():
            idx = stage_index(s.stage)
            if idx == 0 or idx == len(FABRIC_ORDER) - 1:
                continue
            if not self._fabric.in_edges(s.stage):
                self._findings.append(FabricFinding(
                    kind=FindingKind.ORPHAN_STAGE,
                    subject_id=s.stage.value,
                    detail="no incoming edge",
                    severity=3, at=at,
                ))
            if not self._fabric.out_edges(s.stage):
                self._findings.append(FabricFinding(
                    kind=FindingKind.ORPHAN_STAGE,
                    subject_id=s.stage.value,
                    detail="no outgoing edge",
                    severity=3, at=at,
                ))

        # Missing stage findings
        for s in FABRIC_ORDER:
            if not self._fabric.has_stage(s):
                self._findings.append(FabricFinding(
                    kind=FindingKind.STAGE_MISSING,
                    subject_id=s.value,
                    detail="canonical stage missing",
                    severity=5, at=at,
                ))

        # Unplugged stage: present but zero edges (isolated entirely)
        for s in self._fabric.stages():
            if not self._fabric.in_edges(s.stage) \
               and not self._fabric.out_edges(s.stage):
                if stage_index(s.stage) not in (
                    0, len(FABRIC_ORDER) - 1,
                ):
                    self._findings.append(FabricFinding(
                        kind=FindingKind.UNPLUGGED_STAGE,
                        subject_id=s.stage.value,
                        detail="stage present but has no edges",
                        severity=4, at=at,
                    ))

        # Broken chain: an edge whose contracts are not wired correctly
        # (defensive — should never happen after add_edge validation)
        for e in self._fabric.edges():
            try:
                _ = self._fabric.stage(e.producer)
                _ = self._fabric.stage(e.consumer)
            except KeyError:
                self._findings.append(FabricFinding(
                    kind=FindingKind.BROKEN_CHAIN,
                    subject_id=e.edge_id,
                    detail="edge references unregistered stage",
                    severity=5, at=at,
                ))

        # Coverage gap: some stage below min_health_for_coherent
        threshold = health_rank(cfg.min_health_for_coherent)
        for s in self._fabric.stages():
            if health_rank(s.health) < threshold:
                self._findings.append(FabricFinding(
                    kind=FindingKind.COVERAGE_GAP,
                    subject_id=s.stage.value,
                    detail=(
                        f"health {getattr(s.health, 'value', s.health)} "
                        f"below threshold "
                        f"{cfg.min_health_for_coherent.value}"
                    ),
                    severity=4, at=at,
                ))

        # Coherent finding — only if no non-coherent findings
        non_coherent_kinds = {
            FindingKind.STAGE_MISSING,
            FindingKind.STAGE_DEGRADED,
            FindingKind.INPUT_CONTRACT_UNMET,
            FindingKind.ORPHAN_STAGE,
            FindingKind.BROKEN_CHAIN,
            FindingKind.UNPLUGGED_STAGE,
            FindingKind.COVERAGE_GAP,
        }
        if not any(f.kind in non_coherent_kinds for f in self._findings):
            self._findings.append(FabricFinding(
                kind=FindingKind.FABRIC_COHERENT,
                subject_id="fabric",
                detail=(
                    f"all {len(self._fabric.stages())} stages plugged "
                    f"and coherent"
                ),
                severity=1, at=at,
            ))

        # Persist
        records: List[StageRecord] = []
        for s in self._fabric.stages():
            rec = StageRecord(
                stage=s.stage, health=s.health,
                phase_source=s.phase_source,
                input_count=len(s.inputs),
                output_count=len(s.outputs),
                state_ref=s.state_ref, updated_at=at,
            )
            self._store.put(rec)
            records.append(rec)

        if isinstance(self._store, SqliteFabricStore):
            for i, f in enumerate(self._findings):
                self._store.put_finding(
                    f"f-{i:08d}-{f.kind.value}", f,
                )

        self._violations = check_invariants(self.snapshot())
        return tuple(records)

    # ---- queries ---------------------------------------------------------

    def findings(self) -> Tuple[FabricFinding, ...]:
        return tuple(self._findings)

    def findings_by_kind(self) -> Mapping[FindingKind, int]:
        out: Dict[FindingKind, int] = {k: 0 for k in FindingKind}
        for f in self._findings:
            out[f.kind] += 1
        return out

    def is_coherent(self) -> bool:
        return any(
            f.kind is FindingKind.FABRIC_COHERENT
            for f in self._findings
        )

    def stage_health(self, s: FabricStage) -> Optional[StageHealth]:
        if not self._fabric.has_stage(s):
            return None
        return self._fabric.stage(s).health

    def top_findings(
        self, *, k: int = 10,
    ) -> Tuple[FabricFinding, ...]:
        if k <= 0:
            raise ValueError("k must be > 0")
        ordered = sorted(
            self._findings,
            key=lambda f: (-f.severity, f.kind.value, f.subject_id),
        )
        return tuple(ordered[:k])

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return self._violations

    def record(self, s: FabricStage) -> Optional[StageRecord]:
        return self._store.get(s)

    def coverage(self) -> float:
        """Fraction of canonical stages present AND healthy."""
        total = len(FABRIC_ORDER)
        if total == 0:
            return 1.0
        healthy = sum(
            1 for s in FABRIC_ORDER
            if self._fabric.has_stage(s)
            and self._fabric.stage(s).health is StageHealth.HEALTHY
        )
        return healthy / total

    def snapshot(self) -> FabricSnapshot:
        return FabricSnapshot(
            fabric=self._fabric,
            findings=tuple(self._findings),
        )


# =============================================================================
# SECTION 9 — TESTS
# =============================================================================


def _t0() -> datetime:
    from datetime import timezone
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


# ---- domain ----

def test_contract_requires_name() -> None:
    try:
        Contract(name="")
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_stage_node_requires_phase_source() -> None:
    try:
        StageNode(
            stage=FabricStage.DIGITAL_ESTATE,
            phase_source="", health=StageHealth.HEALTHY,
            inputs=frozenset(), outputs=frozenset(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_stage_node_requires_aware_time() -> None:
    from datetime import datetime as dt
    try:
        StageNode(
            stage=FabricStage.DIGITAL_ESTATE,
            phase_source="x", health=StageHealth.HEALTHY,
            inputs=frozenset(), outputs=frozenset(),
            at=dt(2026, 1, 1),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_stage_edge_requires_contracts() -> None:
    try:
        StageEdge(
            edge_id="e",
            producer=FabricStage.DIGITAL_ESTATE,
            consumer=FabricStage.SECURITY_STATE,
            contracts=frozenset(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_stage_edge_self_rejected() -> None:
    try:
        StageEdge(
            edge_id="e",
            producer=FabricStage.SECURITY_STATE,
            consumer=FabricStage.SECURITY_STATE,
            contracts=frozenset({_c("x")}),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_stage_edge_backward_rejected() -> None:
    try:
        StageEdge(
            edge_id="e",
            producer=FabricStage.LEARNING,
            consumer=FabricStage.DIGITAL_ESTATE,
            contracts=frozenset({_c("x")}),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_stage_index_ordering() -> None:
    assert stage_index(FabricStage.DIGITAL_ESTATE) < \
        stage_index(FabricStage.SECURITY_STATE)
    assert stage_index(FabricStage.LEARNING) < \
        stage_index(FabricStage.FUTURE_THREAT_DISCOVERY)
    assert stage_index(FabricStage.FUTURE_THREAT_DISCOVERY) < \
        stage_index(FabricStage.DEFENSIVE_INNOVATION)


def test_health_rank_ordering() -> None:
    assert health_rank(StageHealth.ABSENT) < \
        health_rank(StageHealth.DEGRADED)
    assert health_rank(StageHealth.DEGRADED) < \
        health_rank(StageHealth.PARTIAL)
    assert health_rank(StageHealth.PARTIAL) < \
        health_rank(StageHealth.HEALTHY)


# ---- fabric graph ----

def test_fabric_add_stage_duplicate_rejected() -> None:
    f = SecurityFabric()
    f.add_stage(canonical_stage(FabricStage.DIGITAL_ESTATE))
    try:
        f.add_stage(canonical_stage(FabricStage.DIGITAL_ESTATE))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_fabric_add_edge_unknown_producer() -> None:
    f = SecurityFabric()
    f.add_stage(canonical_stage(FabricStage.SECURITY_STATE))
    try:
        f.add_edge(canonical_edge(
            FabricStage.DIGITAL_ESTATE, FabricStage.SECURITY_STATE,
        ))
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_fabric_add_edge_contract_must_be_output() -> None:
    f = SecurityFabric()
    f.add_stage(StageNode(
        stage=FabricStage.DIGITAL_ESTATE,
        phase_source="x", health=StageHealth.HEALTHY,
        inputs=frozenset(),
        outputs=frozenset({_c("something_else")}),
    ))
    f.add_stage(canonical_stage(FabricStage.SECURITY_STATE))
    try:
        f.add_edge(StageEdge(
            edge_id="e",
            producer=FabricStage.DIGITAL_ESTATE,
            consumer=FabricStage.SECURITY_STATE,
            contracts=frozenset({_c("estate_inventory")}),
        ))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_fabric_reachable() -> None:
    f = SecurityFabric()
    for i in range(len(FABRIC_ORDER) - 1):
        try:
            f.add_stage(canonical_stage(FABRIC_ORDER[i]))
        except ValueError:
            pass
        try:
            f.add_stage(canonical_stage(FABRIC_ORDER[i + 1]))
        except ValueError:
            pass
    for i in range(len(FABRIC_ORDER) - 1):
        try:
            f.add_edge(canonical_edge(
                FABRIC_ORDER[i], FABRIC_ORDER[i + 1],
            ))
        except ValueError:
            pass
    # re-register cleanly
    f = SecurityFabric()
    for s in FABRIC_ORDER:
        f.add_stage(canonical_stage(s))
    for i in range(len(FABRIC_ORDER) - 1):
        f.add_edge(canonical_edge(
            FABRIC_ORDER[i], FABRIC_ORDER[i + 1],
        ))
    reach = f.reachable(FabricStage.DIGITAL_ESTATE)
    assert FabricStage.DEFENSIVE_INNOVATION in reach


def test_fabric_upstream_of() -> None:
    f = SecurityFabric()
    for s in FABRIC_ORDER:
        f.add_stage(canonical_stage(s))
    for i in range(len(FABRIC_ORDER) - 1):
        f.add_edge(canonical_edge(
            FABRIC_ORDER[i], FABRIC_ORDER[i + 1],
        ))
    upstream = f.upstream_of(FabricStage.AUTHORITY_STATE)
    assert FabricStage.DIGITAL_ESTATE in upstream
    assert FabricStage.EVIDENCE_STATE in upstream


# ---- canonical contracts ----

def test_canonical_stage_has_phase_source() -> None:
    node = canonical_stage(FabricStage.INVARIANTS)
    assert node.phase_source == "phase-21"


def test_canonical_edge_digital_to_security() -> None:
    e = canonical_edge(
        FabricStage.DIGITAL_ESTATE, FabricStage.SECURITY_STATE,
    )
    assert e.producer is FabricStage.DIGITAL_ESTATE
    assert e.consumer is FabricStage.SECURITY_STATE
    assert any(c.name == "estate_inventory" for c in e.contracts)


def test_canonical_edge_no_contract_flow() -> None:
    # DEFENSIVE_INNOVATION has no outputs → cannot drive any edge
    try:
        canonical_edge(
            FabricStage.DEFENSIVE_INNOVATION,
            FabricStage.DIGITAL_ESTATE,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- engine construction ----

def test_engine_plug_canonical_stage() -> None:
    eng = CrossDomainFabricEngine()
    eng.plug_canonical_stage(FabricStage.DIGITAL_ESTATE)
    assert eng.stage_health(FabricStage.DIGITAL_ESTATE) is \
        StageHealth.HEALTHY


def test_engine_plug_canonical_chain() -> None:
    eng = CrossDomainFabricEngine()
    eng.plug_canonical_chain()
    assert len(eng.fabric().stages()) == len(FABRIC_ORDER)
    assert len(eng.fabric().edges()) == len(FABRIC_ORDER)


def test_engine_recompute_requires_aware_time() -> None:
    from datetime import datetime as dt
    eng = CrossDomainFabricEngine()
    eng.plug_canonical_chain()
    try:
        eng.recompute(at=dt(2026, 1, 1))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_full_chain_coherent() -> None:
    eng = CrossDomainFabricEngine()
    eng.plug_canonical_chain()
    eng.recompute(at=_t0())
    assert eng.is_coherent()
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.FABRIC_COHERENT in kinds


def test_engine_full_chain_no_violations() -> None:
    eng = CrossDomainFabricEngine()
    eng.plug_canonical_chain()
    eng.recompute(at=_t0())
    assert eng.violations() == ()


def test_engine_missing_stage_finding() -> None:
    eng = CrossDomainFabricEngine()
    # plug only first three
    for s in FABRIC_ORDER[:3]:
        eng.plug_canonical_stage(s)
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.STAGE_MISSING in kinds
    assert not eng.is_coherent()


def test_engine_degraded_stage_finding() -> None:
    eng = CrossDomainFabricEngine()
    eng.plug_canonical_chain(health_by_stage={
        FabricStage.INVARIANTS: StageHealth.DEGRADED,
    })
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.STAGE_DEGRADED in kinds


def test_engine_unmet_contract_finding() -> None:
    # Register DIGITAL_ESTATE + AUTHORITY_STATE with no edge between
    eng = CrossDomainFabricEngine()
    eng.plug_canonical_stage(FabricStage.DIGITAL_ESTATE)
    eng.plug_canonical_stage(FabricStage.AUTHORITY_STATE)
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.INPUT_CONTRACT_UNMET in kinds


def test_engine_coverage_gap_finding() -> None:
    eng = CrossDomainFabricEngine()
    eng.plug_canonical_chain(health_by_stage={
        FabricStage.LEARNING: StageHealth.DEGRADED,
    })
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.COVERAGE_GAP in kinds


def test_engine_absent_stage_finding() -> None:
    eng = CrossDomainFabricEngine()
    eng.plug_canonical_chain(health_by_stage={
        FabricStage.VERIFICATION: StageHealth.ABSENT,
    })
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.STAGE_MISSING in kinds


def test_engine_coverage_fraction() -> None:
    eng = CrossDomainFabricEngine()
    eng.plug_canonical_chain()
    eng.recompute(at=_t0())
    assert eng.coverage() == 1.0


def test_engine_coverage_partial() -> None:
    eng = CrossDomainFabricEngine()
    eng.plug_canonical_chain(health_by_stage={
        FabricStage.INVARIANTS: StageHealth.DEGRADED,
        FabricStage.LEARNING: StageHealth.DEGRADED,
    })
    eng.recompute(at=_t0())
    # 11 healthy out of 13
    expected = 11 / 13
    assert abs(eng.coverage() - expected) < 1e-9


def test_engine_findings_by_kind() -> None:
    eng = CrossDomainFabricEngine()
    eng.plug_canonical_chain()
    eng.recompute(at=_t0())
    counts = eng.findings_by_kind()
    assert counts[FindingKind.FABRIC_COHERENT] == 1


def test_engine_top_findings_sorted() -> None:
    eng = CrossDomainFabricEngine()
    eng.plug_canonical_chain(health_by_stage={
        FabricStage.INVARIANTS: StageHealth.DEGRADED,
        FabricStage.LEARNING: StageHealth.DEGRADED,
    })
    eng.recompute(at=_t0())
    top = eng.top_findings(k=20)
    severities = [f.severity for f in top]
    assert severities == sorted(severities, reverse=True)


def test_engine_top_findings_invalid_k() -> None:
    eng = CrossDomainFabricEngine()
    try:
        eng.top_findings(k=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_record_lookup() -> None:
    eng = CrossDomainFabricEngine()
    eng.plug_canonical_chain()
    eng.recompute(at=_t0())
    rec = eng.record(FabricStage.DIGITAL_ESTATE)
    assert rec is not None
    assert rec.phase_source == "phase-05..10"


def test_engine_orphan_stage_detection() -> None:
    eng = CrossDomainFabricEngine()
    # Register two stages without any edge
    eng.plug_canonical_stage(FabricStage.DIGITAL_ESTATE)
    eng.plug_canonical_stage(FabricStage.SECURITY_STATE)
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    # SECURITY_STATE has no in-edge and is not the first stage → orphan
    assert FindingKind.ORPHAN_STAGE in kinds


def test_engine_unplugged_stage_detection() -> None:
    eng = CrossDomainFabricEngine()
    eng.plug_canonical_stage(FabricStage.DIGITAL_ESTATE)
    eng.plug_canonical_stage(FabricStage.LEARNING)  # isolated middle
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.UNPLUGGED_STAGE in kinds


def test_engine_stage_health_lookup() -> None:
    eng = CrossDomainFabricEngine()
    eng.plug_canonical_chain()
    assert eng.stage_health(FabricStage.INVARIANTS) is \
        StageHealth.HEALTHY


def test_engine_stage_health_unknown() -> None:
    eng = CrossDomainFabricEngine()
    assert eng.stage_health(FabricStage.INVARIANTS) is None


def test_engine_config_validation() -> None:
    # min_health_for_coherent as HEALTHY is fine
    FabricConfig(min_health_for_coherent=StageHealth.HEALTHY)


def test_engine_set_config() -> None:
    eng = CrossDomainFabricEngine()
    cfg = FabricConfig(min_health_for_coherent=StageHealth.HEALTHY)
    eng.set_config(cfg)
    assert eng.config() is cfg


def test_engine_config_strict_health_marks_partial_as_coverage_gap() -> None:
    eng = CrossDomainFabricEngine()
    eng.set_config(FabricConfig(
        min_health_for_coherent=StageHealth.HEALTHY,
    ))
    eng.plug_canonical_chain(health_by_stage={
        FabricStage.INVARIANTS: StageHealth.PARTIAL,
    })
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.COVERAGE_GAP in kinds


# ---- invariants ----

def test_invariant_clean_snapshot() -> None:
    eng = CrossDomainFabricEngine()
    eng.plug_canonical_chain()
    eng.recompute(at=_t0())
    assert eng.violations() == ()


def test_invariant_contracts_wired() -> None:
    eng = CrossDomainFabricEngine()
    eng.plug_canonical_stage(FabricStage.DIGITAL_ESTATE)
    eng.plug_canonical_stage(FabricStage.SECURITY_STATE)
    # no edge → contract unmet
    eng.recompute(at=_t0())
    v = eng.violations()
    assert any(
        x.invariant_id == "fabric.contracts_wired" for x in v
    )


def test_invariant_no_orphan_stages() -> None:
    eng = CrossDomainFabricEngine()
    eng.plug_canonical_stage(FabricStage.DIGITAL_ESTATE)
    eng.plug_canonical_stage(FabricStage.SECURITY_STATE)
    eng.recompute(at=_t0())
    v = eng.violations()
    assert any(
        x.invariant_id == "fabric.no_orphan_stages" for x in v
    )


def test_invariant_health_bounded() -> None:
    # Force a bogus health rank by direct mutation
    eng = CrossDomainFabricEngine()
    eng.plug_canonical_stage(FabricStage.DIGITAL_ESTATE)
    bad = object.__new__(StageNode)
    object.__setattr__(bad, "stage", FabricStage.SECURITY_STATE)
    object.__setattr__(bad, "phase_source", "phase-01..05")
    object.__setattr__(bad, "health", "invalid")
    object.__setattr__(bad, "inputs", frozenset())
    object.__setattr__(bad, "outputs", frozenset())
    object.__setattr__(bad, "state_ref", None)
    object.__setattr__(bad, "at", None)
    eng.fabric()._nodes[FabricStage.SECURITY_STATE] = bad  # type: ignore
    eng.fabric()._out.setdefault(FabricStage.SECURITY_STATE, [])
    eng.fabric()._in.setdefault(FabricStage.SECURITY_STATE, [])
    eng.recompute(at=_t0())
    v = eng.violations()
    assert any(
        x.invariant_id == "fabric.health_bounded" for x in v
    )


def test_invariant_healthy_requires_state_ref() -> None:
    eng = CrossDomainFabricEngine()
    eng.plug_canonical_stage(
        FabricStage.DIGITAL_ESTATE,
        health=StageHealth.HEALTHY, state_ref=None,
    )
    eng.recompute(at=_t0())
    v = eng.violations()
    assert any(
        x.invariant_id == "fabric.healthy_requires_state_ref"
        for x in v
    )


# ---- store ----

def test_in_memory_store_rejects_stale() -> None:
    s = InMemoryFabricStore()
    t = _t0()
    s.put(StageRecord(
        FabricStage.DIGITAL_ESTATE, StageHealth.HEALTHY,
        "phase-05..10", 0, 1, "ref", t,
    ))
    earlier = t.replace(year=t.year - 1)
    try:
        s.put(StageRecord(
            FabricStage.DIGITAL_ESTATE, StageHealth.HEALTHY,
            "phase-05..10", 0, 1, "ref", earlier,
        ))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "fabric.db")
    store = SqliteFabricStore(db)
    store.put(StageRecord(
        FabricStage.INVARIANTS, StageHealth.HEALTHY, "phase-21",
        2, 1, "ref:invariants", _t0(),
    ))
    got = store.get(FabricStage.INVARIANTS)
    assert got is not None
    assert got.phase_source == "phase-21"
    assert got.health is StageHealth.HEALTHY


def test_sqlite_store_finding_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "fabric.db")
    store = SqliteFabricStore(db)
    f = FabricFinding(
        kind=FindingKind.FABRIC_COHERENT,
        subject_id="fabric", detail="ok", severity=1, at=_t0(),
    )
    store.put_finding("fid-1", f)
    row = store._conn.execute(
        "SELECT payload_json FROM fabric_findings "
        "WHERE finding_id = 'fid-1'"
    ).fetchone()
    assert row is not None
    payload = json.loads(row[0])
    assert payload["kind"] == "fabric_coherent"


# =============================================================================
# SECTION 10 — MANUAL RUNNER
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
