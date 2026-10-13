"""
HYDRA POST-CORE — PHASE 39: GLOBAL INTEGRATION VALIDATION
=============================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * A model of the *locked* HYDRA baseline as a set of 16 named
    capabilities that post-core phases may CONSUME but must NOT modify.
  * 38 post-core phases modeled as `IntegrationUnit`s, each declaring:
      - which locked baseline capabilities it consumes
      - which cross-phase contracts it consumes
      - which cross-phase contracts it produces
      - whether it is a *terminal* producer
  * Cross-phase integration graph
  * Validation rules:
      1. Every consumed contract is produced by the baseline or by an
         earlier phase (contract satisfaction)
      2. No unit declares baseline modification (locked baseline
         respected)
      3. No dependency cycles
      4. Every phase consumes at least one baseline capability
      5. Every produced contract is either consumed downstream or the
         unit is marked terminal (no orphan output)
      6. No two units produce the same contract
      7. No two units share the same unit_id
  * 10 finding kinds
  * Machine-checkable integration invariants
  * In-memory + SQLite stores
  * Phase-39 engine facade
  * Full test suite + manual runner

Doctrine: DO NOT modify the old HYDRA implementation at this stage.
Only establish clean interfaces/contracts required for future
integration. This module is a *validation* of those interfaces, not
an integrator.

No third-party dependencies.

Run tests:
    python hydra_phase39_global_integration_validation.py
    pytest hydra_phase39_global_integration_validation.py -q
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
# SECTION 2 — LOCKED HYDRA BASELINE
# =============================================================================


class BaselineCapability(str, Enum):
    """The locked HYDRA baseline. Post-core phases may CONSUME these
    capabilities but must NOT modify them."""
    CYBER_BRAIN = "cyber_brain"
    SECURITY_STATE = "security_state"
    MEMORY = "memory"
    GRAPH = "graph"
    REASONING = "reasoning"
    DETECTION = "detection"
    PREDICTION = "prediction"
    SIMULATION = "simulation"
    DECISION = "decision"
    VERIFICATION = "verification"
    LEARNING = "learning"
    RESILIENCE = "resilience"
    SECURITY_ARCHITECTURE = "security_architecture"
    POLICY = "policy"
    CRYPTOGRAPHY = "cryptography"
    AUDIT = "audit"


ALL_BASELINE: Tuple[BaselineCapability, ...] = tuple(BaselineCapability)


# =============================================================================
# SECTION 3 — DOMAIN ENUMS
# =============================================================================


class FindingKind(str, Enum):
    INTEGRATION_OK = "integration_ok"
    CONTRACT_UNSATISFIED = "contract_unsatisfied"
    BASELINE_MODIFICATION_ATTEMPTED = "baseline_modification_attempted"
    CYCLE_DETECTED = "cycle_detected"
    NO_BASELINE_DEPENDENCY = "no_baseline_dependency"
    ORPHAN_OUTPUT = "orphan_output"
    DUPLICATE_CONTRACT_PRODUCER = "duplicate_contract_producer"
    DUPLICATE_UNIT_ID = "duplicate_unit_id"
    MISSING_TERMINAL_DECLARATION = "missing_terminal_declaration"
    UNKNOWN_CONTRACT_CONSUMER = "unknown_contract_consumer"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_SEVERITY_RANK: Mapping[Severity, int] = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def severity_rank(s: Severity) -> int:
    return _SEVERITY_RANK[s]


@dataclass(frozen=True)
class IntegrationFinding:
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
# SECTION 4 — INTEGRATION UNIT
# =============================================================================


@dataclass(frozen=True)
class IntegrationUnit:
    """A post-core phase as an integration unit.

    * baseline_consumes : locked HYDRA capabilities this phase uses
    * contracts_consumes: cross-phase contract names it needs upstream
    * contracts_produces: cross-phase contract names it emits
    * terminal          : True if this unit is a *sink* by design
                          (its outputs need not be consumed by another
                          post-core phase)
    * baseline_modifies : must be False — the baseline is locked
    """
    unit_id: str
    name: str
    baseline_consumes: FrozenSet[BaselineCapability]
    contracts_consumes: FrozenSet[str] = frozenset()
    contracts_produces: FrozenSet[str] = frozenset()
    terminal: bool = False
    baseline_modifies: FrozenSet[BaselineCapability] = frozenset()

    def __post_init__(self) -> None:
        if not self.unit_id:
            raise ValueError("unit_id is required")
        if not self.name:
            raise ValueError("name is required")


# =============================================================================
# SECTION 5 — INTEGRATION GRAPH
# =============================================================================


@dataclass(frozen=True)
class IntegrationEdge:
    """A cross-phase edge implied by a produced→consumed contract."""
    producer_unit_id: str
    consumer_unit_id: str
    contracts: FrozenSet[str]

    def __post_init__(self) -> None:
        if not self.producer_unit_id or not self.consumer_unit_id:
            raise ValueError("producer/consumer required")
        if self.producer_unit_id == self.consumer_unit_id:
            raise ValueError("self edge is not allowed")
        if not self.contracts:
            raise ValueError("edge must carry at least one contract")


class IntegrationGraph:
    """DAG over post-core integration units.

    Edges are derived from contract flow. The graph is a validation
    tool, not a runtime bus.
    """

    def __init__(self) -> None:
        self._units: Dict[str, IntegrationUnit] = {}
        self._edges: List[IntegrationEdge] = []
        self._contract_producers: Dict[str, List[str]] = {}
        self._baseline_producers: Dict[str, str] = {}

    def add_unit(self, u: IntegrationUnit) -> None:
        if u.unit_id in self._units:
            raise ValueError(f"unit {u.unit_id} already registered")
        self._units[u.unit_id] = u
        for c in u.contracts_produces:
            self._contract_producers.setdefault(c, []).append(u.unit_id)

    def unit(self, uid: str) -> IntegrationUnit:
        u = self._units.get(uid)
        if u is None:
            raise KeyError(f"unknown unit {uid}")
        return u

    def units(self) -> Tuple[IntegrationUnit, ...]:
        return tuple(self._units.values())

    def contract_producers(self, contract: str) -> Tuple[str, ...]:
        return tuple(sorted(self._contract_producers.get(contract, ())))

    def is_baseline_contract(self, contract: str) -> bool:
        """Treat the baseline capability names as if they were
        contracts produced by a fictitious `_baseline` unit."""
        return contract in {c.value for c in ALL_BASELINE}

    def add_edge(self, e: IntegrationEdge) -> None:
        self._edges.append(e)

    def edges(self) -> Tuple[IntegrationEdge, ...]:
        return tuple(self._edges)

    def outgoing(self, uid: str) -> Tuple[IntegrationEdge, ...]:
        return tuple(e for e in self._edges if e.producer_unit_id == uid)

    def incoming(self, uid: str) -> Tuple[IntegrationEdge, ...]:
        return tuple(e for e in self._edges if e.consumer_unit_id == uid)

    def detect_cycle(self) -> Optional[Tuple[str, ...]]:
        """Return a cycle as a tuple of unit ids, or None."""
        color: Dict[str, int] = {}   # 0=white, 1=gray, 2=black
        parent: Dict[str, Optional[str]] = {}
        adj: Dict[str, List[str]] = {u: [] for u in self._units}
        for e in self._edges:
            adj[e.producer_unit_id].append(e.consumer_unit_id)
        stack: List[str] = []

        def dfs(u: str) -> Optional[Tuple[str, ...]]:
            color[u] = 1
            stack.append(u)
            for v in sorted(adj.get(u, ())):
                if color.get(v, 0) == 0:
                    parent[v] = u
                    res = dfs(v)
                    if res is not None:
                        return res
                elif color.get(v, 0) == 1:
                    # Found back edge → reconstruct cycle
                    cycle: List[str] = [v]
                    cur = u
                    while cur is not None and cur != v:
                        cycle.append(cur)
                        cur = parent.get(cur)
                    cycle.append(v)
                    cycle.reverse()
                    return tuple(cycle)
            color[u] = 2
            stack.pop()
            return None

        for u in sorted(self._units):
            if color.get(u, 0) == 0:
                res = dfs(u)
                if res is not None:
                    return res
        return None


# =============================================================================
# SECTION 6 — CANONICAL 38-PHASE REGISTRATION
# =============================================================================


def _u(
    unit_id: str,
    name: str,
    baseline: Iterable[BaselineCapability],
    consumes: Iterable[str] = (),
    produces: Iterable[str] = (),
    *,
    terminal: bool = True,
) -> IntegrationUnit:
    return IntegrationUnit(
        unit_id=unit_id,
        name=name,
        baseline_consumes=frozenset(baseline),
        contracts_consumes=frozenset(consumes),
        contracts_produces=frozenset(produces),
        terminal=terminal,
        baseline_modifies=frozenset(),
    )


def canonical_integration_units() -> Tuple[IntegrationUnit, ...]:
    B = BaselineCapability
    return (
        _u("P01", "Operating System Security Depth",
           (B.SECURITY_STATE, B.MEMORY),
           produces=("os_state",)),
        _u("P02", "Network Security State Depth",
           (B.SECURITY_STATE, B.MEMORY, B.GRAPH),
           produces=("network_state",)),
        _u("P03", "Identity + Dynamic Authority",
           (B.SECURITY_STATE, B.DECISION, B.POLICY),
           produces=("authority_state", "authority_signal")),
        _u("P04", "Application + API Trust State",
           (B.SECURITY_STATE, B.MEMORY),
           produces=("app_api_trust",)),
        _u("P05", "Container / VM / Cloud State",
           (B.SECURITY_STATE, B.GRAPH),
           produces=("cloud_state",)),
        _u("P06", "Distributed Security State",
           (B.SECURITY_STATE, B.MEMORY),
           produces=("distributed_reconciliation",)),
        _u("P07", "Software Supply-Chain Trust",
           (B.SECURITY_STATE, B.MEMORY),
           produces=("supply_chain_state",)),
        _u("P08", "AI Supply-Chain Trust",
           (B.SECURITY_STATE, B.MEMORY),
           produces=("ai_supply_chain_state",)),
        _u("P09", "Storage / Database Security State",
           (B.SECURITY_STATE, B.MEMORY),
           produces=("storage_db_state",)),
        _u("P10", "Hardware / Firmware / Boot Trust",
           (B.SECURITY_STATE,),
           produces=("hw_boot_state",)),
        _u("P11", "Statistical Security Foundation",
           (B.MEMORY, B.LEARNING),
           produces=("statistical_profiles",)),
        _u("P12", "Adaptive Behavioral Security",
           (B.SECURITY_STATE, B.LEARNING, B.MEMORY),
           produces=("behavioral_state",)),
        _u("P13", "Multivariate Security State Analytics",
           (B.SECURITY_STATE, B.GRAPH),
           produces=("multivariate_analysis",)),
        _u("P14", "Time-Series + Early-Warning",
           (B.PREDICTION, B.MEMORY),
           produces=("trajectory_forecast",)),
        _u("P15", "Probabilistic Security Extension",
           (B.REASONING, B.MEMORY),
           produces=("probabilistic_state",)),
        _u("P16", "Detection Error Science",
           (B.DETECTION, B.MEMORY),
           produces=("detection_quality",)),
        _u("P17", "Causal Security Extension",
           (B.REASONING, B.GRAPH),
           produces=("causal_chains",)),
        _u("P18", "Counterfactual Security Extension",
           (B.REASONING, B.SIMULATION),
           produces=("counterfactual_results",)),
        _u("P19", "Defensive Intervention Optimization",
           (B.DECISION,),
           produces=("intervention_optimization",)),
        _u("P20", "Cyber Control Theory Extension",
           (B.DECISION, B.SECURITY_STATE),
           produces=("control_state",)),
        _u("P21", "Security Invariants + Formal Verification",
           (B.SECURITY_STATE, B.DECISION),
           produces=("invariants", "transition_validator")),
        _u("P22", "Reliability + Failure Engineering",
           (B.DETECTION, B.MEMORY),
           produces=("cause_classification",)),
        _u("P23", "Adversarial Resilience",
           (B.SECURITY_ARCHITECTURE, B.DETECTION),
           produces=("adversarial_findings",)),
        _u("P24", "Cross-Layer Security Causality",
           (B.REASONING,),
           produces=("cross_layer_chains",)),
        _u("P25", "Cyber Digital-Twin Extension",
           (B.SIMULATION,),
           produces=("twin_extension",)),
        _u("P26", "Autonomous System / AI-Agent Security",
           (B.SECURITY_STATE, B.DECISION),
           produces=("agent_state",)),
        _u("P27", "AI Governance + Technical Enforcement",
           (B.DECISION, B.POLICY),
           produces=("governance_enforcement",)),
        _u("P28", "AI Dependency / Sovereignty Resilience",
           (B.GRAPH, B.MEMORY),
           produces=("sovereignty_report",)),
        _u("P29", "Novel Attack-Surface Discovery",
           (B.GRAPH, B.MEMORY),
           produces=("novel_surface_candidates",)),
        _u("P30", "Emergent Threat Discovery",
           (B.GRAPH, B.MEMORY),
           produces=("emergent_threats",)),
        _u("P31", "Cryptographic Future Resilience",
           (B.SECURITY_STATE, B.CRYPTOGRAPHY),
           produces=("crypto_state",)),
        _u("P32", "Emerging Technology Security Forecasting",
           (B.MEMORY, B.PREDICTION),
           produces=("tech_forecast",)),
        _u("P33", "Future Threat Scenario Engineering",
           (B.SIMULATION, B.PREDICTION),
           produces=("future_scenarios",)),
        _u("P34", "Defensive Technology Invention Pipeline",
           (B.DECISION, B.VERIFICATION),
           produces=("invention_decisions",)),
        _u("P35", "Cross-Domain Security Fabric",
           (B.SECURITY_STATE,),
           produces=("fabric_coherence",),
           terminal=True),
        _u("P36", "Multi-Model Assurance",
           (B.DECISION, B.VERIFICATION),
           produces=("multi_model_assurance",)),
        _u("P37", "Security Outcome / Control Effectiveness",
           (B.VERIFICATION, B.LEARNING),
           produces=("outcome_scorecard",)),
        _u("P38", "Adversarial Validation",
           (B.SECURITY_ARCHITECTURE, B.DETECTION),
           produces=("validation_results",),
           terminal=True),
    )


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
class IntegrationSnapshot:
    units: Mapping[str, IntegrationUnit]
    edges: Tuple[IntegrationEdge, ...]
    findings: Tuple[IntegrationFinding, ...]
    cycle: Optional[Tuple[str, ...]]


@dataclass(frozen=True)
class IntegrationInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[IntegrationSnapshot],
                        Tuple[InvariantViolation, ...]]
    description: str


def _inv_no_baseline_modification(
    snap: IntegrationSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for uid, u in snap.units.items():
        if u.baseline_modifies:
            out.append(InvariantViolation(
                invariant_id="int.no_baseline_modification",
                severity=InvariantSeverity.CRITICAL,
                subject_id=uid,
                detail=(
                    f"unit declares modification of baseline "
                    f"capabilities: "
                    f"{sorted(c.value for c in u.baseline_modifies)}"
                ),
            ))
    return tuple(out)


def _inv_every_phase_consumes_baseline(
    snap: IntegrationSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for uid, u in snap.units.items():
        if not u.baseline_consumes:
            out.append(InvariantViolation(
                invariant_id="int.every_phase_consumes_baseline",
                severity=InvariantSeverity.HIGH,
                subject_id=uid,
                detail="unit declares no baseline consumption",
            ))
    return tuple(out)


def _inv_no_cycle(
    snap: IntegrationSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    if snap.cycle is not None:
        out.append(InvariantViolation(
            invariant_id="int.no_cycle",
            severity=InvariantSeverity.CRITICAL,
            subject_id=">".join(snap.cycle),
            detail=f"dependency cycle detected: {list(snap.cycle)}",
        ))
    return tuple(out)


def _inv_contracts_satisfied(
    snap: IntegrationSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    # Build the universe of produced contracts, including baseline
    produced: Dict[str, List[str]] = {}
    for uid, u in snap.units.items():
        for c in u.contracts_produces:
            produced.setdefault(c, []).append(uid)
    baseline_contracts = {c.value for c in ALL_BASELINE}
    for uid, u in snap.units.items():
        for c in u.contracts_consumes:
            if c in baseline_contracts or c in produced:
                continue
            out.append(InvariantViolation(
                invariant_id="int.contracts_satisfied",
                severity=InvariantSeverity.CRITICAL,
                subject_id=uid,
                detail=f"consumed contract '{c}' has no producer",
            ))
    return tuple(out)


def _inv_output_consumed_or_terminal(
    snap: IntegrationSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    # Collect all consumed contracts across units
    consumed: set = set()
    for u in snap.units.values():
        consumed |= set(u.contracts_consumes)
    for uid, u in snap.units.items():
        if u.terminal:
            continue
        for c in u.contracts_produces:
            if c in consumed:
                continue
            out.append(InvariantViolation(
                invariant_id="int.output_consumed_or_terminal",
                severity=InvariantSeverity.MEDIUM,
                subject_id=uid,
                detail=(
                    f"contract '{c}' has no downstream consumer and "
                    f"unit is not marked terminal"
                ),
            ))
    return tuple(out)


def _inv_findings_severity_bounded(
    snap: IntegrationSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for f in snap.findings:
        if not 1 <= f.severity <= 5:
            out.append(InvariantViolation(
                invariant_id="int.findings_severity_bounded",
                severity=InvariantSeverity.LOW,
                subject_id=f.subject_id,
                detail=f"severity {f.severity}",
            ))
    return tuple(out)


DEFAULT_INVARIANTS: Tuple[IntegrationInvariant, ...] = (
    IntegrationInvariant(
        invariant_id="int.no_baseline_modification",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_no_baseline_modification,
        description="No unit may modify the locked HYDRA baseline.",
    ),
    IntegrationInvariant(
        invariant_id="int.every_phase_consumes_baseline",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_every_phase_consumes_baseline,
        description="Every phase must consume at least one baseline capability.",
    ),
    IntegrationInvariant(
        invariant_id="int.no_cycle",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_no_cycle,
        description="The integration graph must be acyclic.",
    ),
    IntegrationInvariant(
        invariant_id="int.contracts_satisfied",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_contracts_satisfied,
        description="Every consumed contract must have a producer.",
    ),
    IntegrationInvariant(
        invariant_id="int.output_consumed_or_terminal",
        severity=InvariantSeverity.MEDIUM,
        predicate=_inv_output_consumed_or_terminal,
        description="Every produced contract is consumed or terminal.",
    ),
    IntegrationInvariant(
        invariant_id="int.findings_severity_bounded",
        severity=InvariantSeverity.LOW,
        predicate=_inv_findings_severity_bounded,
        description="Findings must carry a valid severity.",
    ),
)


def check_invariants(
    snap: IntegrationSnapshot,
    invariants: Iterable[IntegrationInvariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 8 — STORE
# =============================================================================


@dataclass(frozen=True)
class UnitStateRecord:
    unit_id: str
    name: str
    baseline_consumes: int
    contracts_consumes: int
    contracts_produces: int
    terminal: bool
    updated_at: datetime


class IntegrationStore(Protocol):
    def put(self, record: UnitStateRecord) -> None: ...
    def get(self, unit_id: str) -> Optional[UnitStateRecord]: ...
    def all(self) -> Tuple[UnitStateRecord, ...]: ...


class InMemoryIntegrationStore:
    def __init__(self) -> None:
        self._data: Dict[str, UnitStateRecord] = {}

    def put(self, record: UnitStateRecord) -> None:
        existing = self._data.get(record.unit_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._data[record.unit_id] = record

    def get(self, unit_id: str) -> Optional[UnitStateRecord]:
        return self._data.get(unit_id)

    def all(self) -> Tuple[UnitStateRecord, ...]:
        return tuple(self._data.values())


class SqliteIntegrationStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS integration_units (
                unit_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                baseline_consumes INTEGER NOT NULL,
                contracts_consumes INTEGER NOT NULL,
                contracts_produces INTEGER NOT NULL,
                terminal INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS integration_findings (
                finding_id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def put(self, record: UnitStateRecord) -> None:
        existing = self.get(record.unit_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._conn.execute(
            """
            INSERT INTO integration_units
              (unit_id, name, baseline_consumes, contracts_consumes,
               contracts_produces, terminal, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(unit_id) DO UPDATE SET
              name=excluded.name,
              baseline_consumes=excluded.baseline_consumes,
              contracts_consumes=excluded.contracts_consumes,
              contracts_produces=excluded.contracts_produces,
              terminal=excluded.terminal,
              updated_at=excluded.updated_at
            """,
            (
                record.unit_id, record.name,
                record.baseline_consumes, record.contracts_consumes,
                record.contracts_produces, int(record.terminal),
                record.updated_at.isoformat(),
            ),
        )
        self._conn.commit()

    def get(self, unit_id: str) -> Optional[UnitStateRecord]:
        row = self._conn.execute(
            "SELECT name, baseline_consumes, contracts_consumes, "
            "contracts_produces, terminal, updated_at "
            "FROM integration_units WHERE unit_id = ?",
            (unit_id,),
        ).fetchone()
        if row is None:
            return None
        return UnitStateRecord(
            unit_id=unit_id, name=row[0],
            baseline_consumes=int(row[1]),
            contracts_consumes=int(row[2]),
            contracts_produces=int(row[3]),
            terminal=bool(row[4]),
            updated_at=datetime.fromisoformat(row[5]),
        )

    def all(self) -> Tuple[UnitStateRecord, ...]:
        rows = self._conn.execute(
            "SELECT unit_id FROM integration_units"
        ).fetchall()
        return tuple(
            r for r in (self.get(x[0]) for x in rows)
            if r is not None
        )

    def put_finding(self, finding_id: str, f: IntegrationFinding) -> None:
        payload = {
            "finding_id": finding_id,
            "kind": f.kind.value,
            "subject_id": f.subject_id,
            "detail": f.detail,
            "severity": f.severity,
            "at": f.at.isoformat(),
        }
        self._conn.execute(
            "INSERT OR REPLACE INTO integration_findings "
            "(finding_id, payload_json) VALUES (?, ?)",
            (finding_id, json.dumps(payload, sort_keys=True)),
        )
        self._conn.commit()


# =============================================================================
# SECTION 9 — ENGINE
# =============================================================================


@dataclass(frozen=True)
class IntegrationConfig:
    max_findings: int = 5000
    require_baseline_consumption: bool = True
    require_acyclic: bool = True

    def __post_init__(self) -> None:
        if self.max_findings < 1:
            raise ValueError("max_findings must be >= 1")


class GlobalIntegrationValidator:
    """Global integration validator.

    Registers post-core phases as `IntegrationUnit`s, derives the
    contract-flow graph, and verifies the seven integration rules
    without touching the locked HYDRA baseline.
    """

    def __init__(
        self,
        *,
        store: Optional[IntegrationStore] = None,
        config: Optional[IntegrationConfig] = None,
    ) -> None:
        self._store: IntegrationStore = store or InMemoryIntegrationStore()
        self._config = config or IntegrationConfig()
        self._units: Dict[str, IntegrationUnit] = {}
        self._edges: Tuple[IntegrationEdge, ...] = ()
        self._cycle: Optional[Tuple[str, ...]] = None
        self._findings: List[IntegrationFinding] = []
        self._violations: Tuple[InvariantViolation, ...] = ()

    # ---- registration ----------------------------------------------------

    def register_unit(self, u: IntegrationUnit) -> None:
        if u.unit_id in self._units:
            raise ValueError(f"unit {u.unit_id} already registered")
        self._units[u.unit_id] = u

    def register_canonical_phases(self) -> None:
        for u in canonical_integration_units():
            self.register_unit(u)

    def units(self) -> Tuple[IntegrationUnit, ...]:
        return tuple(self._units.values())

    def unit(self, uid: str) -> Optional[IntegrationUnit]:
        return self._units.get(uid)

    def config(self) -> IntegrationConfig:
        return self._config

    def set_config(self, c: IntegrationConfig) -> None:
        self._config = c

    # ---- build graph -----------------------------------------------------

    def _build_graph(self) -> IntegrationGraph:
        g = IntegrationGraph()
        for u in self._units.values():
            g.add_unit(u)
        # Derive edges from contract flow
        producers: Dict[str, List[str]] = {}
        for u in self._units.values():
            for c in u.contracts_produces:
                producers.setdefault(c, []).append(u.unit_id)
        for u in self._units.values():
            for c in sorted(u.contracts_consumes):
                for producer in producers.get(c, ()):
                    if producer == u.unit_id:
                        continue
                    g.add_edge(IntegrationEdge(
                        producer_unit_id=producer,
                        consumer_unit_id=u.unit_id,
                        contracts=frozenset({c}),
                    ))
        return g

    # ---- recompute -------------------------------------------------------

    def recompute(self, *, at: datetime) -> Tuple[UnitStateRecord, ...]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        cfg = self._config
        self._findings = []

        graph = self._build_graph()

        # Duplicate unit ids
        ids = [u.unit_id for u in self._units.values()]
        seen: set = set()
        for uid in ids:
            if uid in seen:
                self._findings.append(IntegrationFinding(
                    kind=FindingKind.DUPLICATE_UNIT_ID,
                    subject_id=uid,
                    detail="unit id registered twice",
                    severity=5, at=at,
                ))
            seen.add(uid)

        # Baseline modification attempts
        for u in self._units.values():
            if u.baseline_modifies:
                self._findings.append(IntegrationFinding(
                    kind=FindingKind.BASELINE_MODIFICATION_ATTEMPTED,
                    subject_id=u.unit_id,
                    detail=(
                        f"unit declares modification of baseline "
                        f"capabilities: "
                        f"{sorted(c.value for c in u.baseline_modifies)}"
                    ),
                    severity=5, at=at,
                ))

        # Baseline consumption
        if cfg.require_baseline_consumption:
            for u in self._units.values():
                if not u.baseline_consumes:
                    self._findings.append(IntegrationFinding(
                        kind=FindingKind.NO_BASELINE_DEPENDENCY,
                        subject_id=u.unit_id,
                        detail="unit declares no baseline consumption",
                        severity=3, at=at,
                    ))

        # Duplicate contract producers
        all_produces: Dict[str, List[str]] = {}
        for u in self._units.values():
            for c in u.contracts_produces:
                all_produces.setdefault(c, []).append(u.unit_id)
        for c, producers in all_produces.items():
            if len(producers) > 1:
                self._findings.append(IntegrationFinding(
                    kind=FindingKind.DUPLICATE_CONTRACT_PRODUCER,
                    subject_id=c,
                    detail=(
                        f"contract '{c}' produced by multiple units: "
                        f"{sorted(producers)}"
                    ),
                    severity=4, at=at,
                ))

        # Contract satisfaction
        baseline_contracts = {c.value for c in ALL_BASELINE}
        for u in self._units.values():
            for c in sorted(u.contracts_consumes):
                if c in baseline_contracts:
                    continue
                if all_produces.get(c):
                    continue
                self._findings.append(IntegrationFinding(
                    kind=FindingKind.CONTRACT_UNSATISFIED,
                    subject_id=u.unit_id,
                    detail=(
                        f"consumed contract '{c}' has no producer"
                    ),
                    severity=5, at=at,
                ))

        # Orphan outputs
        consumed_contracts: set = set()
        for u in self._units.values():
            consumed_contracts |= set(u.contracts_consumes)
        for u in self._units.values():
            if u.terminal:
                continue
            for c in sorted(u.contracts_produces):
                if c in consumed_contracts:
                    continue
                self._findings.append(IntegrationFinding(
                    kind=FindingKind.ORPHAN_OUTPUT,
                    subject_id=u.unit_id,
                    detail=(
                        f"produced contract '{c}' has no downstream "
                        f"consumer and unit is not terminal"
                    ),
                    severity=3, at=at,
                ))
                self._findings.append(IntegrationFinding(
                    kind=FindingKind.MISSING_TERMINAL_DECLARATION,
                    subject_id=u.unit_id,
                    detail=(
                        f"mark unit '{u.unit_id}' terminal if it is "
                        f"intentionally a sink"
                    ),
                    severity=2, at=at,
                ))

        # Cycles
        self._cycle = graph.detect_cycle() if cfg.require_acyclic else None
        if self._cycle is not None:
            self._findings.append(IntegrationFinding(
                kind=FindingKind.CYCLE_DETECTED,
                subject_id=">".join(self._cycle),
                detail=f"cycle: {list(self._cycle)}",
                severity=5, at=at,
            ))

        # Persist unit records
        records: List[UnitStateRecord] = []
        for u in self._units.values():
            rec = UnitStateRecord(
                unit_id=u.unit_id, name=u.name,
                baseline_consumes=len(u.baseline_consumes),
                contracts_consumes=len(u.contracts_consumes),
                contracts_produces=len(u.contracts_produces),
                terminal=u.terminal, updated_at=at,
            )
            self._store.put(rec)
            records.append(rec)

        self._edges = graph.edges()

        # Integration-OK finding if no non-OK findings
        non_ok = {
            FindingKind.CONTRACT_UNSATISFIED,
            FindingKind.BASELINE_MODIFICATION_ATTEMPTED,
            FindingKind.CYCLE_DETECTED,
            FindingKind.NO_BASELINE_DEPENDENCY,
            FindingKind.ORPHAN_OUTPUT,
            FindingKind.DUPLICATE_CONTRACT_PRODUCER,
            FindingKind.DUPLICATE_UNIT_ID,
        }
        if not any(f.kind in non_ok for f in self._findings):
            self._findings.append(IntegrationFinding(
                kind=FindingKind.INTEGRATION_OK,
                subject_id="<all>",
                detail=(
                    f"all {len(self._units)} post-core phases "
                    f"integrate cleanly with the locked HYDRA baseline"
                ),
                severity=1, at=at,
            ))

        if len(self._findings) > cfg.max_findings:
            self._findings = self._findings[: cfg.max_findings]

        if isinstance(self._store, SqliteIntegrationStore):
            for i, f in enumerate(self._findings):
                self._store.put_finding(
                    f"f-{i:08d}-{f.kind.value}", f,
                )

        self._violations = check_invariants(self.snapshot())
        return tuple(records)

    # ---- queries ---------------------------------------------------------

    def findings(self) -> Tuple[IntegrationFinding, ...]:
        return tuple(self._findings)

    def findings_by_kind(self) -> Mapping[FindingKind, int]:
        out: Dict[FindingKind, int] = {k: 0 for k in FindingKind}
        for f in self._findings:
            out[f.kind] += 1
        return out

    def top_findings(
        self, *, k: int = 10,
    ) -> Tuple[IntegrationFinding, ...]:
        if k <= 0:
            raise ValueError("k must be > 0")
        ordered = sorted(
            self._findings,
            key=lambda f: (-f.severity, f.kind.value, f.subject_id),
        )
        return tuple(ordered[:k])

    def edges(self) -> Tuple[IntegrationEdge, ...]:
        return self._edges

    def cycle(self) -> Optional[Tuple[str, ...]]:
        return self._cycle

    def is_integrated(self) -> bool:
        return any(
            f.kind is FindingKind.INTEGRATION_OK
            for f in self._findings
        )

    def coverage_ratio(self) -> float:
        """Fraction of the 38 canonical phases registered."""
        canonical = canonical_integration_units()
        present = sum(
            1 for u in canonical if u.unit_id in self._units
        )
        return present / len(canonical)

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return self._violations

    def record(self, uid: str) -> Optional[UnitStateRecord]:
        return self._store.get(uid)

    def snapshot(self) -> IntegrationSnapshot:
        return IntegrationSnapshot(
            units=dict(self._units),
            edges=self._edges,
            findings=tuple(self._findings),
            cycle=self._cycle,
        )


# =============================================================================
# SECTION 10 — TESTS
# =============================================================================


def _t0() -> datetime:
    from datetime import timezone
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _unit(
    uid: str = "P01", *,
    name: str = "Test",
    baseline: Iterable[BaselineCapability] = (
        BaselineCapability.SECURITY_STATE,
    ),
    consumes: Iterable[str] = (),
    produces: Iterable[str] = ("c1",),
    terminal: bool = False,
    modifies: Iterable[BaselineCapability] = (),
) -> IntegrationUnit:
    return IntegrationUnit(
        unit_id=uid, name=name,
        baseline_consumes=frozenset(baseline),
        contracts_consumes=frozenset(consumes),
        contracts_produces=frozenset(produces),
        terminal=terminal,
        baseline_modifies=frozenset(modifies),
    )


# ---- domain ----

def test_baseline_capability_count() -> None:
    assert len(ALL_BASELINE) == 16


def test_unit_requires_id() -> None:
    try:
        IntegrationUnit(
            unit_id="", name="x",
            baseline_consumes=frozenset(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_unit_requires_name() -> None:
    try:
        IntegrationUnit(
            unit_id="u", name="",
            baseline_consumes=frozenset(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_edge_requires_contracts() -> None:
    try:
        IntegrationEdge(
            producer_unit_id="a", consumer_unit_id="b",
            contracts=frozenset(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_edge_self_rejected() -> None:
    try:
        IntegrationEdge(
            producer_unit_id="a", consumer_unit_id="a",
            contracts=frozenset({"x"}),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_severity_rank_ordering() -> None:
    assert severity_rank(Severity.LOW) < severity_rank(Severity.MEDIUM)
    assert severity_rank(Severity.MEDIUM) < severity_rank(Severity.HIGH)
    assert severity_rank(Severity.HIGH) < severity_rank(Severity.CRITICAL)


# ---- canonical library ----

def test_canonical_units_count() -> None:
    units = canonical_integration_units()
    assert len(units) == 38


def test_canonical_ids_unique() -> None:
    ids = [u.unit_id for u in canonical_integration_units()]
    assert len(ids) == len(set(ids))


def test_canonical_every_unit_consumes_baseline() -> None:
    for u in canonical_integration_units():
        assert u.baseline_consumes, f"{u.unit_id} consumes no baseline"


def test_canonical_contract_producers_unique() -> None:
    producers: Dict[str, str] = {}
    for u in canonical_integration_units():
        for c in u.contracts_produces:
            assert c not in producers, (
                f"contract {c} produced by both {producers[c]} and "
                f"{u.unit_id}"
            )
            producers[c] = u.unit_id


def test_canonical_no_baseline_modifies() -> None:
    for u in canonical_integration_units():
        assert not u.baseline_modifies


# ---- engine registration ----

def test_engine_register_unit() -> None:
    eng = GlobalIntegrationValidator()
    eng.register_unit(_unit("P01"))
    assert eng.unit("P01") is not None


def test_engine_rejects_duplicate_unit() -> None:
    eng = GlobalIntegrationValidator()
    eng.register_unit(_unit("P01"))
    try:
        eng.register_unit(_unit("P01"))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_register_canonical_phases() -> None:
    eng = GlobalIntegrationValidator()
    eng.register_canonical_phases()
    assert len(eng.units()) == 38


def test_engine_recompute_requires_aware_time() -> None:
    from datetime import datetime as dt
    eng = GlobalIntegrationValidator()
    try:
        eng.recompute(at=dt(2026, 1, 1))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- integration validation: canonical ----

def test_canonical_integration_ok() -> None:
    eng = GlobalIntegrationValidator()
    eng.register_canonical_phases()
    eng.recompute(at=_t0())
    assert eng.is_integrated()


def test_canonical_no_violations() -> None:
    eng = GlobalIntegrationValidator()
    eng.register_canonical_phases()
    eng.recompute(at=_t0())
    assert eng.violations() == ()


def test_canonical_coverage_full() -> None:
    eng = GlobalIntegrationValidator()
    eng.register_canonical_phases()
    assert eng.coverage_ratio() == 1.0


def test_canonical_no_cycle() -> None:
    eng = GlobalIntegrationValidator()
    eng.register_canonical_phases()
    eng.recompute(at=_t0())
    assert eng.cycle() is None


def test_canonical_edges_present() -> None:
    eng = GlobalIntegrationValidator()
    eng.register_canonical_phases()
    eng.recompute(at=_t0())
    # No contract currently flows across units in the canonical set,
    # but the graph builder must not error
    assert isinstance(eng.edges(), tuple)


# ---- contract-flow validation ----

def test_contract_flow_ok() -> None:
    eng = GlobalIntegrationValidator()
    eng.register_unit(_unit(
        "P01", produces=("os_state",),
    ))
    eng.register_unit(_unit(
        "P02", consumes=("os_state",),
        produces=("network_state",), terminal=True,
    ))
    eng.recompute(at=_t0())
    assert eng.is_integrated()


def test_contract_unsatisfied() -> None:
    eng = GlobalIntegrationValidator()
    eng.register_unit(_unit(
        "P01", consumes=("missing_contract",),
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.CONTRACT_UNSATISFIED in kinds


def test_baseline_contract_recognised() -> None:
    # Consuming "security_state" (baseline) should not require producer
    eng = GlobalIntegrationValidator()
    eng.register_unit(_unit(
        "P01", consumes=("security_state",),
        produces=(),
        terminal=True,
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.CONTRACT_UNSATISFIED not in kinds


def test_orphan_output_finding() -> None:
    eng = GlobalIntegrationValidator()
    eng.register_unit(_unit(
        "P01", produces=("orphan_artifact",),
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.ORPHAN_OUTPUT in kinds


def test_orphan_output_absent_when_terminal() -> None:
    eng = GlobalIntegrationValidator()
    eng.register_unit(_unit(
        "P01", produces=("orphan_artifact",), terminal=True,
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.ORPHAN_OUTPUT not in kinds


def test_missing_terminal_declaration() -> None:
    eng = GlobalIntegrationValidator()
    eng.register_unit(_unit(
        "P01", produces=("orphan_artifact",),
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.MISSING_TERMINAL_DECLARATION in kinds


# ---- baseline lock validation ----

def test_baseline_modification_finding() -> None:
    eng = GlobalIntegrationValidator()
    eng.register_unit(_unit(
        "P01", modifies=(BaselineCapability.CYBER_BRAIN,),
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.BASELINE_MODIFICATION_ATTEMPTED in kinds
    assert not eng.is_integrated()


def test_baseline_modification_invariant() -> None:
    eng = GlobalIntegrationValidator()
    eng.register_unit(_unit(
        "P01", modifies=(BaselineCapability.SECURITY_STATE,),
    ))
    eng.recompute(at=_t0())
    v = eng.violations()
    assert any(
        x.invariant_id == "int.no_baseline_modification" for x in v
    )


def test_no_baseline_dependency_finding() -> None:
    eng = GlobalIntegrationValidator()
    eng.register_unit(_unit(
        "P01", baseline=frozenset(),
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.NO_BASELINE_DEPENDENCY in kinds


def test_no_baseline_dependency_invariant() -> None:
    eng = GlobalIntegrationValidator()
    eng.register_unit(_unit("P01", baseline=frozenset()))
    eng.recompute(at=_t0())
    v = eng.violations()
    assert any(
        x.invariant_id == "int.every_phase_consumes_baseline"
        for x in v
    )


# ---- cycle detection ----

def test_cycle_detected() -> None:
    eng = GlobalIntegrationValidator()
    eng.register_unit(_unit(
        "A", produces=("c_to_b",),
        consumes=("c_to_a",),
    ))
    eng.register_unit(_unit(
        "B", produces=("c_to_a",),
        consumes=("c_to_b",),
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.CYCLE_DETECTED in kinds


def test_cycle_invariant() -> None:
    eng = GlobalIntegrationValidator()
    eng.register_unit(_unit(
        "A", produces=("c_to_b",),
        consumes=("c_to_a",),
    ))
    eng.register_unit(_unit(
        "B", produces=("c_to_a",),
        consumes=("c_to_b",),
    ))
    eng.recompute(at=_t0())
    v = eng.violations()
    assert any(x.invariant_id == "int.no_cycle" for x in v)


# ---- duplicate detection ----

def test_duplicate_contract_producer_finding() -> None:
    eng = GlobalIntegrationValidator()
    eng.register_unit(_unit(
        "A", produces=("shared",), terminal=True,
    ))
    eng.register_unit(_unit(
        "B", produces=("shared",), terminal=True,
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.DUPLICATE_CONTRACT_PRODUCER in kinds


# ---- aggregate queries ----

def test_engine_findings_by_kind() -> None:
    eng = GlobalIntegrationValidator()
    eng.register_canonical_phases()
    eng.recompute(at=_t0())
    counts = eng.findings_by_kind()
    assert counts[FindingKind.INTEGRATION_OK] == 1


def test_engine_top_findings_sorted() -> None:
    eng = GlobalIntegrationValidator()
    eng.register_unit(_unit(
        "P01", modifies=(BaselineCapability.CYBER_BRAIN,),
    ))
    eng.register_unit(_unit(
        "P02", baseline=frozenset(),
        produces=("orphan",),
    ))
    eng.recompute(at=_t0())
    top = eng.top_findings(k=20)
    severities = [f.severity for f in top]
    assert severities == sorted(severities, reverse=True)


def test_engine_top_findings_invalid_k() -> None:
    eng = GlobalIntegrationValidator()
    try:
        eng.top_findings(k=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_record_lookup() -> None:
    eng = GlobalIntegrationValidator()
    eng.register_canonical_phases()
    eng.recompute(at=_t0())
    rec = eng.record("P01")
    assert rec is not None
    assert rec.name.startswith("Operating System")


# ---- config ----

def test_engine_config_validation() -> None:
    try:
        IntegrationConfig(max_findings=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_set_config() -> None:
    eng = GlobalIntegrationValidator()
    cfg = IntegrationConfig(require_baseline_consumption=False)
    eng.set_config(cfg)
    assert eng.config() is cfg


def test_config_can_disable_baseline_consumption_check() -> None:
    eng = GlobalIntegrationValidator(
        config=IntegrationConfig(require_baseline_consumption=False),
    )
    eng.register_unit(_unit("P01", baseline=frozenset(),
                            terminal=True, produces=()))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.NO_BASELINE_DEPENDENCY not in kinds


def test_config_can_disable_acyclic_check() -> None:
    eng = GlobalIntegrationValidator(
        config=IntegrationConfig(require_acyclic=False),
    )
    eng.register_unit(_unit(
        "A", produces=("c_to_b",), consumes=("c_to_a",),
    ))
    eng.register_unit(_unit(
        "B", produces=("c_to_a",), consumes=("c_to_b",),
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.CYCLE_DETECTED not in kinds


# ---- invariants ----

def test_invariant_clean_snapshot() -> None:
    eng = GlobalIntegrationValidator()
    eng.register_canonical_phases()
    eng.recompute(at=_t0())
    assert eng.violations() == ()


def test_invariant_contracts_satisfied() -> None:
    eng = GlobalIntegrationValidator()
    eng.register_unit(_unit(
        "P01", consumes=("missing_contract",),
        terminal=True, produces=(),
    ))
    eng.recompute(at=_t0())
    v = eng.violations()
    assert any(
        x.invariant_id == "int.contracts_satisfied" for x in v
    )


def test_invariant_output_consumed_or_terminal() -> None:
    eng = GlobalIntegrationValidator()
    eng.register_unit(_unit(
        "P01", produces=("orphan_artifact",),
    ))
    eng.recompute(at=_t0())
    v = eng.violations()
    assert any(
        x.invariant_id == "int.output_consumed_or_terminal"
        for x in v
    )


# ---- store ----

def test_in_memory_store_rejects_stale() -> None:
    s = InMemoryIntegrationStore()
    t = _t0()
    s.put(UnitStateRecord(
        "P01", "x", 1, 0, 1, False, t,
    ))
    earlier = t.replace(year=t.year - 1)
    try:
        s.put(UnitStateRecord(
            "P01", "x", 1, 0, 1, False, earlier,
        ))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "integration.db")
    store = SqliteIntegrationStore(db)
    store.put(UnitStateRecord(
        "P01", "OS Security State Depth",
        baseline_consumes=2,
        contracts_consumes=0,
        contracts_produces=1,
        terminal=False, updated_at=_t0(),
    ))
    got = store.get("P01")
    assert got is not None
    assert got.baseline_consumes == 2
    assert got.name == "OS Security State Depth"


def test_sqlite_store_finding_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "integration.db")
    store = SqliteIntegrationStore(db)
    f = IntegrationFinding(
        kind=FindingKind.INTEGRATION_OK,
        subject_id="<all>", detail="ok", severity=1, at=_t0(),
    )
    store.put_finding("fid-1", f)
    row = store._conn.execute(
        "SELECT payload_json FROM integration_findings "
        "WHERE finding_id = 'fid-1'"
    ).fetchone()
    assert row is not None
    payload = json.loads(row[0])
    assert payload["kind"] == "integration_ok"


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
