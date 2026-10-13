"""
HYDRA POST-CORE — PHASE 25: CYBER DIGITAL-TWIN EXTENSION
===========================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * Extension-layer domain — 13 twin domains including FUTURE_TECH
  * Twin-projection model — augments the *existing* digital twin with:
      - trust state
      - authority state
      - control effectiveness (measured, not merely present)
      - recovery state
      - future-technology projection
  * Cross-domain dependency graph
  * Emergent attack-surface analysis across domains
  * State-transition rules on twin nodes
  * Findings — emergent surface, ineffective control, weak recovery,
    cross-domain blast radius, future-tech gap, trust/authority
    mismatch, orphaned recovery
  * Machine-checkable twin-extension invariants
  * In-memory + SQLite stores
  * Phase-25 engine facade
  * Full test suite + manual runner

Doctrine: DO NOT create a second digital twin. The existing HYDRA
digital twin remains the source of simulation. This module is a
*projection layer* that consumes twin observations (entity refs,
topology, simulated outcomes) and adds trust / authority / control /
recovery / future-technology semantics plus emergent attack-surface
analysis.

No third-party dependencies.

Run tests:
    python hydra_phase25_digital_twin_extension.py
    pytest hydra_phase25_digital_twin_extension.py -q
"""
from __future__ import annotations

import json
import math
import sqlite3
from collections import deque
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


class TwinSource(Protocol):
    """Read-only view into the *existing* digital twin.

    The extension layer never owns the twin; it reads observations from
    it. Concrete integration with HYDRA's twin is a later stage.
    """
    def entity_refs(self) -> FrozenSet[str]: ...
    def topology_links(self) -> FrozenSet[Tuple[str, str]]: ...
    def latest_outcome(self, entity_ref: str) -> Optional[Mapping[str, Any]]: ...


# =============================================================================
# SECTION 2 — DOMAIN
# =============================================================================


class TwinDomain(str, Enum):
    HARDWARE = "hardware"
    FIRMWARE = "firmware"
    OS = "os"
    NETWORK = "network"
    IDENTITY = "identity"
    APPLICATION = "application"
    API = "api"
    CLOUD = "cloud"
    CONTAINER = "container"
    DATA = "data"
    AI = "ai"
    AGENT = "agent"
    FUTURE_TECH = "future_tech"


ALL_DOMAINS: Tuple[TwinDomain, ...] = tuple(TwinDomain)


class TrustLevel(str, Enum):
    UNKNOWN = "unknown"
    UNVERIFIED = "unverified"
    VERIFIED = "verified"
    DEGRADED = "degraded"
    COMPROMISED = "compromised"


_TRUST_RANK: Mapping[TrustLevel, int] = {
    TrustLevel.COMPROMISED: 0,
    TrustLevel.DEGRADED: 1,
    TrustLevel.UNVERIFIED: 2,
    TrustLevel.UNKNOWN: 3,
    TrustLevel.VERIFIED: 4,
}


def trust_rank(t: TrustLevel) -> int:
    return _TRUST_RANK[t]


class AuthorityState(str, Enum):
    NONE = "none"
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    ADMIN = "admin"


_AUTH_RANK: Mapping[AuthorityState, int] = {
    AuthorityState.NONE: 0,
    AuthorityState.READ: 1,
    AuthorityState.WRITE: 2,
    AuthorityState.EXECUTE: 3,
    AuthorityState.ADMIN: 4,
}


def authority_rank(a: AuthorityState) -> int:
    return _AUTH_RANK[a]


class RecoveryState(str, Enum):
    UNTESTED = "untested"
    TESTED_FAILED = "tested_failed"
    TESTED_OK = "tested_ok"
    VERIFIED_BASELINE = "verified_baseline"


_RECOVERY_RANK: Mapping[RecoveryState, int] = {
    RecoveryState.UNTESTED: 0,
    RecoveryState.TESTED_FAILED: 1,
    RecoveryState.TESTED_OK: 2,
    RecoveryState.VERIFIED_BASELINE: 3,
}


def recovery_rank(r: RecoveryState) -> int:
    return _RECOVERY_RANK[r]


class FindingKind(str, Enum):
    EMERGENT_ATTACK_SURFACE = "emergent_attack_surface"
    INEFFECTIVE_CONTROL = "ineffective_control"
    WEAK_RECOVERY = "weak_recovery"
    CROSS_DOMAIN_BLAST_RADIUS = "cross_domain_blast_radius"
    FUTURE_TECH_GAP = "future_tech_gap"
    TRUST_AUTHORITY_MISMATCH = "trust_authority_mismatch"
    ORPHANED_RECOVERY = "orphaned_recovery"
    DISCONNECTED_FUTURE_TECH = "disconnected_future_tech"


@dataclass(frozen=True)
class TwinFinding:
    kind: FindingKind
    subject_id: str
    domain: Optional[TwinDomain]
    detail: str
    severity: int
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        if not 1 <= self.severity <= 5:
            raise ValueError("severity must be in [1,5]")


# =============================================================================
# SECTION 3 — TWIN PROJECTION
# =============================================================================


@dataclass(frozen=True)
class TwinNode:
    """A projection of an existing twin entity, augmented with
    trust / authority / control / recovery / future-tech semantics.

    `entity_ref` points into the existing HYDRA twin; this node does
    not *own* the entity.
    """
    node_id: str
    entity_ref: str
    domain: TwinDomain
    criticality: float
    trust: TrustLevel
    authority: AuthorityState
    control_effectiveness: float
    recovery: RecoveryState
    present: bool = True
    future_tech: bool = False
    maturity: float = 1.0     # 0..1; only meaningful when future_tech
    at: Optional[datetime] = None

    def __post_init__(self) -> None:
        if not self.node_id:
            raise ValueError("node_id is required")
        if not self.entity_ref:
            raise ValueError("entity_ref is required")
        if not 0.0 <= self.criticality <= 1.0:
            raise ValueError("criticality must be within [0,1]")
        if not 0.0 <= self.control_effectiveness <= 1.0:
            raise ValueError("control_effectiveness must be within [0,1]")
        if not 0.0 <= self.maturity <= 1.0:
            raise ValueError("maturity must be within [0,1]")
        if self.at is not None and self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

    @property
    def individual_surface(self) -> float:
        """Individual attack-surface score for this node alone.

        Higher = more exposed. Combines:
          * trust deficit
          * authority exposure
          * control ineffectiveness
          * recovery weakness
          * future-tech immaturity
        weighted and scaled by criticality.
        """
        trust_deficit = 1.0 - (trust_rank(self.trust) / 4.0)
        authority_exposure = authority_rank(self.authority) / 4.0
        control_deficit = 1.0 - self.control_effectiveness
        recovery_deficit = 1.0 - (recovery_rank(self.recovery) / 3.0)
        future_deficit = 0.0
        if self.future_tech and self.present:
            future_deficit = 1.0 - self.maturity

        raw = (
            0.30 * trust_deficit
            + 0.25 * authority_exposure
            + 0.20 * control_deficit
            + 0.15 * recovery_deficit
            + 0.10 * future_deficit
        )
        return max(0.0, min(1.0, raw * (0.5 + 0.5 * self.criticality)))


@dataclass(frozen=True)
class CrossDomainLink:
    link_id: str
    src_node_id: str
    dst_node_id: str
    kind: str
    weight: float             # 0 < w <= 1
    at: datetime

    def __post_init__(self) -> None:
        if not self.link_id:
            raise ValueError("link_id is required")
        if not self.src_node_id or not self.dst_node_id:
            raise ValueError("src/dst node ids required")
        if self.src_node_id == self.dst_node_id:
            raise ValueError("self-links are not allowed")
        if not self.kind:
            raise ValueError("kind is required")
        if not 0.0 < self.weight <= 1.0:
            raise ValueError("weight must be in (0,1]")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


class TwinGraph:
    """Cross-domain dependency graph over twin nodes."""

    def __init__(self) -> None:
        self._nodes: Dict[str, TwinNode] = {}
        self._out: Dict[str, List[CrossDomainLink]] = {}
        self._in: Dict[str, List[CrossDomainLink]] = {}
        self._links: Dict[str, CrossDomainLink] = {}

    # nodes

    def add_node(self, node: TwinNode) -> None:
        if node.node_id in self._nodes:
            raise ValueError(f"node {node.node_id} already exists")
        self._nodes[node.node_id] = node
        self._out.setdefault(node.node_id, [])
        self._in.setdefault(node.node_id, [])

    def node(self, node_id: str) -> TwinNode:
        n = self._nodes.get(node_id)
        if n is None:
            raise KeyError(f"unknown node {node_id}")
        return n

    def nodes(self) -> Tuple[TwinNode, ...]:
        return tuple(self._nodes.values())

    def nodes_of_domain(self, domain: TwinDomain) -> Tuple[TwinNode, ...]:
        return tuple(n for n in self._nodes.values() if n.domain is domain)

    def future_tech_nodes(self) -> Tuple[TwinNode, ...]:
        return tuple(n for n in self._nodes.values() if n.future_tech)

    def present_domains(self) -> FrozenSet[TwinDomain]:
        return frozenset(n.domain for n in self._nodes.values())

    # links

    def add_link(self, link: CrossDomainLink) -> None:
        if link.link_id in self._links:
            raise ValueError(f"link {link.link_id} already exists")
        if link.src_node_id not in self._nodes:
            raise KeyError(f"src {link.src_node_id} not registered")
        if link.dst_node_id not in self._nodes:
            raise KeyError(f"dst {link.dst_node_id} not registered")
        for existing in self._out.get(link.src_node_id, []):
            if existing.dst_node_id == link.dst_node_id \
               and existing.kind == link.kind:
                raise ValueError(
                    f"duplicate link {link.src_node_id}->"
                    f"{link.dst_node_id} ({link.kind})"
                )
        self._links[link.link_id] = link
        self._out[link.src_node_id].append(link)
        self._in[link.dst_node_id].append(link)

    def link(self, link_id: str) -> CrossDomainLink:
        l = self._links.get(link_id)
        if l is None:
            raise KeyError(f"unknown link {link_id}")
        return l

    def links(self) -> Tuple[CrossDomainLink, ...]:
        return tuple(self._links.values())

    def out_links(self, node_id: str) -> Tuple[CrossDomainLink, ...]:
        return tuple(self._out.get(node_id, ()))

    def in_links(self, node_id: str) -> Tuple[CrossDomainLink, ...]:
        return tuple(self._in.get(node_id, ()))

    def parents(self, node_id: str) -> Tuple[str, ...]:
        return tuple(l.src_node_id for l in self._in.get(node_id, ()))

    def children(self, node_id: str) -> Tuple[str, ...]:
        return tuple(l.dst_node_id for l in self._out.get(node_id, ()))

    def transitive_reach(self, node_id: str) -> Tuple[str, ...]:
        out: List[str] = []
        seen: set = set()
        stack = [node_id]
        while stack:
            cur = stack.pop()
            for l in self._out.get(cur, ()):
                if l.dst_node_id in seen:
                    continue
                seen.add(l.dst_node_id)
                out.append(l.dst_node_id)
                stack.append(l.dst_node_id)
        return tuple(out)

    def domains_reached(self, node_id: str) -> FrozenSet[TwinDomain]:
        return frozenset(
            self._nodes[nid].domain
            for nid in self.transitive_reach(node_id)
            if nid in self._nodes
        )


# =============================================================================
# SECTION 4 — EMERGENT ATTACK SURFACE
# =============================================================================


@dataclass(frozen=True)
class EmergentSurface:
    """A cross-domain combination whose joint attack surface is
    meaningfully larger than the sum of its parts.

    Detection rule: for each cross-domain edge, joint = 1 − (1−a)(1−b)
    (probability-union of the two individual surfaces, weighted by
    criticality and edge weight). If joint ≥ threshold and at least one
    endpoint has individual surface below the threshold, we call it
    emergent.
    """
    surface_id: str
    src_node_id: str
    dst_node_id: str
    src_domain: TwinDomain
    dst_domain: TwinDomain
    src_individual: float
    dst_individual: float
    joint_surface: float
    emergent_delta: float
    criticality: float
    at: datetime

    def __post_init__(self) -> None:
        for n, v in (
            ("src_individual", self.src_individual),
            ("dst_individual", self.dst_individual),
            ("joint_surface", self.joint_surface),
            ("emergent_delta", self.emergent_delta),
            ("criticality", self.criticality),
        ):
            if not 0.0 <= v <= 1.0:
                raise ValueError(f"{n} must be within [0,1]")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


@dataclass(frozen=True)
class EmergentSurfaceConfig:
    joint_threshold: float = 0.6
    individual_below: float = 0.5
    min_emergent_delta: float = 0.15

    def __post_init__(self) -> None:
        for n, v in (
            ("joint_threshold", self.joint_threshold),
            ("individual_below", self.individual_below),
            ("min_emergent_delta", self.min_emergent_delta),
        ):
            if not 0.0 <= v <= 1.0:
                raise ValueError(f"{n} must be within [0,1]")


def _joint_surface(
    a: float, b: float, *, weight: float, crit: float,
) -> float:
    """Union of two independent surfaces, modulated by edge weight and
    combined criticality."""
    union = 1.0 - (1.0 - a) * (1.0 - b)
    return max(0.0, min(1.0, union * weight * (0.5 + 0.5 * crit)))


def detect_emergent_surfaces(
    graph: TwinGraph,
    *,
    config: EmergentSurfaceConfig,
    at: datetime,
) -> Tuple[EmergentSurface, ...]:
    if at.tzinfo is None:
        raise ValueError("at must be timezone-aware")
    out: List[EmergentSurface] = []
    for link in graph.links():
        src = graph.node(link.src_node_id)
        dst = graph.node(link.dst_node_id)
        if src.domain is dst.domain:
            continue
        a = src.individual_surface
        b = dst.individual_surface
        crit = max(src.criticality, dst.criticality)
        joint = _joint_surface(a, b, weight=link.weight, crit=crit)
        delta = joint - max(a, b)
        if joint < config.joint_threshold:
            continue
        if min(a, b) > config.individual_below:
            continue
        if delta < config.min_emergent_delta:
            continue
        out.append(EmergentSurface(
            surface_id=f"emerge:{link.link_id}",
            src_node_id=src.node_id,
            dst_node_id=dst.node_id,
            src_domain=src.domain,
            dst_domain=dst.domain,
            src_individual=a,
            dst_individual=b,
            joint_surface=joint,
            emergent_delta=max(0.0, min(1.0, delta)),
            criticality=crit,
            at=at,
        ))
    out.sort(key=lambda s: (-s.joint_surface, s.surface_id))
    return tuple(out)


# =============================================================================
# SECTION 5 — INVARIANTS
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
class TwinSnapshot:
    graph: TwinGraph
    emergent_surfaces: Tuple[EmergentSurface, ...]
    findings: Tuple[TwinFinding, ...]


@dataclass(frozen=True)
class TwinInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[TwinSnapshot], Tuple[InvariantViolation, ...]]
    description: str


def _inv_trust_authority_consistency(
    snap: TwinSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for n in snap.graph.nodes():
        if not n.present:
            continue
        if authority_rank(n.authority) >= authority_rank(
            AuthorityState.EXECUTE
        ) and trust_rank(n.trust) < trust_rank(TrustLevel.VERIFIED):
            out.append(InvariantViolation(
                invariant_id="twin.trust_authority_consistency",
                severity=InvariantSeverity.CRITICAL,
                subject_id=n.node_id,
                detail=(
                    f"authority {n.authority.value} exceeds verified "
                    f"trust {n.trust.value}"
                ),
            ))
    return tuple(out)


def _inv_emergent_surface_bounded(
    snap: TwinSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for s in snap.emergent_surfaces:
        if not 0.0 <= s.joint_surface <= 1.0:
            out.append(InvariantViolation(
                invariant_id="twin.emergent_surface_bounded",
                severity=InvariantSeverity.HIGH,
                subject_id=s.surface_id,
                detail=f"joint surface {s.joint_surface} out of [0,1]",
            ))
    return tuple(out)


def _inv_future_tech_has_maturity(
    snap: TwinSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for n in snap.graph.nodes():
        if n.future_tech and n.present:
            if not 0.0 <= n.maturity <= 1.0:
                out.append(InvariantViolation(
                    invariant_id="twin.future_tech_has_maturity",
                    severity=InvariantSeverity.HIGH,
                    subject_id=n.node_id,
                    detail=f"maturity {n.maturity} out of [0,1]",
                ))
    return tuple(out)


def _inv_control_effectiveness_bounded(
    snap: TwinSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for n in snap.graph.nodes():
        if not 0.0 <= n.control_effectiveness <= 1.0:
            out.append(InvariantViolation(
                invariant_id="twin.control_effectiveness_bounded",
                severity=InvariantSeverity.HIGH,
                subject_id=n.node_id,
                detail=f"control_effectiveness {n.control_effectiveness}",
            ))
    return tuple(out)


def _inv_emergent_requires_cross_domain(
    snap: TwinSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for s in snap.emergent_surfaces:
        if s.src_domain is s.dst_domain:
            out.append(InvariantViolation(
                invariant_id="twin.emergent_requires_cross_domain",
                severity=InvariantSeverity.HIGH,
                subject_id=s.surface_id,
                detail="emergent surface within a single domain",
            ))
    return tuple(out)


def _inv_findings_have_positive_severity(
    snap: TwinSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for f in snap.findings:
        if not 1 <= f.severity <= 5:
            out.append(InvariantViolation(
                invariant_id="twin.findings_positive_severity",
                severity=InvariantSeverity.LOW,
                subject_id=f.subject_id,
                detail=f"severity {f.severity}",
            ))
    return tuple(out)


DEFAULT_INVARIANTS: Tuple[TwinInvariant, ...] = (
    TwinInvariant(
        invariant_id="twin.trust_authority_consistency",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_trust_authority_consistency,
        description="Authority must not exceed verified trust.",
    ),
    TwinInvariant(
        invariant_id="twin.emergent_surface_bounded",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_emergent_surface_bounded,
        description="Emergent surface joint score must lie within [0,1].",
    ),
    TwinInvariant(
        invariant_id="twin.future_tech_has_maturity",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_future_tech_has_maturity,
        description="Present future-tech nodes must carry maturity.",
    ),
    TwinInvariant(
        invariant_id="twin.control_effectiveness_bounded",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_control_effectiveness_bounded,
        description="Control effectiveness must lie within [0,1].",
    ),
    TwinInvariant(
        invariant_id="twin.emergent_requires_cross_domain",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_emergent_requires_cross_domain,
        description="Emergent surfaces must span different domains.",
    ),
    TwinInvariant(
        invariant_id="twin.findings_positive_severity",
        severity=InvariantSeverity.LOW,
        predicate=_inv_findings_have_positive_severity,
        description="Findings must carry a valid severity.",
    ),
)


def check_invariants(
    snap: TwinSnapshot,
    invariants: Iterable[TwinInvariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 6 — STORE
# =============================================================================


@dataclass(frozen=True)
class TwinNodeRecord:
    node_id: str
    domain: TwinDomain
    trust: TrustLevel
    authority: AuthorityState
    recovery: RecoveryState
    control_effectiveness: float
    individual_surface: float
    future_tech: bool
    updated_at: datetime


class TwinStore(Protocol):
    def put(self, record: TwinNodeRecord) -> None: ...
    def get(self, node_id: str) -> Optional[TwinNodeRecord]: ...
    def all(self) -> Tuple[TwinNodeRecord, ...]: ...


class InMemoryTwinStore:
    def __init__(self) -> None:
        self._data: Dict[str, TwinNodeRecord] = {}

    def put(self, record: TwinNodeRecord) -> None:
        existing = self._data.get(record.node_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._data[record.node_id] = record

    def get(self, node_id: str) -> Optional[TwinNodeRecord]:
        return self._data.get(node_id)

    def all(self) -> Tuple[TwinNodeRecord, ...]:
        return tuple(self._data.values())


class SqliteTwinStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS twin_nodes (
                node_id TEXT PRIMARY KEY,
                domain TEXT NOT NULL,
                trust TEXT NOT NULL,
                authority TEXT NOT NULL,
                recovery TEXT NOT NULL,
                control_effectiveness REAL NOT NULL,
                individual_surface REAL NOT NULL,
                future_tech INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS twin_findings (
                finding_id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def put(self, record: TwinNodeRecord) -> None:
        existing = self.get(record.node_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._conn.execute(
            """
            INSERT INTO twin_nodes
              (node_id, domain, trust, authority, recovery,
               control_effectiveness, individual_surface, future_tech,
               updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(node_id) DO UPDATE SET
              domain=excluded.domain,
              trust=excluded.trust,
              authority=excluded.authority,
              recovery=excluded.recovery,
              control_effectiveness=excluded.control_effectiveness,
              individual_surface=excluded.individual_surface,
              future_tech=excluded.future_tech,
              updated_at=excluded.updated_at
            """,
            (
                record.node_id, record.domain.value, record.trust.value,
                record.authority.value, record.recovery.value,
                record.control_effectiveness, record.individual_surface,
                int(record.future_tech),
                record.updated_at.isoformat(),
            ),
        )
        self._conn.commit()

    def get(self, node_id: str) -> Optional[TwinNodeRecord]:
        row = self._conn.execute(
            "SELECT domain, trust, authority, recovery, "
            "control_effectiveness, individual_surface, future_tech, "
            "updated_at FROM twin_nodes WHERE node_id = ?",
            (node_id,),
        ).fetchone()
        if row is None:
            return None
        return TwinNodeRecord(
            node_id=node_id, domain=TwinDomain(row[0]),
            trust=TrustLevel(row[1]), authority=AuthorityState(row[2]),
            recovery=RecoveryState(row[3]),
            control_effectiveness=float(row[4]),
            individual_surface=float(row[5]),
            future_tech=bool(row[6]),
            updated_at=datetime.fromisoformat(row[7]),
        )

    def all(self) -> Tuple[TwinNodeRecord, ...]:
        rows = self._conn.execute("SELECT node_id FROM twin_nodes").fetchall()
        return tuple(
            r for r in (self.get(x[0]) for x in rows) if r is not None
        )

    def put_finding(self, finding_id: str, finding: TwinFinding) -> None:
        payload = {
            "finding_id": finding_id,
            "kind": finding.kind.value,
            "subject_id": finding.subject_id,
            "domain": finding.domain.value if finding.domain else None,
            "detail": finding.detail,
            "severity": finding.severity,
            "at": finding.at.isoformat(),
        }
        self._conn.execute(
            "INSERT OR REPLACE INTO twin_findings "
            "(finding_id, payload_json) VALUES (?, ?)",
            (finding_id, json.dumps(payload, sort_keys=True)),
        )
        self._conn.commit()


# =============================================================================
# SECTION 7 — ENGINE
# =============================================================================


class TwinExtensionEngine:
    """Digital-twin extension engine.

    Reads a TwinSource (the existing HYDRA twin), maintains an
    augmented projection (trust / authority / control / recovery /
    future-tech), and produces emergent attack-surface analysis.
    """

    def __init__(
        self,
        *,
        store: Optional[TwinStore] = None,
        emergent_config: Optional[EmergentSurfaceConfig] = None,
        weak_control_threshold: float = 0.4,
        weak_recovery_below: RecoveryState = RecoveryState.TESTED_OK,
        cross_domain_reach_threshold: int = 3,
        future_tech_maturity_min: float = 0.5,
    ) -> None:
        for n, v in (
            ("weak_control_threshold", weak_control_threshold),
            ("future_tech_maturity_min", future_tech_maturity_min),
        ):
            if not 0.0 <= v <= 1.0:
                raise ValueError(f"{n} must be within [0,1]")
        if cross_domain_reach_threshold < 1:
            raise ValueError(
                "cross_domain_reach_threshold must be >= 1"
            )
        self._store: TwinStore = store or InMemoryTwinStore()
        self._graph = TwinGraph()
        self._emergent_config = emergent_config or EmergentSurfaceConfig()
        self._weak_control = weak_control_threshold
        self._weak_recovery = weak_recovery_below
        self._cross_domain_reach = cross_domain_reach_threshold
        self._future_maturity_min = future_tech_maturity_min

        self._surfaces: Tuple[EmergentSurface, ...] = ()
        self._findings: List[TwinFinding] = []
        self._violations: Tuple[InvariantViolation, ...] = ()

    # ---- registration ----------------------------------------------------

    def add_node(self, node: TwinNode) -> None:
        self._graph.add_node(node)

    def add_link(self, link: CrossDomainLink) -> None:
        self._graph.add_link(link)

    def graph(self) -> TwinGraph:
        return self._graph

    # ---- config ----------------------------------------------------------

    def set_emergent_config(self, config: EmergentSurfaceConfig) -> None:
        self._emergent_config = config

    def emergent_config(self) -> EmergentSurfaceConfig:
        return self._emergent_config

    def set_weak_control_threshold(self, x: float) -> None:
        if not 0.0 <= x <= 1.0:
            raise ValueError("threshold must be within [0,1]")
        self._weak_control = x

    def set_weak_recovery_state(self, state: RecoveryState) -> None:
        self._weak_recovery = state

    def set_cross_domain_reach_threshold(self, n: int) -> None:
        if n < 1:
            raise ValueError("threshold must be >= 1")
        self._cross_domain_reach = n

    def set_future_maturity_min(self, x: float) -> None:
        if not 0.0 <= x <= 1.0:
            raise ValueError("maturity min must be within [0,1]")
        self._future_maturity_min = x

    # ---- recompute -------------------------------------------------------

    def recompute(self, *, at: datetime) -> Tuple[TwinNodeRecord, ...]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

        self._surfaces = detect_emergent_surfaces(
            self._graph, config=self._emergent_config, at=at,
        )
        self._findings = []

        # Per-node findings
        records: List[TwinNodeRecord] = []
        for n in self._graph.nodes():
            self._emit_node_findings(n, at=at)
            rec = TwinNodeRecord(
                node_id=n.node_id, domain=n.domain, trust=n.trust,
                authority=n.authority, recovery=n.recovery,
                control_effectiveness=n.control_effectiveness,
                individual_surface=n.individual_surface,
                future_tech=n.future_tech, updated_at=at,
            )
            self._store.put(rec)
            records.append(rec)

        # Emergent surface findings
        for s in self._surfaces:
            self._findings.append(TwinFinding(
                kind=FindingKind.EMERGENT_ATTACK_SURFACE,
                subject_id=s.surface_id,
                domain=None,
                detail=(
                    f"cross-domain {s.src_domain.value} × "
                    f"{s.dst_domain.value}: joint {s.joint_surface:.3f} "
                    f"(src {s.src_individual:.2f}, dst "
                    f"{s.dst_individual:.2f}, delta {s.emergent_delta:.2f})"
                ),
                severity=4, at=at,
            ))

        # Cross-domain blast radius
        for n in self._graph.nodes():
            domains = self._graph.domains_reached(n.node_id)
            if len(domains) >= self._cross_domain_reach:
                self._findings.append(TwinFinding(
                    kind=FindingKind.CROSS_DOMAIN_BLAST_RADIUS,
                    subject_id=n.node_id, domain=n.domain,
                    detail=(
                        f"reach spans {len(domains)} domain(s): "
                        f"{sorted(d.value for d in domains)}"
                    ),
                    severity=4, at=at,
                ))

        # Persist findings
        if isinstance(self._store, SqliteTwinStore):
            for i, f in enumerate(self._findings):
                self._store.put_finding(f"f-{i:08d}-{f.kind.value}", f)

        self._violations = check_invariants(self.snapshot())
        return tuple(records)

    def _emit_node_findings(self, n: TwinNode, *, at: datetime) -> None:
        # Ineffective control
        if n.present and n.control_effectiveness < self._weak_control:
            self._findings.append(TwinFinding(
                kind=FindingKind.INEFFECTIVE_CONTROL,
                subject_id=n.node_id, domain=n.domain,
                detail=(
                    f"control_effectiveness {n.control_effectiveness:.2f} "
                    f"< {self._weak_control:.2f}"
                ),
                severity=4, at=at,
            ))

        # Weak recovery
        if n.present and n.criticality >= 0.6 \
           and recovery_rank(n.recovery) < recovery_rank(
               self._weak_recovery
           ):
            self._findings.append(TwinFinding(
                kind=FindingKind.WEAK_RECOVERY,
                subject_id=n.node_id, domain=n.domain,
                detail=(
                    f"recovery {n.recovery.value} below "
                    f"{self._weak_recovery.value} on criticality "
                    f"{n.criticality:.2f}"
                ),
                severity=4, at=at,
            ))

        # Trust / authority mismatch
        if n.present and authority_rank(n.authority) >= \
                authority_rank(AuthorityState.EXECUTE) \
           and trust_rank(n.trust) < trust_rank(TrustLevel.VERIFIED):
            self._findings.append(TwinFinding(
                kind=FindingKind.TRUST_AUTHORITY_MISMATCH,
                subject_id=n.node_id, domain=n.domain,
                detail=(
                    f"authority {n.authority.value} > verified trust "
                    f"{n.trust.value}"
                ),
                severity=5, at=at,
            ))

        # Future-tech gap
        if n.future_tech and n.present \
           and n.maturity < self._future_maturity_min \
           and n.control_effectiveness < self._weak_control:
            self._findings.append(TwinFinding(
                kind=FindingKind.FUTURE_TECH_GAP,
                subject_id=n.node_id, domain=TwinDomain.FUTURE_TECH,
                detail=(
                    f"future tech maturity {n.maturity:.2f} and "
                    f"control {n.control_effectiveness:.2f} below "
                    f"thresholds"
                ),
                severity=4, at=at,
            ))

        # Orphaned recovery — verified_baseline with no incoming
        # dependency edge to a control-bearing node
        if n.recovery is RecoveryState.VERIFIED_BASELINE \
           and not self._graph.in_links(n.node_id) \
           and n.domain is not TwinDomain.HARDWARE \
           and n.domain is not TwinDomain.FIRMWARE:
            self._findings.append(TwinFinding(
                kind=FindingKind.ORPHANED_RECOVERY,
                subject_id=n.node_id, domain=n.domain,
                detail="verified baseline without upstream dependency",
                severity=3, at=at,
            ))

        # Disconnected future tech (present, no links)
        if n.future_tech and n.present \
           and not self._graph.in_links(n.node_id) \
           and not self._graph.out_links(n.node_id):
            self._findings.append(TwinFinding(
                kind=FindingKind.DISCONNECTED_FUTURE_TECH,
                subject_id=n.node_id, domain=TwinDomain.FUTURE_TECH,
                detail="future-tech node present but disconnected",
                severity=3, at=at,
            ))

    # ---- queries ---------------------------------------------------------

    def emergent_surfaces(self) -> Tuple[EmergentSurface, ...]:
        return self._surfaces

    def findings(self) -> Tuple[TwinFinding, ...]:
        return tuple(self._findings)

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return self._violations

    def record(self, node_id: str) -> Optional[TwinNodeRecord]:
        return self._store.get(node_id)

    def top_surfaces(
        self, *, k: int = 10,
    ) -> Tuple[EmergentSurface, ...]:
        if k <= 0:
            raise ValueError("k must be > 0")
        return tuple(self._surfaces[:k])

    def snapshot(self) -> TwinSnapshot:
        return TwinSnapshot(
            graph=self._graph,
            emergent_surfaces=self._surfaces,
            findings=tuple(self._findings),
        )


# =============================================================================
# SECTION 8 — TESTS
# =============================================================================


def _t0() -> datetime:
    from datetime import timezone
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _node(
    nid: str, domain: TwinDomain = TwinDomain.OS, *,
    entity_ref: Optional[str] = None,
    criticality: float = 0.5,
    trust: TrustLevel = TrustLevel.VERIFIED,
    authority: AuthorityState = AuthorityState.READ,
    control_effectiveness: float = 0.9,
    recovery: RecoveryState = RecoveryState.VERIFIED_BASELINE,
    present: bool = True,
    future_tech: bool = False,
    maturity: float = 1.0,
    at: Optional[datetime] = None,
) -> TwinNode:
    return TwinNode(
        node_id=nid, entity_ref=entity_ref or f"ref:{nid}",
        domain=domain, criticality=criticality, trust=trust,
        authority=authority, control_effectiveness=control_effectiveness,
        recovery=recovery, present=present, future_tech=future_tech,
        maturity=maturity, at=at or _t0(),
    )


def _link(
    lid: str, src: str, dst: str, *,
    kind: str = "depends_on", weight: float = 0.9,
    at: Optional[datetime] = None,
) -> CrossDomainLink:
    return CrossDomainLink(
        link_id=lid, src_node_id=src, dst_node_id=dst, kind=kind,
        weight=weight, at=at or _t0(),
    )


# ---- domain ----

def test_node_requires_id() -> None:
    try:
        TwinNode(
            node_id="", entity_ref="r", domain=TwinDomain.OS,
            criticality=0.5, trust=TrustLevel.VERIFIED,
            authority=AuthorityState.READ,
            control_effectiveness=0.9,
            recovery=RecoveryState.VERIFIED_BASELINE,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_node_criticality_bounds() -> None:
    try:
        _node("n", criticality=1.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_node_control_bounds() -> None:
    try:
        _node("n", control_effectiveness=1.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_link_rejects_self() -> None:
    try:
        _link("l", "a", "a")
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_link_weight_bounds() -> None:
    try:
        _link("l", "a", "b", weight=0.0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_trust_rank_ordering() -> None:
    assert trust_rank(TrustLevel.COMPROMISED) < \
        trust_rank(TrustLevel.VERIFIED)
    assert trust_rank(TrustLevel.DEGRADED) < \
        trust_rank(TrustLevel.UNVERIFIED)


def test_authority_rank_ordering() -> None:
    assert authority_rank(AuthorityState.NONE) < \
        authority_rank(AuthorityState.READ)
    assert authority_rank(AuthorityState.EXECUTE) < \
        authority_rank(AuthorityState.ADMIN)


def test_recovery_rank_ordering() -> None:
    assert recovery_rank(RecoveryState.UNTESTED) < \
        recovery_rank(RecoveryState.VERIFIED_BASELINE)


# ---- individual surface ----

def test_individual_surface_low_for_verified() -> None:
    n = _node("n", trust=TrustLevel.VERIFIED,
              authority=AuthorityState.READ,
              control_effectiveness=1.0,
              recovery=RecoveryState.VERIFIED_BASELINE,
              criticality=0.5)
    assert n.individual_surface < 0.35


def test_individual_surface_high_for_compromised() -> None:
    n = _node("n", trust=TrustLevel.COMPROMISED,
              authority=AuthorityState.ADMIN,
              control_effectiveness=0.0,
              recovery=RecoveryState.UNTESTED,
              criticality=1.0)
    assert n.individual_surface > 0.7


def test_individual_surface_scales_with_criticality() -> None:
    low = _node("a", criticality=0.1)
    high = _node("b", criticality=1.0)
    assert high.individual_surface > low.individual_surface


def test_individual_surface_future_tech_adds_risk() -> None:
    normal = _node("a", future_tech=False)
    future = _node("b", future_tech=True, maturity=0.0)
    assert future.individual_surface > normal.individual_surface


# ---- graph ----

def test_graph_rejects_duplicate_node() -> None:
    g = TwinGraph()
    g.add_node(_node("a"))
    try:
        g.add_node(_node("a"))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_graph_rejects_duplicate_link() -> None:
    g = TwinGraph()
    g.add_node(_node("a"))
    g.add_node(_node("b"))
    g.add_link(_link("l", "a", "b", kind="depends_on"))
    try:
        g.add_link(_link("l2", "a", "b", kind="depends_on"))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_graph_unknown_endpoint_rejected() -> None:
    g = TwinGraph()
    g.add_node(_node("a"))
    try:
        g.add_link(_link("l", "a", "missing"))
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_graph_parents_children() -> None:
    g = TwinGraph()
    g.add_node(_node("a"))
    g.add_node(_node("b"))
    g.add_link(_link("l", "a", "b"))
    assert g.parents("b") == ("a",)
    assert g.children("a") == ("b",)


def test_graph_transitive_reach() -> None:
    g = TwinGraph()
    g.add_node(_node("a"))
    g.add_node(_node("b"))
    g.add_node(_node("c"))
    g.add_link(_link("l1", "a", "b"))
    g.add_link(_link("l2", "b", "c"))
    assert set(g.transitive_reach("a")) == {"b", "c"}


def test_graph_domains_reached() -> None:
    g = TwinGraph()
    g.add_node(_node("a", TwinDomain.OS))
    g.add_node(_node("b", TwinDomain.IDENTITY))
    g.add_node(_node("c", TwinDomain.DATA))
    g.add_link(_link("l1", "a", "b"))
    g.add_link(_link("l2", "b", "c"))
    domains = g.domains_reached("a")
    assert TwinDomain.IDENTITY in domains
    assert TwinDomain.DATA in domains


# ---- emergent surface ----

def test_emergent_surface_detected_across_domains() -> None:
    g = TwinGraph()
    # individually mediocre nodes but high criticality
    g.add_node(_node(
        "a", TwinDomain.IDENTITY, criticality=0.9,
        trust=TrustLevel.UNVERIFIED, authority=AuthorityState.EXECUTE,
        control_effectiveness=0.75,
        recovery=RecoveryState.UNTESTED,
    ))
    g.add_node(_node(
        "b", TwinDomain.DATA, criticality=0.9,
        trust=TrustLevel.UNVERIFIED, authority=AuthorityState.WRITE,
        control_effectiveness=0.6,
        recovery=RecoveryState.UNTESTED,
    ))
    g.add_link(_link("l", "a", "b", weight=0.95))
    surfaces = detect_emergent_surfaces(
        g, config=EmergentSurfaceConfig(), at=_t0(),
    )
    assert len(surfaces) == 1
    assert surfaces[0].src_domain is TwinDomain.IDENTITY
    assert surfaces[0].dst_domain is TwinDomain.DATA


def test_emergent_surface_skips_same_domain() -> None:
    g = TwinGraph()
    g.add_node(_node(
        "a", TwinDomain.IDENTITY, criticality=0.9,
        trust=TrustLevel.UNVERIFIED, authority=AuthorityState.EXECUTE,
        control_effectiveness=0.4,
        recovery=RecoveryState.UNTESTED,
    ))
    g.add_node(_node(
        "b", TwinDomain.IDENTITY, criticality=0.9,
        trust=TrustLevel.UNVERIFIED, authority=AuthorityState.EXECUTE,
        control_effectiveness=0.4,
        recovery=RecoveryState.UNTESTED,
    ))
    g.add_link(_link("l", "a", "b", weight=0.95))
    surfaces = detect_emergent_surfaces(
        g, config=EmergentSurfaceConfig(), at=_t0(),
    )
    assert surfaces == ()


def test_emergent_surface_skips_when_both_high_individual() -> None:
    # Both nodes already individually exposed → not emergent
    g = TwinGraph()
    g.add_node(_node(
        "a", TwinDomain.IDENTITY, criticality=1.0,
        trust=TrustLevel.COMPROMISED, authority=AuthorityState.ADMIN,
        control_effectiveness=0.0,
        recovery=RecoveryState.UNTESTED,
    ))
    g.add_node(_node(
        "b", TwinDomain.DATA, criticality=1.0,
        trust=TrustLevel.COMPROMISED, authority=AuthorityState.ADMIN,
        control_effectiveness=0.0,
        recovery=RecoveryState.UNTESTED,
    ))
    g.add_link(_link("l", "a", "b", weight=0.95))
    surfaces = detect_emergent_surfaces(
        g, config=EmergentSurfaceConfig(individual_below=0.5),
        at=_t0(),
    )
    assert surfaces == ()


def test_emergent_surface_requires_aware_time() -> None:
    from datetime import datetime as dt
    g = TwinGraph()
    try:
        detect_emergent_surfaces(g, config=EmergentSurfaceConfig(),
                                 at=dt(2026, 1, 1))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- engine ----

def test_engine_adds_nodes_and_links() -> None:
    eng = TwinExtensionEngine()
    eng.add_node(_node("a"))
    eng.add_node(_node("b"))
    eng.add_link(_link("l", "a", "b"))
    assert len(eng.graph().links()) == 1


def test_engine_recompute_produces_records() -> None:
    eng = TwinExtensionEngine()
    eng.add_node(_node("a"))
    eng.add_node(_node("b", TwinDomain.IDENTITY))
    eng.add_link(_link("l", "a", "b"))
    records = eng.recompute(at=_t0())
    assert len(records) == 2


def test_engine_ineffective_control_finding() -> None:
    eng = TwinExtensionEngine(weak_control_threshold=0.5)
    eng.add_node(_node("a", control_effectiveness=0.1))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.INEFFECTIVE_CONTROL in kinds


def test_engine_weak_recovery_finding() -> None:
    eng = TwinExtensionEngine(
        weak_recovery_below=RecoveryState.TESTED_OK,
    )
    eng.add_node(_node(
        "a", criticality=0.9,
        recovery=RecoveryState.UNTESTED,
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.WEAK_RECOVERY in kinds


def test_engine_trust_authority_mismatch_finding() -> None:
    eng = TwinExtensionEngine()
    eng.add_node(_node(
        "a", trust=TrustLevel.UNVERIFIED,
        authority=AuthorityState.EXECUTE,
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.TRUST_AUTHORITY_MISMATCH in kinds


def test_engine_future_tech_gap_finding() -> None:
    eng = TwinExtensionEngine()
    eng.add_node(_node(
        "a", domain=TwinDomain.FUTURE_TECH,
        future_tech=True, maturity=0.1,
        control_effectiveness=0.1,
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.FUTURE_TECH_GAP in kinds


def test_engine_disconnected_future_tech_finding() -> None:
    eng = TwinExtensionEngine()
    eng.add_node(_node(
        "a", domain=TwinDomain.FUTURE_TECH,
        future_tech=True, maturity=0.9,
        control_effectiveness=0.9,
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.DISCONNECTED_FUTURE_TECH in kinds


def test_engine_orphaned_recovery_finding() -> None:
    eng = TwinExtensionEngine()
    eng.add_node(_node(
        "a", domain=TwinDomain.APPLICATION,
        recovery=RecoveryState.VERIFIED_BASELINE,
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.ORPHANED_RECOVERY in kinds


def test_engine_orphaned_recovery_skips_hardware() -> None:
    eng = TwinExtensionEngine()
    eng.add_node(_node(
        "a", domain=TwinDomain.HARDWARE,
        recovery=RecoveryState.VERIFIED_BASELINE,
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.ORPHANED_RECOVERY not in kinds


def test_engine_emergent_surface_finding() -> None:
    eng = TwinExtensionEngine()
    eng.add_node(_node(
        "a", TwinDomain.IDENTITY, criticality=0.9,
        trust=TrustLevel.UNVERIFIED, authority=AuthorityState.EXECUTE,
        control_effectiveness=0.75,
        recovery=RecoveryState.UNTESTED,
    ))
    eng.add_node(_node(
        "b", TwinDomain.DATA, criticality=0.9,
        trust=TrustLevel.UNVERIFIED, authority=AuthorityState.WRITE,
        control_effectiveness=0.6,
        recovery=RecoveryState.UNTESTED,
    ))
    eng.add_link(_link("l", "a", "b", weight=0.95))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.EMERGENT_ATTACK_SURFACE in kinds


def test_engine_cross_domain_blast_radius_finding() -> None:
    eng = TwinExtensionEngine(cross_domain_reach_threshold=2)
    eng.add_node(_node("a", TwinDomain.OS))
    eng.add_node(_node("b", TwinDomain.IDENTITY))
    eng.add_node(_node("c", TwinDomain.DATA))
    eng.add_link(_link("l1", "a", "b"))
    eng.add_link(_link("l2", "b", "c"))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.CROSS_DOMAIN_BLAST_RADIUS in kinds


def test_engine_rejects_unknown_node_link() -> None:
    eng = TwinExtensionEngine()
    eng.add_node(_node("a"))
    try:
        eng.add_link(_link("l", "a", "missing"))
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_engine_top_surfaces_sorted() -> None:
    eng = TwinExtensionEngine()
    # two pairs of high-emergence nodes
    for i in range(2):
        eng.add_node(_node(
            f"a{i}", TwinDomain.IDENTITY, criticality=0.9,
            trust=TrustLevel.UNVERIFIED,
            authority=AuthorityState.EXECUTE,
            control_effectiveness=0.4,
            recovery=RecoveryState.UNTESTED,
        ))
        eng.add_node(_node(
            f"b{i}", TwinDomain.DATA, criticality=0.9,
            trust=TrustLevel.UNVERIFIED,
            authority=AuthorityState.WRITE,
            control_effectiveness=0.4,
            recovery=RecoveryState.UNTESTED,
        ))
        eng.add_link(_link(f"l{i}", f"a{i}", f"b{i}", weight=0.95))
    eng.recompute(at=_t0())
    surfaces = eng.top_surfaces(k=10)
    strengths = [s.joint_surface for s in surfaces]
    assert strengths == sorted(strengths, reverse=True)


def test_engine_top_surfaces_invalid_k() -> None:
    eng = TwinExtensionEngine()
    try:
        eng.top_surfaces(k=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_recompute_requires_aware_time() -> None:
    from datetime import datetime as dt
    eng = TwinExtensionEngine()
    try:
        eng.recompute(at=dt(2026, 1, 1))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_record_lookup() -> None:
    eng = TwinExtensionEngine()
    eng.add_node(_node("a"))
    eng.recompute(at=_t0())
    rec = eng.record("a")
    assert rec is not None
    assert rec.trust is TrustLevel.VERIFIED


def test_engine_config_validation() -> None:
    try:
        TwinExtensionEngine(weak_control_threshold=1.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_set_weak_control() -> None:
    eng = TwinExtensionEngine()
    eng.set_weak_control_threshold(0.75)
    eng.add_node(_node("a", control_effectiveness=0.6))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.INEFFECTIVE_CONTROL in kinds


def test_engine_set_cross_domain_reach() -> None:
    eng = TwinExtensionEngine()
    eng.set_cross_domain_reach_threshold(10)
    eng.add_node(_node("a"))
    eng.recompute(at=_t0())
    assert not any(
        f.kind is FindingKind.CROSS_DOMAIN_BLAST_RADIUS
        for f in eng.findings()
    )


# ---- invariants ----

def test_invariant_clean_snapshot() -> None:
    eng = TwinExtensionEngine()
    eng.add_node(_node("a", trust=TrustLevel.VERIFIED,
                       authority=AuthorityState.EXECUTE,
                       control_effectiveness=0.9,
                       recovery=RecoveryState.VERIFIED_BASELINE))
    eng.recompute(at=_t0())
    assert eng.violations() == ()


def test_invariant_trust_authority_consistency() -> None:
    eng = TwinExtensionEngine()
    eng.add_node(_node(
        "bad", trust=TrustLevel.UNVERIFIED,
        authority=AuthorityState.ADMIN,
    ))
    eng.recompute(at=_t0())
    v = eng.violations()
    assert any(
        x.invariant_id == "twin.trust_authority_consistency" for x in v
    )


def test_invariant_emergent_requires_cross_domain() -> None:
    # Craft an emergent surface with same domain (invariant should fail)
    bad = EmergentSurface(
        surface_id="s", src_node_id="a", dst_node_id="b",
        src_domain=TwinDomain.DATA, dst_domain=TwinDomain.DATA,
        src_individual=0.3, dst_individual=0.3,
        joint_surface=0.7, emergent_delta=0.4,
        criticality=0.9, at=_t0(),
    )
    snap = TwinSnapshot(
        graph=TwinGraph(), emergent_surfaces=(bad,), findings=(),
    )
    v = check_invariants(snap)
    assert any(
        x.invariant_id == "twin.emergent_requires_cross_domain"
        for x in v
    )


def test_invariant_emergent_surface_bounded() -> None:
    bad = object.__new__(EmergentSurface)
    object.__setattr__(bad, "surface_id", "s")
    object.__setattr__(bad, "src_node_id", "a")
    object.__setattr__(bad, "dst_node_id", "b")
    object.__setattr__(bad, "src_domain", TwinDomain.OS)
    object.__setattr__(bad, "dst_domain", TwinDomain.DATA)
    object.__setattr__(bad, "src_individual", 0.3)
    object.__setattr__(bad, "dst_individual", 0.3)
    object.__setattr__(bad, "joint_surface", 1.5)
    object.__setattr__(bad, "emergent_delta", 0.4)
    object.__setattr__(bad, "criticality", 0.9)
    object.__setattr__(bad, "at", _t0())
    snap = TwinSnapshot(
        graph=TwinGraph(), emergent_surfaces=(bad,), findings=(),
    )
    v = check_invariants(snap)
    assert any(
        x.invariant_id == "twin.emergent_surface_bounded" for x in v
    )


# ---- store ----

def test_in_memory_store_rejects_stale() -> None:
    s = InMemoryTwinStore()
    t = _t0()
    s.put(TwinNodeRecord(
        "n", TwinDomain.OS, TrustLevel.VERIFIED,
        AuthorityState.READ, RecoveryState.VERIFIED_BASELINE,
        0.9, 0.1, False, t,
    ))
    earlier = t.replace(year=t.year - 1)
    try:
        s.put(TwinNodeRecord(
            "n", TwinDomain.OS, TrustLevel.UNVERIFIED,
            AuthorityState.NONE, RecoveryState.UNTESTED,
            0.5, 0.4, False, earlier,
        ))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "twin.db")
    store = SqliteTwinStore(db)
    store.put(TwinNodeRecord(
        "n", TwinDomain.IDENTITY, TrustLevel.VERIFIED,
        AuthorityState.EXECUTE, RecoveryState.TESTED_OK,
        0.85, 0.2, False, _t0(),
    ))
    got = store.get("n")
    assert got is not None
    assert got.domain is TwinDomain.IDENTITY
    assert got.authority is AuthorityState.EXECUTE


def test_sqlite_store_finding_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "twin.db")
    store = SqliteTwinStore(db)
    f = TwinFinding(
        kind=FindingKind.EMERGENT_ATTACK_SURFACE,
        subject_id="s1", domain=None,
        detail="cross-domain", severity=4, at=_t0(),
    )
    store.put_finding("fid-1", f)
    row = store._conn.execute(
        "SELECT payload_json FROM twin_findings WHERE finding_id = 'fid-1'"
    ).fetchone()
    assert row is not None
    payload = json.loads(row[0])
    assert payload["kind"] == "emergent_attack_surface"


# =============================================================================
# SECTION 9 — MANUAL RUNNER
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
